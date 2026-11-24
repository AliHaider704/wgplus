//go:build windows

package wgbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestVoipTunWindowsMibStructInitialization(t *testing.T) {
	// Verify Windows iphlpapi Initialize* accepts our exact Go ABI struct sizes without error/panic.
	var addrRow winMibUnicastIPAddressRow
	procInitUnicastIpAddrEntry.Call(uintptr(unsafe.Pointer(&addrRow)))
	if unsafe.Sizeof(addrRow) == 0 {
		t.Fatal("unexpected zero size for winMibUnicastIPAddressRow")
	}

	var fwdRow winMibIPForwardRow2
	procInitIpForwardEntry.Call(uintptr(unsafe.Pointer(&fwdRow)))
	if fwdRow.ValidLifetime == 0 && fwdRow.Metric == 0 {
		// ValidLifetime defaults to 0xffffffff after InitializeIpForwardEntry
		t.Fatalf("InitializeIpForwardEntry did not populate defaults: %+v", fwdRow)
	}
}

func TestVoipTunIPv4UDPBuildParseAndChecksums(t *testing.T) {
	srcIP := [4]byte{91, 108, 9, 23}
	dstIP := [4]byte{10, 254, 254, 2}
	payload := []byte{0x00, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0x11, 0x22, 0x33} // odd length tests trailing byte

	buf := make([]byte, 28+len(payload))
	n, err := buildIPv4UDPPacket(buf, srcIP, dstIP, 1400, 54321, payload, 42)
	if err != nil {
		t.Fatalf("buildIPv4UDPPacket: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("expected length %d, got %d", len(buf), n)
	}

	// RFC 1071 verification: checksum over entire valid IPv4 header must equal 0.
	if got := internetChecksum(0, buf[:20]); got != 0 {
		t.Fatalf("invalid IPv4 header checksum residual: 0x%04x", got)
	}

	// RFC 768 verification: checksum over pseudo-header + UDP header/payload must equal 0.
	var pseudo uint32
	pseudo += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	pseudo += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	pseudo += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	pseudo += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	pseudo += uint32(17)
	pseudo += uint32(uint16(8 + len(payload)))
	if got := internetChecksum(pseudo, buf[20:n]); got != 0 {
		t.Fatalf("invalid UDP checksum residual: 0x%04x", got)
	}

	gotSrc, gotDst, gotSP, gotDP, gotPayload, ok := parseIPv4UDP(buf[:n])
	if !ok {
		t.Fatal("parseIPv4UDP failed on valid packet")
	}
	if gotSrc != srcIP || gotDst != dstIP || gotSP != 1400 || gotDP != 54321 || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("parsed mismatch: src=%v dst=%v sp=%d dp=%d payload=%x", gotSrc, gotDst, gotSP, gotDP, gotPayload)
	}

	// Non-UDP packet (TCP protocol=6) must be ignored.
	tcpPkt := append([]byte(nil), buf[:n]...)
	tcpPkt[9] = 6
	if _, _, _, _, _, ok := parseIPv4UDP(tcpPkt); ok {
		t.Fatal("expected parseIPv4UDP to reject protocol=6 TCP packet")
	}

	// Fragmented packet (MF flag) must be ignored.
	fragPkt := append([]byte(nil), buf[:n]...)
	binary.BigEndian.PutUint16(fragPkt[6:8], 0x2000)
	if _, _, _, _, _, ok := parseIPv4UDP(fragPkt); ok {
		t.Fatal("expected parseIPv4UDP to reject fragmented IPv4 packet")
	}
}

func TestFilterTelegramCidrsExcludesActiveEndpointLoop(t *testing.T) {
	all := filterTelegramCidrsForEndpoint(netip.MustParseAddr("162.159.193.1"))
	if len(all) != len(telegramVoipCIDRStrings) {
		t.Fatalf("expected all %d CIDRs for non-Telegram WG endpoint, got %d", len(telegramVoipCIDRStrings), len(all))
	}

	// Endpoint inside 91.108.8.0/21 must omit that CIDR so WireGuard outer UDP never loops.
	loopSafe := filterTelegramCidrsForEndpoint(parseEndpointIPAddr("91.108.9.72:51820"))
	if len(loopSafe) != len(telegramVoipCIDRStrings)-1 {
		t.Fatalf("expected %d CIDRs after excluding overlapping range, got %d", len(telegramVoipCIDRStrings)-1, len(loopSafe))
	}
	for _, p := range loopSafe {
		if p.Contains(netip.MustParseAddr("91.108.9.72")) {
			t.Fatalf("prefix %s unexpectedly contains WireGuard endpoint 91.108.9.72", p)
		}
	}
}

type redirectDialer struct {
	targetAddr string
}

func (d redirectDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var netd net.Dialer
	return netd.DialContext(ctx, network, d.targetAddr)
}

func TestVoipTunTcpForwarderLoopback(t *testing.T) {
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp4 failed: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, aErr := echoLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a client gVisor stack acting as the Windows OS TCP/IP stack attached to Wintun.
	cliOpts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	}
	cliStack := stack.New(cliOpts)
	defer cliStack.Close()
	cliEp := channel.New(256, voipTunMTU, "")
	if tcpipErr := cliStack.CreateNIC(1, cliEp); tcpipErr != nil {
		t.Fatalf("cliStack CreateNIC: %v", tcpipErr)
	}
	_ = cliStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(voipTunLocalIPv4).WithPrefix(),
	}, stack.AddressProperties{})
	cliStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

	sess := &winVoipTunSession{
		dialer:  redirectDialer{targetAddr: echoAddr},
		ctx:     ctx,
		cancel:  cancel,
		writeCh: make(chan voipTunWriteItem, 128),
		statEnt: trackClientConnStart(voipTunClientLabel),
		nat:     make(map[voipTunNatKey]*voipTunNatEntry),
	}
	defer trackClientConnEnd(sess.statEnt)
	sess.initTcpForwarder()
	if sess.tcpEp == nil {
		t.Fatal("initTcpForwarder failed to initialize gVisor TCP endpoint")
	}
	defer func() {
		sess.closed.Store(true)
		sess.tcpStack.Close()
		sess.tcpEp.Close()
	}()

	// Pump IPv4 packets between cliEp (simulated OS) <-> sess.tcpEp (VoIP TUN forwarder).
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-sess.writeCh:
				if item.bufPtr == nil {
					continue
				}
				raw := append([]byte(nil), (*item.bufPtr)[:item.n]...)
				voipTunPktPool.Put(item.bufPtr)
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
				cliEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	}()
	go func() {
		for {
			pkt := cliEp.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			raw := append([]byte(nil), view.AsSlice()...)
			view.Release()
			inPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			sess.tcpEp.InjectInbound(header.IPv4ProtocolNumber, inPkt)
			inPkt.DecRef()
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 4*time.Second)
	defer dialCancel()
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4([4]byte{149, 154, 167, 51}),
		Port: uint16(echoPort),
	}
	conn, err := gonet.DialContextTCP(dialCtx, cliStack, fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialContextTCP over VoipTun forwarder failed: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	msg := []byte("tgcalls-tcp-reflector-ok")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("unexpected TCP payload: got %q want %q", got, msg)
	}
}

