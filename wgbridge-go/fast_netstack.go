package wgbridge

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	fastTunQueueDepth = 2048
	fastTunBatchSize  = 64
)

type fastNetTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
	dnsServers     []netip.Addr
	hasV4, hasV6   bool
}

type fastNet fastNetTun

// createFastNetTUN creates a mobile-optimized gVisor userspace TCP/UDP/IP stack with:
// - Buffered batch packet delivery (64 packets/batch, 2048 queue depth)
// - TCP RACK-TLP fast loss recovery for cellular 4G/5G jitter and packet reordering
// - TCP SACK + CUBIC congestion control
// - Global TCP_NODELAY (Nagle disabled) for zero-latency MTProto signaling
// - Enlarged 4MB max Send/Receive windows with Receive Buffer Moderation enabled
func createFastNetTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *fastNet, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	dev := &fastNetTun{
		ep:             channel.New(fastTunQueueDepth, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 16),
		incomingPacket: make(chan *buffer.View, fastTunQueueDepth),
		dnsServers:     dnsServers,
		mtu:            mtu,
	}

	// 1. Enable TCP SACK
	sackOpt := tcpip.TCPSACKEnabled(true)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// 2. Enable TCP RACK loss detection (vital on 4G/5G CGNAT links with burst loss & reordering)
	rackOpt := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rackOpt)

	// 3. Disable Nagle's algorithm globally across the tunnel stack (zero delay for MTProto frames)
	noDelayOpt := tcpip.TCPDelayEnabled(false)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &noDelayOpt)

	// 4. Enable CUBIC congestion control for high-BDP cellular links
	ccOpt := tcpip.CongestionControlOption("cubic")
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)

	// 5. Enable TCP Receive Buffer Auto-Tuning (Moderation) and high-throughput window ranges
	modOpt := tcpip.TCPModerateReceiveBufferOption(true)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &modOpt)

	txBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: 262144,
		Max:     4194304,
	}
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &txBufOpt)

	rxBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 524288,
		Max:     4194304,
	}
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBufOpt)

	dev.notifyHandle = dev.ep.AddNotify(dev)
	if tcpipErr := dev.stack.CreateNIC(1, dev.ep); tcpipErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	dev.events <- tun.EventUp
	return dev, (*fastNet)(dev), nil
}

func (tun *fastNetTun) Name() (string, error) {
	return "go", nil
}

func (tun *fastNetTun) File() *os.File {
	return nil
}

func (tun *fastNetTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *fastNetTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	view.Release()
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	count := 1

	// Opportunistically drain queued outbound tunnel packets in a single batch
	maxBatch := len(buf)
	for count < maxBatch {
		select {
		case nextView, ok := <-tun.incomingPacket:
			if !ok {
				return count, nil
			}
			rn, rErr := nextView.Read(buf[count][offset:])
			nextView.Release()
			if rErr != nil {
				return count, nil
			}
			sizes[count] = rn
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (tun *fastNetTun) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		pkb.DecRef()
	}
	return len(buf), nil
}

func (tun *fastNetTun) WriteNotify() {
	for {
		pkt := tun.ep.Read()
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		select {
		case tun.incomingPacket <- view:
		default:
			view.Release()
		}
	}
}

func (tun *fastNetTun) Close() error {
	tun.stack.RemoveNIC(1)
	tun.stack.Close()
	tun.ep.RemoveNotify(tun.notifyHandle)
	tun.ep.Close()

	if tun.events != nil {
		close(tun.events)
	}
	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}
	return nil
}

func (tun *fastNetTun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *fastNetTun) BatchSize() int {
	return fastTunBatchSize
}

func convertToFullAddrFast(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (fnet *fastNet) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddrFast(addr)
	return gonet.DialContextTCP(ctx, fnet.stack, fa, pn)
}

func (fnet *fastNet) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := convertToFullAddrFast(addr)
	return gonet.ListenTCP(fnet.stack, fa, pn)
}

func (fnet *fastNet) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return fnet.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return fnet.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (fnet *fastNet) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddrFast(laddr)
		lfa = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddrFast(raddr)
		rfa = &addr
	}
	return gonet.DialUDP(fnet.stack, lfa, rfa, pn)
}

func (fnet *fastNet) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
	}
	return fnet.DialUDPAddrPort(la, ra)
}

func (fnet *fastNet) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return fnet.DialUDP(laddr, nil)
}

var fastProtoSplitter = regexp.MustCompile(`^(tcp|udp)(4|6)?$`)

func (fnet *fastNet) LookupContextHost(ctx context.Context, host string) ([]netip.Addr, error) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" || strings.EqualFold(trimmed, "localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if ip, err := netip.ParseAddr(trimmed); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	// Resolve domain inside the tunnel via configured tunnel DNS servers
	clean := strings.TrimSuffix(trimmed, ".")
	if !strings.HasSuffix(clean, ".") {
		clean += "."
	}
	dn, err := dnsmessage.NewName(clean)
	if err != nil {
		return nil, err
	}
	servers := fnet.dnsServers
	if len(servers) == 0 {
		servers = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	for _, srv := range servers {
		qCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		uConn, dErr := fnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(srv, 53))
		if dErr != nil {
			cancel()
			continue
		}
		if dl, ok := qCtx.Deadline(); ok {
			_ = uConn.SetDeadline(dl)
		}
		txID := uint16(rand.Intn(65535))
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               txID,
				RecursionDesired: true,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dn,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		packed, pErr := msg.Pack()
		if pErr != nil {
			_ = uConn.Close()
			cancel()
			continue
		}
		_, wErr := uConn.Write(packed)
		if wErr != nil {
			_ = uConn.Close()
			cancel()
			continue
		}
		respBuf := make([]byte, 1500)
		rn, rErr := uConn.Read(respBuf)
		_ = uConn.Close()
		cancel()
		if rErr != nil || rn <= 0 {
			continue
		}
		var parser dnsmessage.Parser
		hdr, hErr := parser.Start(respBuf[:rn])
		if hErr != nil || hdr.ID != txID {
			continue
		}
		_ = parser.SkipAllQuestions()
		var out []netip.Addr
		for {
			ah, aErr := parser.AnswerHeader()
			if aErr != nil {
				break
			}
			if ah.Type == dnsmessage.TypeA {
				ar, errA := parser.AResource()
				if errA == nil {
					out = append(out, netip.AddrFrom4(ar.A))
				}
			} else {
				_ = parser.SkipAnswer()
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, errors.New("tunnel DNS lookup failed")
}

func (fnet *fastNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	matches := fastProtoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	var acceptV4, acceptV6 bool
	if len(matches[2]) == 0 {
		acceptV4 = true
		acceptV6 = true
	} else {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}

	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("invalid port")}
	}

	// Fast path for direct IP literals (99.9% of Telegram MTProto and VoIP traffic): zero DNS lookup overhead!
	if directIP, pErr := netip.ParseAddr(host); pErr == nil {
		unmapped := directIP.Unmap()
		target := netip.AddrPortFrom(unmapped, uint16(port))
		switch matches[1] {
		case "tcp":
			return fnet.DialContextTCPAddrPort(ctx, target)
		case "udp":
			return fnet.DialUDPAddrPort(netip.AddrPort{}, target)
		}
	}

	ips, err := fnet.LookupContextHost(ctx, host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no suitable address found")
		}
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	var firstErr error
	for _, ip := range ips {
		unmapped := ip.Unmap()
		if (unmapped.Is4() && !acceptV4) || (unmapped.Is6() && !acceptV6) {
			continue
		}
		target := netip.AddrPortFrom(unmapped, uint16(port))
		var c net.Conn
		switch matches[1] {
		case "tcp":
			c, err = fnet.DialContextTCPAddrPort(ctx, target)
		case "udp":
			c, err = fnet.DialUDPAddrPort(netip.AddrPort{}, target)
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no reachable address")
	}
	return nil, firstErr
}

func (fnet *fastNet) Dial(network, address string) (net.Conn, error) {
	return fnet.DialContext(context.Background(), network, address)
}
