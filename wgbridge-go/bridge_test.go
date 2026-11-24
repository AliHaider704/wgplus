package wgbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type localNetDialer struct{}

func (localNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func generateTestKeypairHex(t *testing.T) (privHex string, pubHex string) {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	privHex = hex.EncodeToString(raw[:])
	pub, err := derivePublicKeyFromHex(privHex)
	if err != nil {
		t.Fatalf("derivePublicKeyFromHex failed: %v", err)
	}
	pubHex = hex.EncodeToString(pub[:])
	return privHex, pubHex
}

type localWgPeerServer struct {
	dev      *device.Device
	tnet     *netstack.Net
	udpPort  int
	privHex  string
	pubHex   string
	closeAll func()
}

func startLocalWgServer(
	t *testing.T,
	serverIP string,
	mtu int,
	clientPubHex string,
	pskHex string,
	awgParams string,
) *localWgPeerServer {
	t.Helper()
	srvPriv, srvPub := generateTestKeypairHex(t)
	awgCfg, err := parseAwgConfig(awgParams)
	if err != nil {
		t.Fatalf("parseAwgConfig server failed: %v", err)
	}

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(serverIP)},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		mtu,
	)
	if err != nil {
		t.Fatalf("server CreateNetTUN failed: %v", err)
	}

	bindImpl, err := newAwgBind(newPlatformBind(), awgCfg, srvPriv, clientPubHex)
	if err != nil {
		t.Fatalf("server newAwgBind failed: %v", err)
	}

	dev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", srvPriv)
	fmt.Fprintf(&uapi, "listen_port=0\n")
	fmt.Fprintf(&uapi, "public_key=%s\n", clientPubHex)
	if pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", pskHex)
	}
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")

	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		t.Fatalf("server IpcSet failed: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("server Up failed: %v", err)
	}

	ipcGet, err := dev.IpcGet()
	if err != nil {
		dev.Close()
		t.Fatalf("server IpcGet failed: %v", err)
	}
	listenPort := 0
	for _, line := range strings.Split(ipcGet, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "listen_port=") {
			_, _ = fmt.Sscanf(strings.TrimPrefix(line, "listen_port="), "%d", &listenPort)
		}
	}
	if listenPort <= 0 {
		dev.Close()
		t.Fatalf("server listen_port not assigned: %s", ipcGet)
	}

	return &localWgPeerServer{
		dev:     dev,
		tnet:    tnet,
		udpPort: listenPort,
		privHex: srvPriv,
		pubHex:  srvPub,
		closeAll: func() {
			dev.Close()
		},
	}
}

type udpLinkProxy struct {
	addr              string
	cleartextWgFrames atomic.Int64
	junkSizedFrames   atomic.Int64
	totalFrames       atomic.Int64
	droppedOversized  atomic.Int64
	closeFn           func()
}

func startUdpLinkProxy(
	t *testing.T,
	serverPort int,
	maxOuterUdpBytes int,
	artificialDelay time.Duration,
	junkMin int,
	junkMax int,
) *udpLinkProxy {
	t.Helper()
	proxyConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("proxy ListenUDP failed: %v", err)
	}
	srvConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort})
	if err != nil {
		_ = proxyConn.Close()
		t.Fatalf("proxy DialUDP failed: %v", err)
	}

	p := &udpLinkProxy{
		addr: fmt.Sprintf("127.0.0.1:%d", proxyConn.LocalAddr().(*net.UDPAddr).Port),
		closeFn: func() {
			_ = proxyConn.Close()
			_ = srvConn.Close()
		},
	}

	var clientAddrVal atomic.Value
	inspectPacket := func(pkt []byte) {
		p.totalFrames.Add(1)
		if len(pkt) >= 4 {
			hdr := binary.LittleEndian.Uint32(pkt[0:4])
			if (hdr == 1 && len(pkt) == 148) ||
				(hdr == 2 && len(pkt) == 92) ||
				(hdr == 3 && len(pkt) == 64) ||
				(hdr == 4 && len(pkt) >= 32) {
				p.cleartextWgFrames.Add(1)
			}
		}
		if junkMin > 0 && len(pkt) >= junkMin && len(pkt) <= junkMax {
			p.junkSizedFrames.Add(1)
		}
	}

	// Client -> Server
	go func() {
		buf := make([]byte, 65535)
		for {
			n, cAddr, rErr := proxyConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			clientAddrVal.Store(cAddr)
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			inspectPacket(pkt)
			if maxOuterUdpBytes > 0 && n > maxOuterUdpBytes {
				p.droppedOversized.Add(1)
				continue
			}
			if artificialDelay > 0 {
				time.AfterFunc(artificialDelay, func() {
					_, _ = srvConn.Write(pkt)
				})
			} else {
				_, _ = srvConn.Write(pkt)
			}
		}
	}()

	// Server -> Client
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rErr := srvConn.Read(buf)
			if rErr != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			inspectPacket(pkt)
			if maxOuterUdpBytes > 0 && n > maxOuterUdpBytes {
				p.droppedOversized.Add(1)
				continue
			}
			cAny := clientAddrVal.Load()
			if cAddr, ok := cAny.(*net.UDPAddr); ok && cAddr != nil {
				if artificialDelay > 0 {
					time.AfterFunc(artificialDelay, func() {
						_, _ = proxyConn.WriteToUDP(pkt, cAddr)
					})
				} else {
					_, _ = proxyConn.WriteToUDP(pkt, cAddr)
				}
			}
		}
	}()

	return p
}

func dialSocks5TcpIPv4(socksPort int, ip [4]byte, dstPort uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		return nil, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil || greet[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("SOCKS5 greet err=%v resp=%v", err, greet)
	}
	req := []byte{
		0x05, 0x01, 0x00, 0x01,
		ip[0], ip[1], ip[2], ip[3],
		byte(dstPort >> 8), byte(dstPort & 0xff),
	}
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		_ = c.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("SOCKS5 connect rejected with code 0x%02x", resp[1])
	}
	return c, nil
}

func TestKeyNormalizationAndMTU(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	got, err := normalizeHexKey(hexKey)
	if err != nil || got != hexKey {
		t.Fatalf("expected valid hex key, got=%q err=%v", got, err)
	}

	b64Key := "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="
	gotB64, err := normalizeHexKey(b64Key)
	if err != nil || gotB64 != hexKey {
		t.Fatalf("expected normalized b64 key %q, got=%q err=%v", hexKey, gotB64, err)
	}

	if normalizeMTU(0) != 1280 || normalizeMTU(1100) != 1280 || normalizeMTU(1500) != 1420 || normalizeMTU(1380) != 1380 {
		t.Fatalf("unexpected MTU normalization bounds")
	}
}

func TestTunnelLifecycleWithPresharedKeyAndStats(t *testing.T) {
	priv, _ := generateTestKeypairHex(t)
	_, pub := generateTestKeypairHex(t)
	psk := "e85a26586e1f2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a172"

	port, err := StartTunnelWithOptions(priv, psk, "10.66.66.2/32", "1.1.1.1", pub, "127.0.0.1:51820", 25, 1360)
	if err != nil {
		t.Fatalf("StartTunnelWithOptions failed: %v", err)
	}
	defer StopTunnel()

	if !IsRunning() || GetActivePort() != port || port <= 0 {
		t.Fatalf("expected active tunnel on positive port, got port=%d", port)
	}

	stats := GetTunnelStats()
	if !strings.Contains(stats, "rx_bytes=") || !strings.Contains(stats, "tx_bytes=") || !strings.Contains(stats, "last_handshake_time_sec=") {
		t.Fatalf("unexpected UAPI stats output: %q", stats)
	}

	if err := UpdatePeerEndpoint("127.0.0.1:51821"); err != nil {
		t.Fatalf("UpdatePeerEndpoint failed: %v", err)
	}

	StopTunnel()
	if IsRunning() || GetActivePort() != 0 {
		t.Fatalf("expected tunnel stopped")
	}
}

func TestSocks5UdpAssociateVoipRelay(t *testing.T) {
	echoUdp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed binding mock echo UDP: %v", err)
	}
	defer echoUdp.Close()
	echoPort := echoUdp.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := echoUdp.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			replyPayload := append([]byte("VOIP_ACK:"), buf[:n]...)
			_, _ = echoUdp.WriteToUDP(replyPayload, addr)
		}
	}()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed binding test SOCKS5 TCP: %v", err)
	}
	defer socksLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			c, aErr := socksLn.Accept()
			if aErr != nil {
				return
			}
			go handleSocks5Client(ctx, c, localNetDialer{})
		}
	}()

	ctrl, err := net.DialTimeout("tcp", socksLn.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("failed dialing SOCKS5 TCP: %v", err)
	}
	defer ctrl.Close()

	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting write failed: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, greet); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("unexpected greeting response: %v err=%v", greet, err)
	}

	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("UDP ASSOCIATE request failed: %v", err)
	}
	assocResp := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, assocResp); err != nil || assocResp[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed: resp=%v err=%v", assocResp, err)
	}
	relayPort := int(binary.BigEndian.Uint16(assocResp[8:10]))
	if relayPort <= 0 {
		t.Fatalf("invalid relay port: %d", relayPort)
	}

	clientUdp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relayPort})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer clientUdp.Close()
	_ = clientUdp.SetDeadline(time.Now().Add(3 * time.Second))

	rtpFrame := []byte("OPUS_VOICE_FRAME_001")
	pkt := make([]byte, 10+len(rtpFrame))
	pkt[0], pkt[1], pkt[2], pkt[3] = 0x00, 0x00, 0x00, 0x01
	pkt[4], pkt[5], pkt[6], pkt[7] = 127, 0, 0, 1
	binary.BigEndian.PutUint16(pkt[8:10], uint16(echoPort))
	copy(pkt[10:], rtpFrame)

	if _, err := clientUdp.Write(pkt); err != nil {
		t.Fatalf("failed sending SOCKS5 UDP packet: %v", err)
	}

	recvBuf := make([]byte, 512)
	rn, err := clientUdp.Read(recvBuf)
	if err != nil {
		t.Fatalf("failed reading SOCKS5 UDP reply: %v", err)
	}
	replyHost, replyPort, payload, err := parseSocks5UdpDatagram(recvBuf[:rn])
	if err != nil {
		t.Fatalf("invalid SOCKS5 UDP reply header: %v", err)
	}
	expectedPayload := "VOIP_ACK:OPUS_VOICE_FRAME_001"
	if string(payload) != expectedPayload {
		t.Fatalf("expected payload %q from %s:%d, got %q", expectedPayload, replyHost, replyPort, string(payload))
	}
}

// Feature 1 Test A: Full AmneziaWG 1.5 tunnel (Jc, Jmin, Jmax, S1..S4, H1..H4 ranges) + wire DPI inspection + TCP & VoIP UDP
func TestAmneziaWgFullTunnelTcpAndUdpRelayWithWireInspection(t *testing.T) {
	clientPriv, clientPub := generateTestKeypairHex(t)
	psk, _ := generateTestKeypairHex(t)

	awgSpec := "Jc=4\nJmin=60\nJmax=130\nS1=44\nS2=36\nS3=20\nS4=16\n" +
		"H1=120000100-120000200\nH2=220000100-220000200\nH3=320000100-320000200\nH4=420000100-420000200"

	srv := startLocalWgServer(t, "10.88.0.1", 1360, clientPub, psk, awgSpec)
	defer srv.closeAll()

	// Host a TCP responder on server's virtual IP 10.88.0.1:8080
	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 88, 0, 1), Port: 8080})
	if err != nil {
		t.Fatalf("server netstack ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("AWG_TUNNEL_TCP_OK"))
			}(c)
		}
	}()

	// Host a UDP VoIP responder on server's virtual IP 10.88.0.1:9999
	udpSrv, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 88, 0, 1), Port: 9999})
	if err != nil {
		t.Fatalf("server netstack ListenUDP failed: %v", err)
	}
	defer udpSrv.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, rAddr, rErr := udpSrv.ReadFrom(buf)
			if rErr != nil {
				return
			}
			_, _ = udpSrv.WriteTo(append([]byte("AWG_UDP_OK:"), buf[:n]...), rAddr)
		}
	}()

	// Route outer UDP through DPI-inspecting proxy
	dpiProxy := startUdpLinkProxy(t, srv.udpPort, 0, 0, 60, 130)
	defer dpiProxy.closeFn()

	socksPort, err := StartTunnelAdvanced(
		clientPriv,
		psk,
		"10.88.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		dpiProxy.addr,
		25,
		1360,
		awgSpec,
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced with AmneziaWG failed: %v", err)
	}
	defer StopTunnel()

	// 1. Verify TCP CONNECT over AmneziaWG tunnel
	tcpClient, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 88, 0, 1}, 8080)
	if err != nil {
		t.Fatalf("SOCKS5 TCP over AmneziaWG failed: %v", err)
	}
	if _, err := tcpClient.Write([]byte("PING")); err != nil {
		t.Fatalf("TCP write failed: %v", err)
	}
	reply, err := io.ReadAll(tcpClient)
	_ = tcpClient.Close()
	if err != nil || string(reply) != "AWG_TUNNEL_TCP_OK" {
		t.Fatalf("unexpected AmneziaWG TCP reply=%q err=%v", string(reply), err)
	}

	// 2. Verify UDP ASSOCIATE (VoIP) over AmneziaWG tunnel
	ctrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 3*time.Second)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE ctrl dial failed: %v", err)
	}
	defer ctrl.Close()
	_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	_, _ = io.ReadFull(ctrl, greet)
	_, _ = ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	assocResp := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, assocResp); err != nil || assocResp[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed over AmneziaWG: %v", err)
	}
	relayPort := int(binary.BigEndian.Uint16(assocResp[8:10]))
	uClient, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relayPort})
	if err != nil {
		t.Fatalf("DialUDP relay failed: %v", err)
	}
	defer uClient.Close()
	_ = uClient.SetDeadline(time.Now().Add(3 * time.Second))

	voipFrame := []byte("VOICE_CALL_99")
	uPkt := make([]byte, 10+len(voipFrame))
	uPkt[3] = 0x01
	uPkt[4], uPkt[5], uPkt[6], uPkt[7] = 10, 88, 0, 1
	binary.BigEndian.PutUint16(uPkt[8:10], 9999)
	copy(uPkt[10:], voipFrame)
	if _, err := uClient.Write(uPkt); err != nil {
		t.Fatalf("UDP VoIP write failed: %v", err)
	}
	uRecv := make([]byte, 256)
	un, err := uClient.Read(uRecv)
	if err != nil {
		t.Fatalf("UDP VoIP read failed: %v", err)
	}
	_, _, uPayload, err := parseSocks5UdpDatagram(uRecv[:un])
	if err != nil || string(uPayload) != "AWG_UDP_OK:VOICE_CALL_99" {
		t.Fatalf("unexpected AmneziaWG VoIP reply=%q err=%v", string(uPayload), err)
	}

	// 3. Assert DPI wire-inspection guarantees: zero cleartext WireGuard headers & Jc>=4 junk packets emitted
	if dpiProxy.cleartextWgFrames.Load() != 0 {
		t.Fatalf("DPI leak! Found %d cleartext WireGuard packets on wire", dpiProxy.cleartextWgFrames.Load())
	}
	if dpiProxy.junkSizedFrames.Load() < 4 {
		t.Fatalf("expected at least Jc=4 junk frames in [60..130] bytes, got %d", dpiProxy.junkSizedFrames.Load())
	}
}

// Feature 1 Test B: Client-only Jc/Jmin/Jmax DPI junk preset works seamlessly against a vanilla WireGuard server
func TestClientOnlyJunkPresetWorksAgainstVanillaWireGuardServer(t *testing.T) {
	clientPriv, clientPub := generateTestKeypairHex(t)
	vanillaSrv := startLocalWgServer(t, "10.89.0.1", 1280, clientPub, "", "")
	defer vanillaSrv.closeAll()

	tcpLn, err := vanillaSrv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 89, 0, 1), Port: 8081})
	if err != nil {
		t.Fatalf("vanilla server ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("VANILLA_WG_OK"))
			_ = c.Close()
		}
	}()

	dpiProxy := startUdpLinkProxy(t, vanillaSrv.udpPort, 0, 0, 50, 110)
	defer dpiProxy.closeFn()

	socksPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.89.0.2/32",
		"1.1.1.1",
		vanillaSrv.pubHex,
		dpiProxy.addr,
		25,
		1280,
		"Jc=3\nJmin=50\nJmax=110",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced client-junk failed: %v", err)
	}
	defer StopTunnel()

	c, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 89, 0, 1}, 8081)
	if err != nil {
		t.Fatalf("SOCKS5 dial over vanilla server failed: %v", err)
	}
	resp, _ := io.ReadAll(c)
	_ = c.Close()
	if string(resp) != "VANILLA_WG_OK" {
		t.Fatalf("expected VANILLA_WG_OK, got %q", string(resp))
	}
	if dpiProxy.junkSizedFrames.Load() < 3 {
		t.Fatalf("expected >=3 junk packets before vanilla handshake, got %d", dpiProxy.junkSizedFrames.Load())
	}
}

// Feature 2 Test: Concurrent cryptographic handshake latency probing without interrupting active tunnel
func TestProbeEndpointHandshakeMsConcurrentAndNonDisruptive(t *testing.T) {
	// Active tunnel peer
	activePriv, activePub := generateTestKeypairHex(t)
	activeSrv := startLocalWgServer(t, "10.90.0.1", 1280, activePub, "", "")
	defer activeSrv.closeAll()

	tcpLn, err := activeSrv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 90, 0, 1), Port: 80})
	if err != nil {
		t.Fatalf("activeSrv ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("STILL_ALIVE"))
			_ = c.Close()
		}
	}()

	socksPort, err := StartTunnelAdvanced(
		activePriv,
		"",
		"10.90.0.2/32",
		"1.1.1.1",
		activeSrv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", activeSrv.udpPort),
		25,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	// Candidate 1: Fast local AmneziaWG server (~1-20ms)
	p1Priv, p1Pub := generateTestKeypairHex(t)
	awgParams := "Jc=2;Jmin=40;Jmax=80;S1=24;S2=20;H1=500100;H2=600100"
	fastSrv := startLocalWgServer(t, "10.91.0.1", 1280, p1Pub, "", awgParams)
	defer fastSrv.closeAll()

	// Candidate 2: Delayed WireGuard server (+45ms one-way => >= 85ms RTT)
	p2Priv, p2Pub := generateTestKeypairHex(t)
	slowSrv := startLocalWgServer(t, "10.92.0.1", 1280, p2Pub, "", "")
	defer slowSrv.closeAll()
	slowProxy := startUdpLinkProxy(t, slowSrv.udpPort, 0, 45*time.Millisecond, 0, 0)
	defer slowProxy.closeFn()

	// Candidate 3: Unreachable / blocked UDP port
	p3Priv, _ := generateTestKeypairHex(t)
	_, p3Pub := generateTestKeypairHex(t)
	deadConn, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	deadPort := deadConn.LocalAddr().(*net.UDPAddr).Port
	_ = deadConn.Close()

	var wg sync.WaitGroup
	var fastMs, slowMs, deadMs int
	var fastErr, slowErr, deadErr error

	wg.Add(3)
	go func() {
		defer wg.Done()
		fastMs, fastErr = ProbeEndpointHandshakeMs(
			p1Priv, "", fastSrv.pubHex, fmt.Sprintf("127.0.0.1:%d", fastSrv.udpPort), awgParams, false, 1500,
		)
	}()
	go func() {
		defer wg.Done()
		slowMs, slowErr = ProbeEndpointHandshakeMs(
			p2Priv, "", slowSrv.pubHex, slowProxy.addr, "", false, 1500,
		)
	}()
	go func() {
		defer wg.Done()
		deadMs, deadErr = ProbeEndpointHandshakeMs(
			p3Priv, "", p3Pub, fmt.Sprintf("127.0.0.1:%d", deadPort), "", false, 450,
		)
	}()
	wg.Wait()

	if fastErr != nil || fastMs < 1 || fastMs >= 80 {
		t.Fatalf("expected fastSrv RTT in [1..79]ms, got ms=%d err=%v", fastMs, fastErr)
	}
	if slowErr != nil || slowMs < 80 {
		t.Fatalf("expected slowSrv RTT >= 80ms, got ms=%d err=%v", slowMs, slowErr)
	}
	if deadErr == nil {
		t.Fatalf("expected dead server probe to fail, got ms=%d", deadMs)
	}
	if fastMs >= slowMs {
		t.Fatalf("expected fastMs (%d) < slowMs (%d)", fastMs, slowMs)
	}

	// Confirm active tunnel was completely undisturbed
	c, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 90, 0, 1}, 80)
	if err != nil {
		t.Fatalf("active tunnel disrupted during concurrent probe: %v", err)
	}
	aliveResp, _ := io.ReadAll(c)
	_ = c.Close()
	if string(aliveResp) != "STILL_ALIVE" {
		t.Fatalf("unexpected active tunnel response %q", string(aliveResp))
	}
}

// Feature 4 Test: Strict Kill Switch loopback guard deterministically rejects TCP & UDP
func TestKillSwitchLoopbackGuardRejectsAllTraffic(t *testing.T) {
	guardPort, err := StartKillSwitchGuard()
	if err != nil || guardPort <= 0 {
		t.Fatalf("StartKillSwitchGuard failed: port=%d err=%v", guardPort, err)
	}
	defer StopKillSwitchGuard()

	if GetKillSwitchPort() != guardPort {
		t.Fatalf("expected GetKillSwitchPort()=%d, got %d", guardPort, GetKillSwitchPort())
	}
	// Idempotent second call returns identical port
	guardPort2, err := StartKillSwitchGuard()
	if err != nil || guardPort2 != guardPort {
		t.Fatalf("expected idempotent port %d, got %d err=%v", guardPort, guardPort2, err)
	}

	// 1. Attempt TCP CONNECT -> must fail with SOCKS5 rejection
	if _, err := dialSocks5TcpIPv4(guardPort, [4]byte{149, 154, 167, 50}, 443); err == nil {
		t.Fatalf("Kill switch guard allowed TCP CONNECT!")
	}

	// 2. Attempt UDP ASSOCIATE -> must fail with 0x05 0x01
	ctrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", guardPort), 2*time.Second)
	if err != nil {
		t.Fatalf("Kill switch dial failed: %v", err)
	}
	_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	_, _ = io.ReadFull(ctrl, greet)
	_, _ = ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	resp := make([]byte, 10)
	_, err = io.ReadFull(ctrl, resp)
	_ = ctrl.Close()
	if err != nil || resp[1] == 0x00 {
		t.Fatalf("Kill switch guard failed to reject UDP ASSOCIATE: resp=%v err=%v", resp, err)
	}

	StopKillSwitchGuard()
	if GetKillSwitchPort() != 0 {
		t.Fatalf("expected GetKillSwitchPort()==0 after stop")
	}
}

// Feature 5 Test: Encrypted RFC 8484 DoH wireformat + ISP sinkhole/bogon rejection + live Cloudflare DoH
func TestEncryptedDoHResolverMockSinkholeAndLiveCloudflare(t *testing.T) {
	ClearDnsCache()

	buildMockDnsAnswer := func(ip [4]byte) []byte {
		var b bytes.Buffer
		// ID=0, Flags=0x8180 (QR+RD+RA, NOERROR), QD=1, AN=1
		b.Write([]byte{0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
		// Question: 3vpn4test0 QTYPE=1 QCLASS=1
		b.Write([]byte{3, 'v', 'p', 'n', 4, 't', 'e', 's', 't', 0, 0x00, 0x01, 0x00, 0x01})
		// Answer: pointer 0xC00C, TYPE=A(1), CLASS=IN(1), TTL=60, RDLEN=4, IP
		b.Write([]byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04})
		b.Write(ip[:])
		return b.Bytes()
	}

	var returnSinkhole atomic.Bool
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if returnSinkhole.Load() {
			_, _ = w.Write(buildMockDnsAnswer([4]byte{0, 0, 0, 0}))
		} else {
			_, _ = w.Write(buildMockDnsAnswer([4]byte{198, 51, 100, 77}))
		}
	}))
	defer tlsSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Valid RFC 8484 response
	addr, err := resolveHostViaDoHEndpoint(ctx, tlsSrv.Client(), tlsSrv.URL+"/dns-query", "vpn.test", false)
	if err != nil || addr.String() != "198.51.100.77" {
		t.Fatalf("expected 198.51.100.77 from DoH responder, got addr=%v err=%v", addr, err)
	}

	// 2. Sinkhole / bogon 0.0.0.0 must be rejected!
	returnSinkhole.Store(true)
	if badAddr, sErr := resolveHostViaDoHEndpoint(ctx, tlsSrv.Client(), tlsSrv.URL+"/dns-query", "vpn.test", false); sErr == nil {
		t.Fatalf("expected sinkhole IP to be rejected, got %v", badAddr)
	}

	// 3. Live encrypted DoH query against Cloudflare 1.1.1.1 / Google 8.8.8.8
	ClearDnsCache()
	resolvedLive, liveErr := ResolveEndpointDoH("one.one.one.one:51820", true)
	if liveErr != nil {
		t.Fatalf("ResolveEndpointDoH live query failed: %v", liveErr)
	}
	if resolvedLive != "1.1.1.1:51820" && resolvedLive != "1.0.0.1:51820" {
		t.Fatalf("unexpected live DoH resolution for one.one.one.one:51820 -> %q", resolvedLive)
	}
}

// Feature 6 Test A: Auto-MTU Path Finder detects simulated CGNAT/4G MTU ceiling (1360)
func TestDiscoverOptimalMTUWithSimulatedMobileLinkCeiling(t *testing.T) {
	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.77.0.1", 1420, clientPub, "", "")
	defer srv.closeAll()

	// Full-MSS TCP verifier inside tunnel: reads 3001 bytes ('M'*3000 + '\n') and replies "MTU_OK\n"
	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 77, 0, 1), Port: 9100})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 3001)
				if _, rErr := io.ReadFull(conn, buf); rErr != nil {
					return
				}
				_, _ = conn.Write([]byte("MTU_OK\n"))
			}(c)
		}
	}()

	// Cap outer WireGuard UDP datagrams at 1360 (inner IP) + 32 (WG transport header+tag) = 1392 bytes!
	// Therefore:
	// - candMtu=1420 emits 1452-byte outer UDP -> DROPPED!
	// - candMtu=1392 emits 1424-byte outer UDP -> DROPPED!
	// - candMtu=1360 emits 1392-byte outer UDP -> PASSES!
	cappedLink := startUdpLinkProxy(t, srv.udpPort, 1392, 0, 0, 0)
	defer cappedLink.closeFn()

	bestMtu, err := DiscoverOptimalMTU(
		clientPriv,
		"",
		"10.77.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		cappedLink.addr,
		"",
		false,
		"tcp://10.77.0.1:9100",
		900,
	)
	if err != nil {
		t.Fatalf("DiscoverOptimalMTU failed: %v", err)
	}
	if bestMtu != 1360 {
		t.Fatalf("expected optimal MTU 1360 under 1392-byte outer link cap, got %d", bestMtu)
	}
	if cappedLink.droppedOversized.Load() == 0 {
		t.Fatalf("expected oversized 1420/1392 frames to be tested and dropped by link limiter")
	}
}

// Feature 6 Test B: Smart Idle Battery Saver dynamically toggles persistent_keepalive_interval without dropping tunnel
func TestSmartKeepaliveDynamicAdjustment(t *testing.T) {
	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.95.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 95, 0, 1), Port: 8085})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("KEEPALIVE_TUNNEL_OK"))
			_ = c.Close()
		}
	}()

	socksPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.95.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		25,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	readKeepaliveFromUapi := func() string {
		mu.Lock()
		dev := activeDev
		mu.Unlock()
		ipc, _ := dev.IpcGet()
		for _, line := range strings.Split(ipc, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "persistent_keepalive_interval=") {
				return strings.TrimPrefix(line, "persistent_keepalive_interval=")
			}
		}
		return ""
	}

	if got := readKeepaliveFromUapi(); got != "25" {
		t.Fatalf("expected initial keepalive=25, got %q", got)
	}

	// Simulate app backgrounded > 90s -> pause keepalive (0)
	if err := SetPeerKeepalive(0); err != nil {
		t.Fatalf("SetPeerKeepalive(0) failed: %v", err)
	}
	if got := readKeepaliveFromUapi(); got != "0" {
		t.Fatalf("expected paused keepalive=0, got %q", got)
	}

	// Simulate app foregrounded -> restore keepalive (25)
	if err := SetPeerKeepalive(25); err != nil {
		t.Fatalf("SetPeerKeepalive(25) failed: %v", err)
	}
	if got := readKeepaliveFromUapi(); got != "25" {
		t.Fatalf("expected restored keepalive=25, got %q", got)
	}

	// Verify tunnel still forwards traffic immediately
	c, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 95, 0, 1}, 8085)
	if err != nil {
		t.Fatalf("tunnel broken after SetPeerKeepalive: %v", err)
	}
	resp, _ := io.ReadAll(c)
	_ = c.Close()
	if string(resp) != "KEEPALIVE_TUNNEL_OK" {
		t.Fatalf("unexpected tunnel response %q", string(resp))
	}
}

func TestForceRebindAndHandshakeAndEnsureTunnelAliveAndIpHint(t *testing.T) {
	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.96.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 96, 0, 1), Port: 8086})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("REBIND_RECOVERY_OK"))
			_ = c.Close()
		}
	}()

	// Register a stale IP hint and verify resolution fallback works
	RegisterEndpointIpHint("offline-cellular-test.invalid", "198.51.100.88")
	resolvedHint, err := ResolveEndpointDoH("offline-cellular-test.invalid:51820", false)
	if err != nil || resolvedHint != "198.51.100.88:51820" {
		t.Fatalf("expected stale IP hint fallback 198.51.100.88:51820, got %q err=%v", resolvedHint, err)
	}

	socksPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.96.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		20,
		1280,
		"Jc=3\nJmin=48\nJmax=108",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	if !ForceRebindAndHandshake() {
		t.Fatalf("expected ForceRebindAndHandshake() to succeed against live local server")
	}
	if !EnsureTunnelAlive(1000) {
		t.Fatalf("expected EnsureTunnelAlive(1000) to succeed")
	}

	c, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 96, 0, 1}, 8086)
	if err != nil {
		t.Fatalf("SOCKS5 dial after ForceRebindAndHandshake failed: %v", err)
	}
	resp, _ := io.ReadAll(c)
	_ = c.Close()
	if string(resp) != "REBIND_RECOVERY_OK" {
		t.Fatalf("expected REBIND_RECOVERY_OK, got %q", string(resp))
	}

	// Verify rapid back-to-back ForceRebindAndHandshake (<5s wireguard-go RekeyTimeout) STILL succeeds
	// and preserves monotonic RX/TX counters across peer resets
	statsBefore := GetTunnelStats()
	if !ForceRebindAndHandshake() {
		t.Fatalf("expected rapid back-to-back ForceRebindAndHandshake() to bypass 5s RekeyTimeout and succeed")
	}
	if err := UpdatePeerEndpoint(fmt.Sprintf("127.0.0.1:%d", srv.udpPort)); err != nil {
		t.Fatalf("rapid UpdatePeerEndpoint failed: %v", err)
	}
	c2, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 96, 0, 1}, 8086)
	if err != nil {
		t.Fatalf("SOCKS5 dial after rapid UpdatePeerEndpoint failed: %v", err)
	}
	resp2, _ := io.ReadAll(c2)
	_ = c2.Close()
	if string(resp2) != "REBIND_RECOVERY_OK" {
		t.Fatalf("expected REBIND_RECOVERY_OK after roaming, got %q", string(resp2))
	}
	statsAfter := GetTunnelStats()
	if statsBefore == "" || statsAfter == "" {
		t.Fatalf("expected non-empty stats before=%q after=%q", statsBefore, statsAfter)
	}
}

func TestUnifiedMuxPreservesPortAcrossKillSwitchStartupAndPause(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()

	ksPort, err := StartKillSwitchGuard()
	if err != nil || ksPort <= 0 {
		t.Fatalf("StartKillSwitchGuard failed: port=%d err=%v", ksPort, err)
	}
	defer StopKillSwitchGuard()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.97.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 97, 0, 1), Port: 8087})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, aErr := tcpLn.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("MUX_SEAMLESS_OK"))
			_ = c.Close()
		}
	}()

	// Signal startup pending and verify concurrent SOCKS5 dial waits cleanly for StartTunnelAdvanced
	SetTunnelStartupPending(true)
	dialRes := make(chan error, 1)
	go func() {
		c, dErr := dialSocks5TcpIPv4(ksPort, [4]byte{10, 97, 0, 1}, 8087)
		if dErr != nil {
			dialRes <- dErr
			return
		}
		b, _ := io.ReadAll(c)
		_ = c.Close()
		if string(b) != "MUX_SEAMLESS_OK" {
			dialRes <- fmt.Errorf("unexpected mux payload %q", string(b))
			return
		}
		dialRes <- nil
	}()

	time.Sleep(120 * time.Millisecond)
	tunPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.97.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		SetTunnelStartupPending(false)
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	if tunPort != ksPort {
		t.Fatalf("expected unified mux port %d == ksPort %d (no stale port pollution)", tunPort, ksPort)
	}
	if err := <-dialRes; err != nil {
		t.Fatalf("pending SOCKS5 dial during mux transition failed: %v", err)
	}
}

func TestUdpAssociateFullConeMultiPeerAndDomainReply(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.98.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	// Peer A (STUN-like reflector) learns client source port and tells Peer B to send back to that exact port.
	peerA, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 98, 0, 1), Port: 3478})
	if err != nil {
		t.Fatalf("ListenUDP peerA failed: %v", err)
	}
	defer peerA.Close()

	peerB, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 98, 0, 1), Port: 3479})
	if err != nil {
		t.Fatalf("ListenUDP peerB failed: %v", err)
	}
	defer peerB.Close()

	clientAddrCh := make(chan net.Addr, 2)
	go func() {
		buf := make([]byte, 512)
		for {
			n, rAddr, rErr := peerA.ReadFrom(buf)
			if rErr != nil {
				return
			}
			select {
			case clientAddrCh <- rAddr:
			default:
			}
			_, _ = peerA.WriteTo([]byte("A:"+string(buf[:n])), rAddr)
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, rAddr, rErr := peerB.ReadFrom(buf)
			if rErr != nil {
				return
			}
			select {
			case clientAddrCh <- rAddr:
			default:
			}
			_, _ = peerB.WriteTo([]byte("B:"+string(buf[:n])), rAddr)
		}
	}()

	tunPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.98.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	ctrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tunPort), 3*time.Second)
	if err != nil {
		t.Fatalf("SOCKS5 TCP dial failed: %v", err)
	}
	defer ctrl.Close()
	_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00})
	gResp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, gResp); err != nil || gResp[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting failed: %v %v", gResp, err)
	}
	_, _ = ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	aResp := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, aResp); err != nil || aResp[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed: %v %v", aResp, err)
	}
	relayPort := int(binary.BigEndian.Uint16(aResp[8:10]))

	clientUdp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relayPort})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer clientUdp.Close()
	_ = clientUdp.SetDeadline(time.Now().Add(4 * time.Second))

	buildSocksUdp := func(ip [4]byte, port uint16, payload []byte) []byte {
		pkt := make([]byte, 10+len(payload))
		pkt[3] = 0x01
		copy(pkt[4:8], ip[:])
		binary.BigEndian.PutUint16(pkt[8:10], port)
		copy(pkt[10:], payload)
		return pkt
	}

	// 1. Send to Peer A
	if _, err := clientUdp.Write(buildSocksUdp([4]byte{10, 98, 0, 1}, 3478, []byte("STUN1"))); err != nil {
		t.Fatalf("write to peerA failed: %v", err)
	}
	rxBuf := make([]byte, 512)
	rn, err := clientUdp.Read(rxBuf)
	if err != nil {
		t.Fatalf("read from peerA failed: %v", err)
	}
	rHost, rPort, rPayload, err := parseSocks5UdpDatagram(rxBuf[:rn])
	if err != nil || rHost != "10.98.0.1" || rPort != 3478 || string(rPayload) != "A:STUN1" {
		t.Fatalf("unexpected peerA reply: host=%s port=%d payload=%q err=%v", rHost, rPort, string(rPayload), err)
	}

	learnedClientAddr := <-clientAddrCh

	// 2. Full-Cone test: Peer B sends unsolicited DTLS/ICE packet back to the EXACT port learned by Peer A!
	if _, err := peerB.WriteTo([]byte("UNSOLICITED_DTLS"), learnedClientAddr); err != nil {
		t.Fatalf("unsolicited peerB WriteTo failed: %v", err)
	}
	rn, err = clientUdp.Read(rxBuf)
	if err != nil {
		t.Fatalf("full-cone unsolicited read failed (symmetric NAT bug!): %v", err)
	}
	rHost, rPort, rPayload, err = parseSocks5UdpDatagram(rxBuf[:rn])
	if err != nil || rHost != "10.98.0.1" || rPort != 3479 || string(rPayload) != "UNSOLICITED_DTLS" {
		t.Fatalf("unexpected unsolicited reply: host=%s port=%d payload=%q err=%v", rHost, rPort, string(rPayload), err)
	}

	// 3. Send from same client socket to Peer B and verify Endpoint-Independent source port matches Peer A!
	if _, err := clientUdp.Write(buildSocksUdp([4]byte{10, 98, 0, 1}, 3479, []byte("ICE2"))); err != nil {
		t.Fatalf("write to peerB failed: %v", err)
	}
	rn, err = clientUdp.Read(rxBuf)
	if err != nil {
		t.Fatalf("read from peerB failed: %v", err)
	}
	_, _, rPayload, _ = parseSocks5UdpDatagram(rxBuf[:rn])
	if string(rPayload) != "B:ICE2" {
		t.Fatalf("expected B:ICE2, got %q", string(rPayload))
	}
	peerBSeenAddr := <-clientAddrCh
	if peerBSeenAddr.String() != learnedClientAddr.String() {
		t.Fatalf("symmetric NAT regression! peerA saw %s, peerB saw %s", learnedClientAddr.String(), peerBSeenAddr.String())
	}
}

func TestEnsureTunnelAliveDoesNotWipeHealthyPeer(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.99.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	_, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.99.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	// Wait briefly for initial handshake completion
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if EnsureTunnelAlive(1500) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	epochBefore := GetRecoveryEpoch()
	for i := 0; i < 3; i++ {
		if !EnsureTunnelAlive(1500) {
			t.Fatalf("EnsureTunnelAlive returned false on healthy tunnel")
		}
	}
	epochAfter := GetRecoveryEpoch()
	if epochAfter != epochBefore {
		t.Fatalf("EnsureTunnelAlive wiped/rebound healthy peer! epoch before=%d after=%d", epochBefore, epochAfter)
	}
}

func TestEncryptDecryptBackupV1CrossPlatform(t *testing.T) {
	payload := `{"schema":1,"profiles":[{"id":"p1","name":"WARP","privateKey":"TEST_KEY_123"}]}`
	env, err := EncryptBackupV1(payload, "StrongPass!99")
	if err != nil {
		t.Fatalf("EncryptBackupV1 failed: %v", err)
	}
	if strings.Contains(env, "TEST_KEY_123") {
		t.Fatalf("encrypted backup leaked plaintext secret")
	}
	if !strings.Contains(env, `"format": "wgplus-backup-v1"`) {
		t.Fatalf("unexpected envelope format: %s", env)
	}
	if _, err := DecryptBackupV1(env, "WrongPass"); err == nil {
		t.Fatalf("expected error on wrong passphrase")
	}
	plain, err := DecryptBackupV1(env, "StrongPass!99")
	if err != nil {
		t.Fatalf("DecryptBackupV1 failed: %v", err)
	}
	if plain != payload {
		t.Fatalf("round-trip mismatch: got %q want %q", plain, payload)
	}
}

func TestIpv6FastFailOnIpv4OnlyTunnel(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.95.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tunPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.95.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	defer StopTunnel()

	start := time.Now()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tunPort), 2*time.Second)
	if err != nil {
		t.Fatalf("SOCKS5 dial failed: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	g := make([]byte, 2)
	_, _ = io.ReadFull(c, g)

	// Dial IPv6 literal 2001:67c:4e8::1 port 443 over IPv4-only tunnel
	req := make([]byte, 22)
	req[0], req[1], req[2], req[3] = 0x05, 0x01, 0x00, 0x04
	copy(req[4:20], net.ParseIP("2001:67c:4e8::1").To16())
	binary.BigEndian.PutUint16(req[20:22], 443)
	_, _ = c.Write(req)

	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("failed reading SOCKS5 IPv6 fast-fail reply: %v", err)
	}
	elapsed := time.Since(start)
	if resp[1] != 0x03 {
		t.Fatalf("expected SOCKS5 reply 0x03 (network unreachable), got 0x%02x", resp[1])
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("IPv6 fast-fail took too long (%v)", elapsed)
	}
}

func TestHopCooldownIsHandshakeHealthyAndFailFast(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	defer StopTunnel()

	clientPriv, clientPub := generateTestKeypairHex(t)
	_, deadPeerPub := generateTestKeypairHex(t)

	// Start tunnel against a non-responsive blackhole port so hsSec remains 0.
	socksPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.97.0.2/32",
		"1.1.1.1",
		deadPeerPub,
		"127.0.0.1:9",
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced dead peer failed: %v", err)
	}
	if IsHandshakeHealthy() {
		t.Fatal("expected IsHandshakeHealthy() == false when no handshake completed")
	}

	// Rapid hopActivePeer calls must be throttled by minHardHopInterval cooldown.
	epochStart := GetRecoveryEpoch()
	_ = hopActivePeer(true, true)
	epochAfterFirst := GetRecoveryEpoch()
	_ = hopActivePeer(true, true)
	_ = hopActivePeer(true, true)
	epochAfterBursts := GetRecoveryEpoch()
	if epochAfterFirst <= epochStart {
		t.Fatalf("expected first hopActivePeer to increment epoch (%d -> %d)", epochStart, epochAfterFirst)
	}
	if epochAfterBursts != epochAfterFirst {
		t.Fatalf("expected cooldown to block immediate burst hops, epoch went %d -> %d", epochAfterFirst, epochAfterBursts)
	}

	// SOCKS5 CONNECT must fail fast with 0x04 when handshake is absent (instead of hanging 12s).
	start := time.Now()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		t.Fatalf("SOCKS5 dial failed: %v", err)
	}
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	_, _ = io.ReadFull(c, greet)
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb})
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		_ = c.Close()
		t.Fatalf("failed reading SOCKS5 fail-fast response: %v", err)
	}
	_ = c.Close()
	if resp[1] != 0x04 {
		t.Fatalf("expected SOCKS5 host unreachable 0x04 when handshake missing, got 0x%02x", resp[1])
	}
	if elapsed := time.Since(start); elapsed > 4500*time.Millisecond {
		t.Fatalf("expected fail-fast SOCKS5 rejection <=4.5s, took %v", elapsed)
	}

	StopTunnel()

	// Now connect to a live peer and confirm IsHandshakeHealthy() == true.
	srv := startLocalWgServer(t, "10.97.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()
	_, err = StartTunnelAdvanced(
		clientPriv,
		"",
		"10.97.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced live peer failed: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !IsHandshakeHealthy() {
		time.Sleep(25 * time.Millisecond)
	}
	if !IsHandshakeHealthy() {
		t.Fatal("expected IsHandshakeHealthy() == true on connected live peer")
	}
}



