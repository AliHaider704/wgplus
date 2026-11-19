package wgbridge

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func resetGlobalDesktopBridgeState() {
	StopHttpProxy()
	StopTunnel()
	StopKillSwitchGuard()
	SetClientGuard(nil)
	SetUdpPeerGuard(nil)
	SetSocksAuth("", "")
	SetDesktopMode(false)
	SetBlockIPv6(false)
	SetPreferredMuxPort(0)
	_ = SetCustomDoH("", "", "")
	ResetClientTelemetry()
}

func dialSocks5WithUserPass(socksPort int, user, pass string, ip [4]byte, dstPort uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := performSocks5Handshake(c, user, pass, 0x01, fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]), dstPort); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func TestDesktopTuningAndBlockIPv6(t *testing.T) {
	defer resetGlobalDesktopBridgeState()

	SetDesktopMode(true)
	SetBlockIPv6(true)

	prof := activeNetstackProfile()
	if prof.queueDepth != desktopTunQueueDepth || prof.batchSize != desktopTunBatchSize || prof.txMax != 16777216 || !prof.blockIPv6 {
		t.Fatalf("unexpected desktop netstack profile: %+v", prof)
	}

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.81.0.1", 1360, clientPub, "", "")
	defer srv.closeAll()

	_, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.81.0.2/32, fd00::2/128",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		25,
		1360,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}

	mu.Lock()
	tnet := activeTnet
	mu.Unlock()

	if _, dErr := tnet.Dial("tcp", "[2001:db8::1]:443"); dErr == nil || !strings.Contains(dErr.Error(), "IPv6 blocked") {
		t.Fatalf("expected IPv6 dial to be blocked when BlockIPv6=true, got err=%v", dErr)
	}

	SetBlockIPv6(false)
	if tnet.blockIPv6.Load() {
		t.Fatalf("expected dynamic SetBlockIPv6(false) to clear activeTnet.blockIPv6")
	}
}

func TestAwg15CpsSignaturePacketsAndReservedBytes(t *testing.T) {
	defer resetGlobalDesktopBridgeState()

	var ctr atomic.Uint32
	pkt1, err := renderCpsPacket("<b 0xc70001> <r 4><rc 5><rd 6><t><c>", &ctr)
	if err != nil {
		t.Fatalf("renderCpsPacket failed: %v", err)
	}
	if len(pkt1) != 26 {
		t.Fatalf("expected 26-byte CPS packet, got %d", len(pkt1))
	}
	if !bytes.Equal(pkt1[:3], []byte{0xc7, 0x00, 0x01}) {
		t.Fatalf("unexpected binary prefix in CPS packet: %x", pkt1[:3])
	}
	for _, ch := range pkt1[7:12] {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
			t.Fatalf("unexpected non-ASCII-letter byte in <rc 5>: %x", ch)
		}
	}
	for _, ch := range pkt1[12:18] {
		if ch < '0' || ch > '9' {
			t.Fatalf("unexpected non-digit byte in <rd 6>: %x", ch)
		}
	}
	if binary.BigEndian.Uint32(pkt1[22:26]) != 1 {
		t.Fatalf("expected first <c> counter == 1, got %d", binary.BigEndian.Uint32(pkt1[22:26]))
	}

	// Verify live tunnel with AWG 1.5 I1 signature + WARP 3-byte Reserved header
	clientPriv, clientPub := generateTestKeypairHex(t)
	awgCfgStr := "I1=<b 0xc0000001><r 16>;Jc=2;Jmin=40;Jmax=80;Reserved=12,34,56"
	srv := startLocalWgServer(t, "10.84.0.1", 1280, clientPub, "", "Reserved=12,34,56")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 84, 0, 1), Port: 8090})
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
			_, _ = c.Write([]byte("AWG15_WARP_OK"))
			_ = c.Close()
		}
	}()

	// Wire inspector ensuring I1 signature packet and Reserved bytes [12,34,56] hit the wire
	wireLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer wireLn.Close()
	srvConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srv.udpPort})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer srvConn.Close()

	var sawI1 atomic.Bool
	var sawReservedHdr atomic.Bool
	var cAddrVal atomic.Value

	go func() {
		buf := make([]byte, 4096)
		for {
			n, cAddr, rErr := wireLn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			cAddrVal.Store(cAddr)
			if n == 20 && bytes.Equal(buf[:4], []byte{0xc0, 0x00, 0x00, 0x01}) {
				sawI1.Store(true)
			}
			if n >= 32 && (buf[0] == 1 || buf[0] == 4) && buf[1] == 12 && buf[2] == 34 && buf[3] == 56 {
				sawReservedHdr.Store(true)
			}
			_, _ = srvConn.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rErr := srvConn.Read(buf)
			if rErr != nil {
				return
			}
			if ca, ok := cAddrVal.Load().(*net.UDPAddr); ok && ca != nil {
				_, _ = wireLn.WriteToUDP(buf[:n], ca)
			}
		}
	}()

	wireAddr := fmt.Sprintf("127.0.0.1:%d", wireLn.LocalAddr().(*net.UDPAddr).Port)
	socksPort, err := StartTunnelAdvanced(
		clientPriv, "", "10.84.0.2/32", "1.1.1.1", srv.pubHex, wireAddr, 25, 1280, awgCfgStr, false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced AWG 1.5 failed: %v", err)
	}

	c, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 84, 0, 1}, 8090)
	if err != nil {
		t.Fatalf("dialSocks5TcpIPv4 failed: %v", err)
	}
	resp, _ := io.ReadAll(c)
	_ = c.Close()
	if string(resp) != "AWG15_WARP_OK" {
		t.Fatalf("expected AWG15_WARP_OK, got %q", string(resp))
	}
	if !sawI1.Load() {
		t.Fatalf("expected AWG 1.5 I1 QUIC signature packet on wire before handshake")
	}
	if !sawReservedHdr.Load() {
		t.Fatalf("expected WARP Reserved bytes [12,34,56] stamped in WireGuard packet headers")
	}
}

func TestSocks5Rfc1929Auth(t *testing.T) {
	defer resetGlobalDesktopBridgeState()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.85.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 85, 0, 1), Port: 8091})
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
			_, _ = c.Write([]byte("AUTH_OK"))
			_ = c.Close()
		}
	}()

	SetSocksAuth("wguser", "wgsecret!123")
	socksPort, err := StartTunnelAdvanced(
		clientPriv, "", "10.85.0.2/32", "1.1.1.1", srv.pubHex, fmt.Sprintf("127.0.0.1:%d", srv.udpPort), 25, 1280, "", false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}

	// 1. No-auth must be rejected
	if _, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 85, 0, 1}, 8091); err == nil {
		t.Fatalf("expected unauthenticated SOCKS5 client to be rejected")
	}

	// 2. Wrong password must be rejected
	if _, err := dialSocks5WithUserPass(socksPort, "wguser", "wrongpass", [4]byte{10, 85, 0, 1}, 8091); err == nil {
		t.Fatalf("expected wrong SOCKS5 password to be rejected")
	}

	// 3. Valid RFC 1929 credentials succeed
	c, err := dialSocks5WithUserPass(socksPort, "wguser", "wgsecret!123", [4]byte{10, 85, 0, 1}, 8091)
	if err != nil {
		t.Fatalf("expected valid RFC 1929 auth to succeed: %v", err)
	}
	got, _ := io.ReadAll(c)
	_ = c.Close()
	if string(got) != "AUTH_OK" {
		t.Fatalf("expected AUTH_OK, got %q", string(got))
	}
}

func TestClientGuardBlocksUnauthorizedLocalPeer(t *testing.T) {
	defer resetGlobalDesktopBridgeState()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.86.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 86, 0, 1), Port: 8092})
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
			_, _ = c.Write([]byte("GUARD_PASSED_PAYLOAD"))
			_ = c.Close()
		}
	}()

	var allowNext atomic.Bool
	allowNext.Store(false)
	SetClientGuard(func(_ net.Addr) (string, bool) {
		if allowNext.Load() {
			return "Telegram.exe", true
		}
		return "curl.exe", false
	})

	socksPort, err := StartTunnelAdvanced(
		clientPriv, "", "10.86.0.2/32", "1.1.1.1", srv.pubHex, fmt.Sprintf("127.0.0.1:%d", srv.udpPort), 25, 1280, "", false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}

	// 1. Blocked peer
	if _, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 86, 0, 1}, 8092); err == nil {
		t.Fatalf("expected ClientGuard to block unauthorized peer")
	}

	// 2. Allowed peer
	allowNext.Store(true)
	c, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 86, 0, 1}, 8092)
	if err != nil {
		t.Fatalf("expected authorized peer to succeed: %v", err)
	}
	got, _ := io.ReadAll(c)
	_ = c.Close()
	if string(got) != "GUARD_PASSED_PAYLOAD" {
		t.Fatalf("expected GUARD_PASSED_PAYLOAD, got %q", string(got))
	}

	var stats detailedTunnelStats
	if err := json.Unmarshal([]byte(GetDetailedStatsJSON()), &stats); err != nil {
		t.Fatalf("invalid detailed stats JSON: %v", err)
	}
	if stats.BlockedLocalAttempts < 1 {
		t.Fatalf("expected blockedLocalAttempts >= 1, got %d", stats.BlockedLocalAttempts)
	}
	var foundTelegram bool
	for _, cl := range stats.Clients {
		if cl.Label == "Telegram.exe" && cl.RxBytes >= uint64(len("GUARD_PASSED_PAYLOAD")) {
			foundTelegram = true
		}
	}
	if !foundTelegram {
		t.Fatalf("expected per-client stats for Telegram.exe, got %+v", stats.Clients)
	}
}

func TestHttpConnectProxyAndKillSwitch(t *testing.T) {
	defer resetGlobalDesktopBridgeState()

	if _, err := StartKillSwitchGuard(); err != nil {
		t.Fatalf("StartKillSwitchGuard failed: %v", err)
	}
	SetSocksAuth("httpu", "httpp")
	httpPort, err := StartHttpProxy(0)
	if err != nil || httpPort <= 0 {
		t.Fatalf("StartHttpProxy failed: port=%d err=%v", httpPort, err)
	}

	sendConnect := func(authHeader string, extraBody string) (string, string, error) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), 3*time.Second)
		if err != nil {
			return "", "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		req := "CONNECT 10.82.0.1:8080 HTTP/1.1\r\nHost: 10.82.0.1:8080\r\n"
		if authHeader != "" {
			req += "Proxy-Authorization: " + authHeader + "\r\n"
		}
		req += "\r\n" + extraBody
		if _, err := io.WriteString(c, req); err != nil {
			return "", "", err
		}
		br := bufio.NewReader(c)
		statusLine, err := br.ReadString('\n')
		if err != nil {
			return "", "", err
		}
		for {
			l, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(l) == "" {
				break
			}
		}
		body, _ := io.ReadAll(br)
		return strings.TrimSpace(statusLine), string(body), nil
	}

	// 1. Missing auth -> 407
	status, _, err := sendConnect("", "")
	if err != nil || !strings.Contains(status, "407") {
		t.Fatalf("expected 407 when Basic auth missing, got status=%q err=%v", status, err)
	}

	// 2. Valid auth while tunnel down + kill switch active -> 503
	validBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("httpu:httpp"))
	status, _, err = sendConnect(validBasic, "")
	if err != nil || !strings.Contains(status, "503") {
		t.Fatalf("expected 503 when kill switch active and tunnel down, got status=%q err=%v", status, err)
	}

	// 3. Bring tunnel up and verify pipelined HTTP CONNECT tunnel
	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.82.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	tcpLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 82, 0, 1), Port: 8080})
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
				buf := make([]byte, 64)
				n, _ := conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP_CONNECT_OK:" + string(buf[:n])))
			}(c)
		}
	}()

	_, err = StartTunnelAdvanced(
		clientPriv, "", "10.82.0.2/32", "1.1.1.1", srv.pubHex, fmt.Sprintf("127.0.0.1:%d", srv.udpPort), 25, 1280, "", false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}

	status, body, err := sendConnect(validBasic, "HELLO_HTTP_CONNECT")
	if err != nil || !strings.Contains(status, "200") || body != "HTTP_CONNECT_OK:HELLO_HTTP_CONNECT" {
		t.Fatalf("expected 200 + HTTP_CONNECT_OK:HELLO_HTTP_CONNECT, got status=%q body=%q err=%v", status, body, err)
	}
}

func TestVerifyRouteAndCallsLocalRelay(t *testing.T) {
	defer resetGlobalDesktopBridgeState()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.83.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	// Mock trace HTTP server on 10.83.0.1:8088
	traceLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 83, 0, 1), Port: 8088})
	if err != nil {
		t.Fatalf("trace ListenTCP failed: %v", err)
	}
	defer traceLn.Close()
	go func() {
		for {
			c, aErr := traceLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				_, _ = conn.Read(buf)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nip=203.0.113.42\nloc=IQ\n")
			}(c)
		}
	}()

	// Mock DC TCP responder on 10.83.0.1:4431
	dcLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 83, 0, 1), Port: 4431})
	if err != nil {
		t.Fatalf("dc ListenTCP failed: %v", err)
	}
	defer dcLn.Close()
	go func() {
		for {
			c, aErr := dcLn.Accept()
			if aErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Mock UDP DNS responder on 10.83.0.1:5353
	udpSrv, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 83, 0, 1), Port: 5353})
	if err != nil {
		t.Fatalf("udp ListenUDP failed: %v", err)
	}
	defer udpSrv.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, rAddr, rErr := udpSrv.ReadFrom(buf)
			if rErr != nil {
				return
			}
			if n < 12 {
				continue
			}
			var resp bytes.Buffer
			resp.Write(buf[:2]) // echo txID
			resp.Write([]byte{0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
			resp.Write(buf[12:n]) // echo question
			resp.Write([]byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 149, 154, 167, 99})
			_, _ = udpSrv.WriteTo(resp.Bytes(), rAddr)
		}
	}()

	SetDesktopMode(true)
	SetSocksAuth("probe", "pass123")
	socksPort, err := StartTunnelAdvanced(
		clientPriv, "", "10.83.0.2/32", "1.1.1.1", srv.pubHex, fmt.Sprintf("127.0.0.1:%d", srv.udpPort), 25, 1280, "", false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}

	tgt := verifyTargets{
		traceDialAddr:   "10.83.0.1:8088",
		traceServerName: "mock.trace",
		traceUseTLS:     false,
		udpDnsTarget:    netip.MustParseAddrPort("10.83.0.1:5353"),
		dcs: []struct {
			name string
			addr string
		}{
			{name: "DC1", addr: "10.83.0.1:4431"},
		},
	}

	raw := verifyRouteAndCallsWithTargets(socksPort, "probe", "pass123", tgt)
	var report routeAndCallsReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("unmarshal VerifyRouteAndCallsJSON failed: %v (raw=%s)", err, raw)
	}
	if !report.Ok || report.ExitIP != "203.0.113.42" || report.Country != "IQ" || !report.UdpOk {
		t.Fatalf("expected full verify pass, got %+v", report)
	}
	if len(report.DcLatencies) != 1 || !report.DcLatencies[0].Ok {
		t.Fatalf("expected DC1 probe ok, got %+v", report.DcLatencies)
	}
}
