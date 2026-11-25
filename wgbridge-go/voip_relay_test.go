package wgbridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVoipEndpointRelayUdpTcpDedupAndStop(t *testing.T) {
	StopAllVoipRelays()
	defer StopAllVoipRelays()

	// Spin up local UDP echo server on 127.0.0.1 (acts as remote Telegram TurnPort/Reflector).
	udpSrv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udpSrv.Close()
	targetPort := udpSrv.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := udpSrv.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			_, _ = udpSrv.WriteToUDP(append([]byte("udp-pong:"), buf[:n]...), addr)
		}
	}()

	// Also spin up TCP echo server on the same IPv4 loopback port if available;
	// if OS prevents same-port TCP bind, use separate port for TCP test.
	tcpSrv, tcpErr := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort)))
	if tcpErr != nil {
		t.Fatalf("Listen tcp4 on %d: %v", targetPort, tcpErr)
	}
	defer tcpSrv.Close()

	go func() {
		for {
			c, aErr := tcpSrv.Accept()
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

	beforeOpen := udpSocketsOpened.Load()
	beforeTx := udpPacketsTx.Load()
	beforeRx := udpPacketsRx.Load()

	localPort := startVoipEndpointRelayWithDialer(ctx, localNetDialer{}, "127.0.0.1", targetPort)
	if localPort <= 0 {
		t.Fatalf("expected valid local relay port, got %d", localPort)
	}

	// Verify deduplication returns the exact same port.
	dupPort := startVoipEndpointRelayWithDialer(ctx, localNetDialer{}, " 127.0.0.1 ", targetPort)
	if dupPort != localPort {
		t.Fatalf("expected deduplicated port %d, got %d", localPort, dupPort)
	}

	// Verify UDP echo round-trip and telemetry increments.
	cliUdp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort})
	if err != nil {
		t.Fatalf("DialUDP relay: %v", err)
	}
	defer cliUdp.Close()
	_ = cliUdp.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := cliUdp.Write([]byte("stun-ping")); err != nil {
		t.Fatalf("cliUdp.Write: %v", err)
	}
	rxBuf := make([]byte, 256)
	rn, err := cliUdp.Read(rxBuf)
	if err != nil {
		t.Fatalf("cliUdp.Read: %v", err)
	}
	if got := string(rxBuf[:rn]); got != "udp-pong:stun-ping" {
		t.Fatalf("unexpected UDP reply %q", got)
	}

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if udpSocketsOpened.Load() > beforeOpen && udpPacketsTx.Load() > beforeTx && udpPacketsRx.Load() > beforeRx {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if udpSocketsOpened.Load() <= beforeOpen || udpPacketsTx.Load() <= beforeTx || udpPacketsRx.Load() <= beforeRx {
		t.Fatalf("expected UDP telemetry counters to increment (opened=%d->%d tx=%d->%d rx=%d->%d)",
			beforeOpen, udpSocketsOpened.Load(),
			beforeTx, udpPacketsTx.Load(),
			beforeRx, udpPacketsRx.Load(),
		)
	}

	// Verify TCP echo round-trip on the same bound loopback port.
	cliTcp, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("Dial tcp4 relay: %v", err)
	}
	_ = cliTcp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cliTcp.Write([]byte("reflector-tcp")); err != nil {
		_ = cliTcp.Close()
		t.Fatalf("cliTcp.Write: %v", err)
	}
	tcpRx := make([]byte, 32)
	if _, err := io.ReadFull(cliTcp, tcpRx[:len("reflector-tcp")]); err != nil {
		_ = cliTcp.Close()
		t.Fatalf("io.ReadFull tcp: %v", err)
	}
	_ = cliTcp.Close()
	if got := string(tcpRx[:len("reflector-tcp")]); got != "reflector-tcp" {
		t.Fatalf("unexpected TCP echo %q", got)
	}

	// Verify StopAllVoipRelays shuts down the relay cleanly and closes the port.
	StopAllVoipRelays()

	if c, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), 400*time.Millisecond); dialErr == nil {
		_ = c.Close()
		t.Fatalf("expected TCP relay port %d to be closed after StopAllVoipRelays", localPort)
	}

	// After StopAllVoipRelays, invalid inputs still return 0.
	if p := startVoipEndpointRelayWithDialer(ctx, localNetDialer{}, "", targetPort); p != 0 {
		t.Fatalf("expected 0 for empty host, got %d", p)
	}
	if p := startVoipEndpointRelayWithDialer(ctx, localNetDialer{}, "127.0.0.1", 0); p != 0 {
		t.Fatalf("expected 0 for port 0, got %d", p)
	}
}

func TestVoipRelaySurvivesTunnelRebindAcrossEpoch(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	defer StopTunnel()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.98.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	udpSrv, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 98, 0, 1), Port: 5444})
	if err != nil {
		t.Fatalf("ListenUDP on server failed: %v", err)
	}
	defer udpSrv.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := udpSrv.ReadFrom(buf)
			if rErr != nil {
				return
			}
			_, _ = udpSrv.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	_, err = StartTunnelAdvanced(
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
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !IsHandshakeHealthy() {
		time.Sleep(25 * time.Millisecond)
	}

	localPort := StartVoipEndpointRelay("10.98.0.1", 5444)
	if localPort <= 0 {
		t.Fatalf("expected valid local relay port, got %d", localPort)
	}

	cli, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = cli.Write([]byte("before-hop"))
	rx := make([]byte, 128)
	rn, err := cli.Read(rx)
	if err != nil || string(rx[:rn]) != "echo:before-hop" {
		t.Fatalf("pre-hop UDP echo failed: rn=%d err=%v got=%q", rn, err, string(rx[:rn]))
	}

	// Simulate roaming peer reset; relay port MUST stay alive and recover automatically!
	_ = hopActivePeerInternal(true, true, true)
	hsDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(hsDeadline) && !IsHandshakeHealthy() {
		time.Sleep(25 * time.Millisecond)
	}
	if !IsHandshakeHealthy() {
		t.Fatalf("tunnel did not re-handshake after hopActivePeerInternal; stats=%q", GetTunnelStats())
	}

	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = cli.Write([]byte("after-hop"))
	rn, err = cli.Read(rx)
	if err != nil || string(rx[:rn]) != "echo:after-hop" {
		t.Fatalf("post-hop UDP echo failed: rn=%d err=%v got=%q stats=%q", rn, err, string(rx[:rn]), GetTunnelStats())
	}
}

func TestWgp1ControlRpcVoipRelayAndStatus(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	SetSocksAuth("", "")
	defer func() {
		SetSocksAuth("", "")
		StopTunnel()
		StopKillSwitchGuard()
	}()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.99.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	SetSocksAuth("wg", "secret-wgp1-pass")
	muxPort, err := StartTunnelAdvanced(
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
	if err != nil || muxPort <= 0 {
		t.Fatalf("StartTunnelAdvanced failed: port=%d err=%v", muxPort, err)
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !IsHandshakeHealthy() {
		time.Sleep(25 * time.Millisecond)
	}

	sendWgp1 := func(cmd string) string {
		c, dErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort), 2*time.Second)
		if dErr != nil {
			t.Fatalf("DialTimeout failed: %v", dErr)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, wErr := c.Write([]byte(cmd + "\n")); wErr != nil {
			t.Fatalf("Write failed: %v", wErr)
		}
		raw, rErr := io.ReadAll(c)
		if rErr != nil {
			t.Fatalf("ReadAll failed: %v", rErr)
		}
		return strings.TrimSpace(string(raw))
	}

	// Wrong password must fail closed
	if resp := sendWgp1("WGP1 wrongpass STATUS"); resp != "ERR AUTH" {
		t.Fatalf("expected ERR AUTH for wrong pass, got %q", resp)
	}

	// Authenticated STATUS must report running=true, hsHealthy=true, lastHsSec > 0, and profileSig
	statusResp := sendWgp1("WGP1 secret-wgp1-pass STATUS")
	parts := strings.Fields(statusResp)
	if len(parts) != 5 || parts[0] != "OK" || parts[1] != "true" || parts[2] != "true" {
		t.Fatalf("unexpected STATUS response: %q", statusResp)
	}
	hsSec, convErr := strconv.ParseInt(parts[3], 10, 64)
	if convErr != nil || hsSec <= 0 {
		t.Fatalf("expected positive lastHsSec in STATUS, got %q", statusResp)
	}
	srvPubRaw, _ := hex.DecodeString(srv.pubHex)
	wantSig := fmt.Sprintf("127.0.0.1:%d|%s", srv.udpPort, base64.StdEncoding.EncodeToString(srvPubRaw))
	if parts[4] != wantSig {
		t.Fatalf("expected STATUS profileSig %q, got %q", wantSig, parts[4])
	}

	// Authenticated VOIP_RELAY must bind loopback relay on tunnel owner process
	relayResp := sendWgp1("WGP1 secret-wgp1-pass VOIP_RELAY 10.99.0.1 1400")
	rParts := strings.Fields(relayResp)
	if len(rParts) != 2 || rParts[0] != "OK" {
		t.Fatalf("unexpected VOIP_RELAY response: %q", relayResp)
	}
	relayPort, pErr := strconv.Atoi(rParts[1])
	if pErr != nil || relayPort <= 0 {
		t.Fatalf("invalid relay port from VOIP_RELAY: %q", relayResp)
	}

	// Unauthenticated PUBLIC_STATUS exposes only non-secret flags + sigHash12 (zero raw endpoints/secrets)
	pubResp := sendWgp1("WGP1 - PUBLIC_STATUS")
	pubParts := strings.Fields(pubResp)
	wantHash := ComputeProfileSigHash(wantSig)
	if len(pubParts) != 5 || pubParts[0] != "OK" || pubParts[1] != "true" || pubParts[2] != "true" || pubParts[4] != wantHash {
		t.Fatalf("unexpected PUBLIC_STATUS response %q (want hash %q)", pubResp, wantHash)
	}
	if strings.Contains(pubResp, "secret-wgp1-pass") || strings.Contains(pubResp, srv.pubHex) {
		t.Fatalf("PUBLIC_STATUS leaked secret data: %q", pubResp)
	}

	// RequestRemoteVoipRelayAddr / VOIP_RELAY_ADDR must return valid loopback ip:port
	// and preserve port 1400 whenever 127.0.0.x is bindable on this host OS.
	relayAddr := RequestRemoteVoipRelayAddr(muxPort, "secret-wgp1-pass", "10.99.0.1", 1400)
	rHost, rPortStr, splitErr := net.SplitHostPort(relayAddr)
	if splitErr != nil {
		t.Fatalf("RequestRemoteVoipRelayAddr invalid addr %q: %v", relayAddr, splitErr)
	}
	if !strings.HasPrefix(rHost, "127.") {
		t.Fatalf("expected 127.x loopback IP, got %q", relayAddr)
	}
	rPortNum, rPortErr := strconv.Atoi(rPortStr)
	if rPortErr != nil || rPortNum <= 0 {
		t.Fatalf("expected positive relay port, got %q", relayAddr)
	}
	if rHost != "127.0.0.1" && rPortNum != 1400 {
		t.Fatalf("expected non-127.0.0.1 relay to preserve target port 1400, got %q", relayAddr)
	}

	// Check port-preserving direct Go API + bidirectional UDP traffic over 127.0.0.x or 127.0.0.1
	udpSrv2, uErr2 := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 99, 0, 1), Port: 3478})
	if uErr2 != nil {
		t.Fatalf("ListenUDP on server failed: %v", uErr2)
	}
	defer udpSrv2.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, e := udpSrv2.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = udpSrv2.WriteTo(append([]byte("turn:"), buf[:n]...), addr)
		}
	}()

	addrStr := StartVoipEndpointRelayAddr("10.99.0.1", 3478)
	aHost, aPortStr, aErr := net.SplitHostPort(addrStr)
	if aErr != nil {
		t.Fatalf("StartVoipEndpointRelayAddr failed: %q err=%v", addrStr, aErr)
	}
	aPort, _ := strconv.Atoi(aPortStr)
	if aHost != "127.0.0.1" && aPort != 3478 {
		t.Fatalf("expected preserved port 3478 on %q", addrStr)
	}
	cUdp, cErr := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(aHost), Port: aPort})
	if cErr != nil {
		t.Fatalf("DialUDP %q failed: %v", addrStr, cErr)
	}
	defer cUdp.Close()
	_ = cUdp.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = cUdp.Write([]byte("alloc"))
	rBuf := make([]byte, 64)
	rn, rErr := cUdp.Read(rBuf)
	if rErr != nil || string(rBuf[:rn]) != "turn:alloc" {
		t.Fatalf("bidirectional preserved-port UDP relay failed: rn=%d err=%v got=%q", rn, rErr, string(rBuf[:rn]))
	}

	// Verify local & remote authenticated WGP1 DIAG_BUNDLE returns counters, VoIP relay packets, and ring buffer
	localBundle := BuildEngineDiagnosticsBundleJSON()
	if !strings.Contains(localBundle, `"voipRelays"`) || !strings.Contains(localBundle, `"targetPort":3478`) || strings.Contains(localBundle, "10.99.0.1") {
		t.Fatalf("BuildEngineDiagnosticsBundleJSON missing expected sanitized relay snapshot: %s", localBundle)
	}
	if rejected := RequestRemoteDiagnosticsBundleJSON(muxPort, "wrong-pass"); rejected != "" {
		t.Fatalf("expected wrong password DIAG_BUNDLE to fail, got %q", rejected)
	}
	remoteBundle := RequestRemoteDiagnosticsBundleJSON(muxPort, "secret-wgp1-pass")
	if !strings.Contains(remoteBundle, `"udpTxPkts":1`) || !strings.Contains(remoteBundle, `"udpRxPkts":1`) || !strings.Contains(remoteBundle, `"ringBuffer"`) {
		t.Fatalf("RequestRemoteDiagnosticsBundleJSON missing relay counters or ring buffer: %s", remoteBundle)
	}

	// Normal SOCKS5 (0x05) handshake on same muxPort still succeeds after first-byte peek
	socksConn, sErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", muxPort), 2*time.Second)
	if sErr != nil {
		t.Fatalf("SOCKS5 dial failed: %v", sErr)
	}
	defer socksConn.Close()
	_ = socksConn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = socksConn.Write([]byte{0x05, 0x01, 0x02})
	methodReply := make([]byte, 2)
	if _, mErr := io.ReadFull(socksConn, methodReply); mErr != nil || methodReply[0] != 0x05 || methodReply[1] != 0x02 {
		t.Fatalf("SOCKS5 method reply mismatch: err=%v reply=%v", mErr, methodReply)
	}
}

