package wgbridge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
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

	// Spin up paired local UDP+TCP echo servers on 127.0.0.1 (binding TCP first avoids WinNAT excluded ranges).
	var udpSrv *net.UDPConn
	var tcpSrv net.Listener
	var targetPort int
	for attempt := 0; attempt < 8; attempt++ {
		ln, tcpErr := net.Listen("tcp4", "127.0.0.1:0")
		if tcpErr != nil {
			continue
		}
		p := ln.Addr().(*net.TCPAddr).Port
		pc, udpErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if udpErr == nil {
			tcpSrv = ln
			udpSrv = pc
			targetPort = p
			break
		}
		_ = ln.Close()
	}
	if udpSrv == nil || tcpSrv == nil {
		t.Fatalf("failed binding paired UDP/TCP echo ports")
	}
	defer udpSrv.Close()
	defer tcpSrv.Close()

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

func TestVoipRelayPreservePortPrefersCanonicalLoopbackThenSpills(t *testing.T) {
	StopAllVoipRelays()
	defer StopAllVoipRelays()

	// Find a free high port across both TCP4 and UDP4 on 127.0.0.1.
	var targetPort int
	for attempt := 0; attempt < 8; attempt++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			continue
		}
		p := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if p >= 1024 && (p < 48729 || p > 48735) {
			targetPort = p
			break
		}
	}
	if targetPort <= 0 {
		t.Fatalf("failed to probe a free high port")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr1 := startVoipEndpointRelayAddrWithDialer(ctx, localNetDialer{}, "198.51.100.10", targetPort)
	want1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort))
	if addr1 != want1 {
		t.Fatalf("expected primary preserve-port relay on %q, got %q", want1, addr1)
	}

	addr2 := startVoipEndpointRelayAddrWithDialer(ctx, localNetDialer{}, "198.51.100.11", targetPort)
	h2, p2Str, err := net.SplitHostPort(addr2)
	if err != nil {
		t.Fatalf("invalid spilled relay addr %q: %v", addr2, err)
	}
	if !strings.HasPrefix(h2, "127.0.0.") || h2 == "127.0.0.1" {
		t.Fatalf("expected second relay on same port to spill to 127.0.0.x (!=127.0.0.1), got %q", addr2)
	}
	if p2, _ := strconv.Atoi(p2Str); p2 != targetPort {
		t.Fatalf("expected spilled relay to preserve port %d, got %q", targetPort, addr2)
	}
}

func TestVoipRelayStunTurnTcpToUdpBridge(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	defer StopTunnel()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.97.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	// Start a UDP-only mock TURN server on 10.97.0.1:1400 (NO TCP listener on server!).
	udpTurn, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 97, 0, 1), Port: 1400})
	if err != nil {
		t.Fatalf("ListenUDP 10.97.0.1:1400 failed: %v", err)
	}
	defer udpTurn.Close()

	stunReqChan := make(chan []byte, 4)
	chanReqChan := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := udpTurn.ReadFrom(buf)
			if rErr != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			if n >= 8 && (pkt[0]&0xC0) == 0x00 && binary.BigEndian.Uint32(pkt[4:8]) == 0x2112A442 {
				stunReqChan <- pkt
				// Reply with a 20-byte STUN Binding Success Response keeping exact txid.
				resp := make([]byte, 20)
				binary.BigEndian.PutUint16(resp[0:2], 0x0101)
				binary.BigEndian.PutUint16(resp[2:4], 0)
				binary.BigEndian.PutUint32(resp[4:8], 0x2112A442)
				copy(resp[8:20], pkt[8:20])
				_, _ = udpTurn.WriteTo(resp, addr)
			} else if n >= 4 && (pkt[0]&0xC0) == 0x40 {
				chanReqChan <- pkt
				// Reply with an unpadded 9-byte TURN ChannelData ("world", len=5).
				resp := []byte{0x40, 0x01, 0x00, 0x05, 'w', 'o', 'r', 'l', 'd'}
				_, _ = udpTurn.WriteTo(resp, addr)
			}
		}
	}()

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
		t.Fatalf("StartTunnelAdvanced failed: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !IsHandshakeHealthy() {
		time.Sleep(25 * time.Millisecond)
	}

	relayAddr := StartVoipEndpointRelayAddr("10.97.0.1", 1400)
	if relayAddr == "" {
		t.Fatalf("expected non-empty relayAddr for 10.97.0.1:1400")
	}

	tcpCli, err := net.DialTimeout("tcp4", relayAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout tcp4 %q failed: %v", relayAddr, err)
	}
	defer tcpCli.Close()
	_ = tcpCli.SetDeadline(time.Now().Add(4 * time.Second))

	// 1) Send a 24-byte STUN Binding Request with 4-byte attr over TCP -> expect exact 24B over UDP and 20B STUN reply back.
	stunReq := make([]byte, 24)
	binary.BigEndian.PutUint16(stunReq[0:2], 0x0001)
	binary.BigEndian.PutUint16(stunReq[2:4], 4)
	binary.BigEndian.PutUint32(stunReq[4:8], 0x2112A442)
	copy(stunReq[8:20], []byte("123456789012"))
	copy(stunReq[20:24], []byte{0xde, 0xad, 0xbe, 0xef})
	if err := writeAllVoipConn(tcpCli, stunReq); err != nil {
		t.Fatalf("write STUN req over TCP failed: %v", err)
	}

	select {
	case gotUdp := <-stunReqChan:
		if len(gotUdp) != 24 || string(gotUdp) != string(stunReq) {
			t.Fatalf("UDP TURN server got unexpected STUN req len=%d", len(gotUdp))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for bridged STUN UDP packet")
	}

	stunResp := make([]byte, 20)
	if _, err := io.ReadFull(tcpCli, stunResp); err != nil {
		t.Fatalf("ReadFull STUN resp over TCP failed: %v", err)
	}
	if binary.BigEndian.Uint16(stunResp[0:2]) != 0x0101 || string(stunResp[8:20]) != "123456789012" {
		t.Fatalf("unexpected STUN resp over TCP: %x", stunResp)
	}

	// 2) Send 4-byte aligned TURN ChannelData over TCP (cLen=5 + 3 zero pad = 12B) -> expect unpadded 9B UDP ("hello") and padded 12B TCP reply ("world\0\0\0").
	chanTcpReq := []byte{0x40, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0, 0, 0}
	if err := writeAllVoipConn(tcpCli, chanTcpReq); err != nil {
		t.Fatalf("write ChannelData over TCP failed: %v", err)
	}

	select {
	case gotUdp := <-chanReqChan:
		if len(gotUdp) != 9 || string(gotUdp[4:]) != "hello" {
			t.Fatalf("expected unpadded 9B ChannelData over UDP, got len=%d %q", len(gotUdp), string(gotUdp))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for bridged ChannelData UDP packet")
	}

	chanTcpResp := make([]byte, 12)
	if _, err := io.ReadFull(tcpCli, chanTcpResp); err != nil {
		t.Fatalf("ReadFull ChannelData resp over TCP failed: %v", err)
	}
	if string(chanTcpResp) != string([]byte{0x40, 0x01, 0x00, 0x05, 'w', 'o', 'r', 'l', 'd', 0, 0, 0}) {
		t.Fatalf("expected 4-byte padded 12B ChannelData over TCP, got %x", chanTcpResp)
	}
}

