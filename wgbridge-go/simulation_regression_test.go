package wgbridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func reserveFreeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed reserving free loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestSimulationXiaomiUnrootedOwnerYieldAndVoipSurvival(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	SetPreferredMuxPort(0)
	SetSocksAuth("", "")
	defer func() {
		StopKillSwitchGuard()
		StopTunnel()
		SetPreferredMuxPort(0)
		SetSocksAuth("", "")
	}()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.94.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	voipEcho, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.IPv4(10, 94, 0, 1), Port: 1400})
	if err != nil {
		t.Fatalf("server ListenUDP failed: %v", err)
	}
	defer voipEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, rAddr, rErr := voipEcho.ReadFrom(buf)
			if rErr != nil {
				return
			}
			_, _ = voipEcho.WriteTo(buf[:n], rAddr)
		}
	}()

	muxPort := reserveFreeLoopbackPort(t)
	SetPreferredMuxPort(muxPort)
	SetSocksAuth("wg", "secretpass")

	// Owner A starts tunnel on muxPort (simulating background companion org.telegram.wgplus.module)
	ownerPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.94.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		25,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("Owner A StartTunnelAdvanced failed: %v", err)
	}
	if ownerPort != muxPort {
		t.Fatalf("expected Owner A on preferred muxPort=%d, got %d", muxPort, ownerPort)
	}

	// Open VoIP relay on Owner A
	relayA := StartVoipEndpointRelayAddr("10.94.0.1", 1400)
	if relayA == "" {
		t.Fatal("expected non-empty VoIP relay address on Owner A")
	}

	// Unauthenticated YIELD must be rejected while Owner A remains active
	if RequestRemoteTunnelYield(ownerPort, "wrongpass") {
		t.Fatal("unauthenticated WGP1 YIELD must be rejected")
	}
	if !IsRunning() || GetActivePort() != ownerPort {
		t.Fatalf("tunnel must remain running on port %d after rejected YIELD", ownerPort)
	}

	// Authenticated YIELD releases Owner A cleanly so foreground Telegram can claim exact same port
	if !RequestRemoteTunnelYield(ownerPort, "secretpass") {
		t.Fatal("authenticated WGP1 YIELD should succeed")
	}
	if IsRunning() || GetActivePort() != 0 {
		t.Fatalf("expected Owner A stopped cleanly after YIELD, running=%v port=%d", IsRunning(), GetActivePort())
	}

	// Foreground Telegram B immediately claims the same canonical port
	SetPreferredMuxPort(muxPort)
	SetSocksAuth("wg", "secretpass")
	fgPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.94.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		25,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("Foreground client StartTunnelAdvanced after YIELD failed: %v", err)
	}
	if fgPort != muxPort {
		t.Fatalf("expected Foreground client to reclaim exact port %d, got %d", muxPort, fgPort)
	}

	relayB := RequestRemoteVoipRelayAddr(fgPort, "secretpass", "10.94.0.1", 1400)
	if relayB == "" {
		t.Fatal("expected non-empty VoIP relay on reclaimed Foreground mux")
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", relayB)
	if err != nil {
		t.Fatalf("invalid relayB addr %q: %v", relayB, err)
	}
	rtpConn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP relayB failed: %v", err)
	}
	defer rtpConn.Close()

	// Pump continuous RTP-like frames for >1.6s to confirm call survives seamlessly with zero drops
	const packetCount = 28
	rxBuf := make([]byte, 256)
	for i := 0; i < packetCount; i++ {
		msg := fmt.Sprintf("RTP_SEQ_%03d", i)
		_ = rtpConn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := rtpConn.Write([]byte(msg)); err != nil {
			t.Fatalf("RTP write %d failed: %v", i, err)
		}
		rn, err := rtpConn.Read(rxBuf)
		if err != nil || string(rxBuf[:rn]) != msg {
			t.Fatalf("RTP read %d failed: got=%q want=%q err=%v stats=%q hs=%v tel=%s diag=%s",
				i, string(rxBuf[:rn]), msg, err, GetTunnelStats(), IsHandshakeHealthy(), GetUdpTelemetryJSON(), GetDiagnosticsJSON())
		}
		time.Sleep(60 * time.Millisecond)
	}
}

func TestSimulationSamsungNineHourOfflineZombieTcpReset(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	SetPreferredMuxPort(0)
	SetSocksAuth("", "")
	defer func() {
		StopKillSwitchGuard()
		StopTunnel()
		SetPreferredMuxPort(0)
		SetSocksAuth("", "")
	}()

	clientPriv, clientPub := generateTestKeypairHex(t)
	srv := startLocalWgServer(t, "10.93.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()

	// Listener 1: silent blackhole simulating half-open DC connections left open overnight
	silentLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 93, 0, 1), Port: 443})
	if err != nil {
		t.Fatalf("silent ListenTCP failed: %v", err)
	}
	defer silentLn.Close()
	var srvAccepted sync.WaitGroup
	srvAccepted.Add(10)
	var srvConnsMu sync.Mutex
	var srvConns []net.Conn
	defer func() {
		srvConnsMu.Lock()
		for _, c := range srvConns {
			_ = c.Close()
		}
		srvConnsMu.Unlock()
	}()
	go func() {
		for {
			c, aErr := silentLn.Accept()
			if aErr != nil {
				return
			}
			srvConnsMu.Lock()
			idx := len(srvConns)
			srvConns = append(srvConns, c)
			srvConnsMu.Unlock()
			if idx < 10 {
				srvAccepted.Done()
			}
		}
	}()

	// Listener 2: healthy MTProto responder after wake
	freshLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 93, 0, 1), Port: 444})
	if err != nil {
		t.Fatalf("fresh ListenTCP failed: %v", err)
	}
	defer freshLn.Close()
	go func() {
		for {
			c, aErr := freshLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("MTPROTO_DIFF_OK"))
			}(c)
		}
	}()

	socksPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.93.0.2/32",
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

	const zombieCount = 10
	zombies := make([]net.Conn, 0, zombieCount)
	for i := 0; i < zombieCount; i++ {
		c, dErr := dialSocks5TcpIPv4(socksPort, [4]byte{10, 93, 0, 1}, 443)
		if dErr != nil {
			t.Fatalf("failed opening zombie conn #%d: %v", i, dErr)
		}
		_ = c.SetDeadline(time.Time{})
		zombies = append(zombies, c)
		defer c.Close()
	}
	srvAccepted.Wait()

	// Confirm telemetry reflects activeTcpConns == 10 just like Samsung SM-S918B report
	telRaw := GetUdpTelemetryJSON()
	var telMap map[string]any
	if err := json.Unmarshal([]byte(telRaw), &telMap); err != nil {
		t.Fatalf("unmarshal telemetry failed: %v (%s)", err, telRaw)
	}
	if int(telMap["activeTcpConns"].(float64)) != zombieCount {
		t.Fatalf("expected activeTcpConns=%d before reset, got %v", zombieCount, telMap["activeTcpConns"])
	}

	readerUnblocked := make(chan int, zombieCount)
	for i, z := range zombies {
		idx := i
		conn := z
		go func() {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 16)
			_, _ = conn.Read(buf)
			readerUnblocked <- idx
		}()
	}

	// Wake-up reset after 9h offline sleep
	closed := ResetActiveProxyConnections("wifi_restored_after_9h_sleep")
	if closed != zombieCount {
		t.Fatalf("expected ResetActiveProxyConnections to close %d streams, got %d", zombieCount, closed)
	}

	deadline := time.After(900 * time.Millisecond)
	for i := 0; i < zombieCount; i++ {
		select {
		case <-readerUnblocked:
		case <-deadline:
			t.Fatalf("zombie socket #%d remained hung after ResetActiveProxyConnections", i)
		}
	}

	// Wait briefly for relay goroutines to decrement activeTcpConns to 0
	zeroDeadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(zeroDeadline) {
		var m map[string]any
		_ = json.Unmarshal([]byte(GetUdpTelemetryJSON()), &m)
		if int(m["activeTcpConns"].(float64)) == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = json.Unmarshal([]byte(GetUdpTelemetryJSON()), &telMap)
	if int(telMap["activeTcpConns"].(float64)) != 0 {
		t.Fatalf("expected activeTcpConns==0 after reset, got %v", telMap["activeTcpConns"])
	}

	// Verify brand-new 11th connection succeeds immediately to fetch updates
	freshConn, err := dialSocks5TcpIPv4(socksPort, [4]byte{10, 93, 0, 1}, 444)
	if err != nil {
		t.Fatalf("fresh SOCKS5 dial after reset failed: %v", err)
	}
	reply, err := io.ReadAll(freshConn)
	_ = freshConn.Close()
	if err != nil || !strings.Contains(string(reply), "MTPROTO_DIFF_OK") {
		t.Fatalf("unexpected fresh reply after sleep reset: reply=%q err=%v", string(reply), err)
	}

	// Wait briefly for relay goroutine cleanup before testing idle ResetActiveProxyConnections
	idleDeadline := time.Now().Add(800 * time.Millisecond)
	for time.Now().Before(idleDeadline) {
		var m map[string]any
		_ = json.Unmarshal([]byte(GetUdpTelemetryJSON()), &m)
		if int(m["activeTcpConns"].(float64)) == 0 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	// Also verify explicit ResetActiveProxyConnections increments recoveryEpoch even when 0 active streams remain
	epochBeforeIdle := GetRecoveryEpoch()
	idleClosed := ResetActiveProxyConnections("idle_check")
	if idleClosed != 0 {
		t.Fatalf("expected 0 closed streams on idle reset, got %d", idleClosed)
	}
	if GetRecoveryEpoch() < epochBeforeIdle+1 {
		t.Fatalf("expected recoveryEpoch to increment on idle ResetActiveProxyConnections (%d -> %d)", epochBeforeIdle, GetRecoveryEpoch())
	}
}

func TestExpiredHandshakeAndUnreachablePeerPacesSocks5AndReconnectResetsStreams(t *testing.T) {
	StopKillSwitchGuard()
	StopTunnel()
	SetPreferredMuxPort(0)
	SetSocksAuth("", "")
	defer func() {
		StopKillSwitchGuard()
		StopTunnel()
		SetPreferredMuxPort(0)
		SetSocksAuth("", "")
	}()

	clientPriv, clientPub := generateTestKeypairHex(t)
	_, deadPeerPub := generateTestKeypairHex(t)

	// 1. Pacing test: blackhole peer with no handshake must pace SOCKS5 rejections instead of spinning <1ms.
	deadPort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.94.0.2/32",
		"1.1.1.1",
		deadPeerPub,
		"127.0.0.1:9",
		20,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced blackhole failed: %v", err)
	}

	paceStart := time.Now()
	for i := 0; i < 2; i++ {
		if _, dErr := dialSocks5TcpIPv4(deadPort, [4]byte{1, 1, 1, 1}, 443); dErr == nil {
			t.Fatalf("expected unreachable SOCKS5 error on dead peer attempt #%d", i+1)
		}
	}
	if elapsed := time.Since(paceStart); elapsed < 2*time.Second {
		t.Fatalf("expected paced >=2s total across 2 dead-peer SOCKS5 rejections (anti-spin), got %v", elapsed)
	}

	// 2. Restart stream reset test: active stream on live tunnel must close automatically on StartTunnelAdvanced restart.
	srv := startLocalWgServer(t, "10.94.0.1", 1280, clientPub, "", "")
	defer srv.closeAll()
	silentLn, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 94, 0, 1), Port: 443})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer silentLn.Close()
	go func() {
		for {
			c, aErr := silentLn.Accept()
			if aErr != nil {
				return
			}
			_ = c
		}
	}()

	livePort, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.94.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		25,
		1280,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("StartTunnelAdvanced live 1 failed: %v", err)
	}

	zombieConn, err := dialSocks5TcpIPv4(livePort, [4]byte{10, 94, 0, 1}, 443)
	if err != nil {
		t.Fatalf("zombie dial failed: %v", err)
	}
	defer zombieConn.Close()
	unblocked := make(chan struct{}, 1)
	go func() {
		_ = zombieConn.SetReadDeadline(time.Now().Add(4 * time.Second))
		buf := make([]byte, 8)
		_, _ = zombieConn.Read(buf)
		unblocked <- struct{}{}
	}()

	if _, err := StartTunnelAdvanced(
		clientPriv,
		"",
		"10.94.0.2/32",
		"1.1.1.1",
		srv.pubHex,
		fmt.Sprintf("127.0.0.1:%d", srv.udpPort),
		25,
		1280,
		"",
		false,
	); err != nil {
		t.Fatalf("StartTunnelAdvanced live 2 failed: %v", err)
	}

	select {
	case <-unblocked:
	case <-time.After(900 * time.Millisecond):
		t.Fatal("expected StartTunnelAdvanced restart to close zombie TCP stream automatically")
	}
}
