package wgbridge

import (
	"context"
	"io"
	"net"
	"strconv"
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
