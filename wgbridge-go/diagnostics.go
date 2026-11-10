package wgbridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// StartKillSwitchGuard ensures the unified fail-closed local SOCKS5 mux listener is bound on
// 127.0.0.1 and rejects all outbound TCP CONNECT and UDP ASSOCIATE requests whenever the WireGuard
// tunnel is stopped (and not paused by startupPending). Reuses the exact same local port as StartTunnel.
func StartKillSwitchGuard() (int, error) {
	mu.Lock()
	defer mu.Unlock()

	muxKillSwitch = true
	port, err := ensureMuxListenerLocked()
	if err != nil {
		muxKillSwitch = false
		return 0, err
	}
	notifyMuxWaitersLocked()
	return port, nil
}

// StopKillSwitchGuard disables the kill-switch guard and closes the mux listener if the tunnel is down.
func StopKillSwitchGuard() {
	mu.Lock()
	muxKillSwitch = false
	muxStartupPend = false
	stopMuxIfIdleLocked()
	mu.Unlock()
}

// GetKillSwitchPort returns the active local kill-switch/mux port, or 0 if guard is disabled.
func GetKillSwitchPort() int {
	mu.Lock()
	defer mu.Unlock()
	if !muxKillSwitch || muxListener == nil {
		return 0
	}
	return muxPort
}

// ProbeEndpointHandshakeMs performs an isolated cryptographic WireGuard / AmneziaWG handshake probe
// without disturbing any active tunnel, returning the verified handshake RTT in milliseconds.
func ProbeEndpointHandshakeMs(
	privateKey string,
	presharedKey string,
	peerPublicKey string,
	endpoint string,
	awgParams string,
	useDoH bool,
	timeoutMs int,
) (int, error) {
	privHex, err := normalizeHexKey(privateKey)
	if err != nil {
		return 0, fmt.Errorf("private key error: %w", err)
	}
	pubHex, err := normalizeHexKey(peerPublicKey)
	if err != nil {
		return 0, fmt.Errorf("peer public key error: %w", err)
	}
	var pskHex string
	if strings.TrimSpace(presharedKey) != "" {
		pskHex, err = normalizeHexKey(presharedKey)
		if err != nil {
			return 0, fmt.Errorf("preshared key error: %w", err)
		}
	}
	awgCfg, err := parseAwgConfig(awgParams)
	if err != nil {
		return 0, fmt.Errorf("AmneziaWG config error: %w", err)
	}
	resolvedEndpoint, err := ResolveEndpointDoH(endpoint, useDoH)
	if err != nil {
		return 0, err
	}

	if timeoutMs <= 0 {
		timeoutMs = 3500
	}
	if timeoutMs > 15000 {
		timeoutMs = 15000
	}

	tunDev, probeTnet, err := createFastNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.254.254.2")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		defaultMTU,
	)
	if err != nil {
		return 0, fmt.Errorf("probe netstack error: %w", err)
	}

	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		_ = tunDev.Close()
		return 0, err
	}
	probeDev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))
	probeDev.DisableSomeRoamingForBrokenMobileSemantics()
	defer probeDev.Close()

	peerParams := peerHandshakeParams{
		pubHex:     pubHex,
		pskHex:     pskHex,
		resolvedEp: resolvedEndpoint,
	}
	if err := applyPeerUapi(probeDev, peerParams, privHex, false); err != nil {
		return 0, err
	}
	if err := probeDev.Up(); err != nil {
		return 0, err
	}

	start := time.Now()
	deadline := start.Add(time.Duration(timeoutMs) * time.Millisecond)

	// Trigger immediate Noise_IKpsk2 Handshake Initiation directly on the peer
	triggerPeerHandshakeDirect(probeDev, pubHex, false)
	triggerHandshakePacket(probeTnet)

	retryStep := 0
	nextRetrigger := start.Add(550 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hasCompletedHandshake(probeDev) {
			ms := int(time.Since(start).Milliseconds())
			if ms < 1 {
				ms = 1
			}
			return ms, nil
		}
		if time.Now().After(nextRetrigger) {
			retryStep++
			if retryStep%2 == 1 {
				_ = probeDev.IpcSet("listen_port=0\n")
			}
			_ = applyPeerUapi(probeDev, peerParams, "", true)
			probeDev.DisableSomeRoamingForBrokenMobileSemantics()
			triggerPeerHandshakeDirect(probeDev, pubHex, false)
			nextRetrigger = time.Now().Add(650 * time.Millisecond)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, errors.New("handshake timed out")
}

func triggerHandshakePacket(tnet *fastNet) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	uConn, err := tnet.DialContext(ctx, "udp", "10.254.254.1:53")
	if err == nil {
		_, _ = uConn.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
		_ = uConn.Close()
	}
}

func hasCompletedHandshake(dev *device.Device) bool {
	ipcOut, err := dev.IpcGet()
	if err != nil || ipcOut == "" {
		return false
	}
	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			secStr := strings.TrimPrefix(line, "last_handshake_time_sec=")
			sec, pErr := strconv.ParseInt(secStr, 10, 64)
			if pErr == nil && sec > 0 {
				return true
			}
		}
	}
	return false
}

// DiscoverOptimalMTU probes candidate inner tunnel MTUs from highest to lowest (1420, 1392, 1360, 1320, 1280)
// by transmitting full-MSS segments across the encrypted tunnel to identify the highest unfragmented MTU
// that does not blackhole on mobile/CGNAT paths.
func DiscoverOptimalMTU(
	privateKey string,
	presharedKey string,
	clientIP string,
	dnsServer string,
	peerPublicKey string,
	endpoint string,
	awgParams string,
	useDoH bool,
	probeTarget string,
	stepTimeoutMs int,
) (int, error) {
	privHex, err := normalizeHexKey(privateKey)
	if err != nil {
		return 0, fmt.Errorf("private key error: %w", err)
	}
	pubHex, err := normalizeHexKey(peerPublicKey)
	if err != nil {
		return 0, fmt.Errorf("peer public key error: %w", err)
	}
	var pskHex string
	if strings.TrimSpace(presharedKey) != "" {
		pskHex, err = normalizeHexKey(presharedKey)
		if err != nil {
			return 0, fmt.Errorf("preshared key error: %w", err)
		}
	}
	clientAddrs, err := parseAddresses(clientIP)
	if err != nil {
		return 0, err
	}
	dnsAddrs, err := parseDNS(dnsServer)
	if err != nil {
		return 0, err
	}
	awgCfg, err := parseAwgConfig(awgParams)
	if err != nil {
		return 0, err
	}
	resolvedEndpoint, err := ResolveEndpointDoH(endpoint, useDoH)
	if err != nil {
		return 0, err
	}

	if stepTimeoutMs <= 0 {
		stepTimeoutMs = 2600
	}
	if stepTimeoutMs > 8000 {
		stepTimeoutMs = 8000
	}

	candidates := []int{1420, 1392, 1360, 1320, 1280}
	// If S4 transport padding is active, cap max inner MTU so outer UDP stays safely <= 1452
	maxSafeInner := 1420 - awgCfg.S4
	if maxSafeInner < 1280 {
		maxSafeInner = 1280
	}

	var lastErr error
	for _, candMtu := range candidates {
		if candMtu > maxSafeInner {
			continue
		}
		err := testSingleCandidateMTU(
			privHex,
			pskHex,
			clientAddrs,
			dnsAddrs,
			pubHex,
			resolvedEndpoint,
			awgCfg,
			candMtu,
			probeTarget,
			time.Duration(stepTimeoutMs)*time.Millisecond,
		)
		if err == nil {
			return candMtu, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return 0, fmt.Errorf("all MTU candidates failed: %w", lastErr)
	}
	return defaultMTU, nil
}

func testSingleCandidateMTU(
	privHex string,
	pskHex string,
	clientAddrs []netip.Addr,
	dnsAddrs []netip.Addr,
	pubHex string,
	resolvedEndpoint string,
	awgCfg AwgConfig,
	candMtu int,
	probeTarget string,
	timeout time.Duration,
) error {
	tunDev, probeTnet, err := createFastNetTUN(clientAddrs, dnsAddrs, candMtu)
	if err != nil {
		return err
	}
	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		_ = tunDev.Close()
		return err
	}
	dev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))
	dev.DisableSomeRoamingForBrokenMobileSemantics()
	defer dev.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", privHex)
	fmt.Fprintf(&uapi, "public_key=%s\n", pubHex)
	if pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&uapi, "endpoint=%s\n", resolvedEndpoint)
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")

	if err := dev.IpcSet(uapi.String()); err != nil {
		return err
	}
	if err := dev.Up(); err != nil {
		return err
	}

	triggerPeerHandshakeDirect(dev, pubHex, false)
	waitForHandshakeQuick(dev, 250*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	target := strings.TrimSpace(probeTarget)
	// Plain TCP full-MSS echo/HTTP mode for deterministic tunnel testing ("tcp://host:port")
	if strings.HasPrefix(target, "tcp://") {
		addr := strings.TrimPrefix(target, "tcp://")
		c, dErr := probeTnet.DialContext(ctx, "tcp", addr)
		if dErr != nil {
			return dErr
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(timeout))

		// 3000-byte payload forces gVisor netstack to emit full-MSS (candMtu-byte) IP packets
		payload := bytes.Repeat([]byte("M"), 3000)
		payload = append(payload, '\n')
		if _, wErr := c.Write(payload); wErr != nil {
			return wErr
		}
		ack := make([]byte, 7)
		if _, rErr := io.ReadFull(c, ack); rErr != nil {
			return rErr
		}
		if string(ack) != "MTU_OK\n" {
			return errors.New("unexpected MTU probe ack")
		}
		return nil
	}

	// Production HTTPS full-MSS probe against Cloudflare 1.1.1.1:443 (with 1.0.0.1:443 fallback)
	targets := []string{"1.1.1.1:443", "1.0.0.1:443"}
	serverName := "one.one.one.one"
	if target != "" {
		targets = []string{target}
		if h, _, sErr := net.SplitHostPort(target); sErr == nil && net.ParseIP(h) == nil {
			serverName = h
		}
	}

	var probeErr error
	for _, tAddr := range targets {
		rawConn, dErr := probeTnet.DialContext(ctx, "tcp", tAddr)
		if dErr != nil {
			probeErr = dErr
			continue
		}
		_ = rawConn.SetDeadline(time.Now().Add(timeout))
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		})
		if hErr := tlsConn.HandshakeContext(ctx); hErr != nil {
			_ = rawConn.Close()
			probeErr = hErr
			continue
		}
		// 2600-byte header forces TLS record > 2650 bytes -> netstack emits full candMtu-byte packets
		pad := strings.Repeat("A", 2600)
		req := "GET /cdn-cgi/trace HTTP/1.1\r\n" +
			"Host: " + serverName + "\r\n" +
			"X-Wg-Mtu-Probe: " + pad + "\r\n" +
			"Connection: close\r\n\r\n"
		if _, wErr := tlsConn.Write([]byte(req)); wErr != nil {
			_ = tlsConn.Close()
			probeErr = wErr
			continue
		}
		respBuf := make([]byte, 256)
		n, rErr := tlsConn.Read(respBuf)
		_ = tlsConn.Close()
		if rErr != nil && n == 0 {
			probeErr = rErr
			continue
		}
		if strings.HasPrefix(string(respBuf[:n]), "HTTP/1.") {
			return nil
		}
		probeErr = errors.New("unexpected HTTP response during MTU probe")
	}
	if probeErr != nil {
		return probeErr
	}
	return errors.New("MTU probe failed")
}
