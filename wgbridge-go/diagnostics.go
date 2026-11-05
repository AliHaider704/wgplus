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
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	ksMu       sync.Mutex
	ksListener net.Listener
	ksPort     int
)

// StartKillSwitchGuard starts an isolated fail-closed SOCKS5 listener on 127.0.0.1:0 that deterministically
// rejects all outbound TCP CONNECT and UDP ASSOCIATE requests while the WireGuard tunnel is down or negotiating.
func StartKillSwitchGuard() (int, error) {
	ksMu.Lock()
	defer ksMu.Unlock()

	if ksListener != nil && ksPort > 0 {
		return ksPort, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed binding kill-switch guard: %w", err)
	}
	ksListener = ln
	ksPort = ln.Addr().(*net.TCPAddr).Port

	go ksAcceptLoop(ln)
	return ksPort, nil
}

// StopKillSwitchGuard stops the local fail-closed kill-switch listener if active.
func StopKillSwitchGuard() {
	ksMu.Lock()
	ln := ksListener
	ksListener = nil
	ksPort = 0
	ksMu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
}

// GetKillSwitchPort returns the active local kill-switch port, or 0 if inactive.
func GetKillSwitchPort() int {
	ksMu.Lock()
	defer ksMu.Unlock()
	if ksListener == nil {
		return 0
	}
	return ksPort
}

func ksAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleKillSwitchConn(c)
	}
}

func handleKillSwitchConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	if nMethods > 0 {
		methods := make([]byte, nMethods)
		if _, err := io.ReadFull(c, methods); err != nil {
			return
		}
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHdr); err != nil {
		return
	}
	_, _, _ = readSocks5Target(c, reqHdr[3])
	// Reply 0x01 (General SOCKS server failure) and close immediately: zero packets leave the device.
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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

	tunDev, probeTnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.254.254.2")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		defaultMTU,
	)
	if err != nil {
		return 0, fmt.Errorf("probe netstack error: %w", err)
	}

	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		return 0, err
	}
	probeDev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))
	defer probeDev.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", privHex)
	fmt.Fprintf(&uapi, "public_key=%s\n", pubHex)
	if pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&uapi, "endpoint=%s\n", resolvedEndpoint)
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")

	if err := probeDev.IpcSet(uapi.String()); err != nil {
		return 0, err
	}
	if err := probeDev.Up(); err != nil {
		return 0, err
	}

	start := time.Now()
	deadline := start.Add(time.Duration(timeoutMs) * time.Millisecond)

	// Trigger immediate Noise_IKpsk2 Handshake Initiation
	triggerHandshakePacket(probeTnet)

	nextRetrigger := start.Add(1100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hasCompletedHandshake(probeDev) {
			ms := int(time.Since(start).Milliseconds())
			if ms < 1 {
				ms = 1
			}
			return ms, nil
		}
		if time.Now().After(nextRetrigger) {
			triggerHandshakePacket(probeTnet)
			nextRetrigger = time.Now().Add(1100 * time.Millisecond)
		}
		time.Sleep(12 * time.Millisecond)
	}
	return 0, errors.New("handshake timed out")
}

func triggerHandshakePacket(tnet *netstack.Net) {
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
	tunDev, probeTnet, err := netstack.CreateNetTUN(clientAddrs, dnsAddrs, candMtu)
	if err != nil {
		return err
	}
	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		return err
	}
	dev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))
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
