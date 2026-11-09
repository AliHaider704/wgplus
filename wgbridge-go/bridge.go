package wgbridge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	defaultMTU        = 1280
	minMTU            = 1280
	maxMTU            = 1420
	maxUdpSessionsCap = 64
	tcpCopyBufSize    = 64 * 1024
	udpSocketBufSize  = 1024 * 1024
)

var (
	mu               sync.Mutex
	activeDev        *device.Device
	activeListener   net.Listener
	activeCancel     context.CancelFunc
	activePort       int
	activePeerPubHex string
	activeRawEp      string
	activeUseDoH     bool
	activeKeepAlive  int
	activeStartTime  time.Time
	running          bool

	tcpCopyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tcpCopyBufSize)
			return &b
		},
	}

	udpFrameBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535)
			return &b
		},
	}
)

func normalizeHexKey(raw string) (string, error) {
	k := strings.TrimSpace(raw)
	if len(k) == 64 {
		if _, err := hex.DecodeString(k); err == nil {
			return strings.ToLower(k), nil
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(k, "="))
	}
	if err == nil && len(decoded) == 32 {
		return hex.EncodeToString(decoded), nil
	}
	return "", errors.New("invalid WireGuard key: expected 64-char hex or 32-byte base64 key")
}

func parseAddresses(raw string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("invalid address prefix %q: %w", s, err)
			}
			out = append(out, pfx.Addr().Unmap())
		} else {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", s, err)
			}
			out = append(out, addr.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one client IP address is required")
	}
	return out, nil
}

func parseDNS(raw string) ([]netip.Addr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		trimmed = "1.1.1.1"
	}
	var out []netip.Addr
	for _, part := range strings.Split(trimmed, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			if pfx, err := netip.ParsePrefix(s); err == nil {
				out = append(out, pfx.Addr().Unmap())
				continue
			}
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS server %q: %w", s, err)
		}
		out = append(out, addr.Unmap())
	}
	if len(out) == 0 {
		out = append(out, netip.MustParseAddr("1.1.1.1"))
	}
	return out, nil
}

func normalizeMTU(mtu int) int {
	if mtu <= 0 {
		return defaultMTU
	}
	if mtu < minMTU {
		return minMTU
	}
	if mtu > maxMTU {
		return maxMTU
	}
	return mtu
}

func lookupPeerByHex(dev *device.Device, pubHex string) *device.Peer {
	if dev == nil || len(pubHex) != 64 {
		return nil
	}
	raw, err := hex.DecodeString(pubHex)
	if err != nil || len(raw) != 32 {
		return nil
	}
	var pk device.NoisePublicKey
	copy(pk[:], raw)
	return dev.LookupPeer(pk)
}

func triggerPeerHandshakeDirect(dev *device.Device, pubHex string, isRetry bool) {
	peer := lookupPeerByHex(dev, pubHex)
	if peer != nil {
		_ = peer.SendHandshakeInitiation(isRetry)
	}
}

func waitForHandshakeQuick(dev *device.Device, maxWait time.Duration) bool {
	if dev == nil {
		return false
	}
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if hasCompletedHandshake(dev) {
			return true
		}
		time.Sleep(12 * time.Millisecond)
	}
	return hasCompletedHandshake(dev)
}

// StartTunnel starts the userspace WireGuard tunnel with default MTU (1280) and no PresharedKey.
func StartTunnel(privateKeyHex string, clientIP string, dnsServer string, peerPublicKeyHex string, endpoint string, keepAlive int) (int, error) {
	return StartTunnelWithOptions(privateKeyHex, "", clientIP, dnsServer, peerPublicKeyHex, endpoint, keepAlive, defaultMTU)
}

// StartTunnelWithOptions starts the userspace WireGuard tunnel and local RFC 1928 SOCKS5 (TCP CONNECT + UDP ASSOCIATE) server on 127.0.0.1:0.
func StartTunnelWithOptions(
	privateKey string,
	presharedKey string,
	clientIP string,
	dnsServer string,
	peerPublicKey string,
	endpoint string,
	keepAlive int,
	mtu int,
) (int, error) {
	return StartTunnelAdvanced(privateKey, presharedKey, clientIP, dnsServer, peerPublicKey, endpoint, keepAlive, mtu, "", false)
}

// StartTunnelAdvanced starts the userspace WireGuard / AmneziaWG tunnel with optional DPI obfuscation (awgParams)
// and optional encrypted RFC 8484 DNS-over-HTTPS endpoint resolution (useDoH).
func StartTunnelAdvanced(
	privateKey string,
	presharedKey string,
	clientIP string,
	dnsServer string,
	peerPublicKey string,
	endpoint string,
	keepAlive int,
	mtu int,
	awgParams string,
	useDoH bool,
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
	clientAddrs, err := parseAddresses(clientIP)
	if err != nil {
		return 0, err
	}
	dnsAddrs, err := parseDNS(dnsServer)
	if err != nil {
		return 0, err
	}
	resolvedEndpoint, err := ResolveEndpointDoH(endpoint, useDoH)
	if err != nil {
		return 0, err
	}
	effectiveMTU := normalizeMTU(mtu)
	// Ensure S4 transport padding never pushes outer UDP frames past typical cellular 1452-byte ceiling
	if awgCfg.S4 > 0 && effectiveMTU+awgCfg.S4 > maxMTU {
		effectiveMTU = normalizeMTU(maxMTU - awgCfg.S4)
	}

	mu.Lock()
	defer mu.Unlock()

	stopLocked()

	tunDev, tnet, err := createFastNetTUN(clientAddrs, dnsAddrs, effectiveMTU)
	if err != nil {
		return 0, fmt.Errorf("failed to create fast netstack TUN: %w", err)
	}

	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		_ = tunDev.Close()
		return 0, fmt.Errorf("failed to initialize tunnel bind: %w", err)
	}

	dev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))
	// Essential for 4G/5G CGNAT stability: prevent stray NAT packets from corrupting peer endpoint state
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", privHex)
	fmt.Fprintf(&uapi, "public_key=%s\n", pubHex)
	if pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&uapi, "endpoint=%s\n", resolvedEndpoint)
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")
	if keepAlive > 0 {
		fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", keepAlive)
	}

	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return 0, fmt.Errorf("failed to apply WireGuard UAPI config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return 0, fmt.Errorf("failed to bring WireGuard device up: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		dev.Close()
		return 0, fmt.Errorf("failed to bind local SOCKS5 listener: %w", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())

	activeDev = dev
	activeListener = ln
	activeCancel = cancel
	activePort = port
	activePeerPubHex = pubHex
	activeRawEp = endpoint
	activeUseDoH = useDoH
	activeKeepAlive = keepAlive
	activeStartTime = time.Now()
	running = true

	// Kick off immediate Noise_IKpsk2 Handshake Initiation at t=0ms
	triggerPeerHandshakeDirect(dev, pubHex, false)
	// Give fast peers up to 160ms to complete handshake before returning port to Telegram
	waitForHandshakeQuick(dev, 160*time.Millisecond)

	go acceptLoop(ctx, ln, tnet)
	go tunnelWatchdogLoop(ctx, dev, pubHex)

	return port, nil
}

// tunnelWatchdogLoop runs 24/7 inside the Go runtime to guarantee cellular CGNAT continuity:
// 1. During initial startup, performs fast retry + UDP source-port hopping (BindUpdate) every 550ms
//    instead of waiting for WireGuard's default 5000ms RekeyTimeout.
// 2. Continuously monitors RX/TX progress and handshake freshness, automatically rebinding the local
//    UDP socket and re-initiating handshake whenever a mobile CGNAT pinhole dies or stalls.
func tunnelWatchdogLoop(ctx context.Context, dev *device.Device, pubHex string) {
	// Phase 1: Aggressive initial handshake warmup with source-port hopping
	for attempt := 1; attempt <= 5; attempt++ {
		if hasCompletedHandshake(dev) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(520 * time.Millisecond):
		}
		if hasCompletedHandshake(dev) {
			break
		}
		// Hop local ephemeral UDP port on retry #2 and #4 to bypass CGNAT/DPI port blackholes
		if attempt%2 == 0 {
			_ = dev.BindUpdate()
		}
		triggerPeerHandshakeDirect(dev, pubHex, true)
	}

	// Phase 2: 24/7 continuous health & CGNAT pinhole guardian
	ticker := time.NewTicker(6 * time.Second)
	defer ticker.Stop()

	var lastRx uint64
	var lastTx uint64
	var stalledTicks int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		rx, tx, hsSec := readDeviceCounters(dev)
		nowSec := time.Now().Unix()

		// Case A: Handshake never completed or expired (> 135s old)
		if hsSec <= 0 || (nowSec-hsSec) > 135 {
			_ = dev.BindUpdate()
			triggerPeerHandshakeDirect(dev, pubHex, true)
			stalledTicks = 0
			lastRx = rx
			lastTx = tx
			continue
		}

		// Case B: Outbound traffic is flowing (tx increasing) but zero inbound packets (rx frozen)
		// for 2 consecutive 6s intervals -> CGNAT pinhole collapsed or cellular IP roamed silently!
		if tx > lastTx && rx == lastRx {
			stalledTicks++
			if stalledTicks >= 2 {
				_ = dev.BindUpdate()
				triggerPeerHandshakeDirect(dev, pubHex, true)
				stalledTicks = 0
			} else if p := lookupPeerByHex(dev, pubHex); p != nil {
				p.SendKeepalive()
			}
		} else {
			stalledTicks = 0
		}

		lastRx = rx
		lastTx = tx
	}
}

func readDeviceCounters(dev *device.Device) (rx uint64, tx uint64, hsSec int64) {
	if dev == nil {
		return 0, 0, 0
	}
	ipcOut, err := dev.IpcGet()
	if err != nil || ipcOut == "" {
		return 0, 0, 0
	}
	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "rx_bytes=") {
			rx, _ = strconv.ParseUint(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		} else if strings.HasPrefix(line, "tx_bytes=") {
			tx, _ = strconv.ParseUint(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		} else if strings.HasPrefix(line, "last_handshake_time_sec=") {
			hsSec, _ = strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
		}
	}
	return rx, tx, hsSec
}

// UpdatePeerEndpoint updates the WireGuard peer endpoint dynamically on network handoff,
// rebinds the local UDP socket to the active network interface, and initiates an immediate handshake.
func UpdatePeerEndpoint(endpoint string) error {
	mu.Lock()
	useDoH := activeUseDoH
	mu.Unlock()

	ClearDnsCache()
	resolved, err := ResolveEndpointDoH(endpoint, useDoH)
	if err != nil {
		return err
	}
	mu.Lock()
	if !running || activeDev == nil || activePeerPubHex == "" {
		mu.Unlock()
		return errors.New("tunnel is not running")
	}
	dev := activeDev
	pubHex := activePeerPubHex
	activeRawEp = endpoint
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "public_key=%s\n", pubHex)
	fmt.Fprintf(&uapi, "endpoint=%s\n", resolved)
	err = dev.IpcSet(uapi.String())
	mu.Unlock()

	if err != nil {
		return err
	}
	// Rebind local UDP socket to pick up the new Wi-Fi / 4G / 5G interface and trigger immediate handshake
	_ = dev.BindUpdate()
	triggerPeerHandshakeDirect(dev, pubHex, true)
	return nil
}

// ForceRebindAndHandshake hops to a fresh local UDP source port on the active network interface,
// forces an immediate cryptographic re-handshake, and waits up to 1.2s to verify completion.
func ForceRebindAndHandshake() bool {
	mu.Lock()
	dev := activeDev
	pubHex := activePeerPubHex
	rawEp := activeRawEp
	useDoH := activeUseDoH
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil || pubHex == "" {
		return false
	}

	if strings.TrimSpace(rawEp) != "" {
		ClearDnsCache()
		if resolved, err := ResolveEndpointDoH(rawEp, useDoH); err == nil && resolved != "" {
			var uapi strings.Builder
			fmt.Fprintf(&uapi, "public_key=%s\n", pubHex)
			fmt.Fprintf(&uapi, "endpoint=%s\n", resolved)
			_ = dev.IpcSet(uapi.String())
		}
	}

	_ = dev.BindUpdate()
	if peer := lookupPeerByHex(dev, pubHex); peer != nil {
		_ = peer.SendHandshakeInitiation(true)
	}

	if waitForHandshakeQuick(dev, 550*time.Millisecond) {
		return true
	}
	// Second port hop if first packet was dropped during cellular radio state transition
	_ = dev.BindUpdate()
	triggerPeerHandshakeDirect(dev, pubHex, true)
	return waitForHandshakeQuick(dev, 650*time.Millisecond)
}

// EnsureTunnelAlive checks if the active tunnel has a fresh verified handshake and responsive UDP path;
// if stale, it performs an immediate socket rebind + handshake within timeoutMs.
func EnsureTunnelAlive(timeoutMs int) bool {
	mu.Lock()
	dev := activeDev
	pubHex := activePeerPubHex
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil || pubHex == "" {
		return false
	}

	_, _, hsSec := readDeviceCounters(dev)
	nowSec := time.Now().Unix()
	if hsSec > 0 && (nowSec-hsSec) < 75 {
		if peer := lookupPeerByHex(dev, pubHex); peer != nil {
			peer.SendKeepalive()
		}
		return true
	}

	if timeoutMs <= 0 {
		timeoutMs = 1200
	}
	if timeoutMs > 5000 {
		timeoutMs = 5000
	}

	_ = dev.BindUpdate()
	triggerPeerHandshakeDirect(dev, pubHex, true)
	half := time.Duration(timeoutMs/2) * time.Millisecond
	if waitForHandshakeQuick(dev, half) {
		return true
	}
	_ = dev.BindUpdate()
	triggerPeerHandshakeDirect(dev, pubHex, true)
	return waitForHandshakeQuick(dev, half)
}

// SetPeerKeepalive dynamically adjusts persistent_keepalive_interval on the active peer.
func SetPeerKeepalive(keepAlive int) error {
	if keepAlive < 0 {
		keepAlive = 0
	}
	if keepAlive > 600 {
		keepAlive = 600
	}
	mu.Lock()
	defer mu.Unlock()
	if !running || activeDev == nil || activePeerPubHex == "" {
		return errors.New("tunnel is not running")
	}
	activeKeepAlive = keepAlive
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "public_key=%s\n", activePeerPubHex)
	fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", keepAlive)
	return activeDev.IpcSet(uapi.String())
}

// GetTunnelStats returns UAPI telemetry lines (rx_bytes, tx_bytes, last_handshake_time_sec) for the active peer.
func GetTunnelStats() string {
	mu.Lock()
	dev := activeDev
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil {
		return ""
	}
	ipcOut, err := dev.IpcGet()
	if err != nil || ipcOut == "" {
		return ""
	}

	var rx, tx, hs string
	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "rx_bytes=") {
			rx = strings.TrimPrefix(line, "rx_bytes=")
		} else if strings.HasPrefix(line, "tx_bytes=") {
			tx = strings.TrimPrefix(line, "tx_bytes=")
		} else if strings.HasPrefix(line, "last_handshake_time_sec=") {
			hs = strings.TrimPrefix(line, "last_handshake_time_sec=")
		}
	}
	if rx == "" {
		rx = "0"
	}
	if tx == "" {
		tx = "0"
	}
	if hs == "" {
		hs = "0"
	}
	return fmt.Sprintf("rx_bytes=%s\ntx_bytes=%s\nlast_handshake_time_sec=%s", rx, tx, hs)
}

// StopTunnel stops the active SOCKS5 listener and closes the WireGuard device.
func StopTunnel() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

func stopLocked() {
	if activeCancel != nil {
		activeCancel()
		activeCancel = nil
	}
	if activeListener != nil {
		_ = activeListener.Close()
		activeListener = nil
	}
	if activeDev != nil {
		activeDev.Close()
		activeDev = nil
	}
	activePort = 0
	activePeerPubHex = ""
	activeRawEp = ""
	activeUseDoH = false
	activeKeepAlive = 0
	running = false
}

// IsRunning returns true if the tunnel and SOCKS5 listener are active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running && activeListener != nil && activeDev != nil
}

// GetActivePort returns the active local SOCKS5 port, or 0 if stopped.
func GetActivePort() int {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return 0
	}
	return activePort
}

func tuneLocalTcpSocket(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(20 * time.Second)
	}
}

func acceptLoop(ctx context.Context, ln net.Listener, tnet *fastNet) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			return
		}
		tuneLocalTcpSocket(c)
		go handleSocks5Client(ctx, c, tnet)
	}
}

type udpDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func readSocks5Target(r io.Reader, atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err = io.ReadFull(r, ipBuf); err != nil {
			return "", 0, err
		}
		host = net.IP(ipBuf).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(r, lenBuf); err != nil {
			return "", 0, err
		}
		domBuf := make([]byte, int(lenBuf[0]))
		if _, err = io.ReadFull(r, domBuf); err != nil {
			return "", 0, err
		}
		host = string(domBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err = io.ReadFull(r, ipBuf); err != nil {
			return "", 0, err
		}
		host = net.IP(ipBuf).String()
	default:
		return "", 0, errors.New("unsupported SOCKS5 ATYP")
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	port = binary.BigEndian.Uint16(portBuf)
	return host, port, nil
}

func awaitInitialHandshakeBeforeDial(ctx context.Context) {
	mu.Lock()
	dev := activeDev
	pubHex := activePeerPubHex
	started := activeStartTime
	mu.Unlock()

	if dev == nil || pubHex == "" || hasCompletedHandshake(dev) {
		return
	}
	// If tunnel was started recently (< 4s ago), wait up to 750ms for handshake before firing TCP SYN into netstack
	if time.Since(started) < 4*time.Second {
		triggerPeerHandshakeDirect(dev, pubHex, false)
		deadline := time.Now().Add(750 * time.Millisecond)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil || hasCompletedHandshake(dev) {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
}

func handleSocks5Client(ctx context.Context, client net.Conn, dialer udpDialer) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(20 * time.Second))

	// 1. Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	if nMethods > 0 {
		methods := make([]byte, nMethods)
		if _, err := io.ReadFull(client, methods); err != nil {
			return
		}
	}
	// Reply: SOCKS5, NO AUTHENTICATION REQUIRED (0x00)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		return
	}

	cmd := reqHdr[1]
	host, dstPort, err := readSocks5Target(client, reqHdr[3])
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	switch cmd {
	case 0x01: // TCP CONNECT (MTProto signaling, channels, media, VoIP TCP fallback)
		handleTcpConnect(ctx, client, dialer, host, dstPort)
	case 0x03: // UDP ASSOCIATE (Telegram VoIP / tgcalls voice & video RTP/STUN media)
		handleUdpAssociate(ctx, client, dialer)
	default:
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

type writeCloserConn interface {
	CloseWrite() error
}

func closeWriteOrConn(c net.Conn) {
	if wc, ok := c.(writeCloserConn); ok {
		_ = wc.CloseWrite()
	} else {
		_ = c.Close()
	}
}

func copyWithPooledBuf(dst io.Writer, src io.Reader) {
	bufPtr := tcpCopyBufPool.Get().(*[]byte)
	defer tcpCopyBufPool.Put(bufPtr)
	_, _ = io.CopyBuffer(dst, src, *bufPtr)
}

func handleTcpConnect(ctx context.Context, client net.Conn, dialer udpDialer, host string, dstPort uint16) {
	awaitInitialHandshakeBeforeDial(ctx)

	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	remote, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Clear handshake deadline before streaming
	_ = client.SetDeadline(time.Time{})

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	stopDone := make(chan struct{})
	defer close(stopDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = remote.Close()
		case <-stopDone:
		}
	}()

	done := make(chan struct{}, 2)
	go func() {
		copyWithPooledBuf(remote, client)
		closeWriteOrConn(remote)
		done <- struct{}{}
	}()
	go func() {
		copyWithPooledBuf(client, remote)
		closeWriteOrConn(client)
		done <- struct{}{}
	}()
	<-done
}

type udpRemoteSession struct {
	remoteConn net.Conn
	replyHdr   []byte
	clientAddr atomic.Value // stores *net.UDPAddr
}

func parseSocks5UdpDatagram(pkt []byte) (targetAddr string, replyHdr []byte, payload []byte, err error) {
	if len(pkt) < 10 {
		return "", nil, nil, errors.New("short SOCKS5 UDP packet")
	}
	// RSV must be 0x0000 and FRAG must be 0x00 (RFC 1928 Section 7)
	if pkt[2] != 0x00 {
		return "", nil, nil, errors.New("fragmented SOCKS5 UDP not supported")
	}

	atyp := pkt[3]
	var host string
	var hdrEnd int

	switch atyp {
	case 0x01: // IPv4: 4 + 4 + 2 = 10
		if len(pkt) < 10 {
			return "", nil, nil, errors.New("truncated IPv4 UDP header")
		}
		host = net.IP(pkt[4:8]).String()
		hdrEnd = 10
	case 0x03: // Domain: 4 + 1 + L + 2
		domLen := int(pkt[4])
		hdrEnd = 4 + 1 + domLen + 2
		if domLen == 0 || len(pkt) < hdrEnd {
			return "", nil, nil, errors.New("truncated domain UDP header")
		}
		host = string(pkt[5 : 5+domLen])
	case 0x04: // IPv6: 4 + 16 + 2 = 22
		if len(pkt) < 22 {
			return "", nil, nil, errors.New("truncated IPv6 UDP header")
		}
		host = net.IP(pkt[4:20]).String()
		hdrEnd = 22
	default:
		return "", nil, nil, errors.New("unsupported UDP ATYP")
	}

	dstPort := binary.BigEndian.Uint16(pkt[hdrEnd-2 : hdrEnd])
	targetAddr = net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	hdrCopy := make([]byte, hdrEnd)
	hdrCopy[0] = 0x00
	hdrCopy[1] = 0x00
	hdrCopy[2] = 0x00
	copy(hdrCopy[3:], pkt[3:hdrEnd])

	return targetAddr, hdrCopy, pkt[hdrEnd:], nil
}

func handleUdpAssociate(ctx context.Context, tcpControl net.Conn, dialer udpDialer) {
	awaitInitialHandshakeBeforeDial(ctx)

	udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = tcpControl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = udpLn.SetReadBuffer(udpSocketBufSize)
	_ = udpLn.SetWriteBuffer(udpSocketBufSize)

	relayPort := udpLn.LocalAddr().(*net.UDPAddr).Port

	// Clear deadline on TCP control connection so calls stay alive indefinitely until closed by Telegram
	_ = tcpControl.SetDeadline(time.Time{})

	reply := []byte{
		0x05, 0x00, 0x00, 0x01,
		127, 0, 0, 1,
		byte(relayPort >> 8), byte(relayPort & 0xff),
	}
	if _, err := tcpControl.Write(reply); err != nil {
		_ = udpLn.Close()
		return
	}

	assocCtx, assocCancel := context.WithCancel(ctx)
	var sessMu sync.RWMutex
	sessions := make(map[string]*udpRemoteSession)

	cleanupAll := func() {
		assocCancel()
		_ = udpLn.Close()
		_ = tcpControl.Close()
		sessMu.Lock()
		for k, s := range sessions {
			_ = s.remoteConn.Close()
			delete(sessions, k)
		}
		sessMu.Unlock()
	}
	defer cleanupAll()

	// Tear down immediately if parent tunnel context cancels
	go func() {
		<-assocCtx.Done()
		_ = udpLn.Close()
		_ = tcpControl.Close()
	}()

	// Pump local UDP frames from tgcalls into WireGuard netstack UDP sockets
	go func() {
		bufPtr := udpFrameBufPool.Get().(*[]byte)
		defer udpFrameBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			n, srcAddr, rErr := udpLn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			if srcAddr == nil || !srcAddr.IP.IsLoopback() {
				continue
			}

			targetAddr, replyHdr, payload, pErr := parseSocks5UdpDatagram(buf[:n])
			if pErr != nil || len(payload) == 0 {
				continue
			}

			// Fast read-lock lookup for existing RTP media stream
			sessMu.RLock()
			sess, exists := sessions[targetAddr]
			sessMu.RUnlock()

			if exists {
				sess.clientAddr.Store(srcAddr)
				_, _ = sess.remoteConn.Write(payload)
				continue
			}

			// Slow path: new UDP target session
			sessMu.Lock()
			sess, exists = sessions[targetAddr]
			if !exists {
				if len(sessions) >= maxUdpSessionsCap {
					sessMu.Unlock()
					continue
				}
				dialCtx, cancel := context.WithTimeout(assocCtx, 5*time.Second)
				rConn, dErr := dialer.DialContext(dialCtx, "udp", targetAddr)
				cancel()
				if dErr != nil {
					sessMu.Unlock()
					continue
				}
				sess = &udpRemoteSession{
					remoteConn: rConn,
					replyHdr:   replyHdr,
				}
				sess.clientAddr.Store(srcAddr)
				sessions[targetAddr] = sess
				sessMu.Unlock()

				// Pump return UDP packets from WireGuard netstack back to local client with RFC 1928 UDP header
				go func(key string, s *udpRemoteSession) {
					rBufPtr := udpFrameBufPool.Get().(*[]byte)
					defer udpFrameBufPool.Put(rBufPtr)
					respBuf := *rBufPtr

					outBufPtr := udpFrameBufPool.Get().(*[]byte)
					defer udpFrameBufPool.Put(outBufPtr)
					outPkt := *outBufPtr

					hdrLen := len(s.replyHdr)
					copy(outPkt[:hdrLen], s.replyHdr)

					for {
						rn, readErr := s.remoteConn.Read(respBuf)
						if readErr != nil {
							sessMu.Lock()
							delete(sessions, key)
							sessMu.Unlock()
							_ = s.remoteConn.Close()
							return
						}
						cAddrAny := s.clientAddr.Load()
						if cAddr, ok := cAddrAny.(*net.UDPAddr); ok && cAddr != nil && hdrLen+rn <= len(outPkt) {
							copy(outPkt[hdrLen:hdrLen+rn], respBuf[:rn])
							_, _ = udpLn.WriteToUDP(outPkt[:hdrLen+rn], cAddr)
						}
					}
				}(targetAddr, sess)
			} else {
				sess.clientAddr.Store(srcAddr)
				sessMu.Unlock()
			}

			_, _ = sess.remoteConn.Write(payload)
		}
	}()

	// RFC 1928 Section 7: UDP association stays alive until TCP control socket closes
	ctrlBuf := make([]byte, 16)
	for {
		if _, err := tcpControl.Read(ctrlBuf); err != nil {
			return
		}
	}
}
