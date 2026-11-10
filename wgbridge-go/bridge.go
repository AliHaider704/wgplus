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
	mu                sync.Mutex
	rebindMu          sync.Mutex
	activeDev         *device.Device
	activeCtx         context.Context
	activeCancel      context.CancelFunc
	activeTnet        *fastNet
	activePort        int
	activePeerPubHex  string
	activePskHex      string
	activeResolvedEp  string
	activeRawEp       string
	activeUseDoH      bool
	activeKeepAlive   int
	activeStartTime   time.Time
	baseRxBytes       uint64
	baseTxBytes       uint64
	running           bool
	muxListener       net.Listener
	muxPort           int
	muxKillSwitch     bool
	muxStartupPend    bool
	muxNotifyCh       chan struct{}
	preferredMuxPorts = []int{48729, 48730, 48731, 48732, 0}

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

type peerHandshakeParams struct {
	pubHex     string
	pskHex     string
	resolvedEp string
	keepAlive  int
}

func applyPeerUapi(dev *device.Device, params peerHandshakeParams, privHex string, replacePeers bool) error {
	if dev == nil || params.pubHex == "" {
		return errors.New("missing WireGuard peer config")
	}
	var uapi strings.Builder
	if privHex != "" {
		fmt.Fprintf(&uapi, "private_key=%s\n", privHex)
	}
	if replacePeers {
		uapi.WriteString("replace_peers=true\n")
	}
	fmt.Fprintf(&uapi, "public_key=%s\n", params.pubHex)
	if params.pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", params.pskHex)
	}
	if params.resolvedEp != "" {
		fmt.Fprintf(&uapi, "endpoint=%s\n", params.resolvedEp)
	}
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")
	if params.keepAlive > 0 {
		fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", params.keepAlive)
	}
	return dev.IpcSet(uapi.String())
}

func isActiveDevice(dev *device.Device) bool {
	mu.Lock()
	ok := running && activeDev == dev && dev != nil
	mu.Unlock()
	return ok
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
		if muxDeviceClosedOrReplaced(dev) {
			return false
		}
		time.Sleep(12 * time.Millisecond)
	}
	return hasCompletedHandshake(dev)
}

func muxDeviceClosedOrReplaced(dev *device.Device) bool {
	mu.Lock()
	defer mu.Unlock()
	return activeDev != nil && activeDev != dev
}

// hopActivePeer forces wireguard-go onto a fresh OS ephemeral UDP port (listen_port=0) and,
// when forcePeerReset is true, cleanly recreates the peer so stale lastSentHandshake (5s RekeyTimeout)
// and stale wlan0 sticky PKTINFO source addresses are wiped before initiating a fresh Noise handshake.
func hopActivePeer(hopPort bool, forcePeerReset bool) bool {
	rebindMu.Lock()
	defer rebindMu.Unlock()

	mu.Lock()
	if !running || activeDev == nil || activePeerPubHex == "" {
		mu.Unlock()
		return false
	}
	dev := activeDev
	params := peerHandshakeParams{
		pubHex:     activePeerPubHex,
		pskHex:     activePskHex,
		resolvedEp: activeResolvedEp,
		keepAlive:  activeKeepAlive,
	}
	mu.Unlock()

	if hopPort {
		_ = dev.IpcSet("listen_port=0\n")
	}

	if forcePeerReset && params.resolvedEp != "" {
		rawRx, rawTx, _ := readDeviceCounters(dev)
		mu.Lock()
		if !running || activeDev != dev {
			mu.Unlock()
			return false
		}
		baseRxBytes += rawRx
		baseTxBytes += rawTx
		params = peerHandshakeParams{
			pubHex:     activePeerPubHex,
			pskHex:     activePskHex,
			resolvedEp: activeResolvedEp,
			keepAlive:  activeKeepAlive,
		}
		err := applyPeerUapi(dev, params, "", true)
		if err == nil {
			dev.DisableSomeRoamingForBrokenMobileSemantics()
		}
		mu.Unlock()
	}

	triggerPeerHandshakeDirect(dev, params.pubHex, !forcePeerReset)
	return true
}

func readActiveTotals(dev *device.Device) (rx uint64, tx uint64, hsSec int64) {
	rawRx, rawTx, hs := readDeviceCounters(dev)
	mu.Lock()
	if running && activeDev == dev {
		rx = baseRxBytes + rawRx
		tx = baseTxBytes + rawTx
	} else {
		rx, tx = rawRx, rawTx
	}
	mu.Unlock()
	return rx, tx, hs
}

func notifyMuxWaitersLocked() {
	if muxNotifyCh != nil {
		close(muxNotifyCh)
	}
	muxNotifyCh = make(chan struct{})
}

func ensureMuxListenerLocked() (int, error) {
	if muxListener != nil && muxPort > 0 {
		return muxPort, nil
	}
	var ln net.Listener
	var err error
	for _, p := range preferredMuxPorts {
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			break
		}
	}
	if err != nil {
		return 0, fmt.Errorf("failed to bind local SOCKS5 mux listener: %w", err)
	}
	muxListener = ln
	muxPort = ln.Addr().(*net.TCPAddr).Port
	if muxNotifyCh == nil {
		muxNotifyCh = make(chan struct{})
	}
	go muxAcceptLoop(ln)
	return muxPort, nil
}

// SetTunnelStartupPending tells the unified local SOCKS5 mux to pause incoming proxy dials briefly
// instead of failing them while auto-connect or profile switching negotiates a new WireGuard session.
func SetTunnelStartupPending(pending bool) {
	mu.Lock()
	muxStartupPend = pending
	notifyMuxWaitersLocked()
	mu.Unlock()
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

	stopTunnelOnlyLocked()

	tunDev, tnet, err := createFastNetTUN(clientAddrs, dnsAddrs, effectiveMTU)
	if err != nil {
		stopMuxIfIdleLocked()
		mu.Unlock()
		return 0, fmt.Errorf("failed to create fast netstack TUN: %w", err)
	}

	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		_ = tunDev.Close()
		stopMuxIfIdleLocked()
		mu.Unlock()
		return 0, fmt.Errorf("failed to initialize tunnel bind: %w", err)
	}

	dev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))
	// Essential for 4G/5G CGNAT stability: prevent stray NAT packets from corrupting peer endpoint state
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	peerParams := peerHandshakeParams{
		pubHex:     pubHex,
		pskHex:     pskHex,
		resolvedEp: resolvedEndpoint,
		keepAlive:  keepAlive,
	}
	if err := applyPeerUapi(dev, peerParams, privHex, false); err != nil {
		dev.Close()
		stopMuxIfIdleLocked()
		mu.Unlock()
		return 0, fmt.Errorf("failed to apply WireGuard UAPI config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		stopMuxIfIdleLocked()
		mu.Unlock()
		return 0, fmt.Errorf("failed to bring WireGuard device up: %w", err)
	}

	port, err := ensureMuxListenerLocked()
	if err != nil {
		dev.Close()
		stopMuxIfIdleLocked()
		mu.Unlock()
		return 0, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	activeDev = dev
	activeCtx = ctx
	activeCancel = cancel
	activeTnet = tnet
	activePort = port
	activePeerPubHex = pubHex
	activePskHex = pskHex
	activeResolvedEp = resolvedEndpoint
	activeRawEp = endpoint
	activeUseDoH = useDoH
	activeKeepAlive = keepAlive
	activeStartTime = time.Now()
	baseRxBytes = 0
	baseTxBytes = 0
	running = true
	muxStartupPend = false
	notifyMuxWaitersLocked()

	mu.Unlock()

	// Kick off immediate Noise_IKpsk2 Handshake Initiation at t=0ms
	triggerPeerHandshakeDirect(dev, pubHex, false)
	// Give fast peers up to 160ms to complete handshake before returning port to Telegram
	waitForHandshakeQuick(dev, 160*time.Millisecond)

	go tunnelWatchdogLoop(ctx, dev, pubHex)

	return port, nil
}

// tunnelWatchdogLoop runs 24/7 inside the Go runtime to guarantee cellular CGNAT continuity:
// 1. During initial startup, performs fast UDP ephemeral port hopping (listen_port=0) plus clean peer
//    refresh to bypass wireguard-go's 5s RekeyTimeout instead of waiting 5+ seconds on cellular loss.
// 2. Continuously monitors RX/TX progress (ignoring small 32B keepalive packets) and handshake freshness,
//    automatically hopping ports and re-handshaking whenever a mobile CGNAT pinhole collapses or stalls.
func tunnelWatchdogLoop(ctx context.Context, dev *device.Device, pubHex string) {
	// Phase 1: Aggressive initial handshake warmup with real ephemeral port hops & RekeyTimeout bypass
	retryDelays := []time.Duration{480 * time.Millisecond, 700 * time.Millisecond, 950 * time.Millisecond}
	for _, wait := range retryDelays {
		if hasCompletedHandshake(dev) || !isActiveDevice(dev) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if hasCompletedHandshake(dev) || !isActiveDevice(dev) {
			break
		}
		hopActivePeer(true, true)
	}

	// Phase 2: 24/7 continuous health & CGNAT pinhole guardian
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()

	lastRx, lastTx, _ := readActiveTotals(dev)
	var stalledTicks int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !isActiveDevice(dev) {
			return
		}

		rx, tx, hsSec := readActiveTotals(dev)
		nowSec := time.Now().Unix()

		if rx < lastRx || tx < lastTx {
			lastRx, lastTx = rx, tx
			stalledTicks = 0
			continue
		}

		txDelta := tx - lastTx

		// Case A: Handshake missing, expired past 195s, or >135s stale while real data is queued
		if hsSec <= 0 || (nowSec-hsSec) > 195 || (txDelta >= 128 && (nowSec-hsSec) > 135) {
			hopActivePeer(true, true)
			stalledTicks = 0
			lastRx, lastTx, _ = readActiveTotals(dev)
			continue
		}

		// Case B: Significant outbound payload (>= 128B, ignoring 32B empty keepalive probes)
		// with zero inbound RX across 2 consecutive 8s intervals -> CGNAT pinhole collapsed or silent IP change.
		if txDelta >= 128 && rx == lastRx {
			stalledTicks++
			if stalledTicks >= 2 {
				hopActivePeer(true, true)
				stalledTicks = 0
				lastRx, lastTx, _ = readActiveTotals(dev)
				continue
			}
			triggerPeerHandshakeDirect(dev, pubHex, false)
		} else {
			stalledTicks = 0
		}

		lastRx, lastTx = rx, tx
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

// UpdatePeerEndpoint updates the WireGuard peer endpoint dynamically on genuine network handoff,
// hops onto a fresh OS ephemeral UDP port (:0), resets peer RekeyTimeout/sticky source state,
// and waits briefly to confirm the new Noise handshake completed across the new interface.
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
	activeRawEp = endpoint
	activeResolvedEp = resolved
	mu.Unlock()

	if !hopActivePeer(true, true) {
		return errors.New("tunnel is not running")
	}
	if waitForHandshakeQuick(dev, 700*time.Millisecond) {
		return nil
	}
	// Second attempt after 180ms in case Android netd switched cellular routes asynchronously
	time.Sleep(180 * time.Millisecond)
	if !isActiveDevice(dev) {
		return nil
	}
	hopActivePeer(true, true)
	_ = waitForHandshakeQuick(dev, 850*time.Millisecond)
	return nil
}

// ForceRebindAndHandshake hops to a fresh OS ephemeral UDP source port (:0) on the active network interface,
// forces an immediate cryptographic re-handshake (bypassing 5s RekeyTimeout), and verifies completion.
func ForceRebindAndHandshake() bool {
	mu.Lock()
	dev := activeDev
	rawEp := activeRawEp
	useDoH := activeUseDoH
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil {
		return false
	}

	if strings.TrimSpace(rawEp) != "" {
		ClearDnsCache()
		if resolved, err := ResolveEndpointDoH(rawEp, useDoH); err == nil && resolved != "" {
			mu.Lock()
			if running && activeDev == dev {
				activeResolvedEp = resolved
			}
			mu.Unlock()
		}
	}

	if !hopActivePeer(true, true) {
		return false
	}
	if waitForHandshakeQuick(dev, 600*time.Millisecond) {
		return true
	}
	// Second port hop if first packet was dropped during cellular radio state transition
	if !hopActivePeer(true, true) {
		return false
	}
	return waitForHandshakeQuick(dev, 750*time.Millisecond)
}

// EnsureTunnelAlive checks if the active tunnel has a fresh verified handshake;
// if stale (>= 120s) or uninitialized, it performs a fresh port hop + immediate re-handshake within timeoutMs.
func EnsureTunnelAlive(timeoutMs int) bool {
	mu.Lock()
	dev := activeDev
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil {
		return false
	}

	_, _, hsSec := readDeviceCounters(dev)
	nowSec := time.Now().Unix()
	if hsSec > 0 && (nowSec-hsSec) < 120 {
		return true
	}

	if timeoutMs <= 0 {
		timeoutMs = 1200
	}
	if timeoutMs > 5000 {
		timeoutMs = 5000
	}

	if !hopActivePeer(true, true) {
		return false
	}
	half := time.Duration(timeoutMs/2) * time.Millisecond
	if waitForHandshakeQuick(dev, half) {
		return true
	}
	if !hopActivePeer(true, true) {
		return false
	}
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
	baseRx := baseRxBytes
	baseTx := baseTxBytes
	mu.Unlock()

	if !isUp || dev == nil {
		return ""
	}
	rawRx, rawTx, hsSec := readDeviceCounters(dev)
	return fmt.Sprintf("rx_bytes=%d\ntx_bytes=%d\nlast_handshake_time_sec=%d",
		baseRx+rawRx, baseTx+rawTx, hsSec)
}

// StopTunnel stops the active WireGuard device and closes the unified local SOCKS5 listener
// unless KillSwitchGuard is currently protecting outbound traffic.
func StopTunnel() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

func stopTunnelOnlyLocked() {
	if activeCancel != nil {
		activeCancel()
		activeCancel = nil
	}
	activeCtx = nil
	activeTnet = nil
	if activeDev != nil {
		activeDev.Close()
		activeDev = nil
	}
	activePort = 0
	activePeerPubHex = ""
	activePskHex = ""
	activeResolvedEp = ""
	activeRawEp = ""
	activeUseDoH = false
	activeKeepAlive = 0
	baseRxBytes = 0
	baseTxBytes = 0
	running = false
}

func stopMuxIfIdleLocked() {
	if !running && !muxKillSwitch && muxListener != nil {
		_ = muxListener.Close()
		muxListener = nil
		muxPort = 0
	}
	notifyMuxWaitersLocked()
}

func stopLocked() {
	stopTunnelOnlyLocked()
	muxStartupPend = false
	stopMuxIfIdleLocked()
}

// IsRunning returns true if the tunnel and SOCKS5 listener are active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running && muxListener != nil && activeDev != nil
}

// GetActivePort returns the active local SOCKS5 port, or 0 if stopped.
func GetActivePort() int {
	mu.Lock()
	defer mu.Unlock()
	if !running || muxListener == nil {
		return 0
	}
	return muxPort
}

func tuneLocalTcpSocket(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(20 * time.Second)
	}
}

func muxAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			return
		}
		tuneLocalTcpSocket(c)
		go handleMuxConn(c)
	}
}

func awaitMuxRouteReady(maxWait time.Duration) (context.Context, udpDialer, bool) {
	deadline := time.Now().Add(maxWait)
	for {
		mu.Lock()
		isUp := running
		dialer := activeTnet
		ctx := activeCtx
		lnOpen := muxListener != nil
		pending := muxStartupPend
		ch := muxNotifyCh
		mu.Unlock()

		if isUp && dialer != nil && ctx != nil {
			return ctx, dialer, true
		}
		if !lnOpen || !pending {
			return nil, nil, false
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return nil, nil, false
		}
		timer := time.NewTimer(rem)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
			return nil, nil, false
		}
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

func readSocks5HandshakeAndReq(client net.Conn) (cmd byte, host string, dstPort uint16, reqParsed bool) {
	// 1. Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return 0, "", 0, false
	}
	if hdr[0] != 0x05 {
		return 0, "", 0, false
	}
	nMethods := int(hdr[1])
	if nMethods > 0 {
		methods := make([]byte, nMethods)
		if _, err := io.ReadFull(client, methods); err != nil {
			return 0, "", 0, false
		}
	}
	// Reply: SOCKS5, NO AUTHENTICATION REQUIRED (0x00)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return 0, "", 0, false
	}

	// 2. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil {
		return 0, "", 0, false
	}
	if reqHdr[0] != 0x05 {
		return 0, "", 0, false
	}

	cmd = reqHdr[1]
	host, dstPort, err := readSocks5Target(client, reqHdr[3])
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", 0, false
	}
	return cmd, host, dstPort, true
}

func dispatchSocks5Cmd(ctx context.Context, client net.Conn, dialer udpDialer, cmd byte, host string, dstPort uint16) {
	switch cmd {
	case 0x01: // TCP CONNECT (MTProto signaling, channels, media, VoIP TCP fallback)
		handleTcpConnect(ctx, client, dialer, host, dstPort)
	case 0x03: // UDP ASSOCIATE (Telegram VoIP / tgcalls voice & video RTP/STUN media)
		handleUdpAssociate(ctx, client, dialer)
	default:
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func handleSocks5Client(ctx context.Context, client net.Conn, dialer udpDialer) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))

	cmd, host, dstPort, ok := readSocks5HandshakeAndReq(client)
	if !ok {
		return
	}
	dispatchSocks5Cmd(ctx, client, dialer, cmd, host, dstPort)
}

func handleMuxConn(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))

	cmd, host, dstPort, ok := readSocks5HandshakeAndReq(client)
	if !ok {
		return
	}

	devCtx, dialer, allowed := awaitMuxRouteReady(2800 * time.Millisecond)
	if !allowed {
		// Fail closed: zero plaintext traffic leaves device when tunnel is down.
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	dispatchSocks5Cmd(devCtx, client, dialer, cmd, host, dstPort)
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
