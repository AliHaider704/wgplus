package wgbridge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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

	"golang.zx2c4.com/wireguard/device"
)

const (
	defaultMTU               = 1280
	minMTU                   = 1280
	maxMTU                   = 1420
	maxUdpSessionsCap        = 64
	desktopMaxUdpSessionsCap = 256
	tcpCopyBufSize           = 64 * 1024
	desktopTcpCopyBufSize    = 64 * 1024
	udpSocketBufSize         = 1024 * 1024
	desktopUdpSocketBufSize  = 4 * 1024 * 1024
)

var (
	mu                       sync.Mutex
	rebindMu                 sync.Mutex
	lastForceHopAt           time.Time
	lastAppliedResolvedEp    string
	socksAuthRejectCount     atomic.Int64
	activeDev                *device.Device
	activeCtx                context.Context
	activeCancel             context.CancelFunc
	activeTnet               *fastNet
	activePort               int
	activePeerPubHex         string
	activePskHex             string
	activeResolvedEp         string
	activeRawEp              string
	activeUseDoH             bool
	activeKeepAlive          int
	activeStartTime          time.Time
	handshakeInitMu          sync.Mutex
	lastHandshakeInitAt      time.Time
	baseRxBytes              uint64
	baseTxBytes              uint64
	running                  bool
	muxListener              net.Listener
	muxPort                  int
	muxKillSwitch            bool
	muxStartupPend           bool
	muxNotifyCh              chan struct{}
	preferredMuxPorts        = []int{48729, 48730, 48731, 48732, 0}
	preferredMuxPortOverride int
	recoveryEpoch            atomic.Int64

	socksAuthMu           sync.RWMutex
	socksAuthUser         string
	socksAuthPass         string
	lastSocksAuthDiagNano atomic.Int64

	proxyStreamsMu     sync.Mutex
	nextProxyStreamID  uint64
	activeProxyStreams = make(map[uint64]func())

	tcpCopyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tcpCopyBufSize)
			return &b
		},
	}

	desktopTcpCopyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, desktopTcpCopyBufSize)
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

// SetDesktopMode enables or disables PC-tuned netstack queue depth, batch size, and socket buffers.
func SetDesktopMode(enabled bool) {
	desktopModeFlag.Store(enabled)
}

// SetBlockIPv6 enables or disables IPv6/AAAA blocking inside the userspace tunnel netstack.
func SetBlockIPv6(enabled bool) {
	blockIPv6Flag.Store(enabled)
	mu.Lock()
	if activeTnet != nil {
		activeTnet.blockIPv6.Store(enabled)
	}
	mu.Unlock()
}

// SetSocksAuth configures optional RFC 1929 SOCKS5 username/password authentication
// (and HTTP CONNECT Basic auth). Passing empty strings disables authentication (mobile default).
func SetSocksAuth(username, password string) {
	socksAuthMu.Lock()
	socksAuthUser = username
	socksAuthPass = password
	socksAuthMu.Unlock()
}

func getSocksAuth() (string, string) {
	socksAuthMu.RLock()
	u := socksAuthUser
	p := socksAuthPass
	socksAuthMu.RUnlock()
	return u, p
}

// SetPreferredMuxPort overrides the primary local SOCKS5 port tried first when binding 127.0.0.1.
func SetPreferredMuxPort(port int) {
	mu.Lock()
	if port > 0 && port <= 65535 {
		preferredMuxPortOverride = port
	} else {
		preferredMuxPortOverride = 0
	}
	mu.Unlock()
}

func activeUdpSocketBufSize() int {
	if desktopModeFlag.Load() {
		return desktopUdpSocketBufSize
	}
	return udpSocketBufSize
}

func activeMaxUdpSessionsCap() int {
	if desktopModeFlag.Load() {
		return desktopMaxUdpSessionsCap
	}
	return maxUdpSessionsCap
}

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

func markHandshakeInitNow() {
	handshakeInitMu.Lock()
	lastHandshakeInitAt = time.Now()
	handshakeInitMu.Unlock()
}

func waitNextTai64nTick() {
	handshakeInitMu.Lock()
	prev := lastHandshakeInitAt
	handshakeInitMu.Unlock()
	if !prev.IsZero() {
		// WireGuard drops initiations arriving within 20ms (HandshakeInitationRate = 1s/50)
		// or inside the same ~16.77ms TAI64N bucket; wait 55ms to cover OS timer jitter cleanly.
		if elapsed := time.Since(prev); elapsed >= 0 && elapsed < 55*time.Millisecond {
			time.Sleep(55*time.Millisecond - elapsed)
		}
	}
}

func triggerPeerHandshakeDirect(dev *device.Device, pubHex string, isRetry bool) {
	peer := lookupPeerByHex(dev, pubHex)
	if peer != nil {
		markHandshakeInitNow()
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

const minHardHopInterval = 3500 * time.Millisecond

// hopActivePeer forces wireguard-go onto a fresh OS ephemeral UDP port (listen_port=0) and,
// when forcePeerReset is true, cleanly recreates the peer so stale lastSentHandshake (5s RekeyTimeout)
// and stale wlan0 sticky PKTINFO source addresses are wiped before initiating a fresh Noise handshake.
func hopActivePeer(hopPort bool, forcePeerReset bool) bool {
	return hopActivePeerInternal(hopPort, forcePeerReset, false)
}

func hopActivePeerInternal(hopPort bool, forcePeerReset bool, bypassCooldown bool) bool {
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

	epChanged := params.resolvedEp != "" && params.resolvedEp != lastAppliedResolvedEp

	// Prevent parallel guardian/roaming/watchdog loops from wiping the peer back-to-back
	// before a handshake response can return over high-latency mobile/CGNAT links.
	if forcePeerReset && !bypassCooldown && !epChanged && !lastForceHopAt.IsZero() && time.Since(lastForceHopAt) < minHardHopInterval {
		triggerPeerHandshakeDirect(dev, params.pubHex, true)
		return true
	}

	if hopPort {
		for attempt := 0; attempt < 3; attempt++ {
			if err := dev.IpcSet("listen_port=0\n"); err == nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
	}

	if forcePeerReset && params.resolvedEp != "" {
		// Advance past WireGuard's 20ms HandshakeInitationRate & ~16.77ms TAI64N window BEFORE
		// applyPeerUapi(..., replace_peers=true) because persistent_keepalive immediately triggers an initiation inside IpcSet.
		waitNextTai64nTick()
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
			if params.keepAlive > 0 {
				markHandshakeInitNow()
			}
			dev.DisableSomeRoamingForBrokenMobileSemantics()
			lastAppliedResolvedEp = params.resolvedEp
		}
		mu.Unlock()
		lastForceHopAt = time.Now()
	}

	if forcePeerReset && params.resolvedEp == "" {
		waitNextTai64nTick()
	}
	triggerPeerHandshakeDirect(dev, params.pubHex, !forcePeerReset)
	recoveryEpoch.Add(1)
	if forcePeerReset {
		RecordDiag("TUNNEL", "REBIND", fmt.Sprintf("peer reset hopPort=%v", hopPort))
	}
	return true
}

// GetRecoveryEpoch returns a monotonically increasing counter incremented on each tunnel rebind/hop.
func GetRecoveryEpoch() int64 {
	return recoveryEpoch.Load()
}

func registerProxyStream(closeFn func()) uint64 {
	if closeFn == nil {
		return 0
	}
	proxyStreamsMu.Lock()
	nextProxyStreamID++
	id := nextProxyStreamID
	activeProxyStreams[id] = closeFn
	proxyStreamsMu.Unlock()
	return id
}

func unregisterProxyStream(id uint64) {
	if id == 0 {
		return
	}
	proxyStreamsMu.Lock()
	delete(activeProxyStreams, id)
	proxyStreamsMu.Unlock()
}

// ResetActiveProxyConnections forcefully closes all open local SOCKS5 TCP and UDP proxy streams
// so Telegram tgnet immediately drops zombie loopback sockets after long sleep or session expiry.
func ResetActiveProxyConnections(reason string) int {
	proxyStreamsMu.Lock()
	var closers []func()
	if len(activeProxyStreams) > 0 {
		closers = make([]func(), 0, len(activeProxyStreams))
		for id, fn := range activeProxyStreams {
			closers = append(closers, fn)
			delete(activeProxyStreams, id)
		}
	}
	proxyStreamsMu.Unlock()

	for _, fn := range closers {
		if fn != nil {
			fn()
		}
	}
	recoveryEpoch.Add(1)
	RecordDiag("TUNNEL", "PROXY_RESET", fmt.Sprintf("closed=%d reason=%s", len(closers), strings.TrimSpace(reason)))
	return len(closers)
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
	var candidates []int
	if preferredMuxPortOverride > 0 {
		candidates = append(candidates, preferredMuxPortOverride)
	}
	for _, p := range preferredMuxPorts {
		if p != preferredMuxPortOverride {
			candidates = append(candidates, p)
		}
	}
	var ln net.Listener
	var err error
	for _, p := range candidates {
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

	// Ensure consecutive restarts/handovers advance past WireGuard's 20ms rate limit & TAI64N bucket
	// BEFORE dev.Up() starts the keepalive initiation timer.
	waitNextTai64nTick()

	mu.Lock()

	stopTunnelOnlyLocked()

	tunDev, tnet, err := createFastNetTUN(clientAddrs, dnsAddrs, effectiveMTU)
	if err != nil {
		stopMuxIfIdleLocked()
		mu.Unlock()
		return 0, fmt.Errorf("failed to create fast netstack TUN: %w", err)
	}

	bindImpl, err := newAwgBind(newPlatformBind(), awgCfg, privHex, pubHex)
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
	markHandshakeInitNow()

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
	go tunnelBandwidthSamplerLoop(ctx, dev)

	return port, nil
}

// tunnelWatchdogLoop runs 24/7 inside the Go runtime to guarantee cellular CGNAT continuity:
// 1. During initial startup, performs fast UDP ephemeral port hopping (listen_port=0) plus clean peer
//    refresh to bypass wireguard-go's 5s RekeyTimeout instead of waiting 5+ seconds on cellular loss.
// 2. Continuously monitors RX/TX progress (ignoring small 32B keepalive packets) and handshake freshness,
//    automatically hopping ports and re-handshaking whenever a mobile CGNAT pinhole collapses or stalls.
func tunnelWatchdogLoop(ctx context.Context, dev *device.Device, pubHex string) {
	// Phase 1: Initial handshake warmup. Try soft retries first (350ms, 900ms), then perform
	// at most one hard port hop at 2200ms only if no handshake has landed yet.
	retryDelays := []time.Duration{350 * time.Millisecond, 900 * time.Millisecond, 2200 * time.Millisecond}
	for idx, wait := range retryDelays {
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
		if idx < len(retryDelays)-1 {
			triggerPeerHandshakeDirect(dev, pubHex, true)
		} else {
			hopActivePeer(true, true)
		}
	}

	// Phase 2: 24/7 continuous health & CGNAT pinhole guardian (3s ticks -> 9s stall recovery)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	lastRx, lastTx, _ := readActiveTotals(dev)
	var stalledTicks int
	var noHandshakeTicks int
	var noHandshakeBackoffTicks = 3 // 9s -> 18s -> 30s
	var lastHardHopAt time.Time

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
			noHandshakeTicks = 0
			continue
		}

		txDelta := tx - lastTx
		canHardHop := lastHardHopAt.IsZero() || time.Since(lastHardHopAt) >= 20*time.Second

		// Case A1: Never completed a handshake; nudge softly and apply backed-off hard hops (9s -> 18s -> 30s).
		if hsSec <= 0 {
			noHandshakeTicks++
			if noHandshakeTicks >= noHandshakeBackoffTicks && canHardHop {
				hopActivePeer(true, true)
				lastHardHopAt = time.Now()
				noHandshakeTicks = 0
				if noHandshakeBackoffTicks < 10 {
					noHandshakeBackoffTicks += 3
				}
				stalledTicks = 0
				lastRx, lastTx, _ = readActiveTotals(dev)
				continue
			}
			triggerPeerHandshakeDirect(dev, pubHex, true)
			lastRx, lastTx = rx, tx
			continue
		}
		noHandshakeTicks = 0
		noHandshakeBackoffTicks = 3

		// Case A2: Handshake aging (>135s while real traffic is flowing).
		// Soft-rehandshake ONLY — never wipe the live peer session or hop UDP port here,
		// otherwise active Telegram TCP sockets stall for 2-5 seconds on retransmission.
		hsAge := nowSec - hsSec
		if hsAge > 135 && txDelta >= 128 && rx > lastRx {
			triggerPeerHandshakeDirect(dev, pubHex, true)
			stalledTicks = 0
			lastRx, lastTx = rx, tx
			continue
		}

		// Case B: Outbound payload (>=256B) with zero inbound RX across 3 consecutive 3s intervals (9s).
		stalled := (txDelta >= 256 && rx == lastRx) ||
			(hsAge > 220 && txDelta >= 128 && rx == lastRx)
		if stalled {
			stalledTicks++
			if stalledTicks >= 3 && canHardHop {
				watchdogRecoveries.Add(1)
				RecordDiag("WATCHDOG", "STALL_HOP", fmt.Sprintf("txDelta=%d hsAge=%d", txDelta, hsAge))
				hopActivePeer(true, true)
				if hsAge >= 180 {
					ResetActiveProxyConnections("watchdog_expired_stall")
				}
				lastHardHopAt = time.Now()
				stalledTicks = 0
				lastRx, lastTx, _ = readActiveTotals(dev)
				continue
			}
			triggerPeerHandshakeDirect(dev, pubHex, true)
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

	mu.Lock()
	if !running || activeDev == nil || activePeerPubHex == "" {
		mu.Unlock()
		return errors.New("tunnel is not running")
	}
	dev := activeDev
	activeRawEp = endpoint
	epChanged := false
	if err == nil && resolved != "" {
		epChanged = resolved != activeResolvedEp
		activeResolvedEp = resolved
	}
	pubHex := activePeerPubHex
	mu.Unlock()

	if !hopActivePeerInternal(true, true, epChanged) {
		return errors.New("tunnel is not running")
	}
	if waitForHandshakeQuick(dev, 1400*time.Millisecond) {
		return nil
	}
	// Soft re-nudge after 180ms in case Android netd switched routes asynchronously
	time.Sleep(180 * time.Millisecond)
	if !isActiveDevice(dev) {
		return nil
	}
	triggerPeerHandshakeDirect(dev, pubHex, true)
	_ = waitForHandshakeQuick(dev, 900*time.Millisecond)
	return nil
}

// ForceRebindAndHandshake hops to a fresh OS ephemeral UDP source port (:0) on the active network interface,
// forces an immediate cryptographic re-handshake (within cooldown limits), and verifies completion.
func ForceRebindAndHandshake() bool {
	mu.Lock()
	dev := activeDev
	rawEp := activeRawEp
	useDoH := activeUseDoH
	pubHex := activePeerPubHex
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil {
		return false
	}

	epChanged := false
	if strings.TrimSpace(rawEp) != "" {
		ClearDnsCache()
		if resolved, err := ResolveEndpointDoH(rawEp, useDoH); err == nil && resolved != "" {
			mu.Lock()
			if running && activeDev == dev {
				epChanged = resolved != activeResolvedEp
				activeResolvedEp = resolved
			}
			mu.Unlock()
		}
	}

	if !hopActivePeerInternal(true, true, epChanged) {
		return false
	}
	if waitForHandshakeQuick(dev, 1800*time.Millisecond) {
		return true
	}
	if !isActiveDevice(dev) {
		return false
	}
	triggerPeerHandshakeDirect(dev, pubHex, true)
	return waitForHandshakeQuick(dev, 900*time.Millisecond)
}

// EnsureTunnelAlive verifies the active tunnel is genuinely responsive without disturbing
// healthy WireGuard sessions (RekeyAfterTime=120s). Only if the handshake is missing or >=120s old
// does it attempt a non-disruptive soft handshake first, escalating to at most ONE port hop on actual failure.
func EnsureTunnelAlive(timeoutMs int) bool {
	mu.Lock()
	dev := activeDev
	pubHex := activePeerPubHex
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil {
		return false
	}

	prevRx, _, hsSec := readDeviceCounters(dev)
	nowSec := time.Now().Unix()
	if hsSec > 0 && (nowSec-hsSec) < 120 {
		return true
	}

	if timeoutMs <= 0 {
		timeoutMs = 1800
	}
	if timeoutMs > 5000 {
		timeoutMs = 5000
	}

	if pubHex != "" {
		prevHs := hsSec
		triggerPeerHandshakeDirect(dev, pubHex, true)
		probeWait := time.Duration(timeoutMs) * time.Millisecond
		if probeWait > 1500*time.Millisecond {
			probeWait = 1500 * time.Millisecond
		}
		deadline := time.Now().Add(probeWait)
		for time.Now().Before(deadline) {
			curRx, _, curHs := readDeviceCounters(dev)
			if curHs > 0 && (curHs > prevHs || curRx > prevRx) {
				return true
			}
			if muxDeviceClosedOrReplaced(dev) {
				return false
			}
			time.Sleep(15 * time.Millisecond)
		}
	}

	wasExpired := hsSec <= 0 || (nowSec-hsSec) >= 180
	RecordDiag("TUNNEL", "ENSURE_HOP", fmt.Sprintf("hsSec=%d timeoutMs=%d", hsSec, timeoutMs))
	if !hopActivePeer(true, true) {
		return false
	}
	if wasExpired {
		ResetActiveProxyConnections("expired_handshake_recovery")
	}
	waitDur := time.Duration(timeoutMs) * time.Millisecond
	if waitDur < 1500*time.Millisecond {
		waitDur = 1500 * time.Millisecond
	}
	return waitForHandshakeQuick(dev, waitDur)
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
	stopLocked()
	mu.Unlock()
	StopAllVoipRelays()
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

// IsHandshakeHealthy returns true only when the tunnel is running and has completed
// a fresh WireGuard Noise handshake (last_handshake_time_sec > 0 and < 210s old).
func IsHandshakeHealthy() bool {
	mu.Lock()
	dev := activeDev
	isUp := running
	mu.Unlock()
	if !isUp || dev == nil {
		return false
	}
	_, _, hsSec := readDeviceCounters(dev)
	if hsSec <= 0 {
		return false
	}
	return (time.Now().Unix() - hsSec) < 210
}

// GetSocksAuthRejectCount returns the number of rejected local SOCKS5 authentication attempts.
func GetSocksAuthRejectCount() int64 {
	return socksAuthRejectCount.Load()
}

// ResetSocksAuthRejectCount resets the SOCKS5 auth rejection counter (e.g., after credential sync).
func ResetSocksAuthRejectCount() {
	socksAuthRejectCount.Store(0)
}

func awaitHandshakeReadyOrFail(ctx context.Context, dialer udpDialer, maxWait time.Duration) bool {
	if _, isWgNet := dialer.(*fastNet); !isWgNet {
		return true
	}
	mu.Lock()
	dev := activeDev
	pubHex := activePeerPubHex
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil || pubHex == "" {
		return false
	}
	_, _, hsSec := readDeviceCounters(dev)
	if hsSec > 0 {
		if time.Now().Unix()-hsSec > 135 {
			triggerPeerHandshakeDirect(dev, pubHex, true)
		}
		return true
	}
	// Handshake not yet completed: nudge softly with isRetry=true and wait up to maxWait before failing fast.
	triggerPeerHandshakeDirect(dev, pubHex, true)
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if ctx != nil && ctx.Err() != nil {
			return false
		}
		if hasCompletedHandshake(dev) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return hasCompletedHandshake(dev)
}

func recordSocksAuthReject(reason string) {
	socksAuthRejectCount.Add(1)
	nowNano := time.Now().UnixNano()
	prev := lastSocksAuthDiagNano.Load()
	if nowNano-prev > int64(3*time.Second) && lastSocksAuthDiagNano.CompareAndSwap(prev, nowNano) {
		RecordDiag("SOCKS_AUTH", "REJECT", reason)
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
	var methods []byte
	if nMethods > 0 {
		methods = make([]byte, nMethods)
		if _, err := io.ReadFull(client, methods); err != nil {
			return 0, "", 0, false
		}
	}

	expectedUser, expectedPass := getSocksAuth()
	if expectedUser == "" && expectedPass == "" {
		// Reply: SOCKS5, NO AUTHENTICATION REQUIRED (0x00)
		if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
			return 0, "", 0, false
		}
	} else {
		hasUserPass := false
		for _, m := range methods {
			if m == 0x02 {
				hasUserPass = true
				break
			}
		}
		if !hasUserPass {
			_, _ = client.Write([]byte{0x05, 0xFF})
			recordSocksAuthReject("client omitted user/pass method 0x02")
			return 0, "", 0, false
		}
		if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
			return 0, "", 0, false
		}
		// RFC 1929 subnegotiation: VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
		var subHdr [2]byte
		if _, err := io.ReadFull(client, subHdr[:]); err != nil || subHdr[0] != 0x01 {
			_, _ = client.Write([]byte{0x01, 0x01})
			recordSocksAuthReject("invalid rfc1929 subnegotiation header")
			return 0, "", 0, false
		}
		uBuf := make([]byte, int(subHdr[1]))
		if len(uBuf) > 0 {
			if _, err := io.ReadFull(client, uBuf); err != nil {
				_, _ = client.Write([]byte{0x01, 0x01})
				recordSocksAuthReject("truncated rfc1929 username")
				return 0, "", 0, false
			}
		}
		var pLen [1]byte
		if _, err := io.ReadFull(client, pLen[:]); err != nil {
			_, _ = client.Write([]byte{0x01, 0x01})
			recordSocksAuthReject("missing rfc1929 password length")
			return 0, "", 0, false
		}
		pBuf := make([]byte, int(pLen[0]))
		if len(pBuf) > 0 {
			if _, err := io.ReadFull(client, pBuf); err != nil {
				_, _ = client.Write([]byte{0x01, 0x01})
				recordSocksAuthReject("truncated rfc1929 password")
				return 0, "", 0, false
			}
		}
		uOk := subtle.ConstantTimeCompare(uBuf, []byte(expectedUser))
		pOk := subtle.ConstantTimeCompare(pBuf, []byte(expectedPass))
		if (uOk & pOk) != 1 {
			_, _ = client.Write([]byte{0x01, 0x01})
			recordSocksAuthReject("username/password mismatch")
			return 0, "", 0, false
		}
		if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
			return 0, "", 0, false
		}
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
	dispatchSocks5CmdWithLabel(ctx, client, dialer, cmd, host, dstPort, "local-client")
}

func dispatchSocks5CmdWithLabel(ctx context.Context, client net.Conn, dialer udpDialer, cmd byte, host string, dstPort uint16, clientLabel string) {
	switch cmd {
	case 0x01: // TCP CONNECT (MTProto signaling, channels, media, VoIP TCP fallback)
		handleTcpConnectTracked(ctx, client, dialer, host, dstPort, clientLabel)
	case 0x03: // UDP ASSOCIATE (Telegram VoIP / tgcalls voice & video RTP/STUN media)
		handleUdpAssociateTracked(ctx, client, dialer, clientLabel)
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

type prependByteConn struct {
	net.Conn
	firstByte byte
	consumed  bool
}

func (c *prependByteConn) Read(p []byte) (int, error) {
	if !c.consumed {
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = c.firstByte
		c.consumed = true
		return 1, nil
	}
	return c.Conn.Read(p)
}

// ComputeProfileSigHash returns the 12-hex-char SHA-256 prefix of a normalized profileSig
// so non-secret PUBLIC_STATUS probes can confirm shared-hub profile equivalence without leaking endpoints.
func ComputeProfileSigHash(profileSig string) string {
	trimmed := strings.TrimSpace(profileSig)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])[:12]
}

func readWgpStatusSnapshot() (isUp bool, hsHealthy bool, hsSec int64, profileSig string) {
	mu.Lock()
	isUp = running
	dev := activeDev
	rawEp := strings.TrimSpace(activeRawEp)
	pubHex := strings.TrimSpace(activePeerPubHex)
	mu.Unlock()
	if isUp && dev != nil {
		_, _, hsSec = readDeviceCounters(dev)
	}
	hsHealthy = IsHandshakeHealthy()
	if rawEp != "" && len(pubHex) == 64 {
		if pubRaw, dErr := hex.DecodeString(pubHex); dErr == nil && len(pubRaw) == 32 {
			profileSig = rawEp + "|" + base64.StdEncoding.EncodeToString(pubRaw)
		}
	}
	return isUp, hsHealthy, hsSec, profileSig
}

// SendLocalWgp1Command executes a single-line WGP1 loopback control command from Go so Android
// Main UI Thread callers (such as VoIPService endpoint setup) never trigger StrictMode NetworkOnMainThreadException.
func SendLocalWgp1Command(muxPort int, socksPass string, command string, timeoutMs int) string {
	cmd := strings.TrimSpace(command)
	if muxPort < 1 || muxPort > 65535 || cmd == "" {
		return ""
	}
	if timeoutMs < 80 {
		timeoutMs = 80
	} else if timeoutMs > 2000 {
		timeoutMs = 2000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	passTok := strings.TrimSpace(socksPass)
	if passTok == "" {
		passTok = "-"
	}

	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", muxPort), timeout)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	line := "WGP1 " + passTok + " " + cmd + "\n"
	if _, err := c.Write([]byte(line)); err != nil {
		return ""
	}
	var out [512]byte
	n := 0
	for n < len(out) {
		rn, rErr := c.Read(out[n : n+1])
		if rn > 0 {
			if out[n] == '\n' {
				break
			}
			n++
		}
		if rErr != nil {
			break
		}
	}
	return strings.TrimSpace(string(out[:n]))
}

// RequestRemoteVoipRelayAddr asks a live local mux owner over WGP1 to bind or reuse a
// port-preserving loopback relay ("ip:port") for targetHost:targetPort.
func RequestRemoteVoipRelayAddr(muxPort int, socksPass string, targetHost string, targetPort int) string {
	host := strings.TrimSpace(targetHost)
	if muxPort < 1 || muxPort > 65535 || host == "" || targetPort < 1 || targetPort > 65535 {
		return ""
	}
	resp := SendLocalWgp1Command(muxPort, socksPass, fmt.Sprintf("VOIP_RELAY_ADDR %s %d", host, targetPort), 650)
	if strings.HasPrefix(resp, "OK ") {
		addr := strings.TrimSpace(resp[3:])
		if strings.Contains(addr, ":") {
			return addr
		}
	}
	respLegacy := SendLocalWgp1Command(muxPort, socksPass, fmt.Sprintf("VOIP_RELAY %s %d", host, targetPort), 650)
	if strings.HasPrefix(respLegacy, "OK ") {
		portNum, err := strconv.Atoi(strings.TrimSpace(respLegacy[3:]))
		if err == nil && portNum > 0 && portNum <= 65535 {
			return fmt.Sprintf("127.0.0.1:%d", portNum)
		}
	}
	return ""
}

// RequestRemoteTunnelYield asks a live local mux owner over authenticated WGP1 to release
// its tunnel, kill switch guard, and local mux port for foreground takeover.
func RequestRemoteTunnelYield(muxPort int, socksPass string) bool {
	if muxPort < 1 || muxPort > 65535 {
		return false
	}
	resp := SendLocalWgp1Command(muxPort, socksPass, "YIELD", 800)
	if !strings.HasPrefix(resp, "OK") {
		return false
	}
	time.Sleep(25 * time.Millisecond)
	return true
}

func handleWgpControlConn(client net.Conn, firstByte byte) {
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	buf[0] = firstByte
	n := 1
	for n < len(buf) {
		rn, err := client.Read(buf[n : n+1])
		if rn > 0 {
			if buf[n] == '\n' {
				break
			}
			n++
		}
		if err != nil {
			break
		}
	}
	line := strings.TrimSpace(string(buf[:n]))
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "WGP1" {
		_, _ = client.Write([]byte("ERR CMD\n"))
		return
	}

	// Non-secret status metadata allows local sandboxed clients (before credential sync)
	// to detect whether port 48729 already hosts a running tunnel for the same profile hash.
	if fields[2] == "PUBLIC_STATUS" {
		isUp, hsHealthy, hsSec, profileSig := readWgpStatusSnapshot()
		sigHash := ComputeProfileSigHash(profileSig)
		if sigHash != "" {
			_, _ = fmt.Fprintf(client, "OK %t %t %d %s\n", isUp, hsHealthy, hsSec, sigHash)
		} else {
			_, _ = fmt.Fprintf(client, "OK %t %t %d -\n", isUp, hsHealthy, hsSec)
		}
		return
	}

	_, expectedPass := getSocksAuth()
	if expectedPass != "" {
		passMatch := len(fields[1]) == len(expectedPass) &&
			subtle.ConstantTimeCompare([]byte(fields[1]), []byte(expectedPass)) == 1
		if !passMatch {
			_, _ = client.Write([]byte("ERR AUTH\n"))
			return
		}
	}

	switch fields[2] {
	case "VOIP_RELAY":
		if len(fields) != 5 {
			_, _ = client.Write([]byte("ERR ARGS\n"))
			return
		}
		portNum, err := strconv.Atoi(fields[4])
		if err != nil || portNum < 1 || portNum > 65535 {
			_, _ = client.Write([]byte("ERR PORT\n"))
			return
		}
		if !IsRunning() {
			_, _ = client.Write([]byte("ERR STOPPED\n"))
			return
		}
		lp := StartVoipEndpointRelay(fields[3], portNum)
		if lp <= 0 {
			_, _ = client.Write([]byte("ERR RELAY\n"))
			return
		}
		_, _ = fmt.Fprintf(client, "OK %d\n", lp)
	case "VOIP_RELAY_ADDR":
		if len(fields) != 5 {
			_, _ = client.Write([]byte("ERR ARGS\n"))
			return
		}
		portNum, err := strconv.Atoi(fields[4])
		if err != nil || portNum < 1 || portNum > 65535 {
			_, _ = client.Write([]byte("ERR PORT\n"))
			return
		}
		if !IsRunning() {
			_, _ = client.Write([]byte("ERR STOPPED\n"))
			return
		}
		addr := StartVoipEndpointRelayAddr(fields[3], portNum)
		if addr == "" {
			_, _ = client.Write([]byte("ERR RELAY\n"))
			return
		}
		_, _ = fmt.Fprintf(client, "OK %s\n", addr)
	case "STATUS":
		isUp, hsHealthy, hsSec, profileSig := readWgpStatusSnapshot()
		if profileSig != "" {
			_, _ = fmt.Fprintf(client, "OK %t %t %d %s\n", isUp, hsHealthy, hsSec, profileSig)
		} else {
			_, _ = fmt.Fprintf(client, "OK %t %t %d\n", isUp, hsHealthy, hsSec)
		}
	case "YIELD":
		SetKillSwitchArmed(false)
		StopKillSwitchGuard()
		StopTunnel()
		RecordDiag("TUNNEL", "YIELDED", "released local mux on authenticated YIELD")
		_, _ = client.Write([]byte("OK YIELDED\n"))
	default:
		_, _ = client.Write([]byte("ERR CMD\n"))
	}
}

func handleMuxConn(client net.Conn) {
	defer client.Close()

	clientLabel, clientAllowed := invokeClientGuard(client.RemoteAddr())
	if !clientAllowed {
		blockedLocalAttempts.Add(1)
		return
	}

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var first [1]byte
	if _, err := io.ReadFull(client, first[:]); err != nil {
		return
	}
	if first[0] == 'W' {
		handleWgpControlConn(client, first[0])
		return
	}

	wrapped := &prependByteConn{Conn: client, firstByte: first[0]}
	_ = wrapped.SetDeadline(time.Now().Add(20 * time.Second))

	cmd, host, dstPort, ok := readSocks5HandshakeAndReq(wrapped)
	if !ok {
		return
	}

	devCtx, dialer, allowed := awaitMuxRouteReady(2800 * time.Millisecond)
	if !allowed {
		// Fail closed: zero plaintext traffic leaves device when tunnel is down.
		_, _ = wrapped.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	dispatchSocks5CmdWithLabel(devCtx, wrapped, dialer, cmd, host, dstPort, clientLabel)
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

func copyWithPooledBufTracked(dst io.Writer, src io.Reader, statEnt *clientStatEntry, isTx bool) {
	pool := &tcpCopyBufPool
	if desktopModeFlag.Load() {
		pool = &desktopTcpCopyBufPool
	}
	bufPtr := pool.Get().(*[]byte)
	defer pool.Put(bufPtr)
	buf := *bufPtr

	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			written := 0
			for written < nr {
				nw, wErr := dst.Write(buf[written:nr])
				if nw > 0 {
					written += nw
					if statEnt != nil {
						if isTx {
							recordClientTx(statEnt, nw)
						} else {
							recordClientRx(statEnt, nw)
						}
					}
				}
				if wErr != nil {
					return
				}
				if nw == 0 {
					return
				}
			}
		}
		if rErr != nil {
			return
		}
	}
}

func handleTcpConnect(ctx context.Context, client net.Conn, dialer udpDialer, host string, dstPort uint16) {
	handleTcpConnectTracked(ctx, client, dialer, host, dstPort, "local-client")
}

func handleTcpConnectTracked(ctx context.Context, client net.Conn, dialer udpDialer, host string, dstPort uint16, clientLabel string) {
	// Fast-fail IPv6 literal dials when the tunnel has no IPv6 or IPv6 is blocked so clients
	// (especially logged-out Telegram tgnet) immediately fall back to IPv4 DCs in <1ms.
	if ip, pErr := netip.ParseAddr(host); pErr == nil && ip.Unmap().Is6() {
		if fnet, ok := dialer.(*fastNet); ok && !fnet.SupportsIPv6() {
			udpIpv6DialFastFails.Add(1)
			_, _ = client.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	}

	if !awaitHandshakeReadyOrFail(ctx, dialer, 2500*time.Millisecond) {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	remote, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		var repCode byte = 0x04
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "ipv6 blocked") || strings.Contains(errStr, "no route") || strings.Contains(errStr, "network") {
			repCode = 0x03
		} else if strings.Contains(errStr, "refused") {
			repCode = 0x05
		}
		_, _ = client.Write([]byte{0x05, repCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Clear handshake deadline before streaming
	_ = client.SetDeadline(time.Time{})

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	activeTcpConns.Add(1)
	defer activeTcpConns.Add(-1)
	statEnt := trackClientConnStart(clientLabel)
	defer trackClientConnEnd(statEnt)

	relayTcpBidirectional(ctx, client, remote, statEnt)
}

func relayTcpBidirectional(ctx context.Context, client, remote net.Conn, statEnt *clientStatEntry) {
	var closeOnce sync.Once
	closePair := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = remote.Close()
		})
	}
	streamID := registerProxyStream(closePair)
	defer unregisterProxyStream(streamID)

	stopDone := make(chan struct{})
	defer close(stopDone)
	go func() {
		select {
		case <-ctx.Done():
			closePair()
		case <-stopDone:
		}
	}()

	done := make(chan struct{}, 2)
	go func() {
		copyWithPooledBufTracked(remote, client, statEnt, true)
		closeWriteOrConn(remote)
		done <- struct{}{}
	}()
	go func() {
		copyWithPooledBufTracked(client, remote, statEnt, false)
		closeWriteOrConn(client)
		done <- struct{}{}
	}()
	<-done
	// Allow the reverse direction up to 10s to flush remaining half-closed frames cleanly.
	drainTimer := time.NewTimer(10 * time.Second)
	select {
	case <-done:
		drainTimer.Stop()
	case <-drainTimer.C:
		_ = client.Close()
		_ = remote.Close()
		<-done
	}
}

type udpClientSession struct {
	key        string
	clientAddr *net.UDPAddr
	v4Conn     net.PacketConn
	v6Conn     net.PacketConn
	lastActive atomic.Int64 // UnixNano
	closeOnce  sync.Once
}

func (s *udpClientSession) close() {
	s.closeOnce.Do(func() {
		if s.v4Conn != nil {
			_ = s.v4Conn.Close()
		}
		if s.v6Conn != nil {
			_ = s.v6Conn.Close()
		}
	})
}

type udpGuardDecision struct {
	allowed     bool
	expiresNano int64
}

type udpDnsCacheEntry struct {
	ip          netip.Addr
	expiresNano int64
}

func parseSocks5UdpDatagram(pkt []byte) (host string, dstPort uint16, payload []byte, err error) {
	if len(pkt) < 10 {
		return "", 0, nil, errors.New("short SOCKS5 UDP packet")
	}
	// RSV must be 0x0000 and FRAG must be 0x00 (RFC 1928 Section 7)
	if pkt[2] != 0x00 {
		return "", 0, nil, errors.New("fragmented SOCKS5 UDP not supported")
	}

	atyp := pkt[3]
	var hdrEnd int

	switch atyp {
	case 0x01: // IPv4: 4 + 4 + 2 = 10
		if len(pkt) < 10 {
			return "", 0, nil, errors.New("truncated IPv4 UDP header")
		}
		host = net.IP(pkt[4:8]).String()
		hdrEnd = 10
	case 0x03: // Domain: 4 + 1 + L + 2
		domLen := int(pkt[4])
		hdrEnd = 4 + 1 + domLen + 2
		if domLen == 0 || len(pkt) < hdrEnd {
			return "", 0, nil, errors.New("truncated domain UDP header")
		}
		host = string(pkt[5 : 5+domLen])
	case 0x04: // IPv6: 4 + 16 + 2 = 22
		if len(pkt) < 22 {
			return "", 0, nil, errors.New("truncated IPv6 UDP header")
		}
		host = net.IP(pkt[4:20]).String()
		hdrEnd = 22
	default:
		return "", 0, nil, errors.New("unsupported UDP ATYP")
	}

	dstPort = binary.BigEndian.Uint16(pkt[hdrEnd-2 : hdrEnd])
	return host, dstPort, pkt[hdrEnd:], nil
}

func encodeSocks5UdpReplyHeader(dst []byte, remoteAddr net.Addr) int {
	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return 0
	}
	dst[0] = 0x00
	dst[1] = 0x00
	dst[2] = 0x00
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		dst[3] = 0x01
		copy(dst[4:8], ip4)
		binary.BigEndian.PutUint16(dst[8:10], uint16(udpAddr.Port))
		return 10
	}
	if ip16 := udpAddr.IP.To16(); ip16 != nil {
		dst[3] = 0x04
		copy(dst[4:20], ip16)
		binary.BigEndian.PutUint16(dst[20:22], uint16(udpAddr.Port))
		return 22
	}
	return 0
}

func resolveUdpTargetIP(
	ctx context.Context,
	dialer udpDialer,
	host string,
	dnsCache map[string]udpDnsCacheEntry,
	dnsMu *sync.Mutex,
) (netip.Addr, error) {
	if directIP, err := netip.ParseAddr(host); err == nil {
		unmapped := directIP.Unmap()
		if fnet, ok := dialer.(*fastNet); ok && unmapped.Is6() && !fnet.SupportsIPv6() {
			return netip.Addr{}, errors.New("IPv6 unavailable or blocked")
		}
		return unmapped, nil
	}

	nowNano := time.Now().UnixNano()
	dnsMu.Lock()
	ent, ok := dnsCache[host]
	dnsMu.Unlock()
	if ok && nowNano < ent.expiresNano {
		return ent.ip, nil
	}

	rCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var chosen netip.Addr
	if fnet, ok := dialer.(*fastNet); ok {
		addrs, err := fnet.ResolveUDPTarget(rCtx, host, fnet.SupportsIPv6())
		if err != nil || len(addrs) == 0 {
			if err == nil {
				err = errors.New("no UDP target IP")
			}
			return netip.Addr{}, err
		}
		chosen = addrs[0]
		for _, a := range addrs {
			if a.Is4() {
				chosen = a
				break
			}
		}
	} else {
		ips, err := net.DefaultResolver.LookupNetIP(rCtx, "ip4", host)
		if err != nil || len(ips) == 0 {
			ips, err = net.DefaultResolver.LookupNetIP(rCtx, "ip", host)
		}
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = errors.New("no UDP target IP")
			}
			return netip.Addr{}, err
		}
		chosen = ips[0].Unmap()
	}

	dnsMu.Lock()
	if len(dnsCache) > 256 {
		clear(dnsCache)
	}
	dnsCache[host] = udpDnsCacheEntry{
		ip:          chosen,
		expiresNano: time.Now().Add(30 * time.Second).UnixNano(),
	}
	dnsMu.Unlock()
	return chosen, nil
}

func openFullConePacketConn(dialer udpDialer, isV6 bool) (net.PacketConn, error) {
	if fnet, ok := dialer.(*fastNet); ok {
		return fnet.DialUDPUnconnected(isV6)
	}
	if isV6 {
		return net.ListenPacket("udp6", "[::]:0")
	}
	return net.ListenPacket("udp4", "0.0.0.0:0")
}

func handleUdpAssociate(ctx context.Context, tcpControl net.Conn, dialer udpDialer) {
	handleUdpAssociateTracked(ctx, tcpControl, dialer, "local-client")
}

func handleUdpAssociateTracked(ctx context.Context, tcpControl net.Conn, dialer udpDialer, clientLabel string) {
	if !awaitHandshakeReadyOrFail(ctx, dialer, 2500*time.Millisecond) {
		_, _ = tcpControl.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = tcpControl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	sockBufSz := activeUdpSocketBufSize()
	_ = udpLn.SetReadBuffer(sockBufSz)
	_ = udpLn.SetWriteBuffer(sockBufSz)

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

	RecordDiag("UDP_ASSOC", "OPEN", fmt.Sprintf("label=%s relayPort=%d", clientLabel, relayPort))
	defer RecordDiag("UDP_ASSOC", "CLOSE", fmt.Sprintf("label=%s relayPort=%d", clientLabel, relayPort))

	activeUdpAssocs.Add(1)
	defer activeUdpAssocs.Add(-1)
	statEnt := trackClientConnStart(clientLabel)
	defer trackClientConnEnd(statEnt)

	sessionsCap := activeMaxUdpSessionsCap()
	assocCtx, assocCancel := context.WithCancel(ctx)
	var sessMu sync.RWMutex
	sessions := make(map[string]*udpClientSession)
	var dnsMu sync.Mutex
	dnsCache := make(map[string]udpDnsCacheEntry)
	guardCache := make(map[int]udpGuardDecision)
	var lastGuardDiagNano atomic.Int64

	cleanupAll := func() {
		assocCancel()
		_ = udpLn.Close()
		_ = tcpControl.Close()
		sessMu.Lock()
		for k, s := range sessions {
			s.close()
			delete(sessions, k)
		}
		sessMu.Unlock()
	}
	streamID := registerProxyStream(func() {
		assocCancel()
		_ = udpLn.Close()
		_ = tcpControl.Close()
	})
	defer unregisterProxyStream(streamID)
	defer cleanupAll()

	// Tear down immediately if parent tunnel context cancels
	go func() {
		<-assocCtx.Done()
		_ = udpLn.Close()
		_ = tcpControl.Close()
	}()

	// Reap idle local client UDP sockets so long-lived associations never leak or exhaust sessionsCap
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-assocCtx.Done():
				return
			case <-ticker.C:
			}
			cutoff := time.Now().Add(-120 * time.Second).UnixNano()
			sessMu.Lock()
			for k, s := range sessions {
				if s.lastActive.Load() < cutoff {
					s.close()
					delete(sessions, k)
				}
			}
			sessMu.Unlock()
		}
	}()

	startReturnPump := func(s *udpClientSession, pConn net.PacketConn) {
		go func() {
			rBufPtr := udpFrameBufPool.Get().(*[]byte)
			defer udpFrameBufPool.Put(rBufPtr)
			respBuf := *rBufPtr

			outBufPtr := udpFrameBufPool.Get().(*[]byte)
			defer udpFrameBufPool.Put(outBufPtr)
			outPkt := *outBufPtr

			for {
				rn, rAddr, readErr := pConn.ReadFrom(respBuf)
				if readErr != nil {
					return
				}
				hdrLen := encodeSocks5UdpReplyHeader(outPkt, rAddr)
				if hdrLen == 0 || hdrLen+rn > len(outPkt) {
					continue
				}
				copy(outPkt[hdrLen:hdrLen+rn], respBuf[:rn])
				if _, wErr := udpLn.WriteToUDP(outPkt[:hdrLen+rn], s.clientAddr); wErr == nil {
					s.lastActive.Store(time.Now().UnixNano())
					udpPacketsRx.Add(1)
					recordClientRx(statEnt, rn)
				}
			}
		}()
	}

	// Pump local UDP frames from tgcalls into unconnected Full-Cone gVisor PacketConn sockets
	go func() {
		bufPtr := udpFrameBufPool.Get().(*[]byte)
		defer udpFrameBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			n, srcAddr, rErr := udpLn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			// Do NOT reject non-127.0.0.1 srcAddr.IP here: on Android, tgcalls commonly binds to wlan0/rmnet
			// and sends to 127.0.0.1 over Linux table local; listening strictly on 127.0.0.1 blocks external traffic.
			if srcAddr == nil || srcAddr.Port <= 0 {
				continue
			}

			nowNano := time.Now().UnixNano()
			dec, hasDec := guardCache[srcAddr.Port]
			var allowed bool
			if hasDec && dec.allowed && nowNano < dec.expiresNano {
				allowed = true
			} else {
				allowed = invokeUdpPeerGuard(srcAddr, clientLabel)
				// Only cache positive allow decisions; never lock out a new socket for 10s
				// if GetExtendedUdpTable missed it on the very first STUN packet.
				if allowed {
					if len(guardCache) > 256 {
						clear(guardCache)
					}
					guardCache[srcAddr.Port] = udpGuardDecision{
						allowed:     true,
						expiresNano: nowNano + int64(10*time.Second),
					}
				}
			}
			if !allowed {
				blockedLocalAttempts.Add(1)
				udpGuardDrops.Add(1)
				prevDiag := lastGuardDiagNano.Load()
				if nowNano-prevDiag > int64(5*time.Second) && lastGuardDiagNano.CompareAndSwap(prevDiag, nowNano) {
					RecordDiag("UDP_GUARD", "DROP", fmt.Sprintf("blocked udp port=%d label=%s", srcAddr.Port, clientLabel))
				}
				continue
			}

			host, dstPort, payload, pErr := parseSocks5UdpDatagram(buf[:n])
			if pErr != nil || len(payload) == 0 {
				continue
			}

			clientKey := srcAddr.String()
			sessMu.RLock()
			sess, exists := sessions[clientKey]
			sessMu.RUnlock()

			if !exists {
				sessMu.Lock()
				sess, exists = sessions[clientKey]
				if !exists {
					if len(sessions) >= sessionsCap {
						var oldestKey string
						var oldestTs int64 = nowNano
						for k, cand := range sessions {
							ts := cand.lastActive.Load()
							if oldestKey == "" || ts < oldestTs {
								oldestKey = k
								oldestTs = ts
							}
						}
						if oldestKey != "" {
							sessions[oldestKey].close()
							delete(sessions, oldestKey)
						}
					}
					clientCopy := &net.UDPAddr{
						IP:   append([]byte(nil), srcAddr.IP...),
						Port: srcAddr.Port,
						Zone: srcAddr.Zone,
					}
					sess = &udpClientSession{
						key:        clientKey,
						clientAddr: clientCopy,
					}
					sess.lastActive.Store(nowNano)
					sessions[clientKey] = sess
				}
				sessMu.Unlock()
			}
			sess.lastActive.Store(nowNano)

			targetIP, rErr := resolveUdpTargetIP(assocCtx, dialer, host, dnsCache, &dnsMu)
			if rErr != nil {
				continue
			}
			isV6 := targetIP.Is6()

			var pConn net.PacketConn
			if isV6 {
				sessMu.RLock()
				pConn = sess.v6Conn
				sessMu.RUnlock()
				if pConn == nil {
					newConn, cErr := openFullConePacketConn(dialer, true)
					if cErr != nil {
						continue
					}
					sessMu.Lock()
					if sess.v6Conn == nil {
						sess.v6Conn = newConn
						udpSocketsOpened.Add(1)
						startReturnPump(sess, newConn)
					} else {
						_ = newConn.Close()
					}
					pConn = sess.v6Conn
					sessMu.Unlock()
				}
			} else {
				sessMu.RLock()
				pConn = sess.v4Conn
				sessMu.RUnlock()
				if pConn == nil {
					newConn, cErr := openFullConePacketConn(dialer, false)
					if cErr != nil {
						continue
					}
					sessMu.Lock()
					if sess.v4Conn == nil {
						sess.v4Conn = newConn
						udpSocketsOpened.Add(1)
						startReturnPump(sess, newConn)
					} else {
						_ = newConn.Close()
					}
					pConn = sess.v4Conn
					sessMu.Unlock()
				}
			}

			dstUdpAddr := &net.UDPAddr{
				IP:   net.IP(targetIP.AsSlice()),
				Port: int(dstPort),
			}
			if nw, wErr := pConn.WriteTo(payload, dstUdpAddr); wErr == nil {
				udpPacketsTx.Add(1)
				recordClientTx(statEnt, nw)
			} else {
				udpSendErrors.Add(1)
			}
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
