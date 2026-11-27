package wgbridge

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	nestedMinMTU             = 1200
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
	activeTun                *fastNetTun
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
	activeMtu                int
	activeAwgS4              int
	activeMaxMtuCap          int
	activeStartTime          time.Time
	mtuCalibGen              atomic.Uint64
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
	hostLinkMTU              atomic.Int32
	hostOuterVpn             atomic.Bool
	lastPeerRxAtNano         atomic.Int64
	lastTrackedRxBytes       atomic.Uint64
	lastTrackedHsSec         atomic.Int64
	watchdogStalled          atomic.Bool
	lastProactiveRekeyNano   atomic.Int64

	socksAuthMu           sync.RWMutex
	socksAuthUser         string
	socksAuthPass         string
	socksExtraPasses      []string
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
	if username == "" && password == "" {
		socksExtraPasses = nil
	}
	socksAuthMu.Unlock()
}

// SetSocksExtraPasswords registers additional allowed loopback credentials (e.g. derived from
// sibling local user profiles) so profile switches and multi-client hubs do not trigger auth storms.
func SetSocksExtraPasswords(csv string) {
	var parsed []string
	if strings.TrimSpace(csv) != "" {
		seen := make(map[string]struct{}, 8)
		for _, part := range strings.Split(csv, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			parsed = append(parsed, p)
			if len(parsed) >= 32 {
				break
			}
		}
	}
	socksAuthMu.Lock()
	socksExtraPasses = parsed
	socksAuthMu.Unlock()
}

func getSocksAuth() (string, string) {
	socksAuthMu.RLock()
	u := socksAuthUser
	p := socksAuthPass
	socksAuthMu.RUnlock()
	return u, p
}

func verifySocksPassBytes(candidate []byte) int {
	socksAuthMu.RLock()
	primary := socksAuthPass
	var extras []string
	if len(socksExtraPasses) > 0 {
		extras = append([]string(nil), socksExtraPasses...)
	}
	socksAuthMu.RUnlock()

	matched := subtle.ConstantTimeCompare(candidate, []byte(primary))
	for _, ex := range extras {
		if subtle.ConstantTimeCompare(candidate, []byte(ex)) == 1 {
			matched = 1
		}
	}
	return matched
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

func isIsolatedVirtualInterfaceName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" {
		return false
	}
	for _, tok := range []string{
		"wireguardpluscalls",
		"vmware",
		"vmnet",
		"virtualbox",
		"vboxnet",
		"vethernet",
		"teredo",
		"isatap",
		"6to4",
		"wsl",
		"hyper-v",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func hasOutboundSystemRoute(resolvedEp string) bool {
	target := strings.TrimSpace(resolvedEp)
	network := "udp4"
	isLoopbackTarget := false
	if target == "" {
		target = "1.1.1.1:80"
	} else if host, _, err := net.SplitHostPort(target); err == nil {
		if ip, pErr := netip.ParseAddr(strings.Trim(host, "[]")); pErr == nil {
			unmapped := ip.Unmap()
			if unmapped.IsLoopback() {
				isLoopbackTarget = true
			}
			if unmapped.Is6() {
				network = "udp6"
			}
		}
	}
	c, err := net.Dial(network, target)
	if err != nil {
		return false
	}
	localAddr := c.LocalAddr()
	_ = c.Close()
	if isLoopbackTarget {
		return true
	}
	ua, ok := localAddr.(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return true
	}
	if ua.IP.IsLoopback() {
		return false
	}
	if ifaces, iErr := net.Interfaces(); iErr == nil {
		for _, ifc := range ifaces {
			addrs, aErr := ifc.Addrs()
			if aErr != nil {
				continue
			}
			for _, addr := range addrs {
				ipn, okAddr := addr.(*net.IPNet)
				if okAddr && ipn != nil && ipn.IP != nil && ipn.IP.Equal(ua.IP) {
					if isIsolatedVirtualInterfaceName(ifc.Name) {
						return false
					}
					return true
				}
			}
		}
	}
	return true
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

var (
	cloudflareWarpPeerPubHex, _ = normalizeHexKey("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
	warpFallbackPorts           = [...]string{"2408", "4500", "500", "1701"}
	warpPortCursor              atomic.Uint32
)

func nextWarpFallbackEndpoint(resolvedEp string, pubHex string, curHsSec int64) (string, bool) {
	if curHsSec > 0 || cloudflareWarpPeerPubHex == "" || !strings.EqualFold(strings.TrimSpace(pubHex), cloudflareWarpPeerPubHex) {
		return "", false
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(resolvedEp))
	if err != nil || host == "" {
		return "", false
	}
	isKnownWarpPort := false
	for _, p := range warpFallbackPorts {
		if port == p {
			isKnownWarpPort = true
			break
		}
	}
	if !isKnownWarpPort {
		return "", false
	}
	nextPort := warpFallbackPorts[warpPortCursor.Add(1)%uint32(len(warpFallbackPorts))]
	if nextPort == port {
		nextPort = warpFallbackPorts[warpPortCursor.Add(1)%uint32(len(warpFallbackPorts))]
	}
	return net.JoinHostPort(host, nextPort), true
}

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
		rawRx, rawTx, curHs := readDeviceCounters(dev)
		mu.Lock()
		if !running || activeDev != dev {
			mu.Unlock()
			return false
		}
		baseRxBytes += rawRx
		baseTxBytes += rawTx
		if rotatedEp, ok := nextWarpFallbackEndpoint(activeResolvedEp, activePeerPubHex, curHs); ok {
			activeResolvedEp = rotatedEp
		}
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

func getActiveProxyStreamCount() int {
	proxyStreamsMu.Lock()
	n := len(activeProxyStreams)
	proxyStreamsMu.Unlock()
	return n
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
	// Boot safely at 1280 so handshake/first frames never blackhole on strict routers;
	// store requested custom cap (1281..1419) or allow full auto-calibration up to 1420.
	userCap := maxMTU
	if mtu > defaultMTU && mtu <= maxMTU {
		userCap = mtu
	}
	initialMTU := defaultMTU
	if nestedCap := computeNestedCapMTU(int(hostLinkMTU.Load()), hostOuterVpn.Load()); nestedCap < initialMTU {
		initialMTU = nestedCap
	}

	// Ensure consecutive restarts/handovers advance past WireGuard's 20ms rate limit & TAI64N bucket
	// BEFORE dev.Up() starts the keepalive initiation timer.
	waitNextTai64nTick()

	if getActiveProxyStreamCount() > 0 {
		ResetActiveProxyConnections("tunnel_restart")
	}

	mu.Lock()

	stopTunnelOnlyLocked()

	tunDev, tnet, err := createFastNetTUN(clientAddrs, dnsAddrs, initialMTU)
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
	activeTun, _ = tunDev.(*fastNetTun)
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
	activeMtu = initialMTU
	activeAwgS4 = awgCfg.S4
	activeMaxMtuCap = userCap
	activeStartTime = time.Now()
	baseRxBytes = 0
	baseTxBytes = 0
	lastTrackedRxBytes.Store(0)
	lastTrackedHsSec.Store(0)
	lastPeerRxAtNano.Store(0)
	watchdogStalled.Store(false)
	running = true
	muxStartupPend = false
	notifyMuxWaitersLocked()

	mu.Unlock()

	// Kick off immediate Noise_IKpsk2 Handshake Initiation at t=0ms
	triggerPeerHandshakeDirect(dev, pubHex, false)
	// Give fast peers up to 160ms to complete handshake before returning port to Telegram
	waitForHandshakeQuick(dev, 160*time.Millisecond)

	calibGen := mtuCalibGen.Add(1)
	go autoCalibrateAfterHandshake(ctx, dev, calibGen)
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
	var wasSystemOffline bool

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !isActiveDevice(dev) {
			return
		}

		mu.Lock()
		curEp := activeResolvedEp
		mu.Unlock()
		if !hasOutboundSystemRoute(curEp) {
			wasSystemOffline = true
			stalledTicks = 0
			noHandshakeTicks = 0
			watchdogStalled.Store(false)
			continue
		}
		if wasSystemOffline {
			wasSystemOffline = false
			if hopActivePeer(true, true) {
				CalibrateActiveTunnelMTUAsync()
			}
			ResetActiveProxyConnections("watchdog_route_restored")
			lastHardHopAt = time.Now()
			stalledTicks = 0
			noHandshakeTicks = 0
			watchdogStalled.Store(false)
			lastRx, lastTx, _ = readActiveTotals(dev)
			continue
		}

		rx, tx, hsSec := readActiveTotals(dev)
		updatePeerLivenessFromCounters(rx, hsSec)
		nowSec := time.Now().Unix()

		if rx < lastRx || tx < lastTx {
			lastRx, lastTx = rx, tx
			stalledTicks = 0
			noHandshakeTicks = 0
			watchdogStalled.Store(false)
			continue
		}
		if rx > lastRx {
			watchdogStalled.Store(false)
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

		// Case A2: Proactive background session key renewal starting at 115s so idle sessions
		// stay hot (<180s) continuously 24/7 while online without hopping ports or breaking sockets.
		hsAge := nowSec - hsSec
		if hsAge >= 115 && hsAge < 180 {
			nowNano := time.Now().UnixNano()
			prevRekey := lastProactiveRekeyNano.Load()
			if nowNano-prevRekey >= int64(15*time.Second) && lastProactiveRekeyNano.CompareAndSwap(prevRekey, nowNano) {
				triggerPeerHandshakeDirect(dev, pubHex, true)
			}
			stalledTicks = 0
			lastRx, lastTx = rx, tx
			continue
		}

		// Case B: Outbound payload (>=256B) with zero inbound RX across 3s intervals (9s -> hard hop).
		stalled := (txDelta >= 256 && rx == lastRx) ||
			(hsAge > 220 && txDelta >= 128 && rx == lastRx)
		if stalled {
			stalledTicks++
			watchdogStalled.Store(true)
			if stalledTicks == 1 && GetActiveMTU() > defaultMTU {
				StepDownActiveTunnelMTU(defaultMTU, "watchdog_tx_stall")
			}
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
			watchdogStalled.Store(false)
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
		CalibrateActiveTunnelMTUAsync()
		return nil
	}
	// Soft re-nudge after 180ms in case Android netd switched routes asynchronously
	time.Sleep(180 * time.Millisecond)
	if !isActiveDevice(dev) {
		return nil
	}
	triggerPeerHandshakeDirect(dev, pubHex, true)
	if waitForHandshakeQuick(dev, 900*time.Millisecond) {
		CalibrateActiveTunnelMTUAsync()
	}
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
		CalibrateActiveTunnelMTUAsync()
		return true
	}
	if !isActiveDevice(dev) {
		return false
	}
	triggerPeerHandshakeDirect(dev, pubHex, true)
	ok := waitForHandshakeQuick(dev, 900*time.Millisecond)
	if ok {
		CalibrateActiveTunnelMTUAsync()
	}
	return ok
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
	if getActiveProxyStreamCount() > 0 {
		ResetActiveProxyConnections("tunnel_stop")
	}
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
	activeTun = nil
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
	activeMtu = 0
	activeAwgS4 = 0
	activeMaxMtuCap = 0
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

func isActivePeerPublicKey(pubHex string) bool {
	if strings.TrimSpace(pubHex) == "" {
		return false
	}
	mu.Lock()
	match := running && activeDev != nil && activePeerPubHex != "" && strings.EqualFold(activePeerPubHex, pubHex)
	mu.Unlock()
	return match
}

// GetActiveMTU returns the current live inner tunnel MTU, or 0 if stopped.
func GetActiveMTU() int {
	mu.Lock()
	defer mu.Unlock()
	if !running || activeDev == nil {
		return 0
	}
	return activeMtu
}

func updatePeerLivenessFromCounters(rx uint64, hsSec int64) {
	prevRx := lastTrackedRxBytes.Load()
	prevHs := lastTrackedHsSec.Load()
	if rx > prevRx || (hsSec > 0 && hsSec > prevHs) {
		if rx > prevRx {
			lastTrackedRxBytes.CompareAndSwap(prevRx, rx)
		}
		if hsSec > prevHs {
			lastTrackedHsSec.CompareAndSwap(prevHs, hsSec)
		}
		lastPeerRxAtNano.Store(time.Now().UnixNano())
	}
}

func computeNestedCapMTU(linkMtu int, outerVpn bool) int {
	if outerVpn {
		return nestedMinMTU
	}
	if linkMtu > 0 && linkMtu <= 1360 {
		return nestedMinMTU
	}
	return maxMTU
}

func clampStepDownMTU(mtu int) int {
	floorMtu := minMTU
	if hostOuterVpn.Load() || (hostLinkMTU.Load() > 0 && hostLinkMTU.Load() <= 1360) || (mtu >= nestedMinMTU && mtu < minMTU) {
		floorMtu = nestedMinMTU
	}
	if mtu < floorMtu {
		return floorMtu
	}
	if mtu > maxMTU {
		return maxMTU
	}
	return mtu
}

// SetHostLinkMTU records outer interface MTU and nested-VPN status so inner MTU automatically
// fits inside an outer VPN (e.g. tun1 MTU 1280 -> inner MTU 1200) without blackholing.
func SetHostLinkMTU(linkMtu int, outerVpn bool) {
	prevOuter := hostOuterVpn.Swap(outerVpn)
	prevLink := hostLinkMTU.Swap(int32(linkMtu))
	capMtu := computeNestedCapMTU(linkMtu, outerVpn)
	if capMtu < minMTU {
		StepDownActiveTunnelMTU(capMtu, "nested_link_mtu")
	} else if (prevOuter != outerVpn || (prevLink > 0 && prevLink <= 1360)) && capMtu >= minMTU {
		cur := GetActiveMTU()
		if cur > 0 && cur < minMTU {
			CalibrateActiveTunnelMTUAsync()
		}
	}
}

// IsTunnelHotVerified returns true when the active WireGuard tunnel has a fresh, un-stalled
// handshake and healthy outbound route so foreground wakeups can resume in 0ms without resetting sockets.
func IsTunnelHotVerified() bool {
	mu.Lock()
	dev := activeDev
	isUp := running
	resolvedEp := activeResolvedEp
	mu.Unlock()
	if !isUp || dev == nil {
		return false
	}
	rx, _, hsSec := readActiveTotals(dev)
	if hsSec <= 0 {
		return false
	}
	updatePeerLivenessFromCounters(rx, hsSec)
	if watchdogStalled.Load() {
		return false
	}
	now := time.Now()
	hsAge := now.Unix() - hsSec
	if hsAge >= 135 {
		return false
	}
	if !hasOutboundSystemRoute(resolvedEp) {
		return false
	}
	if hsAge < 90 {
		return true
	}
	lastRxAt := lastPeerRxAtNano.Load()
	return lastRxAt > 0 && (now.UnixNano()-lastRxAt) < int64(45*time.Second)
}

func setActiveTunnelMTUInternal(newMtu int, reason string) int {
	clamped := clampStepDownMTU(newMtu)
	mu.Lock()
	isUp := running && activeDev != nil && activeTun != nil
	tunDev := activeTun
	prev := activeMtu
	if isUp {
		activeMtu = clamped
	}
	mu.Unlock()
	if !isUp || tunDev == nil {
		return 0
	}
	changed := tunDev.SetDynamicMTU(clamped)
	if changed || prev != clamped {
		RecordDiag("MTU", reason, fmt.Sprintf("mtu=%d prev=%d", clamped, prev))
	}
	return clamped
}

// StepDownActiveTunnelMTU lowers the live tunnel MTU in-place immediately without restarting the tunnel.
func StepDownActiveTunnelMTU(targetMtu int, reason string) int {
	clamped := clampStepDownMTU(targetMtu)
	mu.Lock()
	cur := activeMtu
	isUp := running && activeDev != nil && activeTun != nil
	mu.Unlock()
	if !isUp {
		return 0
	}
	if cur <= clamped {
		return cur
	}
	if strings.TrimSpace(reason) == "" {
		reason = "STEP_DOWN"
	}
	return setActiveTunnelMTUInternal(clamped, "STEP_DOWN_"+reason)
}

func detectOutboundInterfaceMTU(resolvedEp string) int {
	probeTarget := strings.TrimSpace(resolvedEp)
	network := "udp4"
	if host, _, err := net.SplitHostPort(probeTarget); err == nil {
		if ip, pErr := netip.ParseAddr(strings.Trim(host, "[]")); pErr == nil && ip.Unmap().Is6() {
			network = "udp6"
		}
	}
	if probeTarget == "" {
		probeTarget = "1.1.1.1:80"
	}
	c, err := net.Dial(network, probeTarget)
	if err != nil {
		return 1500
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return 1500
	}
	localIP := ua.IP
	if ifaces, iErr := net.Interfaces(); iErr == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, aErr := ifc.Addrs()
			if aErr != nil {
				continue
			}
			for _, addr := range addrs {
				ipn, ok := addr.(*net.IPNet)
				if ok && ipn != nil && ipn.IP != nil && ipn.IP.Equal(localIP) {
					if ifc.MTU >= minMTU && ifc.MTU <= 1500 {
						return ifc.MTU
					}
					if ifc.MTU > 1500 {
						return 1500
					}
				}
			}
		}
	}
	return 1500
}

// ComputeLinkCeilingInnerMTU calculates the maximum unfragmented inner WireGuard MTU (1280..1420)
// on 16-byte WireGuard padding boundaries given the physical outer link MTU, IPv4/IPv6 outer header overhead,
// and AmneziaWG S4 junk transport header bytes.
func ComputeLinkCeilingInnerMTU(outerLinkMtu int, resolvedEp string, s4 int) int {
	if outerLinkMtu <= 0 || outerLinkMtu > 1500 {
		outerLinkMtu = detectOutboundInterfaceMTU(resolvedEp)
	}
	outerHdr := 60 // 20B outer IPv4 + 8B UDP + 32B WireGuard transport header/tag
	if host, _, err := net.SplitHostPort(strings.TrimSpace(resolvedEp)); err == nil {
		if ip, pErr := netip.ParseAddr(strings.Trim(host, "[]")); pErr == nil && ip.Unmap().Is6() {
			outerHdr = 80 // 40B outer IPv6 + 8B UDP + 32B WireGuard transport header/tag
		}
	}
	if s4 > 0 {
		outerHdr += s4
	}
	maxPadded := outerLinkMtu - outerHdr
	cand := maxPadded &^ 15
	if maxPadded >= 1424 {
		cand = maxMTU
	}
	return normalizeMTU(cand)
}

func isCloudflareWarpEndpoint(rawEp, resolvedEp string) bool {
	for _, ep := range []string{rawEp, resolvedEp} {
		low := strings.ToLower(strings.TrimSpace(ep))
		if low == "" {
			continue
		}
		if strings.Contains(low, "cloudflareclient") {
			return true
		}
		host := low
		if h, _, err := net.SplitHostPort(low); err == nil {
			host = strings.Trim(h, "[]")
		}
		if strings.HasPrefix(host, "162.159.192.") ||
			strings.HasPrefix(host, "162.159.193.") ||
			strings.HasPrefix(host, "162.159.195.") ||
			strings.HasPrefix(host, "162.159.204.") {
			return true
		}
	}
	return false
}

func autoCalibrateAfterHandshake(ctx context.Context, dev *device.Device, gen uint64) {
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil || mtuCalibGen.Load() != gen || !isActiveDevice(dev) {
			return
		}
		if hasCompletedHandshake(dev) {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if ctx.Err() != nil || mtuCalibGen.Load() != gen || !isActiveDevice(dev) || !hasCompletedHandshake(dev) {
		return
	}
	timer := time.NewTimer(250 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-timer.C:
	}
	if mtuCalibGen.Load() != gen || !isActiveDevice(dev) {
		return
	}
	_ = CalibrateActiveTunnelMTU(1200)
}

// CalibrateActiveTunnelMTUAsync safely steps down oversized MTUs immediately if link ceiling dropped,
// then runs in-tunnel DF ICMP Echo MTU calibration asynchronously.
func CalibrateActiveTunnelMTUAsync() {
	mu.Lock()
	isUp := running && activeDev != nil && activeTun != nil
	ctx := activeCtx
	dev := activeDev
	resolvedEp := activeResolvedEp
	rawEp := activeRawEp
	s4 := activeAwgS4
	curMtu := activeMtu
	mu.Unlock()
	if !isUp || ctx == nil || dev == nil {
		return
	}
	if nestedCap := computeNestedCapMTU(int(hostLinkMTU.Load()), hostOuterVpn.Load()); nestedCap < minMTU {
		StepDownActiveTunnelMTU(nestedCap, "nested_link_mtu")
		return
	}
	if isCloudflareWarpEndpoint(rawEp, resolvedEp) {
		if curMtu > 0 && curMtu < minMTU {
			setActiveTunnelMTUInternal(minMTU, "CALIBRATED_WARP_1280")
		} else {
			StepDownActiveTunnelMTU(minMTU, "warp_cap")
		}
		return
	}
	ceiling := ComputeLinkCeilingInnerMTU(0, resolvedEp, s4)
	if curMtu > ceiling || curMtu > defaultMTU {
		StepDownActiveTunnelMTU(defaultMTU, "pre_recalibrate")
	}
	gen := mtuCalibGen.Add(1)
	go autoCalibrateAfterHandshake(ctx, dev, gen)
}

// CalibrateActiveTunnelMTU probes the live WireGuard path using DF=1 in-tunnel ICMP Echo requests
// across 16-byte-aligned sizes (1280..1420) capped by the outbound physical NIC ceiling, and updates
// the live tunnel MTU in-place without dropping active sockets.
func CalibrateActiveTunnelMTU(timeoutMs int) int {
	if timeoutMs <= 0 {
		timeoutMs = 1200
	}
	if timeoutMs > 5000 {
		timeoutMs = 5000
	}

	mu.Lock()
	isUp := running && activeDev != nil && activeTun != nil
	tunDev := activeTun
	dev := activeDev
	resolvedEp := activeResolvedEp
	rawEp := activeRawEp
	s4 := activeAwgS4
	capMtu := activeMaxMtuCap
	curMtu := activeMtu
	mu.Unlock()
	if !isUp || tunDev == nil || dev == nil {
		return 0
	}
	if !waitForHandshakeQuick(dev, 800*time.Millisecond) {
		return curMtu
	}

	if nestedCap := computeNestedCapMTU(int(hostLinkMTU.Load()), hostOuterVpn.Load()); nestedCap < minMTU {
		return setActiveTunnelMTUInternal(nestedCap, "CALIBRATED_NESTED_VPN")
	}
	if isCloudflareWarpEndpoint(rawEp, resolvedEp) {
		return setActiveTunnelMTUInternal(minMTU, "CALIBRATED_WARP_1280")
	}
	ceiling := ComputeLinkCeilingInnerMTU(0, resolvedEp, s4)
	if capMtu >= minMTU && capMtu < ceiling {
		ceiling = capMtu
	}
	allSteps := []int{1280, 1312, 1328, 1360, 1376, 1392, 1420}
	var steps []int
	for _, s := range allSteps {
		if s <= ceiling {
			steps = append(steps, s)
		}
	}
	if len(steps) <= 1 {
		return setActiveTunnelMTUInternal(minMTU, "CALIBRATED")
	}

	topTarget := steps[len(steps)-1]
	baseSeq := uint16((time.Now().UnixNano() & 0x3fff) + 1)
	seqToMtu := make(map[uint16]int, len(steps)*2)
	var resMu sync.Mutex
	confirmed := make(map[int]bool, len(steps))
	topDoneCh := make(chan struct{}, 1)

	tunDev.mtuProbeMu.Lock()
	tunDev.mtuProbeCb = func(seq uint16, totalLen int) {
		resMu.Lock()
		expected, ok := seqToMtu[seq]
		if ok && totalLen == expected {
			confirmed[expected] = true
			if expected == topTarget {
				select {
				case topDoneCh <- struct{}{}:
				default:
				}
			}
		}
		resMu.Unlock()
	}
	tunDev.mtuProbeMu.Unlock()
	defer func() {
		tunDev.mtuProbeMu.Lock()
		tunDev.mtuProbeCb = nil
		tunDev.mtuProbeMu.Unlock()
	}()

	targets := [][4]byte{{1, 0, 0, 1}, {8, 8, 8, 8}}
	for round := 0; round < len(targets); round++ {
		for idx, sz := range steps {
			seq := baseSeq + uint16(round*len(steps)+idx)
			resMu.Lock()
			seqToMtu[seq] = sz
			resMu.Unlock()
			_ = tunDev.sendIcmpMtuProbe(targets[round], seq, sz)
			time.Sleep(6 * time.Millisecond)
		}
	}

	waitDur := 450 * time.Millisecond
	if cand := time.Duration(timeoutMs) * time.Millisecond / 2; cand > waitDur {
		if cand > 1200*time.Millisecond {
			waitDur = 1200 * time.Millisecond
		} else {
			waitDur = cand
		}
	}
	timer := time.NewTimer(waitDur)
	select {
	case <-topDoneCh:
		timer.Stop()
	case <-timer.C:
	}

	resMu.Lock()
	best := 0
	for _, sz := range steps {
		if confirmed[sz] && sz > best {
			best = sz
		}
	}
	resMu.Unlock()

	if best < minMTU {
		// No ICMP replies received (e.g. peer blocks ICMP): stay safely at 1280 without failing.
		if curMtu > minMTU {
			return setActiveTunnelMTUInternal(minMTU, "CALIBRATED_NO_ICMP")
		}
		return curMtu
	}
	return setActiveTunnelMTUInternal(best, fmt.Sprintf("CALIBRATED_CEIL%d", ceiling))
}
