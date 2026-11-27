package wgbridge

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxVoipRelays     = 48
	voipRelayIdleTTL  = 90 * time.Second
	voipRelayClientID = "voip-relay"
)

type voipRelayUdpSession struct {
	key        string
	clientAddr *net.UDPAddr
	pConn      net.PacketConn
	dialer     udpDialer
	lastActive atomic.Int64
	counted    atomic.Bool
	closeOnce  sync.Once
}

func (s *voipRelayUdpSession) close() {
	s.closeOnce.Do(func() {
		if s.counted.CompareAndSwap(true, false) {
			activeUdpAssocs.Add(-1)
		}
		if s.pConn != nil {
			_ = s.pConn.Close()
		}
	})
}

type voipRelay struct {
	targetKey       string
	targetHost      string
	targetPort      int
	localIP         string
	localPort       int
	followActive    bool
	parentCtx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	dialer          udpDialer
	udpLn           *net.UDPConn
	tcpLn           net.Listener
	statEnt         *clientStatEntry
	lastActive      atomic.Int64
	lastRetErrNano  atomic.Int64
	udpPktsTx       atomic.Uint64
	udpPktsRx       atomic.Uint64
	udpErrs         atomic.Uint64
	tcpConns        atomic.Uint64
	createdAtUnix   int64
	closed          atomic.Bool
	closeOnce       sync.Once

	sessMu   sync.RWMutex
	sessions map[string]*voipRelayUdpSession
	dnsMu    sync.Mutex
	dnsCache map[string]udpDnsCacheEntry
}

var (
	voipRelaysMu sync.Mutex
	voipRelays   = make(map[string]*voipRelay)

	// voipLowTrafficCloses counts relays that closed after >=30s with <100 packets (failed call signature).
	voipLowTrafficCloses         atomic.Uint64
	lastVoipWarmUnix             atomic.Int64
	lastVoipMediaRelayActiveUnix atomic.Int64
)

func warmTunnelForVoipCall() {
	mu.Lock()
	isUp := running
	dev := activeDev
	pubHex := activePeerPubHex
	mu.Unlock()
	if !isUp || dev == nil || pubHex == "" {
		return
	}
	_, _, hsSec := readDeviceCounters(dev)
	nowSec := time.Now().Unix()
	if hsSec > 0 && (nowSec-hsSec) <= 45 {
		return
	}
	prevWarm := lastVoipWarmUnix.Load()
	if nowSec-prevWarm < 3 || !lastVoipWarmUnix.CompareAndSwap(prevWarm, nowSec) {
		return
	}
	go func() {
		if hsSec <= 0 || (nowSec-hsSec) >= 120 {
			_ = EnsureTunnelAlive(1800)
			return
		}
		triggerPeerHandshakeDirect(dev, pubHex, true)
	}()
}

// GetVoipLowTrafficCloseCount reports how many VoIP relays closed looking like a failed call.
func GetVoipLowTrafficCloseCount() int64 {
	return int64(voipLowTrafficCloses.Load())
}

// StartVoipEndpointRelay binds a local 127.0.0.1 UDP (and best-effort TCP) relay
// socket that forwards packets for targetHost:targetPort directly through the active
// WireGuard tunnel netstack. Returns the bound local loopback port, or 0 on failure.
func StartVoipEndpointRelay(targetHost string, targetPort int) int {
	warmTunnelForVoipCall()
	ctx, dialer, ok := getActiveVoipDialer()
	if !ok {
		return 0
	}
	return startVoipEndpointRelayWithDialer(ctx, dialer, strings.TrimSpace(targetHost), targetPort)
}

// StartVoipEndpointRelayAddr binds or reuses a local loopback UDP/TCP relay socket for
// targetHost:targetPort, preserving targetPort on 127.0.0.1 first (or 127.0.0.x on conflict) when
// targetPort >= 1024 (or any port when running as uid=0), falling back to ephemeral 127.0.0.1:0 when needed.
// Returns "ip:port" or "".
func StartVoipEndpointRelayAddr(targetHost string, targetPort int) string {
	warmTunnelForVoipCall()
	ctx, dialer, ok := getActiveVoipDialer()
	if !ok {
		return ""
	}
	return startVoipEndpointRelayAddrWithDialer(ctx, dialer, strings.TrimSpace(targetHost), targetPort)
}

func getActiveVoipDialer() (context.Context, udpDialer, bool) {
	mu.Lock()
	isUp := running
	ctx := activeCtx
	var dialer udpDialer
	if activeTnet != nil {
		dialer = activeTnet
	}
	mu.Unlock()

	if !isUp || ctx == nil || dialer == nil {
		var ok bool
		ctx, dialer, ok = awaitMuxRouteReady(4 * time.Second)
		if !ok || ctx == nil || dialer == nil {
			return nil, nil, false
		}
	}
	return ctx, dialer, true
}

func (r *voipRelay) localAddrString() string {
	if r == nil || r.localPort <= 0 {
		return ""
	}
	ip := r.localIP
	if ip == "" {
		ip = "127.0.0.1"
	}
	return net.JoinHostPort(ip, strconv.Itoa(r.localPort))
}

// StopAllVoipRelays closes all active local VoIP endpoint relays and resets relay state.
func StopAllVoipRelays() {
	voipRelaysMu.Lock()
	snapshot := make([]*voipRelay, 0, len(voipRelays))
	for k, r := range voipRelays {
		snapshot = append(snapshot, r)
		delete(voipRelays, k)
	}
	voipRelaysMu.Unlock()

	for _, r := range snapshot {
		r.close()
	}
}

func startVoipEndpointRelayWithDialer(ctx context.Context, dialer udpDialer, targetHost string, targetPort int) int {
	_, port := startVoipEndpointRelayInternal(ctx, dialer, targetHost, targetPort, false)
	return port
}

func startVoipEndpointRelayAddrWithDialer(ctx context.Context, dialer udpDialer, targetHost string, targetPort int) string {
	ip, port := startVoipEndpointRelayInternal(ctx, dialer, targetHost, targetPort, true)
	if ip == "" || port <= 0 {
		return ""
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func startVoipEndpointRelayInternal(
	ctx context.Context,
	dialer udpDialer,
	targetHost string,
	targetPort int,
	preservePort bool,
) (string, int) {
	trimmedHost := strings.TrimSpace(targetHost)
	if ctx == nil || dialer == nil || trimmedHost == "" || targetPort < 1 || targetPort > 65535 {
		return "", 0
	}
	if ctx.Err() != nil {
		return "", 0
	}

	_, followActive := dialer.(*fastNet)
	modePrefix := "e|"
	if preservePort {
		modePrefix = "p|"
	}
	baseHostPort := net.JoinHostPort(strings.ToLower(trimmedHost), strconv.Itoa(targetPort))
	targetKey := modePrefix + baseHostPort
	nowNano := time.Now().UnixNano()

	voipRelaysMu.Lock()
	if existing, ok := voipRelays[targetKey]; ok {
		if !existing.closed.Load() && existing.ctx.Err() == nil && (followActive || existing.parentCtx == ctx) {
			existing.lastActive.Store(nowNano)
			ip := existing.localIP
			if ip == "" {
				ip = "127.0.0.1"
			}
			port := existing.localPort
			voipRelaysMu.Unlock()
			return ip, port
		}
		delete(voipRelays, targetKey)
		voipRelaysMu.Unlock()
		existing.close()
		voipRelaysMu.Lock()
	}

	var evicted []*voipRelay
	for len(voipRelays) >= maxVoipRelays {
		var oldestKey string
		var oldestTs int64
		for k, cand := range voipRelays {
			ts := cand.lastActive.Load()
			if oldestKey == "" || ts < oldestTs {
				oldestKey = k
				oldestTs = ts
			}
		}
		if oldestKey == "" {
			break
		}
		evicted = append(evicted, voipRelays[oldestKey])
		delete(voipRelays, oldestKey)
	}
	voipRelaysMu.Unlock()

	for _, r := range evicted {
		r.close()
	}

	var (
		udpLn     *net.UDPConn
		tcpLn     net.Listener
		localIP   string
		localPort int
		err       error
	)
	if preservePort {
		udpLn, tcpLn, localIP, localPort, err = bindVoipRelayLoopbackPreservePort(baseHostPort, targetPort)
	} else {
		udpLn, tcpLn, localPort, err = bindVoipRelayLoopback()
		localIP = "127.0.0.1"
	}
	if err != nil {
		RecordDiag("VOIP_RELAY", "BIND_ERR", fmt.Sprintf("target=%s err=%v", baseHostPort, err))
		return "", 0
	}

	sockBufSz := activeUdpSocketBufSize()
	_ = udpLn.SetReadBuffer(sockBufSz)
	_ = udpLn.SetWriteBuffer(sockBufSz)

	var relayCtx context.Context
	var relayCancel context.CancelFunc
	if followActive {
		// Decouple VoIP relay lifetime from ephemeral activeCtx so calls survive roaming/rebinds.
		relayCtx, relayCancel = context.WithCancel(context.Background())
	} else {
		relayCtx, relayCancel = context.WithCancel(ctx)
	}
	r := &voipRelay{
		targetKey:    targetKey,
		targetHost:   trimmedHost,
		targetPort:   targetPort,
		localIP:      localIP,
		localPort:    localPort,
		followActive: followActive,
		parentCtx:    ctx,
		ctx:          relayCtx,
		cancel:       relayCancel,
		dialer:       dialer,
		udpLn:        udpLn,
		tcpLn:        tcpLn,
		statEnt:       trackClientConnStart(voipRelayClientID),
		createdAtUnix: nowNano / int64(time.Second),
		sessions:      make(map[string]*voipRelayUdpSession),
		dnsCache:     make(map[string]udpDnsCacheEntry),
	}
	r.lastActive.Store(nowNano)

	voipRelaysMu.Lock()
	// Check race: another goroutine may have created the same target while we were binding.
	if existing, ok := voipRelays[targetKey]; ok && !existing.closed.Load() && existing.ctx.Err() == nil && (followActive || existing.parentCtx == ctx) {
		existing.lastActive.Store(nowNano)
		eip := existing.localIP
		if eip == "" {
			eip = "127.0.0.1"
		}
		port := existing.localPort
		voipRelaysMu.Unlock()
		r.close()
		return eip, port
	}
	voipRelays[targetKey] = r
	voipRelaysMu.Unlock()

	RecordDiag("VOIP_RELAY", "OPEN", fmt.Sprintf("target=%s localAddr=%s tcp=%v", baseHostPort, r.localAddrString(), tcpLn != nil))
	r.start()
	return localIP, localPort
}

func bindVoipRelayLoopbackPreservePort(targetKey string, targetPort int) (*net.UDPConn, net.Listener, string, int, error) {
	canPreserve := (targetPort >= 1024 || (targetPort >= 1 && os.Geteuid() == 0)) && (targetPort < 48729 || targetPort > 48735)
	if canPreserve {
		// Try canonical 127.0.0.1:<targetPort> first so OEMs that isolate 127.0.0.2+ work on primary endpoint.
		ip1 := net.IPv4(127, 0, 0, 1)
		if udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip1, Port: targetPort}); err == nil {
			if tcpLn, tcpErr := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort))); tcpErr == nil {
				return udpLn, tcpLn, "127.0.0.1", targetPort, nil
			}
			_ = udpLn.Close()
		}

		h := fnv.New32a()
		_, _ = h.Write([]byte(targetKey))
		startOctet := 2 + int(h.Sum32()%248) // 2..249
		for i := 0; i < 32; i++ {
			octet := 2 + ((startOctet - 2 + i) % 248)
			ip := net.IPv4(127, 0, 0, byte(octet))
			ipStr := ip.String()
			udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: targetPort})
			if err != nil {
				continue
			}
			tcpLn, tcpErr := net.Listen("tcp4", net.JoinHostPort(ipStr, strconv.Itoa(targetPort)))
			if tcpErr == nil {
				return udpLn, tcpLn, ipStr, targetPort, nil
			}
			// On conflict on one octet, try next 127.0.0.x first; on final attempt keep UDP working.
			if i < 4 {
				_ = udpLn.Close()
				continue
			}
			return udpLn, nil, ipStr, targetPort, nil
		}
	}
	udpLn, tcpLn, port, err := bindVoipRelayLoopback()
	if err != nil {
		return nil, nil, "", 0, err
	}
	return udpLn, tcpLn, "127.0.0.1", port, nil
}

func bindVoipRelayLoopback() (*net.UDPConn, net.Listener, int, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			lastErr = err
			continue
		}
		port := udpLn.LocalAddr().(*net.UDPAddr).Port
		tcpLn, tcpErr := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if tcpErr == nil {
			return udpLn, tcpLn, port, nil
		}
		if attempt < 3 {
			_ = udpLn.Close()
			lastErr = tcpErr
			continue
		}
		// Keep UDP operational even if all ephemeral TCP-on-same-port retries hit a conflict.
		return udpLn, nil, port, nil
	}
	if lastErr == nil {
		lastErr = net.ErrClosed
	}
	return nil, nil, 0, lastErr
}

func (r *voipRelay) removeFromRegistry() {
	voipRelaysMu.Lock()
	if cur, ok := voipRelays[r.targetKey]; ok && cur == r {
		delete(voipRelays, r.targetKey)
	}
	voipRelaysMu.Unlock()
}

func (r *voipRelay) close() {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		if r.cancel != nil {
			r.cancel()
		}
		if r.udpLn != nil {
			_ = r.udpLn.Close()
		}
		if r.tcpLn != nil {
			_ = r.tcpLn.Close()
		}
		r.sessMu.Lock()
		for k, s := range r.sessions {
			s.close()
			delete(r.sessions, k)
		}
		r.sessMu.Unlock()
		trackClientConnEnd(r.statEnt)
		ageSec := time.Now().Unix() - r.createdAtUnix
		if ageSec < 0 {
			ageSec = 0
		}
		tx, rx, errs := r.udpPktsTx.Load(), r.udpPktsRx.Load(), r.udpErrs.Load()
		totPkts := tx + rx
		if totPkts >= 100 {
			lastVoipMediaRelayActiveUnix.Store(time.Now().Unix())
		}
		RecordDiag("VOIP_RELAY", "CLOSE", fmt.Sprintf("target=%s:%d localAddr=%s ageSec=%d udpTx=%d udpRx=%d errs=%d tcpConns=%d",
			r.targetHost, r.targetPort, r.localAddrString(), ageSec, tx, rx, errs, r.tcpConns.Load()))
		// A call relay that lived >= 30s with <100 packets is only a failed call when no sibling relay
		// in the same call session carried real media.
		if ageSec >= 30 && totPkts < 100 && !r.hasSiblingMediaEvidence() {
			voipLowTrafficCloses.Add(1)
			RecordDiag("VOIP_RELAY", "LOW_TRAFFIC", fmt.Sprintf("target=%s:%d ageSec=%d udpTx=%d udpRx=%d errs=%d", r.targetHost, r.targetPort, ageSec, tx, rx, errs))
		}
	})
}

func (r *voipRelay) hasSiblingMediaEvidence() bool {
	if time.Now().Unix()-lastVoipMediaRelayActiveUnix.Load() <= 20 {
		return true
	}
	voipRelaysMu.Lock()
	defer voipRelaysMu.Unlock()
	for _, other := range voipRelays {
		if other != nil && other != r && (other.udpPktsTx.Load()+other.udpPktsRx.Load()) >= 100 {
			return true
		}
	}
	return false
}

func (r *voipRelay) start() {
	// Cancel and clean up automatically if parent tunnel context closes.
	go func() {
		<-r.ctx.Done()
		r.removeFromRegistry()
		r.close()
	}()

	// Reap idle client sessions and expire the whole relay after 90s of inactivity.
	go r.runIdleReaper()

	// Pump incoming local UDP packets from tgcalls into the WireGuard netstack.
	go r.runUdpLoop()

	if r.tcpLn != nil {
		go r.runTcpAcceptLoop()
	}
}

func (r *voipRelay) runIdleReaper() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		nowNano := time.Now().UnixNano()
		cutoff := nowNano - int64(voipRelayIdleTTL)
		if r.lastActive.Load() < cutoff {
			r.removeFromRegistry()
			r.close()
			return
		}
		r.sessMu.Lock()
		for k, s := range r.sessions {
			if s.lastActive.Load() < cutoff {
				s.close()
				delete(r.sessions, k)
			}
		}
		r.sessMu.Unlock()
	}
}

func (r *voipRelay) getLiveDialer() (context.Context, udpDialer, int64) {
	if !r.followActive {
		return r.ctx, r.dialer, 0
	}
	mu.Lock()
	isUp := running
	tnet := activeTnet
	tCtx := activeCtx
	mu.Unlock()
	if isUp && tnet != nil && tCtx != nil && tCtx.Err() == nil {
		return tCtx, tnet, recoveryEpoch.Load()
	}
	tCtx, dialer, ok := awaitMuxRouteReady(3500 * time.Millisecond)
	if ok && dialer != nil && tCtx != nil {
		return tCtx, dialer, recoveryEpoch.Load()
	}
	return r.ctx, r.dialer, recoveryEpoch.Load()
}

func (r *voipRelay) startReturnPump(s *voipRelayUdpSession) {
	go func() {
		rBufPtr := udpFrameBufPool.Get().(*[]byte)
		defer udpFrameBufPool.Put(rBufPtr)
		respBuf := *rBufPtr

		for {
			rn, _, readErr := s.pConn.ReadFrom(respBuf)
			if readErr != nil {
				return
			}
			if rn <= 0 {
				continue
			}
			if _, wErr := r.udpLn.WriteToUDP(respBuf[:rn], s.clientAddr); wErr == nil {
				nowNano := time.Now().UnixNano()
				s.lastActive.Store(nowNano)
				r.lastActive.Store(nowNano)
				if r.udpPktsRx.Add(1)+r.udpPktsTx.Load() == 100 {
					lastVoipMediaRelayActiveUnix.Store(time.Now().Unix())
				}
				udpPacketsRx.Add(1)
				recordClientRx(r.statEnt, rn)
			} else {
				r.udpErrs.Add(1)
				udpSendErrors.Add(1)
				nowNano := time.Now().UnixNano()
				prev := r.lastRetErrNano.Load()
				if nowNano-prev > int64(5*time.Second) && r.lastRetErrNano.CompareAndSwap(prev, nowNano) {
					RecordDiag("VOIP_RELAY", "RET_ERR", fmt.Sprintf("client=%s err=%v", s.clientAddr.String(), wErr))
				}
			}
		}
	}()
}

func (r *voipRelay) runUdpLoop() {
	bufPtr := udpFrameBufPool.Get().(*[]byte)
	defer udpFrameBufPool.Put(bufPtr)
	buf := *bufPtr
	sessionsCap := activeMaxUdpSessionsCap()
	handshakeChecked := false

	for {
		n, srcAddr, rErr := r.udpLn.ReadFromUDP(buf)
		if rErr != nil {
			return
		}
		// Note: Do NOT reject non-loopback srcAddr.IP here. On Android, tgcalls binds to wlan0
		// (e.g. 192.168.0.x) and sends to 127.0.0.1 over table local; listening exclusively on
		// 127.0.0.1 already blocks external network packets.
		if srcAddr == nil || srcAddr.Port <= 0 || n <= 0 {
			continue
		}

		nowNano := time.Now().UnixNano()
		r.lastActive.Store(nowNano)

		liveCtx, liveDialer, _ := r.getLiveDialer()
		if !handshakeChecked {
			handshakeChecked = true
			_ = awaitHandshakeReadyOrFail(liveCtx, liveDialer, 2500*time.Millisecond)
		}

		targetIP, resErr := resolveUdpTargetIP(liveCtx, liveDialer, r.targetHost, r.dnsCache, &r.dnsMu)
		if resErr != nil {
			r.udpErrs.Add(1)
			udpSendErrors.Add(1)
			continue
		}

		sess, sErr := r.getOrCreateUdpSession(srcAddr, targetIP, liveDialer, nowNano, sessionsCap)
		if sErr != nil {
			r.udpErrs.Add(1)
			udpSendErrors.Add(1)
			continue
		}

		dstAddr := &net.UDPAddr{
			IP:   net.IP(targetIP.AsSlice()),
			Port: r.targetPort,
		}
		if nw, wErr := sess.pConn.WriteTo(buf[:n], dstAddr); wErr != nil {
			// Re-open seamlessly on broken socket / post-rebind race.
			r.sessMu.Lock()
			if cur, ok := r.sessions[sess.key]; ok && cur == sess {
				cur.close()
				delete(r.sessions, sess.key)
			}
			r.sessMu.Unlock()
			liveCtx, liveDialer, _ = r.getLiveDialer()
			if freshSess, fErr := r.getOrCreateUdpSession(srcAddr, targetIP, liveDialer, nowNano, sessionsCap); fErr == nil {
				if nw2, wErr2 := freshSess.pConn.WriteTo(buf[:n], dstAddr); wErr2 == nil {
					r.udpPktsTx.Add(1)
					udpPacketsTx.Add(1)
					recordClientTx(r.statEnt, nw2)
					continue
				}
			}
			r.udpErrs.Add(1)
			udpSendErrors.Add(1)
		} else {
			r.udpPktsTx.Add(1)
			udpPacketsTx.Add(1)
			recordClientTx(r.statEnt, nw)
		}
	}
}

func (r *voipRelay) getOrCreateUdpSession(
	srcAddr *net.UDPAddr,
	targetIP netip.Addr,
	dialer udpDialer,
	nowNano int64,
	sessionsCap int,
) (*voipRelayUdpSession, error) {
	isV6 := targetIP.Is6()
	clientKey := srcAddr.String() + "|" + strconv.FormatBool(isV6)

	r.sessMu.RLock()
	sess, exists := r.sessions[clientKey]
	r.sessMu.RUnlock()
	if exists && (!r.followActive || sess.dialer == dialer) {
		sess.lastActive.Store(nowNano)
		return sess, nil
	}

	var staleSess *voipRelayUdpSession
	r.sessMu.Lock()
	if sess, exists = r.sessions[clientKey]; exists {
		if !r.followActive || sess.dialer == dialer {
			r.sessMu.Unlock()
			sess.lastActive.Store(nowNano)
			return sess, nil
		}
		staleSess = sess
		delete(r.sessions, clientKey)
	}

	if len(r.sessions) >= sessionsCap {
		var oldestKey string
		var oldestTs int64 = nowNano
		for k, cand := range r.sessions {
			ts := cand.lastActive.Load()
			if oldestKey == "" || ts < oldestTs {
				oldestKey = k
				oldestTs = ts
			}
		}
		if oldestKey != "" {
			r.sessions[oldestKey].close()
			delete(r.sessions, oldestKey)
		}
	}
	r.sessMu.Unlock()
	if staleSess != nil {
		staleSess.close()
	}

	newConn, err := openFullConePacketConn(dialer, isV6)
	if err != nil {
		return nil, err
	}

	clientCopy := &net.UDPAddr{
		IP:   append([]byte(nil), srcAddr.IP...),
		Port: srcAddr.Port,
		Zone: srcAddr.Zone,
	}
	newSess := &voipRelayUdpSession{
		key:        clientKey,
		clientAddr: clientCopy,
		pConn:      newConn,
		dialer:     dialer,
	}
	newSess.lastActive.Store(nowNano)

	r.sessMu.Lock()
	if r.closed.Load() {
		r.sessMu.Unlock()
		newSess.close()
		return nil, net.ErrClosed
	}
	if cur, raceWon := r.sessions[clientKey]; raceWon {
		r.sessMu.Unlock()
		newSess.close()
		cur.lastActive.Store(nowNano)
		return cur, nil
	}
	r.sessions[clientKey] = newSess
	newSess.counted.Store(true)
	activeUdpAssocs.Add(1)
	r.sessMu.Unlock()

	udpSocketsOpened.Add(1)
	r.startReturnPump(newSess)
	return newSess, nil
}

func (r *voipRelay) runTcpAcceptLoop() {
	for {
		c, err := r.tcpLn.Accept()
		if err != nil {
			return
		}
		r.tcpConns.Add(1)
		tuneLocalTcpSocket(c)
		go r.handleTcpClient(c)
	}
}

type voipRelayDiagStat struct {
	LocalAddr   string `json:"localAddr"`
	TargetPort  int    `json:"targetPort"`
	UdpSessions int    `json:"udpSessions"`
	UdpTxPkts   uint64 `json:"udpTxPkts"`
	UdpRxPkts   uint64 `json:"udpRxPkts"`
	UdpErrs     uint64 `json:"udpErrs"`
	TcpConns    uint64 `json:"tcpConns"`
	AgeSec      int64  `json:"ageSec"`
	IdleSec     int64  `json:"idleSec"`
	TcpReady    bool   `json:"tcpReady"`
}

func getVoipRelaysDiagSnapshot() []voipRelayDiagStat {
	voipRelaysMu.Lock()
	relays := make([]*voipRelay, 0, len(voipRelays))
	for _, r := range voipRelays {
		if r != nil && !r.closed.Load() {
			relays = append(relays, r)
		}
	}
	voipRelaysMu.Unlock()

	now := time.Now()
	nowUnix := now.Unix()
	nowNano := now.UnixNano()
	out := make([]voipRelayDiagStat, 0, len(relays))
	for _, r := range relays {
		r.sessMu.RLock()
		sessCnt := len(r.sessions)
		r.sessMu.RUnlock()

		age := nowUnix - r.createdAtUnix
		if r.createdAtUnix <= 0 || age < 0 {
			age = 0
		}
		idle := (nowNano - r.lastActive.Load()) / int64(time.Second)
		if idle < 0 {
			idle = 0
		}
		out = append(out, voipRelayDiagStat{
			LocalAddr:   r.localAddrString(),
			TargetPort:  r.targetPort,
			UdpSessions: sessCnt,
			UdpTxPkts:   r.udpPktsTx.Load(),
			UdpRxPkts:   r.udpPktsRx.Load(),
			UdpErrs:     r.udpErrs.Load(),
			TcpConns:    r.tcpConns.Load(),
			AgeSec:      age,
			IdleSec:     idle,
			TcpReady:    r.tcpLn != nil,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetPort != out[j].TargetPort {
			return out[i].TargetPort < out[j].TargetPort
		}
		return out[i].LocalAddr < out[j].LocalAddr
	})
	return out
}

type bufferedVoipConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedVoipConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *bufferedVoipConn) CloseWrite() error {
	if wc, ok := b.Conn.(writeCloserConn); ok {
		return wc.CloseWrite()
	}
	return b.Conn.Close()
}

func writeAllVoipConn(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (r *voipRelay) relayTcpOverTunnel(client net.Conn, br *bufio.Reader, liveCtx context.Context, liveDialer udpDialer, targetIP netip.Addr) {
	network := "tcp4"
	if targetIP.Is6() {
		network = "tcp6"
	}
	targetAddr := net.JoinHostPort(targetIP.String(), strconv.Itoa(r.targetPort))

	dialCtx, cancel := context.WithTimeout(liveCtx, 12*time.Second)
	remote, err := liveDialer.DialContext(dialCtx, network, targetAddr)
	cancel()
	if err != nil {
		return
	}
	defer remote.Close()

	activeTcpConns.Add(1)
	defer activeTcpConns.Add(-1)

	localConn := client
	if br != nil && br.Buffered() > 0 {
		localConn = &bufferedVoipConn{Conn: client, r: br}
	}
	relayTcpBidirectional(r.ctx, localConn, remote, r.statEnt)
}

func (r *voipRelay) bridgeStunTurnTcpToUdp(client net.Conn, br *bufio.Reader, liveCtx context.Context, liveDialer udpDialer, targetIP netip.Addr) {
	pConn, err := openFullConePacketConn(liveDialer, targetIP.Is6())
	if err != nil {
		r.relayTcpOverTunnel(client, br, liveCtx, liveDialer, targetIP)
		return
	}

	udpSocketsOpened.Add(1)
	activeUdpAssocs.Add(1)
	defer activeUdpAssocs.Add(-1)
	defer pConn.Close()

	stopBridge := make(chan struct{})
	defer close(stopBridge)
	go func() {
		select {
		case <-r.ctx.Done():
			_ = client.Close()
			_ = pConn.Close()
		case <-stopBridge:
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rBufPtr := udpFrameBufPool.Get().(*[]byte)
		defer udpFrameBufPool.Put(rBufPtr)
		respBuf := *rBufPtr

		for {
			rn, _, rErr := pConn.ReadFrom(respBuf)
			if rErr != nil {
				_ = client.Close()
				return
			}
			if rn <= 0 {
				continue
			}
			r.lastActive.Store(time.Now().UnixNano())
			r.udpPktsRx.Add(1)
			udpPacketsRx.Add(1)
			recordClientRx(r.statEnt, rn)

			// AsyncStunTCPSocket expects 4-byte padded ChannelData frames over TCP (RFC 5766 §11.4).
			var outFrame []byte
			if rn >= 4 && (respBuf[0]&0xC0) == 0x40 {
				cLen := int(binary.BigEndian.Uint16(respBuf[2:4]))
				if 4+cLen <= rn {
					pad := (4 - (cLen % 4)) % 4
					if 4+cLen+pad <= len(respBuf) {
						for p := 0; p < pad; p++ {
							respBuf[4+cLen+p] = 0
						}
						outFrame = respBuf[:4+cLen+pad]
					}
				}
			}
			if outFrame == nil {
				outFrame = respBuf[:rn]
			}
			_ = client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if wErr := writeAllVoipConn(client, outFrame); wErr != nil {
				_ = pConn.Close()
				return
			}
		}
	}()

	dstAddr := &net.UDPAddr{
		IP:   net.IP(targetIP.AsSlice()),
		Port: r.targetPort,
	}
	frameBuf := make([]byte, 16384+32)
	hdr := frameBuf[:4]
	for {
		_ = client.SetReadDeadline(time.Now().Add(voipRelayIdleTTL))
		if _, rErr := io.ReadFull(br, hdr); rErr != nil {
			break
		}
		msgLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if msgLen > 16384 {
			break
		}
		tcpRem, udpLen := -1, 0
		switch hdr[0] & 0xC0 {
		case 0x00:
			if msgLen%4 == 0 {
				tcpRem = 16 + msgLen
				udpLen = 20 + msgLen
			}
		case 0x40:
			tcpRem = (msgLen + 3) &^ 3
			udpLen = 4 + msgLen
		}
		if tcpRem < 0 || 4+tcpRem > len(frameBuf) {
			break
		}
		_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, rErr := io.ReadFull(br, frameBuf[4:4+tcpRem]); rErr != nil {
			break
		}
		r.lastActive.Store(time.Now().UnixNano())
		nw, wErr := pConn.WriteTo(frameBuf[:udpLen], dstAddr)
		if wErr != nil {
			r.udpErrs.Add(1)
			udpSendErrors.Add(1)
			continue
		}
		r.udpPktsTx.Add(1)
		udpPacketsTx.Add(1)
		recordClientTx(r.statEnt, nw)
	}
	_ = client.Close()
	_ = pConn.Close()
	<-done
}

func (r *voipRelay) handleTcpClient(client net.Conn) {
	defer client.Close()
	r.lastActive.Store(time.Now().UnixNano())

	br := bufio.NewReaderSize(client, 8192)
	_ = client.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	peek, _ := br.Peek(8)
	_ = client.SetReadDeadline(time.Time{})

	liveCtx, liveDialer, _ := r.getLiveDialer()
	if !awaitHandshakeReadyOrFail(liveCtx, liveDialer, 2500*time.Millisecond) {
		return
	}

	targetIP, resErr := resolveUdpTargetIP(liveCtx, liveDialer, r.targetHost, r.dnsCache, &r.dnsMu)
	if resErr != nil {
		return
	}

	if len(peek) >= 8 && (peek[0]&0xC0) == 0x00 && binary.BigEndian.Uint32(peek[4:8]) == 0x2112A442 {
		r.bridgeStunTurnTcpToUdp(client, br, liveCtx, liveDialer, targetIP)
		return
	}
	r.relayTcpOverTunnel(client, br, liveCtx, liveDialer, targetIP)
}
