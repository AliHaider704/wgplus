package wgbridge

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxVoipRelays     = 16
	voipRelayIdleTTL  = 90 * time.Second
	voipRelayClientID = "voip-relay"
)

type voipRelayUdpSession struct {
	key        string
	clientAddr *net.UDPAddr
	pConn      net.PacketConn
	dialer     udpDialer
	lastActive atomic.Int64
	closeOnce  sync.Once
}

func (s *voipRelayUdpSession) close() {
	s.closeOnce.Do(func() {
		if s.pConn != nil {
			_ = s.pConn.Close()
		}
	})
}

type voipRelay struct {
	targetKey       string
	targetHost      string
	targetPort      int
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
)

// StartVoipEndpointRelay binds a local 127.0.0.1 UDP (and best-effort TCP) relay
// socket that forwards packets for targetHost:targetPort directly through the active
// WireGuard tunnel netstack. Returns the bound local loopback port, or 0 on failure.
func StartVoipEndpointRelay(targetHost string, targetPort int) int {
	trimmedHost := strings.TrimSpace(targetHost)
	if trimmedHost == "" || targetPort < 1 || targetPort > 65535 {
		return 0
	}

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
			return 0
		}
	}

	return startVoipEndpointRelayWithDialer(ctx, dialer, trimmedHost, targetPort)
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
	trimmedHost := strings.TrimSpace(targetHost)
	if ctx == nil || dialer == nil || trimmedHost == "" || targetPort < 1 || targetPort > 65535 {
		return 0
	}
	if ctx.Err() != nil {
		return 0
	}

	_, followActive := dialer.(*fastNet)
	targetKey := net.JoinHostPort(strings.ToLower(trimmedHost), strconv.Itoa(targetPort))
	nowNano := time.Now().UnixNano()

	voipRelaysMu.Lock()
	if existing, ok := voipRelays[targetKey]; ok {
		if !existing.closed.Load() && existing.ctx.Err() == nil && (followActive || existing.parentCtx == ctx) {
			existing.lastActive.Store(nowNano)
			port := existing.localPort
			voipRelaysMu.Unlock()
			return port
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

	udpLn, tcpLn, localPort, err := bindVoipRelayLoopback()
	if err != nil {
		RecordDiag("VOIP_RELAY", "BIND_ERR", fmt.Sprintf("target=%s err=%v", targetKey, err))
		return 0
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
		localPort:    localPort,
		followActive: followActive,
		parentCtx:    ctx,
		ctx:          relayCtx,
		cancel:       relayCancel,
		dialer:       dialer,
		udpLn:        udpLn,
		tcpLn:        tcpLn,
		statEnt:      trackClientConnStart(voipRelayClientID),
		sessions:     make(map[string]*voipRelayUdpSession),
		dnsCache:     make(map[string]udpDnsCacheEntry),
	}
	r.lastActive.Store(nowNano)

	voipRelaysMu.Lock()
	// Check race: another goroutine may have created the same target while we were binding.
	if existing, ok := voipRelays[targetKey]; ok && !existing.closed.Load() && existing.ctx.Err() == nil && (followActive || existing.parentCtx == ctx) {
		existing.lastActive.Store(nowNano)
		port := existing.localPort
		voipRelaysMu.Unlock()
		r.close()
		return port
	}
	voipRelays[targetKey] = r
	voipRelaysMu.Unlock()

	RecordDiag("VOIP_RELAY", "OPEN", fmt.Sprintf("target=%s localPort=%d tcp=%v", targetKey, localPort, tcpLn != nil))
	r.start()
	return localPort
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
		r.cancel()
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
		RecordDiag("VOIP_RELAY", "CLOSE", fmt.Sprintf("target=%s localPort=%d", r.targetKey, r.localPort))
	})
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
				udpPacketsRx.Add(1)
				recordClientRx(r.statEnt, rn)
			} else {
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
			udpSendErrors.Add(1)
			continue
		}

		sess, sErr := r.getOrCreateUdpSession(srcAddr, targetIP, liveDialer, nowNano, sessionsCap)
		if sErr != nil {
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
					udpPacketsTx.Add(1)
					recordClientTx(r.statEnt, nw2)
					continue
				}
			}
			udpSendErrors.Add(1)
		} else {
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
		tuneLocalTcpSocket(c)
		go r.handleTcpClient(c)
	}
}

func (r *voipRelay) handleTcpClient(client net.Conn) {
	defer client.Close()
	r.lastActive.Store(time.Now().UnixNano())

	liveCtx, liveDialer, _ := r.getLiveDialer()
	if !awaitHandshakeReadyOrFail(liveCtx, liveDialer, 2500*time.Millisecond) {
		return
	}

	targetIP, resErr := resolveUdpTargetIP(liveCtx, liveDialer, r.targetHost, r.dnsCache, &r.dnsMu)
	if resErr != nil {
		return
	}
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

	relayTcpBidirectional(r.ctx, client, remote, r.statEnt)
}
