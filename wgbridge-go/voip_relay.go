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
	targetKey  string
	targetHost string
	targetPort int
	localPort  int
	parentCtx  context.Context
	ctx        context.Context
	cancel     context.CancelFunc
	dialer     udpDialer
	udpLn      *net.UDPConn
	tcpLn      net.Listener
	statEnt    *clientStatEntry
	lastActive atomic.Int64
	closed     atomic.Bool
	closeOnce  sync.Once

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

	targetKey := net.JoinHostPort(strings.ToLower(trimmedHost), strconv.Itoa(targetPort))
	nowNano := time.Now().UnixNano()

	voipRelaysMu.Lock()
	if existing, ok := voipRelays[targetKey]; ok {
		if !existing.closed.Load() && existing.ctx.Err() == nil && existing.parentCtx == ctx {
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

	relayCtx, relayCancel := context.WithCancel(ctx)
	r := &voipRelay{
		targetKey:  targetKey,
		targetHost: trimmedHost,
		targetPort: targetPort,
		localPort:  localPort,
		parentCtx:  ctx,
		ctx:        relayCtx,
		cancel:     relayCancel,
		dialer:     dialer,
		udpLn:      udpLn,
		tcpLn:      tcpLn,
		statEnt:    trackClientConnStart(voipRelayClientID),
		sessions:   make(map[string]*voipRelayUdpSession),
		dnsCache:   make(map[string]udpDnsCacheEntry),
	}
	r.lastActive.Store(nowNano)

	voipRelaysMu.Lock()
	// Check race: another goroutine may have created the same target while we were binding.
	if existing, ok := voipRelays[targetKey]; ok && !existing.closed.Load() && existing.ctx.Err() == nil && existing.parentCtx == ctx {
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
			}
		}
	}()
}

func (r *voipRelay) runUdpLoop() {
	bufPtr := udpFrameBufPool.Get().(*[]byte)
	defer udpFrameBufPool.Put(bufPtr)
	buf := *bufPtr
	sessionsCap := activeMaxUdpSessionsCap()

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

		targetIP, resErr := resolveUdpTargetIP(r.ctx, r.dialer, r.targetHost, r.dnsCache, &r.dnsMu)
		if resErr != nil {
			udpSendErrors.Add(1)
			continue
		}

		sess, sErr := r.getOrCreateUdpSession(srcAddr, targetIP, nowNano, sessionsCap)
		if sErr != nil {
			udpSendErrors.Add(1)
			continue
		}

		dstAddr := &net.UDPAddr{
			IP:   net.IP(targetIP.AsSlice()),
			Port: r.targetPort,
		}
		if nw, wErr := sess.pConn.WriteTo(buf[:n], dstAddr); wErr == nil {
			udpPacketsTx.Add(1)
			recordClientTx(r.statEnt, nw)
		} else {
			udpSendErrors.Add(1)
		}
	}
}

func (r *voipRelay) getOrCreateUdpSession(
	srcAddr *net.UDPAddr,
	targetIP netip.Addr,
	nowNano int64,
	sessionsCap int,
) (*voipRelayUdpSession, error) {
	isV6 := targetIP.Is6()
	clientKey := srcAddr.String() + "|" + strconv.FormatBool(isV6)

	r.sessMu.RLock()
	sess, exists := r.sessions[clientKey]
	r.sessMu.RUnlock()
	if exists {
		sess.lastActive.Store(nowNano)
		return sess, nil
	}

	r.sessMu.Lock()
	if sess, exists = r.sessions[clientKey]; exists {
		r.sessMu.Unlock()
		sess.lastActive.Store(nowNano)
		return sess, nil
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

	newConn, err := openFullConePacketConn(r.dialer, isV6)
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

	awaitInitialHandshakeBeforeDial(r.ctx)

	targetIP, resErr := resolveUdpTargetIP(r.ctx, r.dialer, r.targetHost, r.dnsCache, &r.dnsMu)
	if resErr != nil {
		return
	}
	network := "tcp4"
	if targetIP.Is6() {
		network = "tcp6"
	}
	targetAddr := net.JoinHostPort(targetIP.String(), strconv.Itoa(r.targetPort))

	dialCtx, cancel := context.WithTimeout(r.ctx, 12*time.Second)
	remote, err := r.dialer.DialContext(dialCtx, network, targetAddr)
	cancel()
	if err != nil {
		return
	}
	defer remote.Close()

	activeTcpConns.Add(1)
	defer activeTcpConns.Add(-1)

	relayTcpBidirectional(r.ctx, client, remote, r.statEnt)
}
