package wgbridge

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
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
)

type udpDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type packetConnDialer interface {
	OpenFullConePacketConn(isV6 bool) (net.PacketConn, error)
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
	resolvedEp := activeResolvedEp
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil || pubHex == "" {
		return false
	}
	_, _, hsSec := readDeviceCounters(dev)
	nowSec := time.Now().Unix()
	if hsSec > 0 && (nowSec-hsSec) < 180 {
		if (nowSec-hsSec) >= 115 && hasOutboundSystemRoute(resolvedEp) {
			nowNano := time.Now().UnixNano()
			prevRekey := lastProactiveRekeyNano.Load()
			if nowNano-prevRekey >= int64(10*time.Second) && lastProactiveRekeyNano.CompareAndSwap(prevRekey, nowNano) {
				triggerPeerHandshakeDirect(dev, pubHex, true)
			}
		}
		return true
	}

	// If the OS has no outbound route, pace quietly instead of spinning handshake retries.
	if !hasOutboundSystemRoute(resolvedEp) {
		idleWait := maxWait
		if idleWait <= 0 || idleWait > 1200*time.Millisecond {
			idleWait = 1200 * time.Millisecond
		}
		timer := time.NewTimer(idleWait)
		if ctx != nil {
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		} else {
			<-timer.C
		}
		return false
	}

	prevHs := hsSec
	startWait := time.Now()
	triggerPeerHandshakeDirect(dev, pubHex, true)
	rehopped := false
	deadline := startWait.Add(maxWait)
	for time.Now().Before(deadline) {
		if ctx != nil && ctx.Err() != nil {
			return false
		}
		_, _, curHs := readDeviceCounters(dev)
		curNow := time.Now().Unix()
		if curHs > 0 && (curNow-curHs) < 180 && (prevHs <= 0 || curHs > prevHs) {
			return true
		}
		if !rehopped && prevHs > 0 && time.Since(startWait) >= 650*time.Millisecond {
			rehopped = true
			_ = hopActivePeer(true, true)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _, curHs := readDeviceCounters(dev)
	if curHs > 0 && (time.Now().Unix()-curHs) < 180 && (prevHs <= 0 || curHs > prevHs) {
		return true
	}
	if minPace := 900 * time.Millisecond; maxWait >= minPace && time.Since(startWait) < minPace {
		time.Sleep(minPace - time.Since(startWait))
	}
	return false
}

func recordSocksAuthReject(reason string) {
	socksAuthRejectCount.Add(1)
	nowNano := time.Now().UnixNano()
	prev := lastSocksAuthDiagNano.Load()
	if nowNano-prev > int64(3*time.Second) && lastSocksAuthDiagNano.CompareAndSwap(prev, nowNano) {
		RecordDiag("SOCKS_AUTH", "REJECT", reason)
	}
}

func sanitizeAuthSubLabel(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw) && b.Len() < 64; i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '#' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func readSocks5HandshakeAndReqWithLabel(client net.Conn) (cmd byte, host string, dstPort uint16, authSubLabel string, reqParsed bool) {
	// 1. Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return 0, "", 0, "", false
	}
	if hdr[0] != 0x05 {
		return 0, "", 0, "", false
	}
	nMethods := int(hdr[1])
	var methods []byte
	if nMethods > 0 {
		methods = make([]byte, nMethods)
		if _, err := io.ReadFull(client, methods); err != nil {
			return 0, "", 0, "", false
		}
	}

	expectedUser, expectedPass := getSocksAuth()
	if expectedUser == "" && expectedPass == "" {
		// Reply: SOCKS5, NO AUTHENTICATION REQUIRED (0x00)
		if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
			return 0, "", 0, "", false
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
			return 0, "", 0, "", false
		}
		if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
			return 0, "", 0, "", false
		}
		// RFC 1929 subnegotiation: VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
		var subHdr [2]byte
		if _, err := io.ReadFull(client, subHdr[:]); err != nil || subHdr[0] != 0x01 {
			_, _ = client.Write([]byte{0x01, 0x01})
			recordSocksAuthReject("invalid rfc1929 subnegotiation header")
			return 0, "", 0, "", false
		}
		uBuf := make([]byte, int(subHdr[1]))
		if len(uBuf) > 0 {
			if _, err := io.ReadFull(client, uBuf); err != nil {
				_, _ = client.Write([]byte{0x01, 0x01})
				recordSocksAuthReject("truncated rfc1929 username")
				return 0, "", 0, "", false
			}
		}
		var pLen [1]byte
		if _, err := io.ReadFull(client, pLen[:]); err != nil {
			_, _ = client.Write([]byte{0x01, 0x01})
			recordSocksAuthReject("missing rfc1929 password length")
			return 0, "", 0, "", false
		}
		pBuf := make([]byte, int(pLen[0]))
		if len(pBuf) > 0 {
			if _, err := io.ReadFull(client, pBuf); err != nil {
				_, _ = client.Write([]byte{0x01, 0x01})
				recordSocksAuthReject("truncated rfc1929 password")
				return 0, "", 0, "", false
			}
		}
		uOk := 0
		expLen := len(expectedUser)
		if len(uBuf) == expLen {
			uOk = subtle.ConstantTimeCompare(uBuf, []byte(expectedUser))
		} else if expectedUser != "" && len(uBuf) > expLen+1 && uBuf[expLen] == ':' {
			if subtle.ConstantTimeCompare(uBuf[:expLen], []byte(expectedUser)) == 1 {
				uOk = 1
				authSubLabel = sanitizeAuthSubLabel(string(uBuf[expLen+1:]))
			}
		}
		pOk := verifySocksPassBytes(pBuf)
		if (uOk & pOk) != 1 {
			_, _ = client.Write([]byte{0x01, 0x01})
			recordSocksAuthReject("username/password mismatch")
			return 0, "", 0, "", false
		}
		if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
			return 0, "", 0, "", false
		}
	}

	// 2. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil {
		return 0, "", 0, "", false
	}
	if reqHdr[0] != 0x05 {
		return 0, "", 0, "", false
	}

	cmd = reqHdr[1]
	host, dstPort, err := readSocks5Target(client, reqHdr[3])
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", 0, "", false
	}
	return cmd, host, dstPort, authSubLabel, true
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

	cmd, host, dstPort, authSubLabel, ok := readSocks5HandshakeAndReqWithLabel(client)
	if !ok {
		return
	}
	label := "local-client"
	if authSubLabel != "" {
		label = authSubLabel
	}
	dispatchSocks5CmdWithLabel(ctx, client, dialer, cmd, host, dstPort, label)
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
	if pd, ok := dialer.(packetConnDialer); ok && pd != nil {
		return pd.OpenFullConePacketConn(isV6)
	}
	return nil, errors.New("udp dialer does not support tunnel packet sockets")
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
