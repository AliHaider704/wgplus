package wgbridge

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	mobileTunQueueDepth  = 1024
	mobileTunBatchSize   = 32
	desktopTunQueueDepth = 1024
	desktopTunBatchSize  = 32

	minTunnelDnsCacheTTL = 15 * time.Second
	maxTunnelDnsCacheTTL = 300 * time.Second
)

var (
	desktopModeFlag atomic.Bool
	blockIPv6Flag   atomic.Bool
)

type netstackProfile struct {
	queueDepth int
	batchSize  int
	txDefault  int
	txMax      int
	rxDefault  int
	rxMax      int
	blockIPv6  bool
}

func mobileNetstackProfile() netstackProfile {
	return netstackProfile{
		queueDepth: mobileTunQueueDepth,
		batchSize:  mobileTunBatchSize,
		txDefault:  262144,
		txMax:      4194304,
		rxDefault:  524288,
		rxMax:      4194304,
		blockIPv6:  blockIPv6Flag.Load(),
	}
}

func desktopNetstackProfile() netstackProfile {
	return netstackProfile{
		queueDepth: desktopTunQueueDepth,
		batchSize:  desktopTunBatchSize,
		txDefault:  262144,
		txMax:      1048576,
		rxDefault:  524288,
		rxMax:      4194304,
		blockIPv6:  blockIPv6Flag.Load(),
	}
}

func activeNetstackProfile() netstackProfile {
	if desktopModeFlag.Load() {
		return desktopNetstackProfile()
	}
	return mobileNetstackProfile()
}

type tunnelDnsEntry struct {
	addrs     []netip.Addr
	expiresAt time.Time
}

type fastNetTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	closeCh        chan struct{}
	closeOnce      sync.Once
	mtu            int
	batchSize      int
	blockIPv6      atomic.Bool
	dnsServers     []netip.Addr
	dnsMu          sync.Mutex
	dnsCache       map[string]tunnelDnsEntry
	hasV4, hasV6   bool
}

type fastNet fastNetTun

// createFastNetTUN creates a userspace gVisor TCP/UDP/IP stack tuned for the active
// platform profile (mobile or desktop) with optional IPv6 blocking.
func createFastNetTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *fastNet, error) {
	return createFastNetTUNWithProfile(localAddresses, dnsServers, mtu, activeNetstackProfile())
}

func createFastNetTUNWithProfile(localAddresses, dnsServers []netip.Addr, mtu int, prof netstackProfile) (tun.Device, *fastNet, error) {
	if prof.queueDepth <= 0 {
		prof.queueDepth = mobileTunQueueDepth
	}
	if prof.batchSize <= 0 {
		prof.batchSize = mobileTunBatchSize
	}
	if prof.txDefault <= 0 {
		prof.txDefault = 262144
	}
	if prof.txMax < prof.txDefault {
		prof.txMax = 4194304
	}
	if prof.rxDefault <= 0 {
		prof.rxDefault = 524288
	}
	if prof.rxMax < prof.rxDefault {
		prof.rxMax = 4194304
	}

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	dev := &fastNetTun{
		ep:             channel.New(prof.queueDepth, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 16),
		incomingPacket: make(chan *buffer.View, prof.queueDepth),
		closeCh:        make(chan struct{}),
		dnsServers:     dnsServers,
		dnsCache:       make(map[string]tunnelDnsEntry),
		mtu:            mtu,
		batchSize:      prof.batchSize,
	}
	dev.blockIPv6.Store(prof.blockIPv6)

	// 1. Enable TCP SACK
	sackOpt := tcpip.TCPSACKEnabled(true)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// 2. Disable Nagle's algorithm globally across the tunnel stack (zero delay for MTProto frames)
	noDelayOpt := tcpip.TCPDelayEnabled(false)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &noDelayOpt)

	// 3. Use NewReno congestion control (avoids gVisor CUBIC+RACK premature cwnd collapse on bursty TUN channels)
	ccOpt := tcpip.CongestionControlOption("reno")
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)

	// 5. Enable TCP Receive Buffer Auto-Tuning (Moderation) and high-throughput window ranges
	modOpt := tcpip.TCPModerateReceiveBufferOption(true)
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &modOpt)

	txBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: prof.txDefault,
		Max:     prof.txMax,
	}
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &txBufOpt)

	rxBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: prof.rxDefault,
		Max:     prof.rxMax,
	}
	_ = dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBufOpt)

	dev.notifyHandle = dev.ep.AddNotify(dev)
	if tcpipErr := dev.stack.CreateNIC(1, dev.ep); tcpipErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	dev.events <- tun.EventUp
	return dev, (*fastNet)(dev), nil
}

func (tun *fastNetTun) Name() (string, error) {
	return "go", nil
}

func (tun *fastNetTun) File() *os.File {
	return nil
}

func (tun *fastNetTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *fastNetTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	var view *buffer.View
	select {
	case v, ok := <-tun.incomingPacket:
		if !ok {
			return 0, os.ErrClosed
		}
		view = v
	case <-tun.closeCh:
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	view.Release()
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	count := 1

	// Opportunistically drain queued outbound tunnel packets in a single batch
	maxBatch := len(buf)
	for count < maxBatch {
		select {
		case nextView, ok := <-tun.incomingPacket:
			if !ok {
				return count, nil
			}
			rn, rErr := nextView.Read(buf[count][offset:])
			nextView.Release()
			if rErr != nil {
				return count, nil
			}
			sizes[count] = rn
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (tun *fastNetTun) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		pkb.DecRef()
	}
	return len(buf), nil
}

func (tun *fastNetTun) WriteNotify() {
	for {
		pkt := tun.ep.Read()
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		select {
		case tun.incomingPacket <- view:
		case <-tun.closeCh:
			view.Release()
			return
		}
	}
}

func (tun *fastNetTun) Close() error {
	tun.closeOnce.Do(func() {
		close(tun.closeCh)
		tun.stack.RemoveNIC(1)
		tun.stack.Close()
		tun.ep.RemoveNotify(tun.notifyHandle)
		tun.ep.Close()

		if tun.events != nil {
			close(tun.events)
		}
	})
	return nil
}

func (tun *fastNetTun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *fastNetTun) BatchSize() int {
	if tun.batchSize > 0 {
		return tun.batchSize
	}
	return mobileTunBatchSize
}

func convertToFullAddrFast(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (fnet *fastNet) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddrFast(addr)
	return gonet.DialContextTCP(ctx, fnet.stack, fa, pn)
}

func (fnet *fastNet) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := convertToFullAddrFast(addr)
	return gonet.ListenTCP(fnet.stack, fa, pn)
}

func (fnet *fastNet) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return fnet.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return fnet.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (fnet *fastNet) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddrFast(laddr)
		lfa = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddrFast(raddr)
		rfa = &addr
	}
	return gonet.DialUDP(fnet.stack, lfa, rfa, pn)
}

func (fnet *fastNet) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
	}
	return fnet.DialUDPAddrPort(la, ra)
}

func (fnet *fastNet) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return fnet.DialUDP(laddr, nil)
}

var fastProtoSplitter = regexp.MustCompile(`^(tcp|udp)(4|6)?$`)

type dnsQueryResult struct {
	addrs []netip.Addr
	ttl   time.Duration
}

func (fnet *fastNet) queryTunnelDnsSingle(ctx context.Context, srv netip.Addr, dn dnsmessage.Name, qType dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	uConn, dErr := fnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(srv, 53))
	if dErr != nil {
		return nil, 0, dErr
	}
	defer uConn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = uConn.SetDeadline(dl)
	} else {
		_ = uConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	}

	txID := uint16(rand.Intn(65534) + 1)
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               txID,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dn,
				Type:  qType,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packed, pErr := msg.Pack()
	if pErr != nil {
		return nil, 0, pErr
	}
	if _, wErr := uConn.Write(packed); wErr != nil {
		return nil, 0, wErr
	}

	respBuf := make([]byte, 1500)
	rn, rErr := uConn.Read(respBuf)
	if rErr != nil || rn <= 0 {
		if rErr == nil {
			rErr = errors.New("empty DNS reply")
		}
		return nil, 0, rErr
	}

	var parser dnsmessage.Parser
	hdr, hErr := parser.Start(respBuf[:rn])
	if hErr != nil || hdr.ID != txID {
		return nil, 0, errors.New("invalid DNS header")
	}
	_ = parser.SkipAllQuestions()

	var out []netip.Addr
	var minTTL uint32 = 60
	ttlSet := false
	for {
		ah, aErr := parser.AnswerHeader()
		if aErr != nil {
			break
		}
		if ah.Type == dnsmessage.TypeA && qType == dnsmessage.TypeA {
			ar, errA := parser.AResource()
			if errA == nil {
				out = append(out, netip.AddrFrom4(ar.A))
				if !ttlSet || ah.TTL < minTTL {
					minTTL = ah.TTL
					ttlSet = true
				}
			}
		} else if ah.Type == dnsmessage.TypeAAAA && qType == dnsmessage.TypeAAAA {
			aaaa, errAAAA := parser.AAAAResource()
			if errAAAA == nil {
				out = append(out, netip.AddrFrom16(aaaa.AAAA))
				if !ttlSet || ah.TTL < minTTL {
					minTTL = ah.TTL
					ttlSet = true
				}
			}
		} else {
			_ = parser.SkipAnswer()
		}
	}
	if len(out) == 0 {
		return nil, 0, errors.New("no matching DNS records")
	}
	ttl := time.Duration(minTTL) * time.Second
	if ttl < minTunnelDnsCacheTTL {
		ttl = minTunnelDnsCacheTTL
	} else if ttl > maxTunnelDnsCacheTTL {
		ttl = maxTunnelDnsCacheTTL
	}
	return out, ttl, nil
}

func (fnet *fastNet) queryServersParallel(ctx context.Context, servers []netip.Addr, dn dnsmessage.Name, qType dnsmessage.Type) (dnsQueryResult, bool) {
	qCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	resCh := make(chan dnsQueryResult, len(servers))
	doneCh := make(chan struct{})
	var wg sync.WaitGroup
	for _, srv := range servers {
		dnsSrv := srv
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, ttl, err := fnet.queryTunnelDnsSingle(qCtx, dnsSrv, dn, qType)
			if err == nil && len(addrs) > 0 {
				select {
				case resCh <- dnsQueryResult{addrs: addrs, ttl: ttl}:
				default:
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case winner := <-resCh:
		return winner, true
	case <-doneCh:
		select {
		case winner := <-resCh:
			return winner, true
		default:
			return dnsQueryResult{}, false
		}
	case <-qCtx.Done():
		return dnsQueryResult{}, false
	}
}

func (fnet *fastNet) LookupContextHost(ctx context.Context, host string) ([]netip.Addr, error) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" || strings.EqualFold(trimmed, "localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if ip, err := netip.ParseAddr(trimmed); err == nil {
		unmapped := ip.Unmap()
		if unmapped.Is6() && fnet.blockIPv6.Load() {
			return nil, errors.New("IPv6 blocked by tunnel policy")
		}
		return []netip.Addr{unmapped}, nil
	}

	allowV6 := !fnet.blockIPv6.Load() && fnet.hasV6
	cacheKey := strings.ToLower(trimmed)
	if allowV6 {
		cacheKey += "|v6"
	} else {
		cacheKey += "|v4"
	}

	now := time.Now()
	fnet.dnsMu.Lock()
	if ent, ok := fnet.dnsCache[cacheKey]; ok && now.Before(ent.expiresAt) && len(ent.addrs) > 0 {
		copied := make([]netip.Addr, len(ent.addrs))
		copy(copied, ent.addrs)
		fnet.dnsMu.Unlock()
		return copied, nil
	}
	fnet.dnsMu.Unlock()

	// Resolve domain inside the tunnel via configured tunnel DNS servers in parallel
	clean := strings.TrimSuffix(trimmed, ".")
	if !strings.HasSuffix(clean, ".") {
		clean += "."
	}
	dn, err := dnsmessage.NewName(clean)
	if err != nil {
		return nil, err
	}
	servers := fnet.dnsServers
	if len(servers) == 0 {
		servers = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	var usable []netip.Addr
	for _, s := range servers {
		if s.Is6() && fnet.blockIPv6.Load() {
			continue
		}
		usable = append(usable, s)
	}
	if len(usable) == 0 {
		usable = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	if resA, ok := fnet.queryServersParallel(ctx, usable, dn, dnsmessage.TypeA); ok {
		fnet.dnsMu.Lock()
		if fnet.dnsCache != nil {
			fnet.dnsCache[cacheKey] = tunnelDnsEntry{
				addrs:     append([]netip.Addr(nil), resA.addrs...),
				expiresAt: time.Now().Add(resA.ttl),
			}
		}
		fnet.dnsMu.Unlock()
		return resA.addrs, nil
	}

	if allowV6 {
		if resAAAA, ok := fnet.queryServersParallel(ctx, usable, dn, dnsmessage.TypeAAAA); ok {
			fnet.dnsMu.Lock()
			if fnet.dnsCache != nil {
				fnet.dnsCache[cacheKey] = tunnelDnsEntry{
					addrs:     append([]netip.Addr(nil), resAAAA.addrs...),
					expiresAt: time.Now().Add(resAAAA.ttl),
				}
			}
			fnet.dnsMu.Unlock()
			return resAAAA.addrs, nil
		}
	}

	return nil, errors.New("tunnel DNS lookup failed")
}

func (fnet *fastNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	matches := fastProtoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	var acceptV4, acceptV6 bool
	if len(matches[2]) == 0 {
		acceptV4 = true
		acceptV6 = !fnet.blockIPv6.Load()
	} else {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4 && !fnet.blockIPv6.Load()
	}
	if !acceptV4 && !acceptV6 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("IPv6 blocked by tunnel policy")}
	}

	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("invalid port")}
	}

	// Fast path for direct IP literals (99.9% of Telegram MTProto and VoIP traffic): zero DNS lookup overhead!
	if directIP, pErr := netip.ParseAddr(host); pErr == nil {
		unmapped := directIP.Unmap()
		if unmapped.Is6() && !acceptV6 {
			return nil, &net.OpError{Op: "dial", Err: errors.New("IPv6 blocked by tunnel policy")}
		}
		if unmapped.Is4() && !acceptV4 {
			return nil, &net.OpError{Op: "dial", Err: errors.New("IPv4 disallowed by network selector")}
		}
		target := netip.AddrPortFrom(unmapped, uint16(port))
		switch matches[1] {
		case "tcp":
			return fnet.DialContextTCPAddrPort(ctx, target)
		case "udp":
			return fnet.DialUDPAddrPort(netip.AddrPort{}, target)
		}
	}

	ips, err := fnet.LookupContextHost(ctx, host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no suitable address found")
		}
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	var firstErr error
	for _, ip := range ips {
		unmapped := ip.Unmap()
		if (unmapped.Is4() && !acceptV4) || (unmapped.Is6() && !acceptV6) {
			continue
		}
		target := netip.AddrPortFrom(unmapped, uint16(port))
		var c net.Conn
		switch matches[1] {
		case "tcp":
			c, err = fnet.DialContextTCPAddrPort(ctx, target)
		case "udp":
			c, err = fnet.DialUDPAddrPort(netip.AddrPort{}, target)
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no reachable address")
	}
	return nil, firstErr
}

func (fnet *fastNet) Dial(network, address string) (net.Conn, error) {
	return fnet.DialContext(context.Background(), network, address)
}
