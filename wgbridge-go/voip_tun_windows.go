//go:build windows

package wgbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	voipTunAdapterName   = "WireGuardPlusCalls"
	voipTunMTU           = 1280
	voipTunRouteMetric   = 5
	voipTunIdleTTL       = 90 * time.Second
	maxVoipTunNatEntries = 64
	voipTunClientLabel   = "voip-tun-win"
	winErrObjExists      = windows.Errno(5010)
)

var voipTunLocalIPv4 = [4]byte{10, 254, 254, 2}

var telegramVoipCIDRStrings = []string{
	"91.108.4.0/22",
	"91.108.8.0/21",
	"91.108.12.0/22",
	"91.108.16.0/22",
	"91.108.20.0/22",
	"91.108.56.0/22",
	"149.154.160.0/20",
	"91.105.192.0/23",
	"185.76.151.0/24",
}

var (
	modVoipIphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitUnicastIpAddrEntry       = modVoipIphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddrEntry     = modVoipIphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddrEntry     = modVoipIphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procGetUnicastIpAddrTable        = modVoipIphlpapi.NewProc("GetUnicastIpAddressTable")
	procInitIpForwardEntry           = modVoipIphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2        = modVoipIphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2        = modVoipIphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetIpForwardTable2           = modVoipIphlpapi.NewProc("GetIpForwardTable2")
	procInitIpInterfaceEntry         = modVoipIphlpapi.NewProc("InitializeIpInterfaceEntry")
	procGetIpInterfaceEntry          = modVoipIphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry          = modVoipIphlpapi.NewProc("SetIpInterfaceEntry")
	procFreeMibTable                 = modVoipIphlpapi.NewProc("FreeMibTable")
)

// ABI-exact mirrors of Windows netioapi.h structs (amd64 / arm64, matching WireGuard winipcfg).
type winRawSockaddrInet struct {
	Family uint16
	Data   [26]byte
}

func (s *winRawSockaddrInet) setIPv4(ip [4]byte) {
	*s = winRawSockaddrInet{}
	addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(s))
	addr4.Family = windows.AF_INET
	addr4.Addr = ip
}

type winIPAddressPrefix struct {
	RawPrefix    winRawSockaddrInet
	PrefixLength uint8
	_            [2]byte
}

func (p *winIPAddressPrefix) setPrefixIPv4(prefix netip.Prefix) error {
	addr := prefix.Addr().Unmap()
	if !addr.Is4() {
		return errors.New("only IPv4 prefix supported")
	}
	p.RawPrefix.setIPv4(addr.As4())
	p.PrefixLength = uint8(prefix.Bits())
	return nil
}

type winMibUnicastIPAddressRow struct {
	Address            winRawSockaddrInet
	InterfaceLUID      uint64
	InterfaceIndex     uint32
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       bool
	DadState           uint32
	ScopeID            uint32
	CreationTimeStamp  int64
}

type winMibUnicastIPAddressTable struct {
	NumEntries uint32
	Table      [1]winMibUnicastIPAddressRow
}

type winMibIPForwardRow2 struct {
	InterfaceLUID        uint64
	InterfaceIndex       uint32
	DestinationPrefix    winIPAddressPrefix
	NextHop              winRawSockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               uint32
}

type winMibIPForwardTable2 struct {
	NumEntries uint32
	Table      [1]winMibIPForwardRow2
}

type winMibIPInterfaceRow struct {
	Family                               uint16
	InterfaceLUID                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	RouterDiscoveryBehavior              int32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMTUDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             int32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NLMTU                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      uint8
	ReceiveOffload                       uint8
	DisableDefaultRoutes                 bool
}

type voipTunNatEntry struct {
	clientIP   [4]byte
	clientPort uint16
	pConn      net.PacketConn
	lastActive atomic.Int64
	closeOnce  sync.Once
}

func (e *voipTunNatEntry) close() {
	e.closeOnce.Do(func() {
		if e.pConn != nil {
			_ = e.pConn.Close()
		}
	})
}

type winVoipTunSession struct {
	tunDev    tun.Device
	dialer    udpDialer
	ctx       context.Context
	cancel    context.CancelFunc
	writeCh   chan []byte
	statEnt   *clientStatEntry
	closed    atomic.Bool
	closeOnce sync.Once
	ipID      atomic.Uint32

	natMu sync.RWMutex
	nat   map[uint16]*voipTunNatEntry
}

var (
	voipTunMu     sync.Mutex
	activeVoipTun *winVoipTunSession
)

// StartWindowsVoipTun creates a scoped Wintun adapter that intercepts only Telegram
// official IPv4 CIDRs and relays UDP call packets (TURN/Reflector/RTP) through the
// active WireGuard tunnel netstack without modifying AyuGram/Telegram Desktop.
func StartWindowsVoipTun(dllDir string) error {
	mu.Lock()
	isUp := running
	parentCtx := activeCtx
	var dialer udpDialer
	if activeTnet != nil {
		dialer = activeTnet
	}
	rawEp := activeResolvedEp
	mu.Unlock()

	if !isUp || parentCtx == nil || dialer == nil {
		var ok bool
		parentCtx, dialer, ok = awaitMuxRouteReady(3 * time.Second)
		if !ok || parentCtx == nil || dialer == nil {
			return errors.New("WireGuard tunnel is not running")
		}
		mu.Lock()
		rawEp = activeResolvedEp
		mu.Unlock()
	}

	StopWindowsVoipTun()

	if trimmedDir := strings.TrimSpace(dllDir); trimmedDir != "" {
		// Pre-load full DLL path so wintun's LoadLibraryEx(LOAD_LIBRARY_SEARCH_APPLICATION_DIR|SYSTEM32)
		// reuses the already-mapped module handle even when exeDir is read-only.
		_, _ = windows.LoadLibrary(filepath.Join(trimmedDir, "wintun.dll"))
		_ = windows.SetDllDirectory(trimmedDir)
	}

	tunDev, err := tun.CreateTUN(voipTunAdapterName, voipTunMTU)
	if err != nil {
		recordVoipTunStartError("CREATE_ERR", err)
		return err
	}

	nativeTun, ok := tunDev.(*tun.NativeTun)
	if !ok {
		_ = tunDev.Close()
		return errors.New("unexpected TUN implementation on Windows")
	}
	luid := nativeTun.LUID()

	epIP := parseEndpointIPAddr(rawEp)
	routes := filterTelegramCidrsForEndpoint(epIP)

	if err := configureVoipTunInterface(luid, routes); err != nil {
		recordVoipTunStartError("CFG_ERR", err)
		_ = tunDev.Close()
		return err
	}

	tunCtx, tunCancel := context.WithCancel(parentCtx)
	sess := &winVoipTunSession{
		tunDev:  tunDev,
		dialer:  dialer,
		ctx:     tunCtx,
		cancel:  tunCancel,
		writeCh: make(chan []byte, 256),
		statEnt: trackClientConnStart(voipTunClientLabel),
		nat:     make(map[uint16]*voipTunNatEntry),
	}

	voipTunMu.Lock()
	activeVoipTun = sess
	voipTunMu.Unlock()

	sess.start()
	RecordDiag(
		"VOIP_TUN",
		"STARTED",
		fmt.Sprintf("adapter=%s routes=%d epExcluded=%v", voipTunAdapterName, len(routes), len(routes) < len(telegramVoipCIDRStrings)),
	)
	return nil
}

// StopWindowsVoipTun tears down the scoped Wintun adapter, routes, and NAT sockets.
func StopWindowsVoipTun() {
	voipTunMu.Lock()
	sess := activeVoipTun
	activeVoipTun = nil
	voipTunMu.Unlock()

	if sess != nil {
		sess.close()
	}
}

// IsWindowsVoipTunActive reports whether the Telegram-only Windows VoIP TUN is running.
func IsWindowsVoipTunActive() bool {
	voipTunMu.Lock()
	sess := activeVoipTun
	voipTunMu.Unlock()
	return sess != nil && !sess.closed.Load() && sess.ctx.Err() == nil
}

func recordVoipTunStartError(code string, err error) {
	if isWindowsAccessDenied(err) {
		RecordDiag("VOIP_TUN", "NO_ADMIN", err.Error())
		return
	}
	RecordDiag("VOIP_TUN", code, err.Error())
}

func isWindowsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "administrator") ||
		strings.Contains(msg, "elevation")
}

func parseEndpointIPAddr(endpoint string) netip.Addr {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return netip.Addr{}
	}
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func filterTelegramCidrsForEndpoint(endpointIP netip.Addr) []netip.Prefix {
	unmapped := endpointIP.Unmap()
	out := make([]netip.Prefix, 0, len(telegramVoipCIDRStrings))
	for _, raw := range telegramVoipCIDRStrings {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		if unmapped.IsValid() && p.Contains(unmapped) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func configureVoipTunInterface(luid uint64, routes []netip.Prefix) error {
	flushVoipTunIPv4(luid)

	// Set interface MTU and low metric so scoped Telegram routes are preferred cleanly.
	var ifRow winMibIPInterfaceRow
	procInitIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&ifRow)))
	ifRow.Family = windows.AF_INET
	ifRow.InterfaceLUID = luid
	if r0, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&ifRow))); r0 == 0 {
		if ifRow.SitePrefixLength > 32 {
			ifRow.SitePrefixLength = 0
		}
		ifRow.UseAutomaticMetric = false
		ifRow.Metric = voipTunRouteMetric
		ifRow.NLMTU = voipTunMTU
		_, _, _ = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&ifRow)))
	}

	// Assign local point-to-point IPv4 address 10.254.254.2/30.
	var addrRow winMibUnicastIPAddressRow
	procInitUnicastIpAddrEntry.Call(uintptr(unsafe.Pointer(&addrRow)))
	addrRow.InterfaceLUID = luid
	addrRow.Address.setIPv4(voipTunLocalIPv4)
	addrRow.OnLinkPrefixLength = 30
	addrRow.DadState = 4 // IpDadStatePreferred
	addrRow.ValidLifetime = 0xffffffff
	addrRow.PreferredLifetime = 0xffffffff
	if r0, _, _ := procCreateUnicastIpAddrEntry.Call(uintptr(unsafe.Pointer(&addrRow))); r0 != 0 {
		err := windows.Errno(r0)
		if err != winErrObjExists {
			return fmt.Errorf("CreateUnicastIpAddressEntry: %w", err)
		}
	}

	// Install on-link IPv4 routes strictly for Telegram official VoIP/DC prefixes.
	for _, p := range routes {
		var rRow winMibIPForwardRow2
		procInitIpForwardEntry.Call(uintptr(unsafe.Pointer(&rRow)))
		rRow.InterfaceLUID = luid
		if err := rRow.DestinationPrefix.setPrefixIPv4(p); err != nil {
			continue
		}
		rRow.NextHop.setIPv4([4]byte{0, 0, 0, 0})
		rRow.Metric = voipTunRouteMetric
		rRow.ValidLifetime = 0xffffffff
		rRow.PreferredLifetime = 0xffffffff
		if r0, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&rRow))); r0 != 0 {
			err := windows.Errno(r0)
			if err != winErrObjExists {
				return fmt.Errorf("CreateIpForwardEntry2(%s): %w", p.String(), err)
			}
		}
	}
	return nil
}

func flushVoipTunIPv4(luid uint64) {
	var addrTab *winMibUnicastIPAddressTable
	if r0, _, _ := procGetUnicastIpAddrTable.Call(uintptr(windows.AF_INET), uintptr(unsafe.Pointer(&addrTab))); r0 == 0 && addrTab != nil {
		rows := unsafe.Slice(&addrTab.Table[0], addrTab.NumEntries)
		for i := range rows {
			if rows[i].InterfaceLUID == luid {
				_, _, _ = procDeleteUnicastIpAddrEntry.Call(uintptr(unsafe.Pointer(&rows[i])))
			}
		}
		procFreeMibTable.Call(uintptr(unsafe.Pointer(addrTab)))
	}

	var fwdTab *winMibIPForwardTable2
	if r0, _, _ := procGetIpForwardTable2.Call(uintptr(windows.AF_INET), uintptr(unsafe.Pointer(&fwdTab))); r0 == 0 && fwdTab != nil {
		rows := unsafe.Slice(&fwdTab.Table[0], fwdTab.NumEntries)
		for i := range rows {
			if rows[i].InterfaceLUID == luid {
				_, _, _ = procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&rows[i])))
			}
		}
		procFreeMibTable.Call(uintptr(unsafe.Pointer(fwdTab)))
	}
}

func (s *winVoipTunSession) start() {
	go func() {
		<-s.ctx.Done()
		voipTunMu.Lock()
		if activeVoipTun == s {
			activeVoipTun = nil
		}
		voipTunMu.Unlock()
		s.close()
	}()
	go s.runWriteLoop()
	go s.runIdleReaper()
	go s.runReadLoop()
}

func (s *winVoipTunSession) close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		if s.tunDev != nil {
			_ = s.tunDev.Close()
		}
		s.natMu.Lock()
		for k, e := range s.nat {
			e.close()
			delete(s.nat, k)
		}
		s.natMu.Unlock()
		trackClientConnEnd(s.statEnt)
		RecordDiag("VOIP_TUN", "STOPPED", "")
	})
}

func (s *winVoipTunSession) runIdleReaper() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		cutoff := time.Now().Add(-voipTunIdleTTL).UnixNano()
		s.natMu.Lock()
		for k, e := range s.nat {
			if e.lastActive.Load() < cutoff {
				e.close()
				delete(s.nat, k)
			}
		}
		s.natMu.Unlock()
	}
}

// runWriteLoop ensures strictly one goroutine ever calls NativeTun.Write (per wireguard/tun requirement).
func (s *winVoipTunSession) runWriteLoop() {
	bufs := make([][]byte, 1)
	for {
		select {
		case <-s.ctx.Done():
			return
		case pkt := <-s.writeCh:
			if len(pkt) == 0 || s.closed.Load() {
				continue
			}
			bufs[0] = pkt
			if _, err := s.tunDev.Write(bufs, 0); err != nil {
				if s.closed.Load() {
					return
				}
			}
		}
	}
}

func (s *winVoipTunSession) enqueueReplyPacket(pkt []byte) {
	if s.closed.Load() || len(pkt) == 0 {
		return
	}
	select {
	case s.writeCh <- pkt:
	case <-s.ctx.Done():
	default:
		// Drop packet rather than blocking NAT read pump on ring saturation.
	}
}

func (s *winVoipTunSession) runReadLoop() {
	buf := make([]byte, 65535)
	bufs := [][]byte{buf}
	sizes := []int{0}

	for {
		n, err := s.tunDev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n <= 0 || sizes[0] <= 0 || sizes[0] > len(buf) {
			continue
		}
		pkt := buf[:sizes[0]]

		srcIP, dstIP, srcPort, dstPort, payload, ok := parseIPv4UDP(pkt)
		if !ok || len(payload) == 0 {
			continue
		}
		if dstIP == ([4]byte{0, 0, 0, 0}) || dstIP == ([4]byte{255, 255, 255, 255}) || (dstIP[0]&0xf0) == 0xe0 {
			continue
		}

		nowNano := time.Now().UnixNano()
		entry, nErr := s.getOrCreateNatEntry(srcIP, dstIP, srcPort, dstPort, nowNano)
		if nErr != nil {
			udpSendErrors.Add(1)
			continue
		}

		dstAddr := &net.UDPAddr{
			IP:   net.IP(dstIP[:]),
			Port: int(dstPort),
		}
		if nw, wErr := entry.pConn.WriteTo(payload, dstAddr); wErr == nil {
			udpPacketsTx.Add(1)
			recordClientTx(s.statEnt, nw)
		} else {
			udpSendErrors.Add(1)
		}
	}
}

func (s *winVoipTunSession) getOrCreateNatEntry(
	clientIP [4]byte,
	dstIP [4]byte,
	srcPort uint16,
	dstPort uint16,
	nowNano int64,
) (*voipTunNatEntry, error) {
	s.natMu.RLock()
	entry, exists := s.nat[srcPort]
	s.natMu.RUnlock()
	if exists {
		entry.lastActive.Store(nowNano)
		return entry, nil
	}

	s.natMu.Lock()
	if entry, exists = s.nat[srcPort]; exists {
		s.natMu.Unlock()
		entry.lastActive.Store(nowNano)
		return entry, nil
	}
	if len(s.nat) >= maxVoipTunNatEntries {
		var oldestPort uint16
		var oldestTs int64 = nowNano
		var hasOldest bool
		for k, cand := range s.nat {
			ts := cand.lastActive.Load()
			if !hasOldest || ts < oldestTs {
				oldestPort = k
				oldestTs = ts
				hasOldest = true
			}
		}
		if hasOldest {
			s.nat[oldestPort].close()
			delete(s.nat, oldestPort)
		}
	}
	s.natMu.Unlock()

	pConn, err := openFullConePacketConn(s.dialer, false)
	if err != nil {
		return nil, err
	}

	newEntry := &voipTunNatEntry{
		clientIP:   clientIP,
		clientPort: srcPort,
		pConn:      pConn,
	}
	newEntry.lastActive.Store(nowNano)

	s.natMu.Lock()
	if s.closed.Load() {
		s.natMu.Unlock()
		newEntry.close()
		return nil, net.ErrClosed
	}
	if cur, raceWon := s.nat[srcPort]; raceWon {
		s.natMu.Unlock()
		newEntry.close()
		cur.lastActive.Store(nowNano)
		return cur, nil
	}
	s.nat[srcPort] = newEntry
	s.natMu.Unlock()

	udpSocketsOpened.Add(1)
	RecordDiag("VOIP_TUN", "NAT_OPEN", fmt.Sprintf("srcPort=%d dst=%d.%d.%d.%d:%d", srcPort, dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort))
	go s.runNatReturnPump(newEntry)
	return newEntry, nil
}

func (s *winVoipTunSession) runNatReturnPump(e *voipTunNatEntry) {
	rBufPtr := udpFrameBufPool.Get().(*[]byte)
	defer udpFrameBufPool.Put(rBufPtr)
	respBuf := *rBufPtr

	for {
		rn, rAddr, err := e.pConn.ReadFrom(respBuf)
		if err != nil {
			return
		}
		if rn <= 0 {
			continue
		}
		udpAddr, ok := rAddr.(*net.UDPAddr)
		if !ok || udpAddr == nil {
			continue
		}
		remoteIP4 := udpAddr.IP.To4()
		if len(remoteIP4) != 4 || udpAddr.Port <= 0 || udpAddr.Port > 65535 {
			continue
		}

		var srcIP4 [4]byte
		copy(srcIP4[:], remoteIP4)
		pkt := make([]byte, 28+rn)
		n, bErr := buildIPv4UDPPacket(pkt, srcIP4, e.clientIP, uint16(udpAddr.Port), e.clientPort, respBuf[:rn], uint16(s.ipID.Add(1)))
		if bErr != nil {
			continue
		}
		e.lastActive.Store(time.Now().UnixNano())
		udpPacketsRx.Add(1)
		recordClientRx(s.statEnt, rn)
		s.enqueueReplyPacket(pkt[:n])
	}
}

func parseIPv4UDP(pkt []byte) (srcIP [4]byte, dstIP [4]byte, srcPort uint16, dstPort uint16, payload []byte, ok bool) {
	if len(pkt) < 28 {
		return srcIP, dstIP, 0, 0, nil, false
	}
	if (pkt[0] >> 4) != 4 {
		return srcIP, dstIP, 0, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return srcIP, dstIP, 0, 0, nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl+8 || totalLen > len(pkt) {
		return srcIP, dstIP, 0, 0, nil, false
	}
	// Ignore fragmented IPv4 packets (More Fragments or non-zero fragment offset).
	if (binary.BigEndian.Uint16(pkt[6:8]) & 0x3fff) != 0 {
		return srcIP, dstIP, 0, 0, nil, false
	}
	if pkt[9] != 17 {
		return srcIP, dstIP, 0, 0, nil, false
	}
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])

	srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if srcPort == 0 || dstPort == 0 || udpLen < 8 || ihl+udpLen > totalLen {
		return srcIP, dstIP, 0, 0, nil, false
	}
	return srcIP, dstIP, srcPort, dstPort, pkt[ihl+8 : ihl+udpLen], true
}

func buildIPv4UDPPacket(
	dstBuf []byte,
	srcIP [4]byte,
	dstIP [4]byte,
	srcPort uint16,
	dstPort uint16,
	payload []byte,
	id uint16,
) (int, error) {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	if totalLen > 65535 || len(dstBuf) < totalLen {
		return 0, errors.New("buffer too small for IPv4+UDP packet")
	}

	// IPv4 Header (20 bytes)
	dstBuf[0] = 0x45
	dstBuf[1] = 0x00
	binary.BigEndian.PutUint16(dstBuf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(dstBuf[4:6], id)
	dstBuf[6] = 0x00
	dstBuf[7] = 0x00
	dstBuf[8] = 64
	dstBuf[9] = 17
	dstBuf[10] = 0
	dstBuf[11] = 0
	copy(dstBuf[12:16], srcIP[:])
	copy(dstBuf[16:20], dstIP[:])
	binary.BigEndian.PutUint16(dstBuf[10:12], internetChecksum(0, dstBuf[:20]))

	// UDP Header (8 bytes) + Payload
	binary.BigEndian.PutUint16(dstBuf[20:22], srcPort)
	binary.BigEndian.PutUint16(dstBuf[22:24], dstPort)
	binary.BigEndian.PutUint16(dstBuf[24:26], uint16(udpLen))
	dstBuf[26] = 0
	dstBuf[27] = 0
	copy(dstBuf[28:totalLen], payload)

	var pseudoAcc uint32
	pseudoAcc += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	pseudoAcc += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	pseudoAcc += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	pseudoAcc += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	pseudoAcc += uint32(17)
	pseudoAcc += uint32(uint16(udpLen))
	udpCS := internetChecksum(pseudoAcc, dstBuf[20:totalLen])
	if udpCS == 0 {
		udpCS = 0xffff
	}
	binary.BigEndian.PutUint16(dstBuf[26:28], udpCS)
	return totalLen, nil
}

func internetChecksum(acc uint32, b []byte) uint16 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		acc += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if i < len(b) {
		acc += uint32(b[i]) << 8
	}
	for (acc >> 16) != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return ^uint16(acc)
}
