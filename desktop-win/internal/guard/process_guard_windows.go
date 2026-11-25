package guard

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"wgplus-win/internal/config"
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
	maxGuardEvents      = 60
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
	modWintrust             = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust      = modWintrust.NewProc("WinVerifyTrust")
	modCrypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam    = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose       = modCrypt32.NewProc("CryptMsgClose")
)

const cmsgSignerInfoParam = 6

type cmsgSignerInfo struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

type mibUdp6RowOwnerPid struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
}

type mibUdp6TableOwnerPid struct {
	NumEntries uint32
	Table      [1]mibUdp6RowOwnerPid
}

type winTrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type winTrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *winTrustFileInfo
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

var winTrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type mibTcpTableOwnerPid struct {
	NumEntries uint32
	Table      [1]mibTcpRowOwnerPid
}

type mibUdpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type mibUdpTableOwnerPid struct {
	NumEntries uint32
	Table      [1]mibUdpRowOwnerPid
}

// GuardEvent records an allowed or blocked loopback connection attempt.
type GuardEvent struct {
	TimestampUnix int64  `json:"timestampUnix"`
	Action        string `json:"action"` // "allow" | "block"
	Protocol      string `json:"protocol"`
	ClientLabel   string `json:"clientLabel"`
	ExePath       string `json:"exePath"`
	PID           uint32 `json:"pid"`
	PeerPort      int    `json:"peerPort"`
}

type cachedProcEntry struct {
	exePath    string
	baseName   string
	createTime uint64
	expiresAt  time.Time
}

// ProcessGuard enforces zero-admin per-process loopback firewall checks on 127.0.0.1.
type ProcessGuard struct {
	mu               sync.RWMutex
	mode             string // "strict" | "log_only"
	selfPid          uint32
	monitoredPorts   map[uint16]bool
	allowedNames     map[string]bool
	allowedPaths     map[string]bool
	verifiedSigPaths map[string]bool
	procCache        map[uint32]cachedProcEntry
	events           []GuardEvent
	blockedCount     atomic.Uint64
	onBlockedFn      func(GuardEvent)
}

var defaultTelegramExeNames = []string{
	"telegram.exe",
	"ayugram.exe",
	"64gram.exe",
	"unigram.exe",
	"forkgram.exe",
	"kotatogram.exe",
	"materialgram.exe",
	"exteragram.exe",
	"cherrygram.exe",
	"ime.exe",
	"nicegram.exe",
}

// NewProcessGuard creates an armored loopback process firewall defaulting to strict allowlist mode.
func NewProcessGuard() *ProcessGuard {
	pg := &ProcessGuard{
		mode:             "strict",
		selfPid:          uint32(os.Getpid()),
		monitoredPorts:   make(map[uint16]bool),
		allowedNames:     make(map[string]bool),
		allowedPaths:     make(map[string]bool),
		verifiedSigPaths: make(map[string]bool),
		procCache:        make(map[uint32]cachedProcEntry),
		events:           make([]GuardEvent, 0, maxGuardEvents),
	}
	for _, n := range defaultTelegramExeNames {
		pg.allowedNames[n] = true
	}
	return pg
}

func (pg *ProcessGuard) SetMode(mode string) {
	pg.mu.Lock()
	if mode == "log_only" {
		pg.mode = "log_only"
	} else {
		pg.mode = "strict"
	}
	pg.mu.Unlock()
}

func (pg *ProcessGuard) SetOnBlocked(fn func(GuardEvent)) {
	pg.mu.Lock()
	pg.onBlockedFn = fn
	pg.mu.Unlock()
}

func (pg *ProcessGuard) SetMonitoredPorts(ports ...int) {
	pg.mu.Lock()
	pg.monitoredPorts = make(map[uint16]bool)
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			pg.monitoredPorts[uint16(p)] = true
		}
	}
	pg.mu.Unlock()
}

// UpdateAllowedClients updates the allowlist from discovered and user-pinned Telegram clients.
func (pg *ProcessGuard) UpdateAllowedClients(clients []config.TelegramClientEntry) {
	names := make(map[string]bool)
	paths := make(map[string]bool)
	for _, n := range defaultTelegramExeNames {
		names[n] = true
	}
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		if p := strings.TrimSpace(c.ExePath); p != "" {
			norm := strings.ToLower(filepath.Clean(p))
			paths[norm] = true
			if base := strings.ToLower(filepath.Base(norm)); base != "" {
				names[base] = true
			}
		}
	}
	pg.mu.Lock()
	pg.allowedNames = names
	pg.allowedPaths = paths
	pg.mu.Unlock()
}

// AllowExecutablePath registers an explicit normalized executable path into the strict allowlist.
func (pg *ProcessGuard) AllowExecutablePath(exePath string) {
	norm := strings.ToLower(filepath.Clean(strings.TrimSpace(exePath)))
	if norm == "" {
		return
	}
	base := strings.ToLower(filepath.Base(norm))
	pg.mu.Lock()
	pg.allowedPaths[norm] = true
	if base != "" {
		pg.allowedNames[base] = true
	}
	pg.mu.Unlock()
}

// AllowExecutableForTest adds an explicit binary path/name during automated tests.
func (pg *ProcessGuard) AllowExecutableForTest(exePath string) {
	pg.AllowExecutablePath(exePath)
}

func (pg *ProcessGuard) Events() []GuardEvent {
	pg.mu.RLock()
	out := make([]GuardEvent, len(pg.events))
	copy(out, pg.events)
	pg.mu.RUnlock()
	return out
}

func (pg *ProcessGuard) BlockedCount() uint64 {
	return pg.blockedCount.Load()
}

func (pg *ProcessGuard) recordEvent(ev GuardEvent) {
	pg.mu.Lock()
	if len(pg.events) >= maxGuardEvents {
		copy(pg.events, pg.events[1:])
		pg.events[len(pg.events)-1] = ev
	} else {
		pg.events = append(pg.events, ev)
	}
	cb := pg.onBlockedFn
	pg.mu.Unlock()

	if ev.Action == "block" {
		pg.blockedCount.Add(1)
		if cb != nil {
			cb(ev)
		}
	}
}

func decodeNetPort(raw uint32) uint16 {
	return uint16(((raw & 0xff) << 8) | ((raw >> 8) & 0xff))
}

func isLoopbackIPv4Raw(raw uint32) bool {
	b := *(*[4]byte)(unsafe.Pointer(&raw))
	return b[0] == 127
}

func (pg *ProcessGuard) ResolveTcpPeerPid(peerPort uint16) (uint32, error) {
	pg.mu.RLock()
	monPorts := pg.monitoredPorts
	pg.mu.RUnlock()

	var size uint32 = 32 * 1024
	var buf []byte
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		r1, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			windows.AF_INET,
			tcpTableOwnerPidAll,
			0,
		)
		if r1 == 0 {
			break
		}
		if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return 0, fmt.Errorf("GetExtendedTcpTable failed with code %d", r1)
		}
		size += 8192
	}
	if len(buf) < 4 {
		return 0, fmt.Errorf("short TCP table buffer")
	}

	tbl := (*mibTcpTableOwnerPid)(unsafe.Pointer(&buf[0]))
	rowCount := int(tbl.NumEntries)
	rows := unsafe.Slice(&tbl.Table[0], rowCount)

	var fallbackPid uint32
	for i := 0; i < rowCount; i++ {
		row := rows[i]
		if !isLoopbackIPv4Raw(row.LocalAddr) {
			continue
		}
		lPort := decodeNetPort(row.LocalPort)
		if lPort != peerPort {
			continue
		}
		rPort := decodeNetPort(row.RemotePort)
		if len(monPorts) > 0 {
			if monPorts[rPort] {
				return row.OwningPid, nil
			}
		} else if rPort != 0 && row.OwningPid != 0 {
			fallbackPid = row.OwningPid
			break
		}
	}
	if fallbackPid != 0 {
		return fallbackPid, nil
	}
	return 0, fmt.Errorf("no matching TCP owner for loopback port %d", peerPort)
}

func isLoopbackOrWildcardIPv4Raw(raw uint32) bool {
	b := *(*[4]byte)(unsafe.Pointer(&raw))
	return b[0] == 127 || (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0)
}

func isLoopbackOrWildcardIPv6Raw(addr [16]byte) bool {
	allZero := true
	for _, v := range addr {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}
	// ::1
	for i := 0; i < 15; i++ {
		if addr[i] != 0 {
			return false
		}
	}
	return addr[15] == 1
}

func queryUdpTable(af uint32) ([]byte, error) {
	var size uint32 = 16 * 1024
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		r1, _, _ := procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(af),
			udpTableOwnerPid,
			0,
		)
		if r1 == 0 {
			return buf, nil
		}
		if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("GetExtendedUdpTable(af=%d) failed with code %d", af, r1)
		}
		size += 8192
	}
	return nil, fmt.Errorf("GetExtendedUdpTable(af=%d) insufficient buffer", af)
}

func (pg *ProcessGuard) ResolveUdpPeerPid(peerPort uint16) (uint32, error) {
	var fallbackPid uint32

	// Query IPv4 UDP table first, preferring loopback (127.x.x.x) or wildcard (0.0.0.0) sockets.
	if buf, err := queryUdpTable(windows.AF_INET); err == nil && len(buf) >= 4 {
		tbl := (*mibUdpTableOwnerPid)(unsafe.Pointer(&buf[0]))
		rowCount := int(tbl.NumEntries)
		rows := unsafe.Slice(&tbl.Table[0], rowCount)
		for i := 0; i < rowCount; i++ {
			row := rows[i]
			if row.OwningPid == 0 || decodeNetPort(row.LocalPort) != peerPort {
				continue
			}
			if isLoopbackOrWildcardIPv4Raw(row.LocalAddr) {
				return row.OwningPid, nil
			}
			if fallbackPid == 0 {
				fallbackPid = row.OwningPid
			}
		}
	}

	// Query IPv6 UDP table as well: Windows libwebrtc/tgcalls commonly binds dual-stack AF_INET6
	// sockets (:: or ::1) to talk to 127.0.0.1 via ::ffff:127.0.0.1.
	if buf6, err := queryUdpTable(windows.AF_INET6); err == nil && len(buf6) >= 4 {
		tbl6 := (*mibUdp6TableOwnerPid)(unsafe.Pointer(&buf6[0]))
		rowCount6 := int(tbl6.NumEntries)
		rows6 := unsafe.Slice(&tbl6.Table[0], rowCount6)
		for i := 0; i < rowCount6; i++ {
			row := rows6[i]
			if row.OwningPid == 0 || decodeNetPort(row.LocalPort) != peerPort {
				continue
			}
			if isLoopbackOrWildcardIPv6Raw(row.LocalAddr) {
				return row.OwningPid, nil
			}
			if fallbackPid == 0 {
				fallbackPid = row.OwningPid
			}
		}
	}

	if fallbackPid != 0 {
		return fallbackPid, nil
	}
	return 0, fmt.Errorf("no matching IPv4/IPv6 UDP owner for port %d", peerPort)
}

func verifyAuthenticodeFile(exePath string) bool {
	if strings.TrimSpace(exePath) == "" {
		return false
	}
	if err := procWinVerifyTrust.Find(); err != nil {
		return false
	}
	pathPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return false
	}
	fi := winTrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(winTrustFileInfo{})),
		pcwszFilePath: pathPtr,
	}
	td := winTrustData{
		cbStruct:            uint32(unsafe.Sizeof(winTrustData{})),
		dwUIChoice:          2, // WTD_UI_NONE
		fdwRevocationChecks: 0, // WTD_REVOKE_NONE
		dwUnionChoice:       1, // WTD_CHOICE_FILE
		pFile:               &fi,
		dwStateAction:       1,      // WTD_STATEACTION_VERIFY
		dwProvFlags:         0x1000, // WTD_CACHE_ONLY_URL_RETRIEVAL
	}
	r1, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&td)),
	)
	td.dwStateAction = 2 // WTD_STATEACTION_CLOSE
	_, _, _ = procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&td)),
	)
	if r1 != 0 {
		return false
	}
	signer, ok := extractAuthenticodeSignerName(exePath)
	if !ok {
		return false
	}
	normPath := strings.ToLower(filepath.Clean(strings.TrimSpace(exePath)))
	return isTrustedTelegramPublisher(signer, normPath)
}

func extractAuthenticodeSignerName(exePath string) (string, bool) {
	if err := procCryptMsgGetParam.Find(); err != nil {
		return "", false
	}
	pathPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return "", false
	}
	var encType, contentType, formatType uint32
	var hStore, hMsg windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(pathPtr),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encType,
		&contentType,
		&formatType,
		&hStore,
		&hMsg,
		nil,
	)
	if err != nil || hStore == 0 || hMsg == 0 {
		if hStore != 0 {
			_ = windows.CertCloseStore(hStore, 0)
		}
		if hMsg != 0 {
			_, _, _ = procCryptMsgClose.Call(uintptr(hMsg))
		}
		return "", false
	}
	defer func() {
		_ = windows.CertCloseStore(hStore, 0)
		_, _, _ = procCryptMsgClose.Call(uintptr(hMsg))
	}()

	var size uint32
	r1, _, _ := procCryptMsgGetParam.Call(
		uintptr(hMsg),
		cmsgSignerInfoParam,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 || size < uint32(unsafe.Sizeof(cmsgSignerInfo{})) || size > 65536 {
		return "", false
	}
	buf := make([]byte, size)
	r1, _, _ = procCryptMsgGetParam.Call(
		uintptr(hMsg),
		cmsgSignerInfoParam,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		return "", false
	}

	si := (*cmsgSignerInfo)(unsafe.Pointer(&buf[0]))
	var certInfo windows.CertInfo
	certInfo.Issuer = si.Issuer
	certInfo.SerialNumber = si.SerialNumber
	certCtx, err := windows.CertFindCertificateInStore(
		hStore,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(&certInfo),
		nil,
	)
	runtime.KeepAlive(buf)
	if err != nil || certCtx == nil {
		return "", false
	}
	defer func() { _ = windows.CertFreeCertificateContext(certCtx) }()

	var nameBuf [256]uint16
	n := windows.CertGetNameString(
		certCtx,
		windows.CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		nil,
		&nameBuf[0],
		uint32(len(nameBuf)),
	)
	if n <= 1 {
		return "", false
	}
	name := strings.TrimSpace(windows.UTF16ToString(nameBuf[:n-1]))
	return name, name != ""
}

func isTrustedTelegramPublisher(signerName, normPath string) bool {
	low := strings.ToLower(strings.TrimSpace(signerName))
	if low == "" {
		return false
	}
	if strings.Contains(low, "telegram") ||
		strings.Contains(low, "ayugram") ||
		strings.Contains(low, "kotatogram") ||
		strings.Contains(low, "64gram") ||
		strings.Contains(low, "forkgram") ||
		strings.Contains(low, "materialgram") ||
		strings.Contains(low, "exteragram") ||
		strings.Contains(low, "cherrygram") ||
		strings.Contains(low, "nicegram") ||
		strings.Contains(low, "unigram") {
		return true
	}
	if strings.Contains(normPath, `\windowsapps\`) &&
		(strings.Contains(low, "38833ff26ba1d") || strings.Contains(low, "microsoft corporation")) {
		return true
	}
	return false
}

func (pg *ProcessGuard) verifyAuthenticodeCached(exePath, normPath string) bool {
	pg.mu.RLock()
	cached, ok := pg.verifiedSigPaths[normPath]
	pg.mu.RUnlock()
	if ok {
		return cached
	}
	valid := verifyAuthenticodeFile(exePath)
	pg.mu.Lock()
	pg.verifiedSigPaths[normPath] = valid
	if valid {
		pg.allowedPaths[normPath] = true
	}
	pg.mu.Unlock()
	return valid
}

func (pg *ProcessGuard) lookupProcessInfo(pid uint32) (exePath string, baseName string) {
	if pid == 0 {
		return "", "system"
	}
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Sprintf("pid:%d", pid)
	}
	defer windows.CloseHandle(hProc)

	var ct, et, kt, ut windows.Filetime
	var createVal uint64
	if tErr := windows.GetProcessTimes(hProc, &ct, &et, &kt, &ut); tErr == nil {
		createVal = (uint64(ct.HighDateTime) << 32) | uint64(ct.LowDateTime)
	}

	now := time.Now()
	pg.mu.RLock()
	ent, ok := pg.procCache[pid]
	pg.mu.RUnlock()
	if ok && now.Before(ent.expiresAt) && (createVal == 0 || ent.createTime == createVal) {
		return ent.exePath, ent.baseName
	}

	var pathBuf [windows.MAX_PATH * 2]uint16
	n := uint32(len(pathBuf))
	if qErr := windows.QueryFullProcessImageName(hProc, 0, &pathBuf[0], &n); qErr == nil && n > 0 {
		exePath = windows.UTF16ToString(pathBuf[:n])
		baseName = filepath.Base(exePath)
	} else {
		baseName = fmt.Sprintf("pid:%d", pid)
	}

	pg.mu.Lock()
	pg.procCache[pid] = cachedProcEntry{
		exePath:    exePath,
		baseName:   baseName,
		createTime: createVal,
		expiresAt:  now.Add(1500 * time.Millisecond),
	}
	pg.mu.Unlock()
	return exePath, baseName
}

func (pg *ProcessGuard) isAllowedProcess(pid uint32, exePath, baseName string) bool {
	if pid == pg.selfPid {
		return true
	}
	pg.mu.RLock()
	mode := pg.mode
	normPath := strings.ToLower(filepath.Clean(strings.TrimSpace(exePath)))
	pathAllowed := normPath != "" && pg.allowedPaths[normPath]
	lowBase := strings.ToLower(strings.TrimSpace(baseName))
	nameAllowed := lowBase != "" && pg.allowedNames[lowBase]
	pg.mu.RUnlock()

	if mode == "log_only" {
		return true
	}
	if pathAllowed {
		return true
	}
	// Never trust an arbitrary exe matching a Telegram filename (e.g. %TEMP%\telegram.exe)
	// unless it passes Windows Authenticode signature verification.
	if nameAllowed && normPath != "" && pg.verifyAuthenticodeCached(exePath, normPath) {
		return true
	}
	return false
}

// ClientLabelForExe returns a stable per-instance label distinguishing multiple
// portable Telegram binaries by hashing their cleaned executable path.
func ClientLabelForExe(exePath, baseName string) string {
	trimmed := strings.TrimSpace(exePath)
	if trimmed != "" {
		clean := strings.ToLower(filepath.Clean(trimmed))
		base := strings.ToLower(strings.TrimSpace(filepath.Base(clean)))
		if base == "" || base == "." {
			base = strings.ToLower(strings.TrimSpace(baseName))
		}
		if base != "" {
			h := fnv.New32a()
			_, _ = h.Write([]byte(clean))
			return fmt.Sprintf("%s#%08x", base, h.Sum32())
		}
	}
	return strings.ToLower(strings.TrimSpace(baseName))
}

// CheckTcpClient inspects an incoming loopback TCP peer (for SOCKS5 / HTTP CONNECT)
// and returns a client label and whether it is allowed to use the tunnel.
func (pg *ProcessGuard) CheckTcpClient(remoteAddr net.Addr) (string, bool) {
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok || tcpAddr == nil || !tcpAddr.IP.IsLoopback() {
		return "non-loopback", false
	}

	pid, err := pg.ResolveTcpPeerPid(uint16(tcpAddr.Port))
	if err != nil {
		pg.mu.RLock()
		isLogOnly := pg.mode == "log_only"
		pg.mu.RUnlock()
		ev := GuardEvent{
			TimestampUnix: time.Now().Unix(),
			Action:        "block",
			Protocol:      "TCP",
			ClientLabel:   "unknown",
			PeerPort:      tcpAddr.Port,
		}
		if isLogOnly {
			ev.Action = "allow"
			pg.recordEvent(ev)
			return "unknown", true
		}
		pg.recordEvent(ev)
		return "unknown", false
	}

	exePath, baseName := pg.lookupProcessInfo(pid)
	label := ClientLabelForExe(exePath, baseName)
	if pid == pg.selfPid {
		label = "WireGuardPlus-Probe"
	}

	allowed := pg.isAllowedProcess(pid, exePath, baseName)
	action := "allow"
	if !allowed {
		action = "block"
	}
	pg.recordEvent(GuardEvent{
		TimestampUnix: time.Now().Unix(),
		Action:        action,
		Protocol:      "TCP",
		ClientLabel:   label,
		ExePath:       exePath,
		PID:           pid,
		PeerPort:      tcpAddr.Port,
	})
	return label, allowed
}

// CheckUdpPeer verifies that loopback UDP frames arriving on a SOCKS5 UDP relay socket
// originate from an allowed process (and match the owning TCP control client when known).
func (pg *ProcessGuard) CheckUdpPeer(remoteAddr *net.UDPAddr, expectedLabel string) bool {
	if remoteAddr == nil || !remoteAddr.IP.IsLoopback() {
		return false
	}
	pid, err := pg.ResolveUdpPeerPid(uint16(remoteAddr.Port))
	if err != nil {
		pg.mu.RLock()
		isLogOnly := pg.mode == "log_only"
		pg.mu.RUnlock()
		if !isLogOnly {
			pg.recordEvent(GuardEvent{
				TimestampUnix: time.Now().Unix(),
				Action:        "block",
				Protocol:      "UDP",
				ClientLabel:   "unknown-udp",
				PID:           0,
				PeerPort:      remoteAddr.Port,
			})
		}
		return isLogOnly
	}
	exePath, baseName := pg.lookupProcessInfo(pid)
	if !pg.isAllowedProcess(pid, exePath, baseName) {
		pg.recordEvent(GuardEvent{
			TimestampUnix: time.Now().Unix(),
			Action:        "block",
			Protocol:      "UDP",
			ClientLabel:   baseName,
			ExePath:       exePath,
			PID:           pid,
			PeerPort:      remoteAddr.Port,
		})
		return false
	}
	if pid != pg.selfPid && expectedLabel != "" && expectedLabel != "local-client" && expectedLabel != "unknown" {
		instLabel := ClientLabelForExe(exePath, baseName)
		if !strings.EqualFold(instLabel, expectedLabel) && !strings.EqualFold(baseName, expectedLabel) {
			pg.recordEvent(GuardEvent{
				TimestampUnix: time.Now().Unix(),
				Action:        "block",
				Protocol:      "UDP",
				ClientLabel:   instLabel,
				ExePath:       exePath,
				PID:           pid,
				PeerPort:      remoteAddr.Port,
			})
			return false
		}
	}
	return true
}
