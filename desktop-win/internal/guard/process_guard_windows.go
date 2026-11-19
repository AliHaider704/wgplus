package guard

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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
)

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
	mu             sync.RWMutex
	mode           string // "strict" | "log_only"
	selfPid        uint32
	monitoredPorts map[uint16]bool
	allowedNames   map[string]bool
	allowedPaths   map[string]bool
	procCache      map[uint32]cachedProcEntry
	events         []GuardEvent
	blockedCount   atomic.Uint64
	onBlockedFn    func(GuardEvent)
}

var defaultTelegramExeNames = []string{
	"telegram.exe",
	"ayugram.exe",
	"64gram.exe",
	"unigram.exe",
	"forkgram.exe",
}

// NewProcessGuard creates an armored loopback process firewall defaulting to strict allowlist mode.
func NewProcessGuard() *ProcessGuard {
	pg := &ProcessGuard{
		mode:           "strict",
		selfPid:        uint32(os.Getpid()),
		monitoredPorts: make(map[uint16]bool),
		allowedNames:   make(map[string]bool),
		allowedPaths:   make(map[string]bool),
		procCache:      make(map[uint32]cachedProcEntry),
		events:         make([]GuardEvent, 0, maxGuardEvents),
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

// AllowExecutableForTest adds an explicit binary path/name during automated tests.
func (pg *ProcessGuard) AllowExecutableForTest(exePath string) {
	norm := strings.ToLower(filepath.Clean(exePath))
	base := strings.ToLower(filepath.Base(norm))
	pg.mu.Lock()
	pg.allowedPaths[norm] = true
	if base != "" {
		pg.allowedNames[base] = true
	}
	pg.mu.Unlock()
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

func (pg *ProcessGuard) ResolveUdpPeerPid(peerPort uint16) (uint32, error) {
	var size uint32 = 16 * 1024
	var buf []byte
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		r1, _, _ := procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			windows.AF_INET,
			udpTableOwnerPid,
			0,
		)
		if r1 == 0 {
			break
		}
		if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return 0, fmt.Errorf("GetExtendedUdpTable failed with code %d", r1)
		}
		size += 4096
	}
	if len(buf) < 4 {
		return 0, fmt.Errorf("short UDP table buffer")
	}

	tbl := (*mibUdpTableOwnerPid)(unsafe.Pointer(&buf[0]))
	rowCount := int(tbl.NumEntries)
	rows := unsafe.Slice(&tbl.Table[0], rowCount)
	for i := 0; i < rowCount; i++ {
		row := rows[i]
		if decodeNetPort(row.LocalPort) == peerPort && row.OwningPid != 0 {
			return row.OwningPid, nil
		}
	}
	return 0, fmt.Errorf("no matching UDP owner for port %d", peerPort)
}

func (pg *ProcessGuard) lookupProcessInfo(pid uint32) (exePath string, baseName string) {
	if pid == 0 {
		return "", "system"
	}
	now := time.Now()
	pg.mu.RLock()
	ent, ok := pg.procCache[pid]
	pg.mu.RUnlock()
	if ok && now.Before(ent.expiresAt) {
		return ent.exePath, ent.baseName
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Sprintf("pid:%d", pid)
	}
	defer windows.CloseHandle(hProc)

	var pathBuf [windows.MAX_PATH * 2]uint16
	n := uint32(len(pathBuf))
	if qErr := windows.QueryFullProcessImageName(hProc, 0, &pathBuf[0], &n); qErr == nil && n > 0 {
		exePath = windows.UTF16ToString(pathBuf[:n])
		baseName = filepath.Base(exePath)
	} else {
		baseName = fmt.Sprintf("pid:%d", pid)
	}

	var ct, et, kt, ut windows.Filetime
	var createVal uint64
	if tErr := windows.GetProcessTimes(hProc, &ct, &et, &kt, &ut); tErr == nil {
		createVal = (uint64(ct.HighDateTime) << 32) | uint64(ct.LowDateTime)
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
	defer pg.mu.RUnlock()

	if pg.mode == "log_only" {
		return true
	}
	normPath := strings.ToLower(filepath.Clean(exePath))
	if normPath != "" && pg.allowedPaths[normPath] {
		return true
	}
	lowBase := strings.ToLower(strings.TrimSpace(baseName))
	return lowBase != "" && pg.allowedNames[lowBase]
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
	label := baseName
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
		if !strings.EqualFold(baseName, expectedLabel) {
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
	}
	return true
}
