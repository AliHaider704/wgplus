package syswin

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapi.NewProc("CancelMibChangeNotify2")

	modResilienceKernel32     = windows.NewLazySystemDLL("kernel32.dll")
	procSetProcessInformation = modResilienceKernel32.NewProc("SetProcessInformation")
	procSetPriorityClass      = modResilienceKernel32.NewProc("SetPriorityClass")
)

const (
	processPowerThrottling             = 4
	processPowerThrottlingVersion      = 1
	powerThrottlingExecSpeed           = 0x1
	powerThrottlingIgnoreTimerRes      = 0x4
	aboveNormalPriorityClass     uint32 = 0x00008000
)

type processPowerThrottlingState struct {
	Version     uint32
	ControlMask uint32
	StateMask   uint32
}

// DisableProcessPowerThrottling opts the background tunnel process out of Windows 11 EcoQoS
// efficiency-core pinning and timer coalescing so WireGuard keepalives stay sub-millisecond.
func DisableProcessPowerThrottling() {
	hProc := windows.CurrentProcess()
	if err := procSetProcessInformation.Find(); err == nil {
		// Disable both EXECUTION_SPEED and IGNORE_TIMER_RESOLUTION (Win11 22H2+); fall back to EXEC_SPEED on older builds.
		st := processPowerThrottlingState{
			Version:     processPowerThrottlingVersion,
			ControlMask: powerThrottlingExecSpeed | powerThrottlingIgnoreTimerRes,
			StateMask:   0,
		}
		r1, _, _ := procSetProcessInformation.Call(
			uintptr(hProc),
			uintptr(processPowerThrottling),
			uintptr(unsafe.Pointer(&st)),
			unsafe.Sizeof(st),
		)
		if r1 == 0 {
			st.ControlMask = powerThrottlingExecSpeed
			_, _, _ = procSetProcessInformation.Call(
				uintptr(hProc),
				uintptr(processPowerThrottling),
				uintptr(unsafe.Pointer(&st)),
				unsafe.Sizeof(st),
			)
		}
	}
	if err := procSetPriorityClass.Find(); err == nil {
		_, _, _ = procSetPriorityClass.Call(uintptr(hProc), uintptr(aboveNormalPriorityClass))
	}
}

var (
	netCallbackOnce    sync.Once
	netCallbackPtr     uintptr
	netWatchMu         sync.Mutex
	activeHostPtr      *Host
	debounceTimer      *time.Timer
	lastNetFingerprint string
)

func isIsolatedVirtualAdapter(name string) bool {
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

func isOuterVpnAdapter(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" || strings.Contains(low, "wireguardpluscalls") {
		return false
	}
	for _, tok := range []string{
		"wireguard",
		"wintun",
		"radmin",
		"tailscale",
		"zerotier",
		"nordlynx",
		"proton",
		"openvpn",
		"tap-windows",
		"tun",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func detectOutboundIPv4AndInterface() (net.IP, int, bool) {
	conn, err := net.Dial("udp4", "1.1.1.1:80")
	if err != nil {
		return nil, 0, false
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return nil, 0, false
	}
	v4 := ua.IP.To4()
	if v4 == nil || v4.IsLoopback() || v4.IsUnspecified() {
		return nil, 0, false
	}
	if ifaces, iErr := net.Interfaces(); iErr == nil {
		for _, iface := range ifaces {
			addrs, aErr := iface.Addrs()
			if aErr != nil {
				continue
			}
			for _, addr := range addrs {
				ipNet, okAddr := addr.(*net.IPNet)
				if okAddr && ipNet != nil && ipNet.IP != nil && ipNet.IP.Equal(v4) {
					if isIsolatedVirtualAdapter(iface.Name) {
						return nil, 0, false
					}
					return v4, iface.MTU, isOuterVpnAdapter(iface.Name)
				}
			}
		}
	}
	return v4, 0, false
}

func detectOutboundIPv4() net.IP {
	v4, _, _ := detectOutboundIPv4AndInterface()
	return v4
}

// DetectOutboundLinkMTU returns the active physical/VPN outbound interface MTU and whether another VPN is active.
func DetectOutboundLinkMTU() (int, bool) {
	_, mtu, outerVpn := detectOutboundIPv4AndInterface()
	return mtu, outerVpn
}

// HasOutboundIPv4 reports whether the host currently has an active non-loopback IPv4 default route.
func HasOutboundIPv4() bool {
	return detectOutboundIPv4() != nil
}

func shouldIncludeInterfaceInFingerprint(name string, flags net.Flags) bool {
	if flags&net.FlagUp == 0 || flags&net.FlagLoopback != 0 {
		return false
	}
	return !isIsolatedVirtualAdapter(name)
}

// getOutboundIPv4Fingerprint returns a deterministic snapshot of the active outbound
// IPv4 route and UP non-loopback IPv4 interfaces so noisy virtual/IPv6/Wintun link events are ignored.
func getOutboundIPv4Fingerprint() string {
	outIP := "none"
	if v4 := detectOutboundIPv4(); v4 != nil {
		outIP = v4.String()
	}

	var entries []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if !shouldIncludeInterfaceInFingerprint(iface.Name, iface.Flags) {
				continue
			}
			addrs, aErr := iface.Addrs()
			if aErr != nil {
				continue
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok || ipNet == nil || ipNet.IP == nil {
					continue
				}
				v4 := ipNet.IP.To4()
				if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
					continue
				}
				entries = append(entries, fmt.Sprintf("%s=%s/%d", iface.Name, v4.String(), iface.MTU))
			}
		}
	}
	sort.Strings(entries)
	if len(entries) == 0 {
		return "out=" + outIP + "|ifaces=none"
	}
	return "out=" + outIP + "|ifaces=" + strings.Join(entries, ",")
}

func getIpChangeCallback() uintptr {
	netCallbackOnce.Do(func() {
		netCallbackPtr = windows.NewCallback(func(_ uintptr, _ uintptr, _ uint32) uintptr {
			netWatchMu.Lock()
			host := activeHostPtr
			if host != nil && host.callbacks.OnNetworkChange != nil {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(1500*time.Millisecond, func() {
					fp := getOutboundIPv4Fingerprint()
					netWatchMu.Lock()
					if fp != "" && fp == lastNetFingerprint {
						netWatchMu.Unlock()
						return
					}
					if fp != "" {
						lastNetFingerprint = fp
					}
					hNow := activeHostPtr
					var cbNow func()
					if hNow != nil {
						cbNow = hNow.callbacks.OnNetworkChange
					}
					netWatchMu.Unlock()
					if cbNow != nil {
						cbNow()
					}
				})
			}
			netWatchMu.Unlock()
			return 0
		})
	})
	return netCallbackPtr
}

func (h *Host) startNetworkWatcher() error {
	initFp := getOutboundIPv4Fingerprint()
	netWatchMu.Lock()
	activeHostPtr = h
	lastNetFingerprint = initFp
	netWatchMu.Unlock()

	var handle windows.Handle
	r1, _, _ := procNotifyIpInterfaceChange.Call(
		windows.AF_INET,
		getIpChangeCallback(),
		0,
		0, // InitialNotification = false
		uintptr(unsafe.Pointer(&handle)),
	)
	if r1 != 0 {
		return fmt.Errorf("NotifyIpInterfaceChange failed with code %d", r1)
	}
	h.mu.Lock()
	h.netHandle = handle
	h.mu.Unlock()
	return nil
}

func (h *Host) stopNetworkWatcher() {
	netWatchMu.Lock()
	if activeHostPtr == h {
		activeHostPtr = nil
		lastNetFingerprint = ""
	}
	if debounceTimer != nil {
		debounceTimer.Stop()
		debounceTimer = nil
	}
	netWatchMu.Unlock()

	h.mu.Lock()
	handle := h.netHandle
	h.netHandle = 0
	h.mu.Unlock()

	if handle != 0 {
		procCancelMibChangeNotify2.Call(uintptr(handle))
	}
}

// WaitForProcessExit waits for pid to terminate (plus a short settle delay) so single-instance
// locks and child WebView2 handles are fully released before launching the replacement window.
func WaitForProcessExit(pid uint32, maxWait time.Duration) {
	if pid == 0 || pid == uint32(os.Getpid()) {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err == nil {
		waitMs := uint32(maxWait.Milliseconds())
		if waitMs == 0 {
			waitMs = 5000
		}
		_, _ = windows.WaitForSingleObject(h, waitMs)
		_ = windows.CloseHandle(h)
	}
	time.Sleep(180 * time.Millisecond)
}

func quoteWinArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, syscall.EscapeArg(a))
	}
	return strings.Join(quoted, " ")
}

// RelaunchElevatedTargetWithArgs prompts Windows UAC to start targetExe elevated, passing --wait-pid
// when waitPid > 0 followed by extraArgs.
func RelaunchElevatedTargetWithArgs(targetExe string, waitPid int, extraArgs ...string) error {
	exePath := strings.TrimSpace(targetExe)
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return err
		}
	}
	args := make([]string, 0, len(extraArgs)+2)
	if waitPid > 0 {
		args = append(args, "--wait-pid", strconv.Itoa(waitPid))
	}
	args = append(args, extraArgs...)

	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exePtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}
	var argsPtr *uint16
	if argStr := quoteWinArgs(args); argStr != "" {
		argsPtr, err = windows.UTF16PtrFromString(argStr)
		if err != nil {
			return err
		}
	}
	dirPtr, err := windows.UTF16PtrFromString(filepath.Dir(exePath))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verbPtr, exePtr, argsPtr, dirPtr, windows.SW_SHOWNORMAL)
}

// RelaunchElevatedWithArgs prompts Windows UAC to start a fresh elevated instance of the current executable.
func RelaunchElevatedWithArgs(waitPid int, extraArgs ...string) error {
	return RelaunchElevatedTargetWithArgs("", waitPid, extraArgs...)
}

// RelaunchElevated prompts Windows UAC to start a fresh Administrator instance of this app.
func RelaunchElevated() error {
	return RelaunchElevatedWithArgs(os.Getpid())
}

// SpawnProcessDetached starts exePath cleanly (elevated if wantElevated and not already elevated),
// forwarding --wait-pid so the new process waits for waitPid to release its single-instance lock.
func SpawnProcessDetached(exePath string, wantElevated bool, waitPid int, extraArgs ...string) error {
	cleanExe := strings.TrimSpace(exePath)
	if cleanExe == "" {
		var err error
		cleanExe, err = os.Executable()
		if err != nil {
			return err
		}
	}
	if wantElevated && !windows.GetCurrentProcessToken().IsElevated() {
		return RelaunchElevatedTargetWithArgs(cleanExe, waitPid, extraArgs...)
	}
	args := make([]string, 0, len(extraArgs)+2)
	if waitPid > 0 {
		args = append(args, "--wait-pid", strconv.Itoa(waitPid))
	}
	args = append(args, extraArgs...)
	cmd := exec.Command(cleanExe, args...)
	cmd.Dir = filepath.Dir(cleanExe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	return cmd.Start()
}
