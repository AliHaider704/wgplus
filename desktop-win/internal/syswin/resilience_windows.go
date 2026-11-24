package syswin

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

var (
	netCallbackOnce    sync.Once
	netCallbackPtr     uintptr
	netWatchMu         sync.Mutex
	activeHostPtr      *Host
	debounceTimer      *time.Timer
	lastNetFingerprint string
)

// getOutboundIPv4Fingerprint returns a deterministic snapshot of the active outbound
// IPv4 route and UP non-loopback IPv4 interfaces so noisy virtual/IPv6 link events are ignored.
func getOutboundIPv4Fingerprint() string {
	outIP := "none"
	if conn, err := net.Dial("udp4", "1.1.1.1:80"); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua != nil && ua.IP != nil {
			if v4 := ua.IP.To4(); v4 != nil {
				outIP = v4.String()
			}
		}
		_ = conn.Close()
	}

	var entries []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
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
				entries = append(entries, iface.Name+"="+v4.String())
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

// RelaunchElevated prompts Windows UAC to start a fresh Administrator instance of this app.
func RelaunchElevated() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exePtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}
	dirPtr, err := windows.UTF16PtrFromString(filepath.Dir(exePath))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verbPtr, exePtr, nil, dirPtr, windows.SW_SHOWNORMAL)
}
