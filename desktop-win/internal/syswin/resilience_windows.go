package syswin

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2 = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

var (
	netCallbackOnce sync.Once
	netCallbackPtr  uintptr
	netWatchMu      sync.Mutex
	activeHostPtr   *Host
	debounceTimer   *time.Timer
)

func getIpChangeCallback() uintptr {
	netCallbackOnce.Do(func() {
		netCallbackPtr = windows.NewCallback(func(_ uintptr, _ uintptr, _ uint32) uintptr {
			netWatchMu.Lock()
			host := activeHostPtr
			if host != nil && host.callbacks.OnNetworkChange != nil {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				cb := host.callbacks.OnNetworkChange
				debounceTimer = time.AfterFunc(450*time.Millisecond, func() {
					cb()
				})
			}
			netWatchMu.Unlock()
			return 0
		})
	})
	return netCallbackPtr
}

func (h *Host) startNetworkWatcher() error {
	netWatchMu.Lock()
	activeHostPtr = h
	netWatchMu.Unlock()

	var handle windows.Handle
	r1, _, _ := procNotifyIpInterfaceChange.Call(
		windows.AF_UNSPEC,
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
