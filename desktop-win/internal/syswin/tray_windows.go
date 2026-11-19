package syswin

import (
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmDestroy         = 0x0002
	wmNull            = 0x0000
	wmUser            = 0x0400
	wmTrayCallback    = wmUser + 101
	wmTrayUpdate      = wmUser + 102
	wmTrayShutdown    = wmUser + 103
	wmPowerBroadcast  = 0x0218
	pbtApmSuspend     = 0x0004
	pbtApmResumeAuto  = 0x0012
	pbtApmResumeSusp  = 0x0007
	wmLButtonUp       = 0x0202
	wmLButtonDblClk   = 0x0203
	wmRButtonUp       = 0x0205

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002
	nifMsg    = 0x00000001
	nifIcon   = 0x00000002
	nifTip    = 0x00000004

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	mfChecked   = 0x00000008
	mfPopup     = 0x00000010

	tpmReturnCmd   = 0x0100
	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080

	menuCmdOpen      = 1001
	menuCmdToggle    = 1002
	menuCmdCopyLink  = 1003
	menuCmdQuit      = 1004
	menuCmdSrvBase   = 2000
	menuCmdCliBase   = 3000
)

type TrayVisualState int

const (
	TrayDisconnected TrayVisualState = iota
	TrayKillSwitch
	TrayConnected
)

type TrayMenuProfile struct {
	ID         string
	Name       string
	LastPingMs int
	Active     bool
}

type TrayMenuClient struct {
	ID      string
	Name    string
	Running bool
}

type TrayCallbacks struct {
	OnOpenWindow    func()
	OnToggleTunnel  func()
	OnSwitchProfile func(profileID string)
	OnAttachClient  func(clientID string)
	OnCopyLink      func()
	OnQuit          func()
	OnSuspend       func()
	OnWake          func()
	OnNetworkChange func()
	GetSnapshot     func() (lang string, state TrayVisualState, tooltip string, connected bool, profiles []TrayMenuProfile, clients []TrayMenuClient)
}

var (
	modUser32          = windows.NewLazySystemDLL("user32.dll")
	modShell32         = windows.NewLazySystemDLL("shell32.dll")
	modGdi32           = windows.NewLazySystemDLL("gdi32.dll")
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")

	procGetModuleHandleW      = modKernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW      = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW       = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow         = modUser32.NewProc("DestroyWindow")
	procDefWindowProcW        = modUser32.NewProc("DefWindowProcW")
	procGetMessageW           = modUser32.NewProc("GetMessageW")
	procTranslateMessage      = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW      = modUser32.NewProc("DispatchMessageW")
	procPostMessageW          = modUser32.NewProc("PostMessageW")
	procPostQuitMessage       = modUser32.NewProc("PostQuitMessage")
	procRegisterWindowMessage = modUser32.NewProc("RegisterWindowMessageW")
	procSetForegroundWindow   = modUser32.NewProc("SetForegroundWindow")
	procGetCursorPos          = modUser32.NewProc("GetCursorPos")
	procCreatePopupMenu       = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW           = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenuEx      = modUser32.NewProc("TrackPopupMenuEx")
	procDestroyMenu           = modUser32.NewProc("DestroyMenu")
	procCreateIconIndirect    = modUser32.NewProc("CreateIconIndirect")
	procDestroyIcon           = modUser32.NewProc("DestroyIcon")
	procShellNotifyIconW      = modShell32.NewProc("Shell_NotifyIconW")
	procCreateBitmap          = modGdi32.NewProc("CreateBitmap")
	procDeleteObject          = modGdi32.NewProc("DeleteObject")
)

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type point struct {
	X int32
	Y int32
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type iconInfo struct {
	FIcon    uint32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

type notifyIconDataW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

// Host manages the native Win32 System Tray icon, popup menu, and WM_POWERBROADCAST listener.
type Host struct {
	mu               sync.Mutex
	hwnd             uintptr
	wmTaskbarCreated uint32
	callbacks        TrayCallbacks
	icons            map[TrayVisualState]uintptr
	started          bool
	stopped          bool
	doneCh           chan struct{}
	netHandle        windows.Handle
}

func createCircleIcon(r, g, b byte) uintptr {
	const size = 32
	pixels := make([]byte, size*size*4)
	cx, cy := float64(size-1)/2.0, float64(size-1)/2.0
	outerR := 12.5

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			dist := math.Sqrt(dx*dx + dy*dy)
			var alpha float64
			if dist <= outerR-0.8 {
				alpha = 1.0
			} else if dist <= outerR+0.8 {
				alpha = (outerR + 0.8 - dist) / 1.6
			}
			if alpha <= 0 {
				continue
			}
			aByte := byte(math.Round(alpha * 255))
			off := (y*size + x) * 4
			// Premultiplied BGRA
			pixels[off+0] = byte(math.Round(float64(b) * alpha))
			pixels[off+1] = byte(math.Round(float64(g) * alpha))
			pixels[off+2] = byte(math.Round(float64(r) * alpha))
			pixels[off+3] = aByte
		}
	}

	andMask := make([]byte, (size/8)*size)
	hColor, _, _ := procCreateBitmap.Call(size, size, 1, 32, uintptr(unsafe.Pointer(&pixels[0])))
	hMask, _, _ := procCreateBitmap.Call(size, size, 1, 1, uintptr(unsafe.Pointer(&andMask[0])))
	if hColor == 0 || hMask == 0 {
		if hColor != 0 {
			procDeleteObject.Call(hColor)
		}
		if hMask != 0 {
			procDeleteObject.Call(hMask)
		}
		return 0
	}
	ii := iconInfo{
		FIcon:    1,
		HbmMask:  hMask,
		HbmColor: hColor,
	}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	procDeleteObject.Call(hColor)
	procDeleteObject.Call(hMask)
	return hIcon
}

// StartHost launches the dedicated Win32 tray + power/network resilience loop.
func StartHost(cb TrayCallbacks, showTrayIcon bool) (*Host, error) {
	h := &Host{
		callbacks: cb,
		icons:     make(map[TrayVisualState]uintptr),
		doneCh:    make(chan struct{}),
	}

	readyCh := make(chan error, 1)
	go h.runMessageLoop(readyCh, showTrayIcon)
	if err := <-readyCh; err != nil {
		return nil, err
	}
	if err := h.startNetworkWatcher(); err != nil {
		// Non-fatal fallback: sleep/wake & Go watchdog remain active
		_ = err
	}
	return h, nil
}

func (h *Host) RefreshTray() {
	h.mu.Lock()
	hwnd := h.hwnd
	stopped := h.stopped
	h.mu.Unlock()
	if hwnd != 0 && !stopped {
		procPostMessageW.Call(hwnd, wmTrayUpdate, 0, 0)
	}
}

func (h *Host) Stop() {
	h.stopNetworkWatcher()
	h.mu.Lock()
	hwnd := h.hwnd
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.stopped = true
	h.mu.Unlock()

	if hwnd != 0 {
		procPostMessageW.Call(hwnd, wmTrayShutdown, 0, 0)
		select {
		case <-h.doneCh:
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *Host) runMessageLoop(readyCh chan<- error, showTrayIcon bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(h.doneCh)

	hInst, _, _ := procGetModuleHandleW.Call(0)
	clsName, _ := windows.UTF16PtrFromString(fmt.Sprintf("WireGuardPlusWinHost_%d", time.Now().UnixNano()))
	tbcStr, _ := windows.UTF16PtrFromString("TaskbarCreated")
	tbcMsg, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(tbcStr)))
	h.wmTaskbarCreated = uint32(tbcMsg)

	h.icons[TrayConnected] = createCircleIcon(0x1A, 0x6B, 0xB8)    // Cobalt #1A6BB8
	h.icons[TrayKillSwitch] = createCircleIcon(0xD9, 0x77, 0x06)   // Amber #D97706
	h.icons[TrayDisconnected] = createCircleIcon(0x64, 0x74, 0x8B) // Slate #64748B
	defer func() {
		for _, ic := range h.icons {
			if ic != 0 {
				procDestroyIcon.Call(ic)
			}
		}
	}()

	var trayVisible bool
	var wndProc uintptr
	wndProc = windows.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
		if h.wmTaskbarCreated != 0 && msg == h.wmTaskbarCreated && trayVisible {
			h.applyTrayIcon(hwnd, nimAdd)
			return 0
		}
		switch msg {
		case wmTrayUpdate:
			if trayVisible {
				h.applyTrayIcon(hwnd, nimModify)
			}
			return 0
		case wmTrayShutdown:
			if trayVisible {
				h.applyTrayIcon(hwnd, nimDelete)
				trayVisible = false
			}
			procDestroyWindow.Call(hwnd)
			return 0
		case wmDestroy:
			if trayVisible {
				h.applyTrayIcon(hwnd, nimDelete)
				trayVisible = false
			}
			procPostQuitMessage.Call(0)
			return 0
		case wmPowerBroadcast:
			switch wParam {
			case pbtApmSuspend:
				if h.callbacks.OnSuspend != nil {
					go h.callbacks.OnSuspend()
				}
			case pbtApmResumeAuto, pbtApmResumeSusp:
				if h.callbacks.OnWake != nil {
					go h.callbacks.OnWake()
				}
			}
			return 1
		case wmTrayCallback:
			ev := uint32(lParam)
			switch ev {
			case wmLButtonDblClk, wmLButtonUp:
				if h.callbacks.OnOpenWindow != nil {
					go h.callbacks.OnOpenWindow()
				}
			case wmRButtonUp:
				h.showContextMenu(hwnd)
			}
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return ret
	})

	wc := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		LpfnWndProc:   wndProc,
		HInstance:     hInst,
		LpszClassName: clsName,
	}
	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		readyCh <- fmt.Errorf("RegisterClassExW failed: %v", regErr)
		return
	}

	// Hidden top-level window (hwndParent=0) ensures WM_POWERBROADCAST & TaskbarCreated delivery.
	hwnd, _, cwErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsName)),
		uintptr(unsafe.Pointer(clsName)),
		0, // WS_OVERLAPPED, not WS_VISIBLE
		0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		readyCh <- fmt.Errorf("CreateWindowExW failed: %v", cwErr)
		return
	}

	h.mu.Lock()
	h.hwnd = hwnd
	h.started = true
	h.mu.Unlock()

	if showTrayIcon {
		h.applyTrayIcon(hwnd, nimAdd)
		trayVisible = true
	}

	readyCh <- nil

	var m winMsg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (h *Host) applyTrayIcon(hwnd uintptr, action uint32) {
	state := TrayDisconnected
	tip := "WireGuard Plus"
	if h.callbacks.GetSnapshot != nil {
		_, st, t, _, _, _ := h.callbacks.GetSnapshot()
		state = st
		if t != "" {
			tip = t
		}
	}

	nid := notifyIconDataW{
		CbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		HWnd:             hwnd,
		UID:              1,
		UFlags:           nifMsg | nifIcon | nifTip,
		UCallbackMessage: wmTrayCallback,
		HIcon:            h.icons[state],
	}
	tipUTF16, _ := windows.UTF16FromString(tip)
	copy(nid.SzTip[:len(nid.SzTip)-1], tipUTF16)

	procShellNotifyIconW.Call(uintptr(action), uintptr(unsafe.Pointer(&nid)))
}

func appendMenuText(hMenu uintptr, flags uint32, id uintptr, text string) {
	u16, _ := windows.UTF16PtrFromString(text)
	procAppendMenuW.Call(hMenu, uintptr(flags), id, uintptr(unsafe.Pointer(u16)))
}

func (h *Host) showContextMenu(hwnd uintptr) {
	lang := "en"
	connected := false
	var profiles []TrayMenuProfile
	var clients []TrayMenuClient
	if h.callbacks.GetSnapshot != nil {
		lang, _, _, connected, profiles, clients = h.callbacks.GetSnapshot()
	}
	isAr := lang == "ar"

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	lblOpen := "Open WireGuard Plus"
	lblConnect := "Connect Tunnel"
	if connected {
		lblConnect = "Disconnect Tunnel"
	}
	lblSwitch := "Switch Server"
	lblAttach := "Attach to Telegram Client"
	lblCopy := "Copy tg://socks Link"
	lblQuit := "Quit"
	if isAr {
		lblOpen = "فتح WireGuard Plus"
		if connected {
			lblConnect = "قطع الاتصال"
		} else {
			lblConnect = "تشغيل النفق"
		}
		lblSwitch = "تبديل الخادم"
		lblAttach = "ربط مع تطبيق تيليغرام"
		lblCopy = "نسخ رابط البروكسي tg://socks"
		lblQuit = "خروج"
	}

	appendMenuText(hMenu, mfString, menuCmdOpen, lblOpen)
	appendMenuText(hMenu, mfString, menuCmdToggle, lblConnect)

	if len(profiles) > 0 {
		subSrv, _, _ := procCreatePopupMenu.Call()
		if subSrv != 0 {
			for i, p := range profiles {
				if i >= 50 {
					break
				}
				label := p.Name
				if p.LastPingMs > 0 {
					label = fmt.Sprintf("%s (%d ms)", p.Name, p.LastPingMs)
				}
				flags := uint32(mfString)
				if p.Active {
					flags |= mfChecked
				}
				appendMenuText(subSrv, flags, uintptr(menuCmdSrvBase+i), label)
			}
			appendMenuText(hMenu, mfPopup, subSrv, lblSwitch)
		}
	}

	if len(clients) > 0 {
		subCli, _, _ := procCreatePopupMenu.Call()
		if subCli != 0 {
			for i, c := range clients {
				if i >= 50 {
					break
				}
				label := c.Name
				if c.Running {
					if isAr {
						label += " [يعمل]"
					} else {
						label += " [Running]"
					}
				}
				appendMenuText(subCli, mfString, uintptr(menuCmdCliBase+i), label)
			}
			appendMenuText(hMenu, mfPopup, subCli, lblAttach)
		}
	}

	appendMenuText(hMenu, mfString, menuCmdCopyLink, lblCopy)
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendMenuText(hMenu, mfString, menuCmdQuit, lblQuit)

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)
	cmd, _, _ := procTrackPopupMenuEx.Call(
		hMenu,
		tpmReturnCmd|tpmRightButton|tpmNoNotify,
		uintptr(pt.X),
		uintptr(pt.Y),
		hwnd,
		0,
	)
	procPostMessageW.Call(hwnd, wmNull, 0, 0)

	id := int(cmd)
	switch {
	case id == menuCmdOpen && h.callbacks.OnOpenWindow != nil:
		go h.callbacks.OnOpenWindow()
	case id == menuCmdToggle && h.callbacks.OnToggleTunnel != nil:
		go h.callbacks.OnToggleTunnel()
	case id == menuCmdCopyLink && h.callbacks.OnCopyLink != nil:
		go h.callbacks.OnCopyLink()
	case id == menuCmdQuit && h.callbacks.OnQuit != nil:
		go h.callbacks.OnQuit()
	case id >= menuCmdSrvBase && id < menuCmdCliBase && h.callbacks.OnSwitchProfile != nil:
		idx := id - menuCmdSrvBase
		if idx >= 0 && idx < len(profiles) {
			pid := profiles[idx].ID
			go h.callbacks.OnSwitchProfile(pid)
		}
	case id >= menuCmdCliBase && id < menuCmdCliBase+100 && h.callbacks.OnAttachClient != nil:
		idx := id - menuCmdCliBase
		if idx >= 0 && idx < len(clients) {
			cid := clients[idx].ID
			go h.callbacks.OnAttachClient(cid)
		}
	}
}
