package syswin

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var (
	procOpenClipboard    = modUser32.NewProc("OpenClipboard")
	procCloseClipboard   = modUser32.NewProc("CloseClipboard")
	procEmptyClipboard   = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData = modUser32.NewProc("SetClipboardData")
	procGlobalAlloc      = modKernel32.NewProc("GlobalAlloc")
	procGlobalFree       = modKernel32.NewProc("GlobalFree")
	procGlobalLock       = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = modKernel32.NewProc("GlobalUnlock")
	procRtlMoveMemory    = modKernel32.NewProc("RtlMoveMemory")
)

// CopyTextToClipboard places UTF-16 text onto the Windows clipboard directly (safe when window is hidden in tray).
func CopyTextToClipboard(text string) error {
	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	byteLen := uintptr(len(utf16) * 2)
	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, byteLen)
	if hMem == 0 {
		return errors.New("GlobalAlloc failed")
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return errors.New("GlobalLock failed")
	}
	procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&utf16[0])), byteLen)
	procGlobalUnlock.Call(hMem)

	opened, _, _ := procOpenClipboard.Call(0)
	if opened == 0 {
		procGlobalFree.Call(hMem)
		return errors.New("OpenClipboard failed")
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()
	res, _, _ := procSetClipboardData.Call(cfUnicodeText, hMem)
	if res == 0 {
		procGlobalFree.Call(hMem)
		return errors.New("SetClipboardData failed")
	}
	return nil
}
