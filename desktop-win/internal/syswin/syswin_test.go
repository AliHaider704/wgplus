package syswin

import "testing"

func TestCircleIconAndHiddenHostLifecycle(t *testing.T) {
	ic := createCircleIcon(0x1A, 0x6B, 0xB8)
	if ic == 0 {
		t.Fatalf("expected non-zero HICON from createCircleIcon")
	}
	procDestroyIcon.Call(ic)

	host, err := StartHost(TrayCallbacks{}, false)
	if err != nil {
		t.Fatalf("StartHost failed: %v", err)
	}
	host.RefreshTray()
	host.Stop()
}
