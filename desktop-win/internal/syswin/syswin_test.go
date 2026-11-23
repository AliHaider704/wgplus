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

func TestOutboundIPv4FingerprintDeterministic(t *testing.T) {
	fp1 := getOutboundIPv4Fingerprint()
	fp2 := getOutboundIPv4Fingerprint()
	if fp1 == "" {
		t.Fatalf("expected non-empty IPv4 fingerprint")
	}
	if fp1 != fp2 {
		t.Fatalf("expected deterministic fingerprint, got %q vs %q", fp1, fp2)
	}
}
