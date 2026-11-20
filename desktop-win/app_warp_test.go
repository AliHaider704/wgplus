package main

import (
	"testing"

	"wgplus-win/internal/config"
)

func TestFindReusableWarpProfileAndTargetSelection(t *testing.T) {
	profiles := []config.ServerProfile{
		{ID: "std-1", Name: "Manual", PrivateKey: "a", PeerPublicKey: "b", Endpoint: "1.2.3.4:51820", IsWarp: false},
		{ID: "warp-broken", Name: "Empty", IsWarp: true},
		{ID: "warp-ok", Name: "WARP", PrivateKey: "priv", PeerPublicKey: "pub", Endpoint: "engage.cloudflareclient.com:2408", IsWarp: true},
	}
	got, ok := findReusableWarpProfile(profiles)
	if !ok || got.ID != "warp-ok" {
		t.Fatalf("expected warp-ok, got ok=%v prof=%+v", ok, got)
	}

	clientsList := []config.TelegramClientEntry{
		{ID: "disabled-running", DisplayName: "Disabled", Enabled: false, Running: true},
		{ID: "stopped-enabled", DisplayName: "StoppedTG", Enabled: true, Running: false},
		{ID: "running-enabled", DisplayName: "RunningTG", Enabled: true, Running: true},
	}
	selected := selectQuickWarpTargetClients(clientsList)
	if len(selected) != 1 || selected[0].ID != "running-enabled" {
		t.Fatalf("expected running-enabled priority, got %+v", selected)
	}

	fallback := selectQuickWarpTargetClients([]config.TelegramClientEntry{
		{ID: "disabled", Enabled: false, Running: true},
		{ID: "first-enabled", Enabled: true, Running: false},
		{ID: "second-enabled", Enabled: true, Running: false},
	})
	if len(fallback) != 1 || fallback[0].ID != "first-enabled" {
		t.Fatalf("expected first-enabled fallback, got %+v", fallback)
	}
}
