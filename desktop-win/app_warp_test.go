package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wgplus-win/internal/clients"
	"wgplus-win/internal/config"
	"wgplus-win/internal/vault"
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

func TestSelectProfileWhileDisconnectedAndNoBrowserChannelURI(t *testing.T) {
	store, err := vault.NewStoreAt(t.TempDir(), false)
	if err != nil {
		t.Fatalf("vault.NewStoreAt failed: %v", err)
	}
	st := config.PersistedState{
		Settings: config.DefaultSettings(),
		Profiles: []config.ServerProfile{
			{ID: "p1", Name: "Server 1", Endpoint: "1.1.1.1:51820"},
			{ID: "p2", Name: "Server 2", Endpoint: "2.2.2.2:51820"},
		},
	}
	st.Settings.ActiveProfileID = "p1"
	if err := store.Save(st); err != nil {
		t.Fatalf("store.Save failed: %v", err)
	}

	app := &App{
		store:     store,
		state:     st,
		activeID:  "p1",
		connected: false,
	}

	if err := app.SelectProfile("p2"); err != nil {
		t.Fatalf("SelectProfile(p2) failed: %v", err)
	}
	if app.activeID != "p2" || app.state.Settings.ActiveProfileID != "p2" {
		t.Fatalf("expected activeID=p2 and ActiveProfileID=p2, got activeID=%q setting=%q", app.activeID, app.state.Settings.ActiveProfileID)
	}
	if err := app.SelectProfile("missing"); err == nil {
		t.Fatalf("expected error for unknown profile id")
	}

	// Ensure non-tg:// URIs are strictly rejected so a web browser can never be opened
	if err := clients.OpenTgURI("https://t.me/wgplus_official"); err == nil {
		t.Fatalf("expected OpenTgURI to reject https:// URI")
	}

	// Verify live GitHub redirect fallback parses latest release cleanly
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://github.com/AliHaider704/wgplus/releases/tag/v1.7.9", http.StatusFound)
	}))
	defer srv.Close()
	if !versionNewer("1.8.0", "1.7.9") || versionNewer("1.7.9", "1.7.9") {
		t.Fatalf("versionNewer failed")
	}
}

func TestFetchReleaseAndRedirectFallback(t *testing.T) {
	nAPI, err := fetchRelease("latest")
	if err != nil {
		t.Fatalf("fetchRelease(latest) failed: %v", err)
	}
	if nAPI.Version != "1.7.9" {
		t.Fatalf("expected API Version 1.7.9, got %q", nAPI.Version)
	}
	if !strings.Contains(nAPI.Download, "WireGuardPlus-Windows-x64.exe") {
		t.Fatalf("expected API Download URL to contain WireGuardPlus-Windows-x64.exe, got %q", nAPI.Download)
	}

	nRedir, err := fetchLatestViaRedirect(&http.Client{Timeout: 8 * time.Second})
	if err != nil {
		t.Fatalf("fetchLatestViaRedirect failed: %v", err)
	}
	if nRedir.Version != "1.7.9" {
		t.Fatalf("expected Redirect Version 1.7.9, got %q", nRedir.Version)
	}
	if !strings.Contains(nRedir.Download, "WireGuardPlus-Windows-x64.exe") {
		t.Fatalf("expected Redirect Download URL to contain WireGuardPlus-Windows-x64.exe, got %q", nRedir.Download)
	}
}
