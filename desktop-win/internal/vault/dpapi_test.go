package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wgplus-win/internal/config"
)

func TestDPAPIProtectAndStoreRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	stStore, err := NewStoreAt(tmp, true)
	if err != nil {
		t.Fatalf("NewStoreAt failed: %v", err)
	}

	state, err := stStore.Load()
	if err != nil {
		t.Fatalf("initial Load failed: %v", err)
	}
	if state.Settings.SocksUser == "" || state.Settings.SocksPass == "" {
		t.Fatalf("expected auto-generated SOCKS5 credentials on first load")
	}

	secretPriv := "uK8mQ1zR9xP3vL7nB5dF2hJ6kM4pS8tV0wY3cE7gI1o="
	state.Profiles = []config.ServerProfile{
		{
			ID:            "p1",
			Name:          "Test Server",
			PrivateKey:    secretPriv,
			PresharedKey:  "abc123psk=",
			ClientIP:      "10.0.0.2/32",
			PeerPublicKey: "peerpub=",
			Endpoint:      "1.2.3.4:51820",
		},
	}
	if err := stStore.Save(state); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	rawDisk, err := os.ReadFile(filepath.Join(tmp, "state.json"))
	if err != nil {
		t.Fatalf("ReadFile state.json failed: %v", err)
	}
	if strings.Contains(string(rawDisk), secretPriv) || strings.Contains(string(rawDisk), "abc123psk=") {
		t.Fatalf("plaintext secret leaked to state.json on disk!")
	}
	if !strings.Contains(string(rawDisk), dpapiPrefix) {
		t.Fatalf("expected dpapi: sealed prefix on disk")
	}

	reloaded, err := stStore.Load()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(reloaded.Profiles) != 1 || reloaded.Profiles[0].PrivateKey != secretPriv || reloaded.Profiles[0].PresharedKey != "abc123psk=" {
		t.Fatalf("DPAPI decrypt mismatch: %+v", reloaded.Profiles)
	}
	if reloaded.Settings.SocksPass != state.Settings.SocksPass {
		t.Fatalf("SOCKS5 pass DPAPI decrypt mismatch")
	}
}

func TestResolvePortableDataDir(t *testing.T) {
	tmp := t.TempDir()
	fakeExe := filepath.Join(tmp, "WireGuardPlus.exe")
	dir, port := ResolveDataDir(fakeExe)
	if port {
		t.Fatalf("did not expect portable mode without flag/dir, got %q", dir)
	}

	if err := os.WriteFile(filepath.Join(tmp, "portable.flag"), []byte("1"), 0600); err != nil {
		t.Fatalf("WriteFile portable.flag failed: %v", err)
	}
	dir, port = ResolveDataDir(fakeExe)
	if !port || dir != filepath.Join(tmp, "wgplus-data") {
		t.Fatalf("expected portable dir %q, got dir=%q portable=%v", filepath.Join(tmp, "wgplus-data"), dir, port)
	}
}

func TestPortableEncryptedBackupRoundTrip(t *testing.T) {
	st := config.PersistedState{
		SchemaVersion: 1,
		Settings:      config.DefaultSettings(),
		Profiles: []config.ServerProfile{
			{ID: "x1", Name: "BackupSrv", PrivateKey: "secret-key-xyz"},
		},
	}
	blob, err := ExportEncryptedBackup(st, "my-strong-pass")
	if err != nil {
		t.Fatalf("ExportEncryptedBackup failed: %v", err)
	}
	if strings.Contains(string(blob), "secret-key-xyz") {
		t.Fatalf("plaintext leaked into encrypted backup")
	}
	if _, err := ImportEncryptedBackup(blob, "wrong-pass"); err == nil {
		t.Fatalf("expected wrong passphrase to fail")
	}
	out, err := ImportEncryptedBackup(blob, "my-strong-pass")
	if err != nil {
		t.Fatalf("ImportEncryptedBackup failed: %v", err)
	}
	if len(out.Profiles) != 1 || out.Profiles[0].PrivateKey != "secret-key-xyz" {
		t.Fatalf("backup payload mismatch: %+v", out)
	}
}
