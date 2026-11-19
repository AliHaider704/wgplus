package clients

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wgplus-win/internal/config"
)

func TestBuildSocksURI(t *testing.T) {
	noAuth := BuildSocksURI(48729, false, "u", "p")
	if noAuth != "tg://socks?server=127.0.0.1&port=48729" {
		t.Fatalf("unexpected no-auth URI: %q", noAuth)
	}
	withAuth := BuildSocksURI(48729, true, "wgp_user", "p@ss word!")
	if !strings.Contains(withAuth, "&user=wgp_user") || !strings.Contains(withAuth, "&pass=p%40ss+word%21") {
		t.Fatalf("unexpected auth URI escaping: %q", withAuth)
	}
}

func TestClassifyPortableVsInstalledByTdataSibling(t *testing.T) {
	tmp := t.TempDir()
	portDir := filepath.Join(tmp, "AyuGramPortable")
	if err := os.MkdirAll(filepath.Join(portDir, "tdata"), 0700); err != nil {
		t.Fatalf("MkdirAll tdata failed: %v", err)
	}
	exePath := filepath.Join(portDir, "AyuGram.exe")
	if err := os.WriteFile(exePath, []byte("stub"), 0600); err != nil {
		t.Fatalf("WriteFile exe failed: %v", err)
	}

	kind, display, isPortable, isMsix := classifyExecutable(exePath, "AyuGram.exe")
	if kind != "ayugram" || !isPortable || isMsix || !strings.Contains(display, "Portable") {
		t.Fatalf("unexpected classification: kind=%q display=%q port=%v msix=%v", kind, display, isPortable, isMsix)
	}

	// Custom portable entry merges cleanly in DiscoverClients
	list := DiscoverClients([]config.TelegramClientEntry{
		{
			ExePath: exePath,
			Enabled: true,
		},
	})
	var found bool
	for _, c := range list {
		if strings.EqualFold(c.ExePath, exePath) && c.Kind == "ayugram" && c.IsPortable {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected custom portable AyuGram entry in DiscoverClients: %+v", list)
	}
}
