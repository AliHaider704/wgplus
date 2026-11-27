package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestIsAllowedReleaseExeURL(t *testing.T) {
	sumsURL, asset, ok := isAllowedReleaseExeURL("https://github.com/AliHaider704/wgplus/releases/download/v2.0.1/WireGuardPlus-Windows-x64.exe")
	if !ok || asset != "WireGuardPlus-Windows-x64.exe" ||
		sumsURL != "https://github.com/AliHaider704/wgplus/releases/download/v2.0.1/SHA256SUMS-windows.txt" {
		t.Fatalf("expected valid release exe URL, got ok=%v asset=%q sumsURL=%q", ok, asset, sumsURL)
	}

	rejected := []string{
		"https://evil.com/WireGuardPlus-Windows-x64.exe",
		"http://github.com/AliHaider704/wgplus/releases/download/v2.0.1/WireGuardPlus-Windows-x64.exe",
		"https://github.com/AliHaider704/wgplus/releases/download/v2.0.1/Other.exe",
		"https://github.com/AliHaider704/wgplus/releases/download/v2.0.1/../WireGuardPlus-Windows-x64.exe",
		"https://github.com/AliHaider704/wgplus/releases/download/v2.0.1/WireGuardPlus-Windows-x64.exe?x=1",
		"https://github.com/user@evil.com/AliHaider704/wgplus/releases/download/v2.0.1/WireGuardPlus-Windows-x64.exe",
	}
	for _, u := range rejected {
		if _, _, ok := isAllowedReleaseExeURL(u); ok {
			t.Fatalf("expected untrusted URL %q to be rejected", u)
		}
	}
}

func TestParseExpectedSHA256AndUpdaterRejectsUntrusted(t *testing.T) {
	sum := sha256.Sum256([]byte("test-binary"))
	hexSum := hex.EncodeToString(sum[:])
	sumsDoc := "deadbeef  WireGuardPlus-Windows-x64-Portable.zip\n" + hexSum + "  WireGuardPlus-Windows-x64.exe\n"

	got, err := parseExpectedSHA256(sumsDoc, "WireGuardPlus-Windows-x64.exe")
	if err != nil || got != hexSum {
		t.Fatalf("parseExpectedSHA256 mismatch: got=%q err=%v", got, err)
	}
	if _, err := parseExpectedSHA256("not-a-hash  WireGuardPlus-Windows-x64.exe\n", "WireGuardPlus-Windows-x64.exe"); err == nil {
		t.Fatal("expected invalid checksum line to fail")
	}

	app := &App{}
	if err := app.ApplySelfUpdate("https://evil.com/WireGuardPlus-Windows-x64.exe"); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("expected untrusted URL error, got %v", err)
	}
	if err := app.ApplySelfUpdate("https://evil.com/page"); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("expected untrusted page URL error, got %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := fetchSumsWithClient(srv.Client(), srv.URL+"/SHA256SUMS-windows.txt"); err == nil {
		t.Fatal("expected 404 checksums fetch to fail")
	}
}

func TestIsMatchingRunningProcessWinRejectsPidReuse(t *testing.T) {
	if isMatchingRunningProcessWin(0, `C:\Fake\WireGuardPlus-Windows-x64.exe`) {
		t.Fatal("PID 0 must never match")
	}
	if isMatchingRunningProcessWin(uint32(os.Getpid()), `C:\Fake\WireGuardPlus-Windows-x64.exe`) {
		t.Fatal("own PID must never match")
	}
	ppid := uint32(os.Getppid())
	if ppid > 0 && isMatchingRunningProcessWin(ppid, `C:\NonExistent\WireGuardPlus-Windows-x64.exe`) {
		t.Fatal("unrelated live parent PID must not match WireGuardPlus exe path")
	}
}

func TestVerifySumsEd25519PrimaryAndBackupAndAntiDowngrade(t *testing.T) {
	if len(updaterEd25519PrimaryPubHex) != 64 || len(updaterEd25519BackupPubHex) != 64 ||
		updaterEd25519PrimaryPubHex == updaterEd25519BackupPubHex {
		t.Fatalf("embedded primary/backup Ed25519 public keys invalid or duplicate")
	}

	primPub, primPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey primary: %v", err)
	}
	backPub, backPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey backup: %v", err)
	}
	_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	primHex := hex.EncodeToString(primPub)
	backHex := hex.EncodeToString(backPub)

	sums := "abcd  WireGuardPlus-Windows-x64.exe\n"
	primSig := hex.EncodeToString(ed25519.Sign(primPriv, []byte(sums))) + "  SHA256SUMS-windows.txt\n"
	backSig := hex.EncodeToString(ed25519.Sign(backPriv, []byte(sums))) + "  SHA256SUMS-windows.txt\n"
	evilSig := hex.EncodeToString(ed25519.Sign(evilPriv, []byte(sums))) + "  SHA256SUMS-windows.txt\n"

	if err := verifySumsEd25519Signature(sums, primSig, primHex, backHex); err != nil {
		t.Fatalf("primary Ed25519 sig should pass: %v", err)
	}
	if err := verifySumsEd25519Signature(sums, backSig, primHex, backHex); err != nil {
		t.Fatalf("backup Ed25519 sig should pass: %v", err)
	}
	if err := verifySumsEd25519Signature(sums+"extra", primSig, primHex, backHex); err == nil {
		t.Fatal("tampered SHA256SUMS must fail Ed25519 verification")
	}
	if err := verifySumsEd25519Signature(sums, evilSig, primHex, backHex); err == nil {
		t.Fatal("rogue signer Ed25519 sig must fail verification")
	}
	if err := verifySumsEd25519Signature(sums, "", primHex, backHex); err == nil {
		t.Fatal("empty signature must fail")
	}

	if !isAllowedUpdaterRedirectHost("github.com") ||
		!isAllowedUpdaterRedirectHost("objects.githubusercontent.com:443") ||
		isAllowedUpdaterRedirectHost("evil.com") ||
		isAllowedUpdaterRedirectHost("github.com.evil.com") ||
		isAllowedUpdaterRedirectHost("evilgithubusercontent.com") {
		t.Fatal("updater redirect host allowlist misbehaved")
	}

	app := &App{}
	for _, oldOrSame := range []string{"v2.0.2", "v" + AppVersion} {
		url := allowedDownloadPrefix + oldOrSame + "/" + windowsAssetNm
		if err := app.ApplySelfUpdate(url); err == nil || !strings.Contains(err.Error(), "non-newer") {
			t.Fatalf("expected anti-downgrade rejection for %s, got %v", url, err)
		}
	}
}
