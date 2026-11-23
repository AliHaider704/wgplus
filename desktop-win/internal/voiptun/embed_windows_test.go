//go:build windows

package voiptun

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureWintunDLLWritesAndVerifiesDigest(t *testing.T) {
	dir := t.TempDir()
	dllPath, err := EnsureWintunDLL(dir)
	if err != nil {
		t.Fatalf("EnsureWintunDLL: %v", err)
	}
	if filepath.Dir(dllPath) != dir || filepath.Base(dllPath) != "wintun.dll" {
		t.Fatalf("unexpected dllPath: %s", dllPath)
	}

	gotBytes, err := os.ReadFile(dllPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	sum := sha256.Sum256(gotBytes)
	gotHex := hex.EncodeToString(sum[:])
	if !strings.EqualFold(gotHex, "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce") {
		t.Fatalf("unexpected wintun.dll SHA-256: %s", gotHex)
	}
	if gotHex != ExpectedSHA256() {
		t.Fatalf("ExpectedSHA256 mismatch: %s vs %s", ExpectedSHA256(), gotHex)
	}

	// Corrupt disk file and confirm EnsureWintunDLL atomically restores valid DLL.
	if err := os.WriteFile(dllPath, []byte("corrupted"), 0600); err != nil {
		t.Fatalf("WriteFile corrupt: %v", err)
	}
	restoredPath, err := EnsureWintunDLL(dir)
	if err != nil {
		t.Fatalf("EnsureWintunDLL restore: %v", err)
	}
	restoredBytes, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("ReadFile restored: %v", err)
	}
	restoredSum := sha256.Sum256(restoredBytes)
	if hex.EncodeToString(restoredSum[:]) != ExpectedSHA256() {
		t.Fatalf("expected restored DLL to match embedded SHA-256")
	}

	appDllPath, err := EnsureWintunDLLForApp(dir)
	if err != nil {
		t.Fatalf("EnsureWintunDLLForApp: %v", err)
	}
	if _, statErr := os.Stat(appDllPath); statErr != nil {
		t.Fatalf("expected app DLL to exist at %s: %v", appDllPath, statErr)
	}
}
