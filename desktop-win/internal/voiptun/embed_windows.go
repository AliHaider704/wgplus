//go:build windows

package voiptun

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed wintun_amd64.dll
var wintunAmd64Bytes []byte

// EnsureWintunDLL writes the embedded Authenticode-signed wintun.dll into dataDir
// if missing or hash-mismatched, returning the verified DLL file path.
func EnsureWintunDLL(dataDir string) (string, error) {
	if len(wintunAmd64Bytes) == 0 {
		return "", fmt.Errorf("embedded wintun_amd64.dll is empty")
	}
	if dataDir == "" {
		return "", fmt.Errorf("dataDir is required")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", err
	}

	expectedSum := sha256.Sum256(wintunAmd64Bytes)
	dllPath := filepath.Join(dataDir, "wintun.dll")
	if cur, err := os.ReadFile(dllPath); err == nil {
		curSum := sha256.Sum256(cur)
		if curSum == expectedSum {
			return dllPath, nil
		}
	}

	tmpFile, err := os.CreateTemp(dataDir, "wintun-*.dll.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(wintunAmd64Bytes); err != nil {
		_ = tmpFile.Close()
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, dllPath); err != nil {
		return "", err
	}
	cleanupTmp = false
	return dllPath, nil
}

// EnsureWintunDLLForApp prefers writing wintun.dll next to the running executable so
// golang.zx2c4.com/wintun's LOAD_LIBRARY_SEARCH_APPLICATION_DIR lookup finds it directly,
// falling back to dataDir when the executable directory is read-only.
func EnsureWintunDLLForApp(dataDir string) (string, error) {
	if exePath, err := os.Executable(); err == nil && exePath != "" {
		if dllPath, exeErr := EnsureWintunDLL(filepath.Dir(exePath)); exeErr == nil {
			return dllPath, nil
		}
	}
	return EnsureWintunDLL(dataDir)
}

// ExpectedSHA256 returns the lowercase hex SHA-256 digest of the embedded wintun_amd64.dll.
func ExpectedSHA256() string {
	sum := sha256.Sum256(wintunAmd64Bytes)
	return hex.EncodeToString(sum[:])
}
