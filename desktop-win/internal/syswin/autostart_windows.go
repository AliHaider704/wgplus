package syswin

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	runRegPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName = "WireGuardPlus"
)

// SetStartWithWindows configures non-admin auto-start under HKCU Run with --minimized.
func SetStartWithWindows(enabled bool, exePath string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runRegPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("failed opening HKCU Run registry key: %w", err)
	}
	defer k.Close()

	if !enabled {
		err := k.DeleteValue(runValueName)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	cleanExe := strings.TrimSpace(exePath)
	if cleanExe == "" {
		return fmt.Errorf("executable path is empty")
	}
	cmd := fmt.Sprintf(`"%s" --minimized`, cleanExe)
	return k.SetStringValue(runValueName, cmd)
}

// IsStartWithWindowsEnabled checks whether the HKCU Run entry is present.
func IsStartWithWindowsEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runRegPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue(runValueName)
	return err == nil && strings.TrimSpace(val) != ""
}
