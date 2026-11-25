package syswin

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	runRegPath        = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName      = "WireGuardPlus"
	scheduledTaskName = "WireGuardPlus_Autostart"
)

func runSchtasksHidden(args ...string) error {
	cmd := exec.Command("schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	return cmd.Run()
}

// SyncStartWithWindows aligns Windows logon startup with both StartWithWindows and AlwaysRunAsAdmin.
// When elevated and alwaysAdmin is true, it installs a highest-privilege Task Scheduler logon task so
// subsequent logins launch as Administrator without UAC prompts; otherwise it uses HKCU Run.
func SyncStartWithWindows(enabled bool, exePath string, alwaysAdmin bool, currentlyElevated bool) error {
	cleanExe := strings.TrimSpace(exePath)
	if !enabled {
		_ = runSchtasksHidden("/Delete", "/F", "/TN", scheduledTaskName)
		return SetStartWithWindows(false, cleanExe)
	}
	if cleanExe == "" {
		return fmt.Errorf("executable path is empty")
	}
	if alwaysAdmin && currentlyElevated {
		trCmd := fmt.Sprintf(`"%s" --minimized`, cleanExe)
		if err := runSchtasksHidden(
			"/Create", "/F",
			"/TN", scheduledTaskName,
			"/TR", trCmd,
			"/SC", "ONLOGON",
			"/RL", "HIGHEST",
			"/IT",
		); err == nil {
			_ = SetStartWithWindows(false, cleanExe)
			return nil
		}
	} else {
		_ = runSchtasksHidden("/Delete", "/F", "/TN", scheduledTaskName)
	}
	return SetStartWithWindows(true, cleanExe)
}

// RegisteredAutostartExe returns the executable path currently registered in HKCU Run, if any.
func RegisteredAutostartExe() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, runRegPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	val, _, err := k.GetStringValue(runValueName)
	if err != nil {
		return ""
	}
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, `"`) {
		if end := strings.IndexByte(val[1:], '"'); end > 0 {
			return strings.TrimSpace(val[1 : 1+end])
		}
	}
	fields := strings.Fields(val)
	if len(fields) > 0 && strings.HasSuffix(strings.ToLower(fields[0]), ".exe") {
		return fields[0]
	}
	return ""
}

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
