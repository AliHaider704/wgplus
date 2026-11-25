package clients

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"wgplus-win/internal/config"
)

var (
	modShell32        = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteW = modShell32.NewProc("ShellExecuteW")
)

type runningProc struct {
	pid      uint32
	baseName string
	exePath  string
}

// ApplyResult describes what happened when dispatching tg://socks to a specific client.
type ApplyResult struct {
	Dispatched           bool   `json:"dispatched"`
	UsedRegistryProtocol bool   `json:"usedRegistryProtocol"`
	ClipboardCopied      bool   `json:"clipboardCopied"`
	NeedsManualPasteNote bool   `json:"needsManualPasteNote"`
	Message              string `json:"message,omitempty"`
}

func stableClientID(kind, key string) string {
	h := sha1.Sum([]byte(kind + "|" + strings.ToLower(strings.TrimSpace(key))))
	return kind + "-" + hex.EncodeToString(h[:6])
}

func hasSiblingTdata(exePath string) bool {
	if strings.TrimSpace(exePath) == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(filepath.Dir(exePath), "tdata"))
	return err == nil && st.IsDir()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func snapshotRunningProcesses() []runningProc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil
	}

	var out []runningProc
	for {
		baseName := windows.UTF16ToString(entry.ExeFile[:])
		low := strings.ToLower(baseName)
		if low == "telegram.exe" ||
			low == "ayugram.exe" ||
			low == "64gram.exe" ||
			low == "unigram.exe" ||
			low == "forkgram.exe" ||
			low == "kotatogram.exe" ||
			low == "materialgram.exe" ||
			low == "exteragram.exe" ||
			low == "cherrygram.exe" ||
			low == "ime.exe" ||
			low == "nicegram.exe" {
			var fullPath string
			if hProc, pErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID); pErr == nil {
				var buf [windows.MAX_PATH * 2]uint16
				n := uint32(len(buf))
				if qErr := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &n); qErr == nil && n > 0 {
					fullPath = windows.UTF16ToString(buf[:n])
				}
				_ = windows.CloseHandle(hProc)
			}
			out = append(out, runningProc{
				pid:      entry.ProcessID,
				baseName: baseName,
				exePath:  fullPath,
			})
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return out
}

func classifyExecutable(exePath string, baseName string) (kind string, displayName string, isPortable bool, isMsix bool) {
	lowBase := strings.ToLower(baseName)
	lowPath := strings.ToLower(exePath)
	portable := hasSiblingTdata(exePath) || strings.Contains(lowPath, "portable")

	switch lowBase {
	case "ayugram.exe":
		if portable {
			return "ayugram", "AyuGramDesktop Portable", true, false
		}
		return "ayugram", "AyuGramDesktop", false, false
	case "64gram.exe":
		if portable {
			return "64gram", "64Gram Portable", true, false
		}
		return "64gram", "64Gram Desktop", false, false
	case "forkgram.exe":
		if portable {
			return "forkgram", "Forkgram Portable", true, false
		}
		return "forkgram", "Forkgram", false, false
	case "kotatogram.exe":
		if portable {
			return "kotatogram", "Kotatogram Portable", true, false
		}
		return "kotatogram", "Kotatogram", false, false
	case "materialgram.exe":
		if portable {
			return "materialgram", "materialgram Portable", true, false
		}
		return "materialgram", "materialgram", false, false
	case "exteragram.exe":
		if portable {
			return "exteragram", "exteraGram Portable", true, false
		}
		return "exteragram", "exteraGram", false, false
	case "cherrygram.exe":
		if portable {
			return "cherrygram", "Cherrygram Portable", true, false
		}
		return "cherrygram", "Cherrygram", false, false
	case "ime.exe":
		if portable {
			return "ime", "iMe Portable", true, false
		}
		return "ime", "iMe Desktop", false, false
	case "nicegram.exe":
		if portable {
			return "nicegram", "Nicegram Portable", true, false
		}
		return "nicegram", "Nicegram Desktop", false, false
	case "unigram.exe":
		return "unigram", "Unigram (MSIX)", false, true
	case "telegram.exe":
		if portable {
			return "tdesktop_portable", "Telegram Desktop Portable", true, false
		}
		return "tdesktop", "Telegram Desktop", false, false
	default:
		if portable {
			return "custom", strings.TrimSuffix(baseName, filepath.Ext(baseName)) + " (Portable)", true, false
		}
		return "custom", strings.TrimSuffix(baseName, filepath.Ext(baseName)), false, false
	}
}

func parseRegistryTgHandlerExe() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Classes\tg\shell\open\command`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	val, _, err := k.GetStringValue("")
	if err != nil {
		return ""
	}
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, `"`) {
		if end := strings.IndexByte(val[1:], '"'); end > 0 {
			return filepath.Clean(val[1 : 1+end])
		}
	}
	fields := strings.Fields(val)
	if len(fields) > 0 && strings.HasSuffix(strings.ToLower(fields[0]), ".exe") {
		return filepath.Clean(fields[0])
	}
	return ""
}

func discoverPortableInCommonRoots() []string {
	var found []string
	home, _ := os.UserHomeDir()
	localApp := os.Getenv("LOCALAPPDATA")
	roots := []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Downloads"),
		filepath.Join(localApp, "Programs"),
	}
	knownExes := []string{"Telegram.exe", "AyuGram.exe", "64Gram.exe", "Forkgram.exe"}

	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			subDir := filepath.Join(root, ent.Name())
			for _, exeName := range knownExes {
				cand := filepath.Join(subDir, exeName)
				if fileExists(cand) {
					found = append(found, cand)
				}
			}
		}
	}
	return found
}

func detectUnigramMsixInstalled() bool {
	localApp := os.Getenv("LOCALAPPDATA")
	if localApp == "" {
		return false
	}
	pkgDir := filepath.Join(localApp, "Packages")
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if ent.IsDir() && strings.Contains(strings.ToLower(ent.Name()), "unigram") {
			return true
		}
	}
	return false
}

// SnapshotRunningPIDs returns active PIDs keyed by lowercase cleaned ExePath
// and "name:<lowercase baseName>" so diagnostics can display every running instance's PIDs.
func SnapshotRunningPIDs() map[string][]uint32 {
	procs := snapshotRunningProcesses()
	out := make(map[string][]uint32, len(procs)*2)
	for _, rp := range procs {
		if rp.exePath != "" {
			key := strings.ToLower(filepath.Clean(rp.exePath))
			out[key] = append(out[key], rp.pid)
		}
		if rp.baseName != "" {
			nkey := "name:" + strings.ToLower(rp.baseName)
			out[nkey] = append(out[nkey], rp.pid)
		}
	}
	return out
}

// DiscoverClients detects installed, MSIX, and portable Telegram desktop clients on Windows
// and merges them with user-pinned custom entries while preserving live running state.
func DiscoverClients(customClients []config.TelegramClientEntry) []config.TelegramClientEntry {
	appData := os.Getenv("APPDATA")
	localApp := os.Getenv("LOCALAPPDATA")

	runningProcs := snapshotRunningProcesses()
	runningByPath := make(map[string]bool)
	runningByName := make(map[string]bool)
	for _, rp := range runningProcs {
		if rp.exePath != "" {
			runningByPath[strings.ToLower(filepath.Clean(rp.exePath))] = true
		}
		runningByName[strings.ToLower(rp.baseName)] = true
	}

	byPath := make(map[string]config.TelegramClientEntry)
	addCandidate := func(exePath string, autoDetected bool) {
		clean := filepath.Clean(exePath)
		if !fileExists(clean) {
			return
		}
		key := strings.ToLower(clean)
		if _, exists := byPath[key]; exists {
			return
		}
		base := filepath.Base(clean)
		kind, display, isPortable, isMsix := classifyExecutable(clean, base)
		if isPortable {
			folderTag := filepath.Base(filepath.Dir(clean))
			if folderTag != "" && !strings.Contains(strings.ToLower(display), strings.ToLower(folderTag)) {
				display = fmt.Sprintf("%s (%s)", display, folderTag)
			}
		}
		byPath[key] = config.TelegramClientEntry{
			ID:           stableClientID(kind, key),
			Kind:         kind,
			DisplayName:  display,
			ExePath:      clean,
			InstallDir:   filepath.Dir(clean),
			IsPortable:   isPortable,
			IsMsix:       isMsix,
			Enabled:      true,
			AutoDetected: autoDetected,
			Running:      runningByPath[key],
		}
	}

	// 1. Standard install paths
	wellKnown := []string{
		filepath.Join(appData, "Telegram Desktop", "Telegram.exe"),
		filepath.Join(appData, "AyuGramDesktop", "AyuGram.exe"),
		filepath.Join(localApp, "AyuGramDesktop", "AyuGram.exe"),
		filepath.Join(appData, "64Gram", "64Gram.exe"),
		filepath.Join(localApp, "64Gram", "64Gram.exe"),
		filepath.Join(appData, "Forkgram", "Forkgram.exe"),
	}
	for _, p := range wellKnown {
		addCandidate(p, true)
	}
	if regExe := parseRegistryTgHandlerExe(); regExe != "" {
		addCandidate(regExe, true)
	}

	// 2. Depth-1 scan in Desktop / Downloads / Local Programs for portable instances
	for _, p := range discoverPortableInCommonRoots() {
		addCandidate(p, true)
	}

	// 3. Currently running Telegram processes (catches portable builds launched from anywhere!)
	for _, rp := range runningProcs {
		if rp.exePath != "" {
			addCandidate(rp.exePath, true)
		}
	}

	// 4. User-added custom clients (override display name / enabled state if path matches)
	for _, cc := range customClients {
		if strings.TrimSpace(cc.ExePath) == "" {
			continue
		}
		clean := filepath.Clean(cc.ExePath)
		key := strings.ToLower(clean)
		if existing, exists := byPath[key]; exists {
			existing.Enabled = cc.Enabled
			if strings.TrimSpace(cc.DisplayName) != "" {
				existing.DisplayName = cc.DisplayName
			}
			existing.AutoDetected = false
			byPath[key] = existing
		} else {
			base := filepath.Base(clean)
			kind, defaultName, isPort, isMsix := classifyExecutable(clean, base)
			disp := strings.TrimSpace(cc.DisplayName)
			if disp == "" {
				disp = defaultName
			}
			byPath[key] = config.TelegramClientEntry{
				ID:           stableClientID(kind, key),
				Kind:         kind,
				DisplayName:  disp,
				ExePath:      clean,
				InstallDir:   filepath.Dir(clean),
				IsPortable:   isPort || cc.IsPortable,
				IsMsix:       isMsix,
				Enabled:      cc.Enabled,
				AutoDetected: false,
				Running:      runningByPath[key],
			}
		}
	}

	out := make([]config.TelegramClientEntry, 0, len(byPath)+1)
	for _, item := range byPath {
		out = append(out, item)
	}

	// 5. Ensure Unigram MSIX entry is present if detected in Packages or running without readable path
	hasUnigram := false
	for i := range out {
		if out[i].Kind == "unigram" {
			hasUnigram = true
			if !out[i].Running && runningByName["unigram.exe"] {
				out[i].Running = true
			}
		}
	}
	if !hasUnigram && (detectUnigramMsixInstalled() || runningByName["unigram.exe"]) {
		out = append(out, config.TelegramClientEntry{
			ID:           "unigram-msix",
			Kind:         "unigram",
			DisplayName:  "Unigram (Microsoft Store)",
			IsMsix:       true,
			Enabled:      true,
			AutoDetected: true,
			Running:      runningByName["unigram.exe"],
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Running != out[j].Running {
			return out[i].Running
		}
		return out[i].DisplayName < out[j].DisplayName
	})
	return out
}

// BuildSocksURI constructs the official Telegram tg://socks deep link for local SOCKS5 configuration.
func BuildSocksURI(port int, authEnabled bool, user, pass string) string {
	if port <= 0 {
		port = 48729
	}
	base := fmt.Sprintf("tg://socks?server=127.0.0.1&port=%d", port)
	if authEnabled && strings.TrimSpace(user) != "" {
		base += "&user=" + url.QueryEscape(user) + "&pass=" + url.QueryEscape(pass)
	}
	return base
}

func shellExecuteOpen(uri string) error {
	verbPtr, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	filePtr, err := windows.UTF16PtrFromString(uri)
	if err != nil {
		return err
	}
	ret, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(filePtr)),
		0,
		0,
		1, // SW_SHOWNORMAL
	)
	if ret <= 32 {
		return fmt.Errorf("ShellExecuteW failed (code %d): %v", ret, callErr)
	}
	return nil
}

// HasTgProtocolHandler checks whether Windows Registry has a registered tg:// protocol handler.
func HasTgProtocolHandler() bool {
	k, err := registry.OpenKey(registry.CLASSES_ROOT, `tg\shell\open\command`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue("")
	return err == nil && strings.TrimSpace(val) != ""
}

// OpenTgURI opens a tg:// URI via ShellExecuteW only if a tg:// protocol handler is registered.
func OpenTgURI(uri string) error {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(uri)), "tg://") {
		return errors.New("only tg:// URIs are allowed")
	}
	if !HasTgProtocolHandler() {
		return errors.New("tg:// protocol handler is not registered")
	}
	return shellExecuteOpen(uri)
}

// ApplyProxyToClient dispatches tg://socks directly to the targeted Telegram/AyuGram/64Gram/Forkgram executable
// (bypassing broken Windows Registry protocol handlers on Portable instances), or via ShellExecuteW for MSIX Unigram.
func ApplyProxyToClient(entry config.TelegramClientEntry, tgURI string) (ApplyResult, error) {
	if strings.TrimSpace(tgURI) == "" {
		return ApplyResult{}, errors.New("empty tg://socks URI")
	}
	if entry.IsMsix || strings.TrimSpace(entry.ExePath) == "" {
		if err := shellExecuteOpen(tgURI); err != nil {
			return ApplyResult{
				Dispatched:           false,
				UsedRegistryProtocol: true,
				NeedsManualPasteNote: true,
				Message:              err.Error(),
			}, err
		}
		return ApplyResult{
			Dispatched:           true,
			UsedRegistryProtocol: true,
			NeedsManualPasteNote: true,
		}, nil
	}

	if !fileExists(entry.ExePath) {
		return ApplyResult{}, fmt.Errorf("executable not found: %s", entry.ExePath)
	}
	cmd := exec.Command(entry.ExePath, "--", tgURI)
	cmd.Dir = filepath.Dir(entry.ExePath)
	if err := cmd.Start(); err != nil {
		return ApplyResult{}, fmt.Errorf("failed launching %s: %w", filepath.Base(entry.ExePath), err)
	}
	// Release process handle so child runs independently without becoming a zombie
	go func() {
		_ = cmd.Wait()
	}()
	return ApplyResult{
		Dispatched:           true,
		UsedRegistryProtocol: false,
	}, nil
}

// WatcherEvent reports changes in running Telegram client instances for Auto-Connect / Auto-Disconnect.
type WatcherEvent struct {
	Clients            []config.TelegramClientEntry
	RunningCount       int
	FirstClientStarted bool
	AllClientsExited   bool
}

// StartWatcher polls running Telegram processes every 2s until ctx cancels.
func StartWatcher(ctx context.Context, getCustom func() []config.TelegramClientEntry, onEvent func(WatcherEvent)) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	prevRunning := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var custom []config.TelegramClientEntry
			if getCustom != nil {
				custom = getCustom()
			}
			list := DiscoverClients(custom)
			runCnt := 0
			for _, c := range list {
				if c.Enabled && c.Running {
					runCnt++
				}
			}
			ev := WatcherEvent{
				Clients:      list,
				RunningCount: runCnt,
			}
			if prevRunning >= 0 {
				if prevRunning == 0 && runCnt > 0 {
					ev.FirstClientStarted = true
				} else if prevRunning > 0 && runCnt == 0 {
					ev.AllClientsExited = true
				}
			}
			prevRunning = runCnt
			if onEvent != nil {
				onEvent(ev)
			}
		}
	}
}
