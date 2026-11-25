package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/windows"
	"wgbridge"
	"wgplus-win/internal/syswin"
	"wgplus-win/internal/vault"
)

// AppVersion must match the release tag (without "v") of this build.
const AppVersion = "2.0.0"

// GetAppVersion returns the running desktop app version string.
func (a *App) GetAppVersion() string {
	return AppVersion
}

const (
	releasesAPI         = "https://api.github.com/repos/AliHaider704/wgplus/releases/"
	windowsAssetNm      = "WireGuardPlus-Windows-x64.exe"
	lastSeenFile        = "last_seen_version"
	runningInstanceFile = "running_instance.json"
)

// ReleaseNotes holds bilingual bullet lists parsed from a release body.
// Convention: bullets after a line containing "[AR]" are Arabic.
type ReleaseNotes struct {
	Version  string   `json:"version"`
	NotesEN  []string `json:"notesEn"`
	NotesAR  []string `json:"notesAr"`
	Download string   `json:"download"`
	Page     string   `json:"page"`
}

// UpdateInfo is returned to the frontend. Available=false when up to date or offline.
type UpdateInfo struct {
	Available bool `json:"available"`
	CheckedOk bool `json:"checkedOk"`
	ReleaseNotes
}

func (a *App) buildUpdaterHTTPClients() []*http.Client {
	clients := []*http.Client{{Timeout: 8 * time.Second}}
	if wgbridge.IsRunning() {
		port := wgbridge.GetActivePort()
		if port > 0 {
			a.mu.Lock()
			auth := a.state.Settings.SocksAuthEnabled
			user := a.state.Settings.SocksUser
			pass := a.state.Settings.SocksPass
			a.mu.Unlock()
			var authCfg *proxy.Auth
			if auth && strings.TrimSpace(user) != "" {
				authCfg = &proxy.Auth{User: user, Password: pass}
			}
			if dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), authCfg, proxy.Direct); err == nil {
				tr := &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.Dial(network, addr)
					},
				}
				clients = append(clients, &http.Client{Timeout: 10 * time.Second, Transport: tr})
			}
		}
	}
	return clients
}

func fetchReleaseWithClient(c *http.Client, path string) (*ReleaseNotes, error) {
	return fetchReleaseFromURL(c, releasesAPI+path)
}

func fetchReleaseFromURL(c *http.Client, fullURL string) (*ReleaseNotes, error) {
	req, _ := http.NewRequest("GET", fullURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WireGuardPlus/"+AppVersion)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github status %d", resp.StatusCode)
	}
	var r struct {
		Tag    string `json:"tag_name"`
		Body   string `json:"body"`
		URL    string `json:"html_url"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	n := &ReleaseNotes{Version: strings.TrimPrefix(r.Tag, "v"), Page: r.URL, Download: r.URL}
	for _, a := range r.Assets {
		if a.Name == windowsAssetNm {
			n.Download = a.URL
		}
	}
	n.NotesEN, n.NotesAR = parseNotes(r.Body)
	return n, nil
}

func fetchLatestViaRedirect(c *http.Client) (*ReleaseNotes, error) {
	return fetchLatestViaRedirectURL(c, "https://github.com/AliHaider704/wgplus/releases/latest")
}

func fetchLatestViaRedirectURL(c *http.Client, latestURL string) (*ReleaseNotes, error) {
	noRedirectClient := &http.Client{
		Timeout:   c.Timeout,
		Transport: c.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest("GET", latestURL, nil)
	req.Header.Set("User-Agent", "WireGuardPlus/"+AppVersion)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	idx := strings.LastIndex(loc, "/tag/v")
	if idx < 0 {
		return nil, fmt.Errorf("no tag redirect (status %d)", resp.StatusCode)
	}
	ver := strings.TrimSpace(strings.TrimPrefix(loc[idx+len("/tag/v"):], "v"))
	if ver == "" {
		return nil, fmt.Errorf("empty version in redirect")
	}
	return &ReleaseNotes{
		Version:  ver,
		Page:     "https://github.com/AliHaider704/wgplus/releases/tag/v" + ver,
		Download: "https://github.com/AliHaider704/wgplus/releases/download/v" + ver + "/" + windowsAssetNm,
	}, nil
}

func fetchRelease(path string, clients ...*http.Client) (*ReleaseNotes, error) {
	if len(clients) == 0 {
		clients = []*http.Client{{Timeout: 8 * time.Second}}
	}
	var lastErr error
	for _, c := range clients {
		if n, err := fetchReleaseWithClient(c, path); err == nil {
			return n, nil
		} else {
			lastErr = err
		}
	}
	if path == "latest" {
		for _, c := range clients {
			if n, err := fetchLatestViaRedirect(c); err == nil {
				return n, nil
			} else {
				lastErr = err
			}
		}
	}
	return nil, lastErr
}

func parseNotes(body string) (en, ar []string) {
	inAR := false
	for _, ln := range strings.Split(body, "\n") {
		s := strings.TrimSpace(ln)
		if strings.Contains(s, "[AR]") {
			inAR = true
			continue
		}
		if strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "* ") {
			item := strings.TrimSpace(strings.ReplaceAll(s[2:], "**", ""))
			if inAR {
				ar = append(ar, item)
			} else {
				en = append(en, item)
			}
		}
	}
	if len(ar) == 0 {
		ar = en
	}
	return
}

func versionNewer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// CheckForUpdate fetches the latest release. Fails open (Available=false) when offline.
func (a *App) CheckForUpdate() UpdateInfo {
	n, err := fetchRelease("latest", a.buildUpdaterHTTPClients()...)
	if err != nil {
		return UpdateInfo{}
	}
	if !versionNewer(n.Version, AppVersion) {
		return UpdateInfo{Available: false, CheckedOk: true}
	}
	return UpdateInfo{Available: true, CheckedOk: true, ReleaseNotes: *n}
}

// GetWhatsNew returns notes for the running version once after each update, else nil.
func (a *App) GetWhatsNew() *ReleaseNotes {
	p := filepath.Join(a.store.DataDir(), lastSeenFile)
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == AppVersion {
		return nil
	}
	n, err := fetchRelease("tags/v"+AppVersion, a.buildUpdaterHTTPClients()...)
	if err != nil {
		return nil // retry next launch
	}
	return n
}

// AckWhatsNew records that the current version's notes were shown.
func (a *App) AckWhatsNew() {
	_ = os.WriteFile(filepath.Join(a.store.DataDir(), lastSeenFile), []byte(AppVersion), 0o600)
}

type runningInstanceMeta struct {
	PID     uint32 `json:"pid"`
	ExePath string `json:"exePath"`
	Version string `json:"version"`
}

func (a *App) recordRunningInstance() {
	if a.store == nil {
		return
	}
	exePath, err := os.Executable()
	if err != nil || strings.TrimSpace(exePath) == "" {
		return
	}
	meta := runningInstanceMeta{
		PID:     uint32(os.Getpid()),
		ExePath: filepath.Clean(exePath),
		Version: AppVersion,
	}
	if raw, mErr := json.Marshal(meta); mErr == nil {
		_ = os.WriteFile(filepath.Join(a.store.DataDir(), runningInstanceFile), raw, 0o600)
	}
}

func cleanupOldExecutableSidecars() {
	exePath, err := os.Executable()
	if err != nil || strings.TrimSpace(exePath) == "" {
		return
	}
	clean := filepath.Clean(exePath)
	dir := filepath.Dir(clean)
	_ = os.Remove(clean + ".old")
	_ = os.Remove(clean + ".download")
	if entries, rErr := os.ReadDir(dir); rErr == nil {
		base := filepath.Base(clean)
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			nm := ent.Name()
			if strings.HasPrefix(nm, base+".old.") ||
				(strings.EqualFold(nm, "WireGuardPlus-Windows-x64-new.exe") && !strings.EqualFold(nm, base)) {
				_ = os.Remove(filepath.Join(dir, nm))
			}
		}
	}
}

func copyFileBytes(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// replaceBinaryFileInPlace replaces targetExe atomically while targetExe may still be executing
// using NTFS rename-while-running, cleaning old sidecars cleanly when possible.
func replaceBinaryFileInPlace(targetExe, newFilePath string) error {
	cleanTarget := filepath.Clean(targetExe)
	cleanNew := filepath.Clean(newFilePath)
	oldPath := cleanTarget + ".old"
	_ = os.Remove(oldPath)
	if _, err := os.Stat(oldPath); err == nil {
		oldPath = fmt.Sprintf("%s.old.%d", cleanTarget, time.Now().UnixNano())
	}

	movedOld := false
	if _, err := os.Stat(cleanTarget); err == nil {
		if rErr := os.Rename(cleanTarget, oldPath); rErr != nil {
			return fmt.Errorf("failed moving existing executable out of the way: %w", rErr)
		}
		movedOld = true
	}

	if rErr := os.Rename(cleanNew, cleanTarget); rErr != nil {
		if cErr := copyFileBytes(cleanNew, cleanTarget, 0o755); cErr != nil {
			if movedOld {
				_ = os.Rename(oldPath, cleanTarget)
			}
			return fmt.Errorf("failed placing new executable at target path: %w", cErr)
		}
		_ = os.Remove(cleanNew)
	}
	_ = os.Remove(oldPath)
	return nil
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isProcessAliveWin(pid uint32) bool {
	if pid == 0 || pid == uint32(os.Getpid()) {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// maybeUpgradeInstalledCopyInPlace detects when a newly downloaded WireGuardPlus .exe was launched
// outside an existing installed copy (e.g. from Downloads), replaces the existing copy in-place,
// and starts the updated installed copy cleanly. Returns true when handoff occurred.
func maybeUpgradeInstalledCopyInPlace() bool {
	myExe, err := os.Executable()
	if err != nil || strings.TrimSpace(myExe) == "" {
		return false
	}
	cleanMy := filepath.Clean(myExe)
	dataDir, portable := vault.ResolveDataDir(cleanMy)
	if portable {
		return false
	}
	lowMy := strings.ToLower(cleanMy)
	if strings.Contains(lowMy, `\temp\`) || strings.Contains(lowMy, `\build\bin\`) {
		return false
	}

	var targetExe string
	var targetPid uint32
	if raw, rErr := os.ReadFile(filepath.Join(dataDir, runningInstanceFile)); rErr == nil {
		var meta runningInstanceMeta
		if json.Unmarshal(raw, &meta) == nil && strings.TrimSpace(meta.ExePath) != "" {
			targetExe = filepath.Clean(meta.ExePath)
			targetPid = meta.PID
		}
	}
	if targetExe == "" {
		if regExe := syswin.RegisteredAutostartExe(); regExe != "" {
			targetExe = filepath.Clean(regExe)
		}
	}
	if targetExe == "" || strings.EqualFold(cleanMy, targetExe) {
		return false
	}
	if !strings.Contains(strings.ToLower(filepath.Base(targetExe)), "wireguardplus") {
		return false
	}
	if st, sErr := os.Stat(targetExe); sErr != nil || st.IsDir() {
		return false
	}

	pidAlive := isProcessAliveWin(targetPid)
	fromDownloads := strings.Contains(lowMy, `\downloads\`)
	if !pidAlive && !fromDownloads {
		return false
	}

	myHash, err1 := fileSHA256Hex(cleanMy)
	targetHash, err2 := fileSHA256Hex(targetExe)
	if err1 != nil || err2 != nil || myHash == targetHash {
		return false
	}

	if pidAlive {
		if h, pErr := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, targetPid); pErr == nil {
			_ = windows.TerminateProcess(h, 0)
			_, _ = windows.WaitForSingleObject(h, 5000)
			_ = windows.CloseHandle(h)
		}
		time.Sleep(200 * time.Millisecond)
	}

	staged := targetExe + ".staged"
	if err := copyFileBytes(cleanMy, staged, 0o755); err != nil {
		return false
	}
	if err := replaceBinaryFileInPlace(targetExe, staged); err != nil {
		_ = os.Remove(staged)
		return false
	}

	wantAdmin := isProcessElevated()
	if store, sErr := vault.NewStoreAt(dataDir, false); sErr == nil {
		if pst, lErr := store.Load(); lErr == nil && pst.Settings.AlwaysRunAsAdmin {
			wantAdmin = true
		}
	}
	if err := syswin.SpawnProcessDetached(targetExe, wantAdmin, os.Getpid(), "--in-place-upgraded"); err != nil {
		return false
	}
	return true
}

func downloadBinaryWithClient(c *http.Client, fullURL, dstPath string) error {
	dlClient := &http.Client{
		Timeout:   90 * time.Second,
		Transport: c.Transport,
	}
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "WireGuardPlus/"+AppVersion)
	resp, err := dlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(dstPath)
		return closeErr
	}
	if n < 2*1024*1024 {
		_ = os.Remove(dstPath)
		return errors.New("downloaded binary too small")
	}
	hdr := make([]byte, 2)
	vf, err := os.Open(dstPath)
	if err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	_, rErr := io.ReadFull(vf, hdr)
	_ = vf.Close()
	if rErr != nil || hdr[0] != 'M' || hdr[1] != 'Z' {
		_ = os.Remove(dstPath)
		return errors.New("downloaded file is not a valid Windows executable")
	}
	return nil
}

// ApplySelfUpdate downloads downloadURL and overwrites the running executable in-place,
// then restarts into the updated version cleanly without manual file moving.
func (a *App) ApplySelfUpdate(downloadURL string) error {
	cleanURL := strings.TrimSpace(downloadURL)
	if !strings.HasPrefix(cleanURL, "https://") || !strings.HasSuffix(strings.ToLower(cleanURL), ".exe") {
		if a.ctx != nil && cleanURL != "" {
			runtime.BrowserOpenURL(a.ctx, cleanURL)
		}
		return nil
	}
	exePath, err := os.Executable()
	if err != nil || strings.TrimSpace(exePath) == "" {
		return errors.New("cannot resolve current executable path")
	}
	cleanExe := filepath.Clean(exePath)
	tmpPath := cleanExe + ".download"

	var lastErr error
	for _, client := range a.buildUpdaterHTTPClients() {
		if dErr := downloadBinaryWithClient(client, cleanURL, tmpPath); dErr == nil {
			lastErr = nil
			break
		} else {
			lastErr = dErr
		}
	}
	if lastErr != nil {
		return lastErr
	}

	if err := replaceBinaryFileInPlace(cleanExe, tmpPath); err != nil {
		return err
	}
	if err := syswin.SpawnProcessDetached(cleanExe, a.ShouldAlwaysRunAsAdmin() || isProcessElevated(), os.Getpid()); err != nil {
		return err
	}
	go func() {
		a.QuitApp()
		time.Sleep(1500 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}
