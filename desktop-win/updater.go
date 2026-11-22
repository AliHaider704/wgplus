package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"wgbridge"
)

// AppVersion must match the release tag (without "v") of this build.
const AppVersion = "1.8.0"

// GetAppVersion returns the running desktop app version string.
func (a *App) GetAppVersion() string {
	return AppVersion
}

const (
	releasesAPI    = "https://api.github.com/repos/AliHaider704/wgplus/releases/"
	windowsAssetNm = "WireGuardPlus-Windows-x64.exe"
	lastSeenFile   = "last_seen_version"
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
