package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AppVersion must match the release tag (without "v") of this build.
const AppVersion = "1.7.9"

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
	ReleaseNotes
}

func fetchRelease(path string) (*ReleaseNotes, error) {
	c := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", releasesAPI+path, nil)
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
	n, err := fetchRelease("latest")
	if err != nil || !versionNewer(n.Version, AppVersion) {
		return UpdateInfo{}
	}
	return UpdateInfo{Available: true, ReleaseNotes: *n}
}

// GetWhatsNew returns notes for the running version once after each update, else nil.
func (a *App) GetWhatsNew() *ReleaseNotes {
	p := filepath.Join(a.store.DataDir(), lastSeenFile)
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == AppVersion {
		return nil
	}
	n, err := fetchRelease("tags/v" + AppVersion)
	if err != nil {
		return nil // retry next launch
	}
	return n
}

// AckWhatsNew records that the current version's notes were shown.
func (a *App) AckWhatsNew() {
	_ = os.WriteFile(filepath.Join(a.store.DataDir(), lastSeenFile), []byte(AppVersion), 0o600)
}
