package main

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"wgbridge"
	"wgplus-win/internal/config"
	"wgplus-win/internal/qr"
	"wgplus-win/internal/syswin"
	"wgplus-win/internal/vault"
	"wgplus-win/internal/warp"
)

func isLikelyWarpProfile(p config.ServerProfile) bool {
	if p.IsWarp {
		return true
	}
	lowName := strings.ToLower(strings.TrimSpace(p.Name))
	if strings.Contains(lowName, "warp") {
		return true
	}
	lowEp := strings.ToLower(strings.TrimSpace(p.Endpoint))
	if strings.Contains(lowEp, "cloudflareclient") {
		return true
	}
	host := lowEp
	if idx := strings.LastIndexByte(lowEp, ':'); idx > 0 && !strings.Contains(lowEp[idx:], "]") {
		host = strings.Trim(lowEp[:idx], "[]")
	}
	return strings.HasPrefix(host, "162.159.192.") ||
		strings.HasPrefix(host, "162.159.193.") ||
		strings.HasPrefix(host, "162.159.195.") ||
		strings.HasPrefix(host, "162.159.204.")
}

func extractAwgReserved(awgParams string) string {
	tokens := strings.FieldsFunc(awgParams, func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r'
	})
	for _, tok := range tokens {
		trimmed := strings.TrimSpace(tok)
		if trimmed == "" {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(trimmed[:eq]), "reserved") {
			val := strings.TrimSpace(trimmed[eq+1:])
			if val != "" {
				return "Reserved=" + val
			}
		}
	}
	return ""
}

func appendAwgReservedToken(awgParams string, reservedToken string) string {
	if reservedToken == "" || extractAwgReserved(awgParams) != "" {
		return awgParams
	}
	trimmed := strings.TrimSpace(awgParams)
	if trimmed == "" {
		return reservedToken
	}
	if strings.Contains(trimmed, "\n") {
		return strings.TrimRight(trimmed, "\r\n") + "\n" + reservedToken
	}
	return strings.TrimRight(trimmed, "; ") + ";" + reservedToken
}

func (a *App) repairCorruptedProfiles() {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for i := range a.state.Profiles {
		if isLikelyWarpProfile(a.state.Profiles[i]) && !a.state.Profiles[i].IsWarp {
			a.state.Profiles[i].IsWarp = true
			changed = true
		}
	}
	if changed && a.store != nil {
		_ = a.store.Save(a.state)
	}
}

func (a *App) SaveProfile(p config.ServerProfile) (config.ServerProfile, error) {
	if strings.TrimSpace(p.PrivateKey) == "" || strings.TrimSpace(p.PeerPublicKey) == "" || strings.TrimSpace(p.Endpoint) == "" {
		return p, errors.New("PrivateKey, PeerPublicKey, and Endpoint are required")
	}
	if strings.TrimSpace(p.ClientIP) == "" {
		p.ClientIP = "10.0.0.2/32"
	}
	if strings.TrimSpace(p.DNS) == "" {
		p.DNS = "1.1.1.1"
	}
	if p.MTU <= 0 {
		p.MTU = 1280
	}
	if p.KeepAlive < 0 {
		p.KeepAlive = 25
	}
	if strings.TrimSpace(p.Name) == "" {
		p.Name = "WireGuard Server"
	}
	if strings.TrimSpace(p.ID) == "" {
		p.ID = config.NewRandomID()
	}

	a.mu.Lock()
	replaced := false
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == p.ID {
			prev := a.state.Profiles[i]
			p.IsWarp = p.IsWarp || prev.IsWarp || isLikelyWarpProfile(p)
			if p.LastPingMs == 0 && prev.LastPingMs != 0 && strings.EqualFold(strings.TrimSpace(prev.Endpoint), strings.TrimSpace(p.Endpoint)) {
				p.LastPingMs = prev.LastPingMs
			}
			if p.IsWarp || prev.IsWarp {
				if prevRes := extractAwgReserved(prev.AwgParams); prevRes != "" && extractAwgReserved(p.AwgParams) == "" {
					p.AwgParams = appendAwgReservedToken(p.AwgParams, prevRes)
				}
			}
			a.state.Profiles[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		if isLikelyWarpProfile(p) {
			p.IsWarp = true
		}
		a.state.Profiles = append(a.state.Profiles, p)
	}
	if a.state.Settings.ActiveProfileID == "" {
		a.state.Settings.ActiveProfileID = p.ID
	}
	err := a.store.Save(a.state)
	isActive := a.connected && a.activeID == p.ID
	a.mu.Unlock()

	if err != nil {
		return p, err
	}
	a.refreshTray()
	a.emitStateChanged()
	if isActive {
		_ = a.Connect(p.ID)
	}
	return p, nil
}

func (a *App) DeleteProfile(id string) error {
	a.mu.Lock()
	var filtered []config.ServerProfile
	for _, p := range a.state.Profiles {
		if p.ID != id {
			filtered = append(filtered, p)
		}
	}
	a.state.Profiles = filtered
	wasActive := a.activeID == id && a.connected
	if a.state.Settings.ActiveProfileID == id {
		if len(filtered) > 0 {
			a.state.Settings.ActiveProfileID = filtered[0].ID
		} else {
			a.state.Settings.ActiveProfileID = ""
		}
	}
	if a.activeID == id {
		a.activeID = a.state.Settings.ActiveProfileID
	}
	err := a.store.Save(a.state)
	a.mu.Unlock()

	if wasActive {
		_ = a.Disconnect()
	} else {
		a.refreshTray()
		a.emitStateChanged()
	}
	return err
}

func (a *App) ImportConfText(raw string, customName string) (config.ServerProfile, error) {
	prof, err := config.ParseWgConf(raw, customName)
	if err != nil {
		return prof, err
	}
	return a.SaveProfile(prof)
}

func (a *App) ImportConfFileDialog() (*config.ServerProfile, error) {
	if a.ctx == nil {
		return nil, errors.New("window context unavailable")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Import WireGuard / AmneziaWG Configuration",
		Filters: []runtime.FileFilter{
			{DisplayName: "WireGuard Config (*.conf)", Pattern: "*.conf"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	prof, err := a.ImportConfText(string(raw), baseName)
	if err != nil {
		return nil, err
	}
	return &prof, nil
}

func (a *App) ExportConfFileDialog(id string) (bool, error) {
	a.mu.Lock()
	var target *config.ServerProfile
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			cp := a.state.Profiles[i]
			target = &cp
			break
		}
	}
	a.mu.Unlock()
	if target == nil {
		return false, errors.New("profile not found")
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export WireGuard Configuration",
		DefaultFilename: sanitizeFileName(target.Name) + ".conf",
		Filters: []runtime.FileFilter{
			{DisplayName: "WireGuard Config (*.conf)", Pattern: "*.conf"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return false, err
	}
	return true, os.WriteFile(path, []byte(config.ExportWgConf(*target)), 0600)
}

func sanitizeFileName(s string) string {
	clean := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) {
			return '-'
		}
		return r
	}, strings.TrimSpace(s))
	if clean == "" {
		return "wgplus-server"
	}
	return clean
}

func (a *App) ImportQRFileDialog() (*config.ServerProfile, error) {
	if a.ctx == nil {
		return nil, errors.New("window context unavailable")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Import WireGuard QR Image",
		Filters: []runtime.FileFilter{
			{DisplayName: "Images (*.png;*.jpg;*.jpeg;*.bmp)", Pattern: "*.png;*.jpg;*.jpeg;*.bmp"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text, err := qr.DecodeQRFromBytes(raw)
	if err != nil {
		return nil, err
	}
	baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	prof, err := a.ImportConfText(text, baseName)
	if err != nil {
		return nil, err
	}
	return &prof, nil
}

func (a *App) ImportQRBytesBase64(b64Data string, defaultName string) (config.ServerProfile, error) {
	clean := strings.TrimSpace(b64Data)
	if comma := strings.IndexByte(clean, ','); comma >= 0 && strings.HasPrefix(clean[:comma], "data:") {
		clean = clean[comma+1:]
	}
	imgBytes, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return config.ServerProfile{}, err
	}
	text, err := qr.DecodeQRFromBytes(imgBytes)
	if err != nil {
		return config.ServerProfile{}, err
	}
	return a.ImportConfText(text, defaultName)
}

func (a *App) ImportQRFromClipboard() (*config.ServerProfile, error) {
	text, err := qr.DecodeQRFromClipboardWindows()
	if err != nil {
		return nil, err
	}
	prof, err := a.ImportConfText(text, "Clipboard QR")
	if err != nil {
		return nil, err
	}
	return &prof, nil
}

func (a *App) ExportProfileQR(id string) (string, error) {
	a.mu.Lock()
	var target *config.ServerProfile
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			cp := a.state.Profiles[i]
			target = &cp
			break
		}
	}
	a.mu.Unlock()
	if target == nil {
		return "", errors.New("profile not found")
	}
	return qr.EncodeConfToPNGDataURL(config.ExportWgConf(*target))
}

func (a *App) GetAwgPreset(name string) string {
	return wgbridge.GetAwgPreset(name)
}

// QuickConnectWarpResult summarizes the outcome of 1-click Free WARP (AWG 1.5) provisioning and binding.
type QuickConnectWarpResult struct {
	Profile         config.ServerProfile `json:"profile"`
	CreatedNew      bool                 `json:"createdNew"`
	AppliedClients  []string             `json:"appliedClients"`
	ClipboardCopied bool                 `json:"clipboardCopied"`
	ProxyURI        string               `json:"proxyUri"`
}

func findReusableWarpProfile(profiles []config.ServerProfile) (config.ServerProfile, bool) {
	for _, p := range profiles {
		if p.IsWarp &&
			strings.TrimSpace(p.PrivateKey) != "" &&
			strings.TrimSpace(p.PeerPublicKey) != "" &&
			strings.TrimSpace(p.Endpoint) != "" {
			return p, true
		}
	}
	return config.ServerProfile{}, false
}

func selectQuickWarpTargetClients(list []config.TelegramClientEntry) []config.TelegramClientEntry {
	var running []config.TelegramClientEntry
	var firstEnabled *config.TelegramClientEntry
	for i := range list {
		c := list[i]
		if !c.Enabled {
			continue
		}
		if c.Running {
			running = append(running, c)
		}
		if firstEnabled == nil {
			cp := c
			firstEnabled = &cp
		}
	}
	if len(running) > 0 {
		return running
	}
	if firstEnabled != nil {
		return []config.TelegramClientEntry{*firstEnabled}
	}
	return nil
}

func (a *App) GenerateWarpProfile() (config.ServerProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	prof, err := warp.GenerateProfile(ctx)
	if err != nil {
		return prof, err
	}
	return a.SaveProfile(prof)
}

// QuickConnectWarp provisions (or reuses) a Cloudflare WARP + AWG 1.5 profile, connects the tunnel,
// and dispatches the local SOCKS5 proxy to active Telegram desktop clients in one click.
func (a *App) QuickConnectWarp(forceNew bool) (QuickConnectWarpResult, error) {
	var prof config.ServerProfile
	createdNew := false

	if !forceNew {
		a.mu.Lock()
		if existing, ok := findReusableWarpProfile(a.state.Profiles); ok {
			prof = existing
		}
		a.mu.Unlock()
	}

	if prof.ID == "" {
		var err error
		prof, err = a.GenerateWarpProfile()
		if err != nil {
			return QuickConnectWarpResult{}, err
		}
		createdNew = true
	}

	if err := a.Connect(prof.ID); err != nil {
		return QuickConnectWarpResult{}, err
	}

	proxyURI := a.GetProxyLink()
	clientsList := a.ScanTelegramClients()
	targets := selectQuickWarpTargetClients(clientsList)

	applied := make([]string, 0, len(targets))
	clipboardCopied := false
	for _, c := range targets {
		res, applyErr := a.ApplyProxyToClient(c.ID)
		if applyErr == nil && res.Dispatched {
			applied = append(applied, c.DisplayName)
			if res.ClipboardCopied {
				clipboardCopied = true
			}
		}
	}

	if len(applied) == 0 && strings.TrimSpace(proxyURI) != "" {
		if err := syswin.CopyTextToClipboard(proxyURI); err == nil {
			clipboardCopied = true
		}
	}

	a.mu.Lock()
	for _, p := range a.state.Profiles {
		if p.ID == prof.ID {
			prof = p
			break
		}
	}
	a.mu.Unlock()

	return QuickConnectWarpResult{
		Profile:         prof,
		CreatedNew:      createdNew,
		AppliedClients:  applied,
		ClipboardCopied: clipboardCopied,
		ProxyURI:        proxyURI,
	}, nil
}

func (a *App) PingProfile(id string) (int, error) {
	a.mu.Lock()
	var target *config.ServerProfile
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			cp := a.state.Profiles[i]
			target = &cp
			break
		}
	}
	useDoHGlobal := a.state.Settings.UseDoH
	a.mu.Unlock()
	if target == nil {
		return -1, errors.New("profile not found")
	}

	ms, err := wgbridge.ProbeEndpointHandshakeMs(
		target.PrivateKey,
		target.PresharedKey,
		target.PeerPublicKey,
		target.Endpoint,
		target.AwgParams,
		useDoHGlobal && target.UseDoH,
		3500,
	)
	pingVal := ms
	if err != nil {
		pingVal = -1
	}

	a.mu.Lock()
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			a.state.Profiles[i].LastPingMs = pingVal
			break
		}
	}
	_ = a.store.Save(a.state)
	a.mu.Unlock()
	a.refreshTray()
	a.emitStateChanged()
	return pingVal, err
}

func (a *App) PingAllProfiles() ([]config.ServerProfile, error) {
	a.mu.Lock()
	profiles := make([]config.ServerProfile, len(a.state.Profiles))
	copy(profiles, a.state.Profiles)
	useDoHGlobal := a.state.Settings.UseDoH
	a.mu.Unlock()

	var wg sync.WaitGroup
	results := make([]int, len(profiles))
	for i, p := range profiles {
		wg.Add(1)
		go func(idx int, prof config.ServerProfile) {
			defer wg.Done()
			ms, err := wgbridge.ProbeEndpointHandshakeMs(
				prof.PrivateKey, prof.PresharedKey, prof.PeerPublicKey, prof.Endpoint, prof.AwgParams, useDoHGlobal && prof.UseDoH, 3200,
			)
			if err != nil {
				results[idx] = -1
			} else {
				results[idx] = ms
			}
		}(i, p)
	}
	wg.Wait()

	a.mu.Lock()
	for i, p := range profiles {
		for j := range a.state.Profiles {
			if a.state.Profiles[j].ID == p.ID {
				a.state.Profiles[j].LastPingMs = results[i]
			}
		}
	}
	_ = a.store.Save(a.state)
	out := make([]config.ServerProfile, len(a.state.Profiles))
	copy(out, a.state.Profiles)
	a.mu.Unlock()

	a.refreshTray()
	a.emitStateChanged()
	return out, nil
}

func (a *App) DiscoverOptimalMTUForProfile(prof config.ServerProfile) (int, error) {
	if strings.TrimSpace(prof.PrivateKey) == "" || strings.TrimSpace(prof.PeerPublicKey) == "" || strings.TrimSpace(prof.Endpoint) == "" {
		return 0, errors.New("PrivateKey, PeerPublicKey, and Endpoint are required")
	}
	if strings.TrimSpace(prof.ClientIP) == "" {
		prof.ClientIP = "10.0.0.2/32"
	}
	if strings.TrimSpace(prof.DNS) == "" {
		prof.DNS = "1.1.1.1"
	}
	a.mu.Lock()
	useDoHGlobal := a.state.Settings.UseDoH
	a.mu.Unlock()

	mtu, err := wgbridge.DiscoverOptimalMTU(
		prof.PrivateKey,
		prof.PresharedKey,
		prof.ClientIP,
		prof.DNS,
		prof.PeerPublicKey,
		prof.Endpoint,
		prof.AwgParams,
		useDoHGlobal && prof.UseDoH,
		"",
		2600,
	)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(prof.ID) != "" {
		a.mu.Lock()
		for i := range a.state.Profiles {
			if a.state.Profiles[i].ID == prof.ID {
				a.state.Profiles[i].MTU = mtu
				break
			}
		}
		_ = a.store.Save(a.state)
		isActive := a.connected && a.activeID == prof.ID
		a.mu.Unlock()
		a.emitStateChanged()
		if isActive && (!wgbridge.IsHandshakeHealthy() || wgbridge.GetActiveMTU() != mtu) {
			_ = a.Connect(prof.ID)
		}
	}
	return mtu, nil
}

func (a *App) DiscoverOptimalMTU(id string) (int, error) {
	a.mu.Lock()
	var target *config.ServerProfile
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			cp := a.state.Profiles[i]
			target = &cp
			break
		}
	}
	a.mu.Unlock()
	if target == nil {
		return 0, errors.New("profile not found")
	}
	return a.DiscoverOptimalMTUForProfile(*target)
}

func (a *App) ExportEncryptedBackupDialog(passphrase string) (bool, error) {
	if a.ctx == nil {
		return false, errors.New("window context unavailable")
	}
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()

	blob, err := vault.ExportEncryptedBackup(st, passphrase)
	if err != nil {
		return false, err
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export Encrypted Portable Backup",
		DefaultFilename: "wireguard-plus-backup.wgplus",
		Filters: []runtime.FileFilter{
			{DisplayName: "WireGuard Plus Backup (*.wgplus)", Pattern: "*.wgplus"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return false, err
	}
	return true, os.WriteFile(path, blob, 0600)
}

func (a *App) ImportEncryptedBackupDialog(passphrase string) (BootstrapState, error) {
	if a.ctx == nil {
		return BootstrapState{}, errors.New("window context unavailable")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Import Encrypted Portable Backup",
		Filters: []runtime.FileFilter{
			{DisplayName: "WireGuard Plus Backup (*.wgplus)", Pattern: "*.wgplus"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return a.GetBootstrapState(), err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return BootstrapState{}, err
	}
	imported, err := vault.ImportEncryptedBackup(raw, passphrase)
	if err != nil {
		return BootstrapState{}, err
	}

	a.mu.Lock()
	a.state.Profiles = imported.Profiles
	a.state.CustomClients = imported.CustomClients
	if imported.Settings.ActiveProfileID != "" {
		a.state.Settings.ActiveProfileID = imported.Settings.ActiveProfileID
	}
	err = a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return BootstrapState{}, err
	}
	a.ScanTelegramClients()
	a.emitStateChanged()
	return a.GetBootstrapState(), nil
}
