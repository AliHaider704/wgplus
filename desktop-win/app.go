package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"wgbridge"
	"wgplus-win/internal/clients"
	"wgplus-win/internal/config"
	"wgplus-win/internal/guard"
	"wgplus-win/internal/qr"
	"wgplus-win/internal/syswin"
	"wgplus-win/internal/vault"
	"wgplus-win/internal/warp"
	"wgplus-win/internal/watchdog"
)

const historyCap = 60

// ClientTrafficStat mirrors wgbridge detailed client counters for typed Wails bindings.
type ClientTrafficStat struct {
	Label        string `json:"label"`
	ActiveConns  int64  `json:"activeConns"`
	RxBytes      uint64 `json:"rxBytes"`
	TxBytes      uint64 `json:"txBytes"`
	LastSeenUnix int64  `json:"lastSeenUnix"`
}

// BridgeStats mirrors wgbridge.GetDetailedStatsJSON output.
type BridgeStats struct {
	Running              bool                `json:"running"`
	KillSwitch           bool                `json:"killSwitch"`
	SocksPort            int                 `json:"socksPort"`
	HttpPort             int                 `json:"httpPort"`
	RxBytes              uint64              `json:"rxBytes"`
	TxBytes              uint64              `json:"txBytes"`
	RxBps                uint64              `json:"rxBps"`
	TxBps                uint64              `json:"txBps"`
	HandshakeAgeSec      int64               `json:"handshakeAgeSec"`
	LastHandshakeUnix    int64               `json:"lastHandshakeUnix"`
	ActiveTcpConns       int64               `json:"activeTcpConns"`
	ActiveUdpAssocs      int64               `json:"activeUdpAssocs"`
	BlockedLocalAttempts uint64              `json:"blockedLocalAttempts"`
	ResolvedEndpoint     string              `json:"resolvedEndpoint"`
	Clients              []ClientTrafficStat `json:"clients"`
}

// BootstrapState is the complete UI hydration payload.
type BootstrapState struct {
	Settings        config.AppSettings           `json:"settings"`
	Profiles        []config.ServerProfile       `json:"profiles"`
	Clients         []config.TelegramClientEntry `json:"clients"`
	PortableMode    bool                         `json:"portableMode"`
	DataDir         string                       `json:"dataDir"`
	Connected       bool                         `json:"connected"`
	Connecting      bool                         `json:"connecting"`
	ActiveProfileID string                       `json:"activeProfileId"`
	LastError       string                       `json:"lastError"`
	ProxyURI        string                       `json:"proxyUri"`
	Stats           BridgeStats                  `json:"stats"`
	GuardEvents     []guard.GuardEvent           `json:"guardEvents"`
	RxHistory       []uint64                     `json:"rxHistory"`
	TxHistory       []uint64                     `json:"txHistory"`
}

// TelemetrySnapshot is emitted every second while the main window is visible.
type TelemetrySnapshot struct {
	Connected       bool                         `json:"connected"`
	Connecting      bool                         `json:"connecting"`
	ActiveProfileID string                       `json:"activeProfileId"`
	LastError       string                       `json:"lastError"`
	Stats           BridgeStats                  `json:"stats"`
	Clients         []config.TelegramClientEntry `json:"clients"`
	GuardEvents     []guard.GuardEvent           `json:"guardEvents"`
	RxHistory       []uint64                     `json:"rxHistory"`
	TxHistory       []uint64                     `json:"txHistory"`
}

// App coordinates the Go WireGuard engine, Windows Process Guard, DPAPI Vault,
// Telegram client dispatcher, Win32 tray/power host, and Wails frontend.
type App struct {
	ctx        context.Context
	bgCtx      context.Context
	bgCancel   context.CancelFunc
	mu         sync.Mutex
	connectMu  sync.Mutex
	store      *vault.Store
	state      config.PersistedState
	procGuard  *guard.ProcessGuard
	trayHost   *syswin.Host
	failover   *watchdog.Monitor
	clients    []config.TelegramClientEntry
	connected  bool
	connecting bool
	activeID   string
	startedAt  time.Time
	lastError  string
	rxHistory  []uint64
	txHistory  []uint64

	windowVisible atomic.Bool
	quitting      atomic.Bool
	startHidden   bool
	pendingConf   string
	manualStop    atomic.Bool
}

// NewApp initializes the DPAPI vault and Windows Process Guard prior to Wails startup.
func NewApp(startHidden bool) (*App, error) {
	store, err := vault.NewStore()
	if err != nil {
		return nil, err
	}
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	pg := guard.NewProcessGuard()

	a := &App{
		store:       store,
		state:       st,
		procGuard:   pg,
		startHidden: startHidden,
		rxHistory:   make([]uint64, 0, historyCap),
		txHistory:   make([]uint64, 0, historyCap),
	}
	a.windowVisible.Store(!startHidden)
	a.clients = clients.DiscoverClients(st.CustomClients)
	pg.UpdateAllowedClients(a.clients)
	pg.SetMode(st.Settings.ProcessGuardMode)
	return a, nil
}

func (a *App) SetPendingImportPath(p string) {
	a.mu.Lock()
	a.pendingConf = p
	a.mu.Unlock()
}

func (a *App) DataDir() string {
	return a.store.DataDir()
}

func (a *App) WebviewDataDir() string {
	return a.store.WebviewDir()
}

func (a *App) ShouldMinimizeToTray() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.Settings.MinimizeToTray
}

// RunSelfCheck executes a headless smoke check of vault, process guard, client detection,
// and fail-closed Kill Switch loopback mux, returning JSON status and exiting cleanly.
func (a *App) RunSelfCheck() (string, error) {
	wgbridge.SetDesktopMode(true)
	wgbridge.SetPreferredMuxPort(a.state.Settings.SocksPort)
	wgbridge.SetBlockIPv6(a.state.Settings.BlockIPv6)
	if a.state.Settings.SocksAuthEnabled {
		wgbridge.SetSocksAuth(a.state.Settings.SocksUser, a.state.Settings.SocksPass)
	}
	wgbridge.SetClientGuard(a.procGuard.CheckTcpClient)
	wgbridge.SetUdpPeerGuard(a.procGuard.CheckUdpPeer)

	ksPort, err := wgbridge.StartKillSwitchGuard()
	if err != nil {
		return "", fmt.Errorf("StartKillSwitchGuard failed: %w", err)
	}
	a.procGuard.SetMonitoredPorts(ksPort)
	statsRaw := wgbridge.GetDetailedStatsJSON()
	wgbridge.StopKillSwitchGuard()
	wgbridge.SetClientGuard(nil)
	wgbridge.SetUdpPeerGuard(nil)
	wgbridge.SetSocksAuth("", "")

	out := map[string]any{
		"ok":              ksPort > 0,
		"portableMode":    a.store.IsPortable(),
		"dataDir":         a.store.DataDir(),
		"socksPort":       ksPort,
		"clientsDetected": len(a.clients),
		"profilesCount":   len(a.state.Profiles),
		"statsPreview":    json.RawMessage(statsRaw),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.bgCtx, a.bgCancel = context.WithCancel(context.Background())

	wgbridge.SetDesktopMode(true)
	a.applyCoreSettings()

	wgbridge.SetClientGuard(a.procGuard.CheckTcpClient)
	wgbridge.SetUdpPeerGuard(a.procGuard.CheckUdpPeer)

	a.mu.Lock()
	ks := a.state.Settings.KillSwitch
	httpOn := a.state.Settings.HttpProxyEnabled
	httpPort := a.state.Settings.HttpProxyPort
	pending := a.pendingConf
	a.pendingConf = ""
	a.mu.Unlock()

	if ks {
		_, _ = wgbridge.StartKillSwitchGuard()
	}
	if httpOn {
		_, _ = wgbridge.StartHttpProxy(httpPort)
	}
	a.syncMonitoredPorts()

	a.failover = watchdog.NewMonitor(watchdog.Dependencies{
		IsRunning: func() bool {
			return wgbridge.IsRunning()
		},
		TunnelUptime: func() time.Duration {
			a.mu.Lock()
			st := a.startedAt
			up := a.connected
			a.mu.Unlock()
			if !up || st.IsZero() {
				return 0
			}
			return time.Since(st)
		},
		SnapshotStats: func() (int64, uint64) {
			st := a.readBridgeStats()
			return st.HandshakeAgeSec, st.TxBytes
		},
		ForceRebind: func() bool {
			return wgbridge.ForceRebindAndHandshake()
		},
		SetPending: func(p bool) {
			wgbridge.SetTunnelStartupPending(p)
		},
		ListProfiles: func() (string, []config.ServerProfile) {
			a.mu.Lock()
			defer a.mu.Unlock()
			cp := make([]config.ServerProfile, len(a.state.Profiles))
			copy(cp, a.state.Profiles)
			return a.activeID, cp
		},
		IsAutoFailover: func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.state.Settings.AutoFailover
		},
		ProbeProfile: func(_ context.Context, p config.ServerProfile) (int, error) {
			return wgbridge.ProbeEndpointHandshakeMs(
				p.PrivateKey, p.PresharedKey, p.PeerPublicKey, p.Endpoint, p.AwgParams, p.UseDoH, 3200,
			)
		},
		SwitchToProfile: func(profileID string) error {
			return a.Connect(profileID)
		},
		OnFailoverSwitch: func(_, toID, toName string, rttMs int) {
			a.emitStateChanged()
			a.refreshTray()
			if a.windowVisible.Load() && a.ctx != nil {
				runtime.EventsEmit(a.ctx, "failover", map[string]any{
					"profileId":   toID,
					"profileName": toName,
					"rttMs":       rttMs,
				})
			}
		},
	}, 5*time.Second)

	host, err := syswin.StartHost(syswin.TrayCallbacks{
		OnOpenWindow:    a.ShowWindow,
		OnToggleTunnel:  a.toggleTunnelFromTray,
		OnSwitchProfile: func(id string) { _ = a.SwitchProfile(id) },
		OnAttachClient:  func(cid string) { _, _ = a.ApplyProxyToClient(cid) },
		OnCopyLink:      func() { _, _ = a.CopyProxyLink() },
		OnQuit:          a.QuitApp,
		OnWake:          a.handleWakeRecovery,
		OnNetworkChange: a.handleNetworkSwitch,
		GetSnapshot:     a.traySnapshot,
	}, true)
	if err == nil {
		a.trayHost = host
	}

	go a.failover.Run(a.bgCtx)
	go a.telemetryLoop(a.bgCtx)
	go clients.StartWatcher(a.bgCtx, func() []config.TelegramClientEntry {
		a.mu.Lock()
		defer a.mu.Unlock()
		cp := make([]config.TelegramClientEntry, len(a.state.CustomClients))
		copy(cp, a.state.CustomClients)
		return cp
	}, a.onClientsWatcherEvent)

	a.syncAutostartRegistry()
	go a.autoConnectOnLaunch()

	if pending != "" {
		if raw, rErr := os.ReadFile(pending); rErr == nil {
			_, _ = a.ImportConfText(string(raw), strings.TrimSuffix(filepath.Base(pending), filepath.Ext(pending)))
			a.ShowWindow()
		}
	}
}

// syncAutostartRegistry keeps the HKCU Run entry aligned with the setting and the current exe path.
func (a *App) syncAutostartRegistry() {
	a.mu.Lock()
	on := a.state.Settings.StartWithWindows
	a.mu.Unlock()
	if exePath, err := os.Executable(); err == nil {
		_ = syswin.SetStartWithWindows(on, exePath)
	}
}

func (a *App) activeConnectTarget() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := a.state.Settings.ActiveProfileID
	if id == "" && len(a.state.Profiles) > 0 {
		id = a.state.Profiles[0].ID
	}
	return id
}

// autoConnectOnLaunch connects the active profile at app start, retrying while the network is still coming up after boot.
func (a *App) autoConnectOnLaunch() {
	a.mu.Lock()
	on := a.state.Settings.AutoConnectOnLaunch
	a.mu.Unlock()
	if !on {
		return
	}
	for i := 0; i < 20; i++ {
		if a.bgCtx.Err() != nil || a.manualStop.Load() {
			return
		}
		id := a.activeConnectTarget()
		if id == "" {
			return
		}
		a.mu.Lock()
		up := a.connected
		a.mu.Unlock()
		if up {
			return
		}
		if err := a.Connect(id); err == nil {
			return
		}
		select {
		case <-a.bgCtx.Done():
			return
		case <-time.After(6 * time.Second):
		}
	}
}

func (a *App) beforeClose(ctx context.Context) bool {
	if !a.quitting.Load() && a.ShouldMinimizeToTray() {
		a.windowVisible.Store(false)
		runtime.WindowHide(ctx)
		return true
	}
	return false
}

func (a *App) shutdown(_ context.Context) {
	if a.bgCancel != nil {
		a.bgCancel()
	}
	if a.trayHost != nil {
		a.trayHost.Stop()
	}
	wgbridge.StopHttpProxy()
	wgbridge.StopTunnel()
	wgbridge.StopKillSwitchGuard()
	wgbridge.SetClientGuard(nil)
	wgbridge.SetUdpPeerGuard(nil)
}

func (a *App) applyCoreSettings() {
	a.mu.Lock()
	s := a.state.Settings
	a.mu.Unlock()

	wgbridge.SetBlockIPv6(s.BlockIPv6)
	wgbridge.SetPreferredMuxPort(s.SocksPort)
	if s.SocksAuthEnabled && s.SocksUser != "" {
		wgbridge.SetSocksAuth(s.SocksUser, s.SocksPass)
	} else {
		wgbridge.SetSocksAuth("", "")
	}
	_ = wgbridge.SetCustomDoH(s.CustomDoHDialAddr, s.CustomDoHServerName, s.CustomDoHURL)
	a.procGuard.SetMode(s.ProcessGuardMode)
}

func (a *App) syncMonitoredPorts() {
	var ports []int
	if sp := wgbridge.GetActivePort(); sp > 0 {
		ports = append(ports, sp)
	}
	if kp := wgbridge.GetKillSwitchPort(); kp > 0 {
		ports = append(ports, kp)
	}
	if hp := wgbridge.GetHttpProxyPort(); hp > 0 {
		ports = append(ports, hp)
	}
	if len(ports) == 0 {
		a.mu.Lock()
		ports = append(ports, a.state.Settings.SocksPort)
		a.mu.Unlock()
	}
	a.procGuard.SetMonitoredPorts(ports...)
}

func (a *App) readBridgeStats() BridgeStats {
	var st BridgeStats
	_ = json.Unmarshal([]byte(wgbridge.GetDetailedStatsJSON()), &st)
	return st
}

func (a *App) mergeClientTraffic(list []config.TelegramClientEntry, stats BridgeStats) []config.TelegramClientEntry {
	byLabel := make(map[string]ClientTrafficStat, len(stats.Clients))
	for _, c := range stats.Clients {
		byLabel[strings.ToLower(c.Label)] = c
	}
	out := make([]config.TelegramClientEntry, len(list))
	copy(out, list)
	for i := range out {
		exeBase := strings.ToLower(filepath.Base(out[i].ExePath))
		if exeBase == "." || exeBase == "" {
			if out[i].Kind == "unigram" {
				exeBase = "unigram.exe"
			}
		}
		if cs, ok := byLabel[exeBase]; ok {
			out[i].ActiveConns = cs.ActiveConns
			out[i].RxBytes = cs.RxBytes
			out[i].TxBytes = cs.TxBytes
		}
	}
	return out
}

func (a *App) telemetryLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := a.readBridgeStats()
			a.mu.Lock()
			if len(a.rxHistory) >= historyCap {
				a.rxHistory = append(a.rxHistory[1:], stats.RxBps)
			} else {
				a.rxHistory = append(a.rxHistory, stats.RxBps)
			}
			if len(a.txHistory) >= historyCap {
				a.txHistory = append(a.txHistory[1:], stats.TxBps)
			} else {
				a.txHistory = append(a.txHistory, stats.TxBps)
			}
			visible := a.windowVisible.Load() && a.ctx != nil
			if visible {
				snap := TelemetrySnapshot{
					Connected:       a.connected,
					Connecting:      a.connecting,
					ActiveProfileID: a.activeID,
					LastError:       a.lastError,
					Stats:           stats,
					Clients:         a.mergeClientTraffic(a.clients, stats),
					GuardEvents:     a.procGuard.Events(),
					RxHistory:       append([]uint64(nil), a.rxHistory...),
					TxHistory:       append([]uint64(nil), a.txHistory...),
				}
				a.mu.Unlock()
				runtime.EventsEmit(a.ctx, "telemetry", snap)
			} else {
				a.mu.Unlock()
			}
		}
	}
}

func (a *App) onClientsWatcherEvent(ev clients.WatcherEvent) {
	a.mu.Lock()
	a.clients = ev.Clients
	autoConn := a.state.Settings.AutoConnectOnTelegram
	autoDisc := a.state.Settings.DisconnectWhenNoTelegram
	targetID := a.state.Settings.ActiveProfileID
	if targetID == "" && len(a.state.Profiles) > 0 {
		targetID = a.state.Profiles[0].ID
	}
	isConn := a.connected
	isBusy := a.connecting
	a.mu.Unlock()

	a.procGuard.UpdateAllowedClients(ev.Clients)
	a.refreshTray()

	if ev.FirstClientStarted && autoConn && !isConn && !isBusy && targetID != "" {
		go func() {
			_ = a.Connect(targetID)
		}()
	} else if ev.AllClientsExited && autoDisc && isConn {
		go func() {
			_ = a.Disconnect()
		}()
	}
}

func (a *App) handleWakeRecovery() {
	wgbridge.ClearDnsCache()
	a.mu.Lock()
	isUp := a.connected
	a.mu.Unlock()
	if !isUp {
		a.mu.Lock()
		on := a.state.Settings.AutoConnectOnLaunch
		busy := a.connecting
		a.mu.Unlock()
		if on && !busy && !a.manualStop.Load() {
			go a.autoConnectOnLaunch()
		}
		return
	}
	if !wgbridge.ForceRebindAndHandshake() && a.failover != nil && a.bgCtx != nil {
		a.failover.TriggerFailover(a.bgCtx)
	}
	a.syncMonitoredPorts()
	a.refreshTray()
	a.emitStateChanged()
}

func (a *App) handleNetworkSwitch() {
	wgbridge.ClearDnsCache()
	a.mu.Lock()
	isUp := a.connected
	a.mu.Unlock()
	if !isUp {
		return
	}
	_ = wgbridge.ForceRebindAndHandshake()
	a.syncMonitoredPorts()
	a.refreshTray()
}

func (a *App) traySnapshot() (string, syswin.TrayVisualState, string, bool, []syswin.TrayMenuProfile, []syswin.TrayMenuClient) {
	a.mu.Lock()
	lang := a.state.Settings.Language
	conn := a.connected
	ks := a.state.Settings.KillSwitch
	active := a.activeID
	profiles := make([]syswin.TrayMenuProfile, 0, len(a.state.Profiles))
	activeName := ""
	for _, p := range a.state.Profiles {
		if p.ID == active {
			activeName = p.Name
		}
		profiles = append(profiles, syswin.TrayMenuProfile{
			ID:         p.ID,
			Name:       p.Name,
			LastPingMs: p.LastPingMs,
			Active:     p.ID == active,
		})
	}
	clis := make([]syswin.TrayMenuClient, 0, len(a.clients))
	for _, c := range a.clients {
		clis = append(clis, syswin.TrayMenuClient{
			ID:      c.ID,
			Name:    c.DisplayName,
			Running: c.Running,
		})
	}
	a.mu.Unlock()

	vis := syswin.TrayDisconnected
	tip := "WireGuard Plus - Disconnected"
	if conn {
		vis = syswin.TrayConnected
		if activeName != "" {
			tip = "WireGuard Plus - " + activeName
		} else {
			tip = "WireGuard Plus - Connected"
		}
	} else if ks {
		vis = syswin.TrayKillSwitch
		tip = "WireGuard Plus - Kill Switch Guard"
	}
	return lang, vis, tip, conn, profiles, clis
}

func (a *App) refreshTray() {
	if a.trayHost != nil {
		a.trayHost.RefreshTray()
	}
}

func (a *App) emitStateChanged() {
	if a.windowVisible.Load() && a.ctx != nil {
		runtime.EventsEmit(a.ctx, "stateChanged", a.GetBootstrapState())
	}
}

func (a *App) toggleTunnelFromTray() {
	a.mu.Lock()
	conn := a.connected
	targetID := a.activeID
	if targetID == "" {
		targetID = a.state.Settings.ActiveProfileID
	}
	if targetID == "" && len(a.state.Profiles) > 0 {
		targetID = a.state.Profiles[0].ID
	}
	a.mu.Unlock()

	if conn {
		_ = a.Disconnect()
		return
	}
	if targetID != "" {
		_ = a.Connect(targetID)
		return
	}
	a.mu.Lock()
	noProfiles := len(a.state.Profiles) == 0
	a.mu.Unlock()
	if noProfiles {
		_, _ = a.QuickConnectWarp(false)
		return
	}
	a.ShowWindow()
}

// ShowWindow restores the main Wails window from tray or minimized state.
func (a *App) ShowWindow() {
	a.windowVisible.Store(true)
	if a.ctx != nil {
		runtime.WindowUnminimise(a.ctx)
		runtime.WindowShow(a.ctx)
		a.emitStateChanged()
	}
}

// HideToTray hides the main window while keeping the background tunnel alive.
func (a *App) HideToTray() {
	a.windowVisible.Store(false)
	if a.ctx != nil {
		runtime.WindowHide(a.ctx)
	}
}

// QuitApp shuts down the tunnel cleanly and exits the application.
func (a *App) QuitApp() {
	a.quitting.Store(true)
	if a.ctx != nil {
		runtime.Quit(a.ctx)
	}
}

// GetBootstrapState returns the complete initial/refreshed state snapshot for the UI.
func (a *App) GetBootstrapState() BootstrapState {
	stats := a.readBridgeStats()
	a.mu.Lock()
	defer a.mu.Unlock()

	profiles := make([]config.ServerProfile, len(a.state.Profiles))
	copy(profiles, a.state.Profiles)

	return BootstrapState{
		Settings:        a.state.Settings,
		Profiles:        profiles,
		Clients:         a.mergeClientTraffic(a.clients, stats),
		PortableMode:    a.store.IsPortable(),
		DataDir:         a.store.DataDir(),
		Connected:       a.connected,
		Connecting:      a.connecting,
		ActiveProfileID: a.activeID,
		LastError:       a.lastError,
		ProxyURI:        a.GetProxyLinkLocked(),
		Stats:           stats,
		GuardEvents:     a.procGuard.Events(),
		RxHistory:       append([]uint64(nil), a.rxHistory...),
		TxHistory:       append([]uint64(nil), a.txHistory...),
	}
}

func (a *App) GetProxyLinkLocked() string {
	port := wgbridge.GetActivePort()
	if port <= 0 {
		port = wgbridge.GetKillSwitchPort()
	}
	if port <= 0 {
		port = a.state.Settings.SocksPort
	}
	return clients.BuildSocksURI(port, a.state.Settings.SocksAuthEnabled, a.state.Settings.SocksUser, a.state.Settings.SocksPass)
}

func (a *App) GetProxyLink() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.GetProxyLinkLocked()
}

func (a *App) CopyProxyLink() (string, error) {
	uri := a.GetProxyLink()
	if err := syswin.CopyTextToClipboard(uri); err != nil {
		return uri, err
	}
	return uri, nil
}

func (a *App) Connect(profileID string) error {
	a.connectMu.Lock()
	defer a.connectMu.Unlock()
	a.manualStop.Store(false)

	a.mu.Lock()
	var prof *config.ServerProfile
	targetID := strings.TrimSpace(profileID)
	if targetID == "" {
		targetID = a.state.Settings.ActiveProfileID
	}
	for i := range a.state.Profiles {
		if targetID == "" || a.state.Profiles[i].ID == targetID {
			cp := a.state.Profiles[i]
			prof = &cp
			break
		}
	}
	if prof == nil {
		a.mu.Unlock()
		return errors.New("no server profile selected or configured")
	}
	wasConnected := a.connected
	useDoH := a.state.Settings.UseDoH && prof.UseDoH
	ks := a.state.Settings.KillSwitch
	a.connecting = true
	a.lastError = ""
	a.mu.Unlock()

	a.emitStateChanged()
	if wasConnected || ks {
		wgbridge.SetTunnelStartupPending(true)
	}

	a.applyCoreSettings()
	port, err := wgbridge.StartTunnelAdvanced(
		prof.PrivateKey,
		prof.PresharedKey,
		prof.ClientIP,
		prof.DNS,
		prof.PeerPublicKey,
		prof.Endpoint,
		prof.KeepAlive,
		prof.MTU,
		prof.AwgParams,
		useDoH,
	)
	wgbridge.SetTunnelStartupPending(false)

	a.mu.Lock()
	a.connecting = false
	if err != nil {
		a.connected = wgbridge.IsRunning()
		a.lastError = err.Error()
		a.mu.Unlock()
		a.refreshTray()
		a.emitStateChanged()
		return err
	}
	a.connected = true
	a.activeID = prof.ID
	a.startedAt = time.Now()
	a.state.Settings.ActiveProfileID = prof.ID
	if port > 0 {
		a.state.Settings.SocksPort = port
	}
	_ = a.store.Save(a.state)
	a.mu.Unlock()

	a.syncMonitoredPorts()
	a.refreshTray()
	a.emitStateChanged()
	return nil
}

func (a *App) Disconnect() error {
	a.connectMu.Lock()
	defer a.connectMu.Unlock()
	a.manualStop.Store(true)

	wgbridge.StopTunnel()
	a.mu.Lock()
	ks := a.state.Settings.KillSwitch
	a.connected = false
	a.connecting = false
	a.startedAt = time.Time{}
	a.mu.Unlock()

	if ks {
		_, _ = wgbridge.StartKillSwitchGuard()
	}
	a.syncMonitoredPorts()
	a.refreshTray()
	a.emitStateChanged()
	return nil
}

func (a *App) SwitchProfile(profileID string) error {
	return a.Connect(profileID)
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
			a.state.Profiles[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
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
		if isActive {
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
	useDoHGlobal := a.state.Settings.UseDoH
	a.mu.Unlock()
	if target == nil {
		return 0, errors.New("profile not found")
	}

	mtu, err := wgbridge.DiscoverOptimalMTU(
		target.PrivateKey,
		target.PresharedKey,
		target.ClientIP,
		target.DNS,
		target.PeerPublicKey,
		target.Endpoint,
		target.AwgParams,
		useDoHGlobal && target.UseDoH,
		"",
		2600,
	)
	if err != nil {
		return 0, err
	}

	a.mu.Lock()
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			a.state.Profiles[i].MTU = mtu
			break
		}
	}
	_ = a.store.Save(a.state)
	isActive := a.connected && a.activeID == id
	a.mu.Unlock()

	a.emitStateChanged()
	if isActive {
		_ = a.Connect(id)
	}
	return mtu, nil
}

func (a *App) VerifyRouteAndCalls() (string, error) {
	a.mu.Lock()
	s := a.state.Settings
	a.mu.Unlock()
	port := wgbridge.GetActivePort()
	if port <= 0 {
		return "", errors.New("tunnel is not running")
	}
	user, pass := "", ""
	if s.SocksAuthEnabled {
		user, pass = s.SocksUser, s.SocksPass
	}
	return wgbridge.VerifyRouteAndCallsJSON(port, user, pass), nil
}

func (a *App) ScanTelegramClients() []config.TelegramClientEntry {
	a.mu.Lock()
	custom := make([]config.TelegramClientEntry, len(a.state.CustomClients))
	copy(custom, a.state.CustomClients)
	a.mu.Unlock()

	list := clients.DiscoverClients(custom)
	a.mu.Lock()
	a.clients = list
	a.mu.Unlock()
	a.procGuard.UpdateAllowedClients(list)
	a.refreshTray()
	a.emitStateChanged()
	return list
}

func (a *App) AddCustomClientDialog() (*config.TelegramClientEntry, error) {
	if a.ctx == nil {
		return nil, errors.New("window context unavailable")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Portable Telegram Client Executable",
		Filters: []runtime.FileFilter{
			{DisplayName: "Windows Executable (*.exe)", Pattern: "*.exe"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return nil, err
	}
	clean := filepath.Clean(path)
	entry := config.TelegramClientEntry{
		ID:           "custom-" + config.NewRandomID(),
		Kind:         "custom",
		DisplayName:  strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean)),
		ExePath:      clean,
		InstallDir:   filepath.Dir(clean),
		IsPortable:   true,
		Enabled:      true,
		AutoDetected: false,
	}

	a.mu.Lock()
	replaced := false
	for i := range a.state.CustomClients {
		if strings.EqualFold(a.state.CustomClients[i].ExePath, clean) {
			a.state.CustomClients[i].Enabled = true
			replaced = true
			break
		}
	}
	if !replaced {
		a.state.CustomClients = append(a.state.CustomClients, entry)
	}
	err = a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	list := a.ScanTelegramClients()
	for i := range list {
		if strings.EqualFold(list[i].ExePath, clean) {
			cp := list[i]
			return &cp, nil
		}
	}
	return &entry, nil
}

func (a *App) RemoveCustomClient(id string) error {
	a.mu.Lock()
	targetPath := ""
	for _, c := range a.clients {
		if c.ID == id {
			targetPath = c.ExePath
			break
		}
	}
	var kept []config.TelegramClientEntry
	for _, cc := range a.state.CustomClients {
		if cc.ID != id && (targetPath == "" || !strings.EqualFold(cc.ExePath, targetPath)) {
			kept = append(kept, cc)
		}
	}
	a.state.CustomClients = kept
	err := a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	a.ScanTelegramClients()
	return nil
}

func (a *App) ToggleClientEnabled(id string, enabled bool) error {
	a.mu.Lock()
	var target *config.TelegramClientEntry
	for i := range a.clients {
		if a.clients[i].ID == id {
			a.clients[i].Enabled = enabled
			cp := a.clients[i]
			target = &cp
			break
		}
	}
	if target != nil && target.ExePath != "" {
		found := false
		for i := range a.state.CustomClients {
			if strings.EqualFold(a.state.CustomClients[i].ExePath, target.ExePath) {
				a.state.CustomClients[i].Enabled = enabled
				found = true
				break
			}
		}
		if !found {
			a.state.CustomClients = append(a.state.CustomClients, *target)
		}
	}
	err := a.store.Save(a.state)
	clientsSnap := make([]config.TelegramClientEntry, len(a.clients))
	copy(clientsSnap, a.clients)
	a.mu.Unlock()

	a.procGuard.UpdateAllowedClients(clientsSnap)
	a.emitStateChanged()
	return err
}

func (a *App) ApplyProxyToClient(clientID string) (clients.ApplyResult, error) {
	a.mu.Lock()
	var target *config.TelegramClientEntry
	for i := range a.clients {
		if a.clients[i].ID == clientID {
			cp := a.clients[i]
			target = &cp
			break
		}
	}
	uri := a.GetProxyLinkLocked()
	a.mu.Unlock()

	if target == nil {
		return clients.ApplyResult{}, errors.New("Telegram client entry not found")
	}
	res, err := clients.ApplyProxyToClient(*target, uri)
	if res.NeedsManualPasteNote {
		if cErr := syswin.CopyTextToClipboard(uri); cErr == nil {
			res.ClipboardCopied = true
		}
	}
	return res, err
}

func (a *App) UpdateSettings(s config.AppSettings) (config.AppSettings, error) {
	a.mu.Lock()
	prev := a.state.Settings
	if s.SocksPort <= 0 || s.SocksPort > 65535 {
		s.SocksPort = 48729
	}
	if s.HttpProxyPort <= 0 || s.HttpProxyPort > 65535 {
		s.HttpProxyPort = 48739
	}
	if s.Language != "ar" {
		s.Language = "en"
	}
	if s.Theme != "light" {
		s.Theme = "dark"
	}
	if s.ProcessGuardMode != "log_only" {
		s.ProcessGuardMode = "strict"
	}
	if strings.TrimSpace(s.SocksUser) == "" {
		s.SocksUser = prev.SocksUser
	}
	if strings.TrimSpace(s.SocksPass) == "" {
		s.SocksPass = prev.SocksPass
	}
	if s.ActiveProfileID == "" {
		s.ActiveProfileID = prev.ActiveProfileID
	}

	if s.StartWithWindows != prev.StartWithWindows {
		exePath, _ := os.Executable()
		if err := syswin.SetStartWithWindows(s.StartWithWindows, exePath); err != nil {
			a.mu.Unlock()
			return prev, err
		}
	}

	a.state.Settings = s
	if err := a.store.Save(a.state); err != nil {
		a.mu.Unlock()
		return prev, err
	}
	isConn := a.connected
	a.mu.Unlock()

	a.applyCoreSettings()

	if !isConn {
		if s.SocksPort != prev.SocksPort {
			wgbridge.StopKillSwitchGuard()
		}
		if s.KillSwitch {
			_, _ = wgbridge.StartKillSwitchGuard()
		} else {
			wgbridge.StopKillSwitchGuard()
		}
	} else if !s.KillSwitch {
		wgbridge.StopKillSwitchGuard()
	}

	if s.HttpProxyEnabled {
		if _, err := wgbridge.StartHttpProxy(s.HttpProxyPort); err != nil {
			return s, err
		}
	} else {
		wgbridge.StopHttpProxy()
	}

	a.syncMonitoredPorts()
	a.refreshTray()
	a.emitStateChanged()
	return s, nil
}

func (a *App) RegenerateSocksCredentials() (config.AppSettings, error) {
	a.mu.Lock()
	s := a.state.Settings
	s.SocksUser = "wgp_" + vault.GenerateRandomCredential(8)
	s.SocksPass = vault.GenerateRandomCredential(22)
	a.state.Settings = s
	err := a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return s, err
	}
	a.applyCoreSettings()
	a.emitStateChanged()
	return s, nil
}

func (a *App) GetGuardEvents() []guard.GuardEvent {
	return a.procGuard.Events()
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
