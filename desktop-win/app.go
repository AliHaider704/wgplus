package main

import (
	"context"
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
	"golang.org/x/sys/windows"
	"wgbridge"
	"wgplus-win/internal/clients"
	"wgplus-win/internal/config"
	"wgplus-win/internal/guard"
	"wgplus-win/internal/syswin"
	"wgplus-win/internal/vault"
	"wgplus-win/internal/voiptun"
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
	VoipTunActive        bool                `json:"voipTunActive"`
	IsAdmin              bool                `json:"isAdmin"`
	HandshakeHealthy     bool                `json:"handshakeHealthy"`
	SocksAuthRejectCount int64               `json:"socksAuthRejectCount"`
	ResolvedEndpoint     string              `json:"resolvedEndpoint"`
	ActiveMtu            int                 `json:"activeMtu"`
	Clients              []ClientTrafficStat `json:"clients"`
}

// BootstrapState is the complete UI hydration payload.
type BootstrapState struct {
	Settings           config.AppSettings           `json:"settings"`
	Profiles           []config.ServerProfile       `json:"profiles"`
	Clients            []config.TelegramClientEntry `json:"clients"`
	PortableMode       bool                         `json:"portableMode"`
	DataDir            string                       `json:"dataDir"`
	Connected          bool                         `json:"connected"`
	Connecting         bool                         `json:"connecting"`
	ConnectedSinceUnix int64                        `json:"connectedSinceUnix"`
	ActiveProfileID    string                       `json:"activeProfileId"`
	LastError          string                       `json:"lastError"`
	ProxyURI           string                       `json:"proxyUri"`
	Stats              BridgeStats                  `json:"stats"`
	GuardEvents        []guard.GuardEvent           `json:"guardEvents"`
	RxHistory          []uint64                     `json:"rxHistory"`
	TxHistory          []uint64                     `json:"txHistory"`
}

// TelemetrySnapshot is emitted every second while the main window is visible.
type TelemetrySnapshot struct {
	Connected          bool                         `json:"connected"`
	Connecting         bool                         `json:"connecting"`
	ConnectedSinceUnix int64                        `json:"connectedSinceUnix"`
	ActiveProfileID    string                       `json:"activeProfileId"`
	LastError          string                       `json:"lastError"`
	Stats              BridgeStats                  `json:"stats"`
	Clients            []config.TelegramClientEntry `json:"clients"`
	GuardEvents        []guard.GuardEvent           `json:"guardEvents"`
	RxHistory          []uint64                     `json:"rxHistory"`
	TxHistory          []uint64                     `json:"txHistory"`
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

	windowVisible  atomic.Bool
	quitting       atomic.Bool
	startHidden    bool
	pendingConf    string
	manualStop     atomic.Bool
	networkOffline atomic.Bool
	recoveryGen    atomic.Uint64
	telemetry      telemetryManager
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
	a.repairCorruptedProfiles()
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

	syswin.DisableProcessPowerThrottling()
	wgbridge.SetDesktopMode(true)
	a.runVersionHygiene()
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
		HasNetwork: syswin.HasOutboundIPv4,
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
		SnapshotTrafficStats: func() (int64, uint64, uint64) {
			st := a.readBridgeStats()
			return st.HandshakeAgeSec, st.RxBytes, st.TxBytes
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

	cleanupOldExecutableSidecars()
	a.recordRunningInstance()
	a.syncAutostartRegistry()
	a.checkPreviousCrashOnStartup()
	go a.autoConnectOnLaunch()
	go a.flushPendingTelemetryAsync()

	if pending != "" {
		if raw, rErr := os.ReadFile(pending); rErr == nil {
			_, _ = a.ImportConfText(string(raw), strings.TrimSuffix(filepath.Base(pending), filepath.Ext(pending)))
			a.ShowWindow()
		}
	}
}

// syncAutostartRegistry keeps Windows startup aligned with StartWithWindows and AlwaysRunAsAdmin.
func (a *App) syncAutostartRegistry() {
	a.mu.Lock()
	on := a.state.Settings.StartWithWindows
	alwaysAdmin := a.state.Settings.AlwaysRunAsAdmin
	a.mu.Unlock()
	if exePath, err := os.Executable(); err == nil {
		_ = syswin.SyncStartWithWindows(on, exePath, alwaysAdmin, isProcessElevated())
	}
}

// ShouldAlwaysRunAsAdmin reports whether the user opted into persistent Administrator elevation.
func (a *App) ShouldAlwaysRunAsAdmin() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.Settings.AlwaysRunAsAdmin
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
	wgbridge.StopWindowsVoipTun()
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

func (a *App) runVersionHygiene() {
	if a.store == nil {
		return
	}
	verPath := filepath.Join(a.store.DataDir(), "last_running_version")
	prevRaw, _ := os.ReadFile(verPath)
	prev := strings.TrimSpace(string(prevRaw))
	if prev != AppVersion {
		wgbridge.ResetSocksAuthRejectCount()
		_ = os.WriteFile(verPath, []byte(AppVersion), 0o600)
		wgbridge.RecordDiag("HYGIENE", "VERSION_UPGRADE", fmt.Sprintf("%s->%s", prev, AppVersion))
	}
}

func (a *App) readBridgeStats() BridgeStats {
	var st BridgeStats
	_ = json.Unmarshal([]byte(wgbridge.GetDetailedStatsJSON()), &st)
	st.VoipTunActive = wgbridge.IsWindowsVoipTunActive()
	st.IsAdmin = isProcessElevated()
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
		instLabel := strings.ToLower(guard.ClientLabelForExe(out[i].ExePath, exeBase))
		cs, ok := byLabel[instLabel]
		if !ok && strings.TrimSpace(out[i].ExePath) == "" {
			cs, ok = byLabel[exeBase]
		}
		if ok {
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

	lastHsHealthy := false
	var lastVoipTunRetry time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := a.readBridgeStats()
			if stats.SocksAuthRejectCount >= 3 {
				wgbridge.ResetSocksAuthRejectCount()
				a.applyCoreSettings()
				msg := fmt.Sprintf("rejects=%d", stats.SocksAuthRejectCount)
				wgbridge.RecordDiag("HYGIENE", "SOCKS_AUTH_RESYNC", msg)
				a.reportAnomalyAsync("SOCKS_AUTH_RESYNC", msg)
			}
			a.mu.Lock()
			isConnNow := a.connected
			a.mu.Unlock()
			if isConnNow && stats.IsAdmin && !stats.VoipTunActive && stats.HandshakeHealthy && time.Since(lastVoipTunRetry) >= 8*time.Second {
				lastVoipTunRetry = time.Now()
				go func(dataDir string) {
					if dllPath, dllErr := voiptun.EnsureWintunDLLForApp(dataDir); dllErr == nil {
						if wgbridge.StartWindowsVoipTun(filepath.Dir(dllPath)) == nil {
							a.emitStateChanged()
						}
					}
				}(a.store.DataDir())
			}
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
			hsChanged := a.connected && (stats.HandshakeHealthy != lastHsHealthy)
			if hsChanged {
				lastHsHealthy = stats.HandshakeHealthy
			} else if !a.connected {
				lastHsHealthy = false
			}
			visible := a.windowVisible.Load() && a.ctx != nil
			var snap TelemetrySnapshot
			if visible {
				var sinceUnix int64
				if a.connected && !a.startedAt.IsZero() {
					sinceUnix = a.startedAt.Unix()
				}
				snap = TelemetrySnapshot{
					Connected:          a.connected,
					Connecting:         a.connecting,
					ConnectedSinceUnix: sinceUnix,
					ActiveProfileID:    a.activeID,
					LastError:          a.lastError,
					Stats:              stats,
					Clients:            a.mergeClientTraffic(a.clients, stats),
					GuardEvents:        a.procGuard.Events(),
					RxHistory:          append([]uint64(nil), a.rxHistory...),
					TxHistory:          append([]uint64(nil), a.txHistory...),
				}
			}
			a.mu.Unlock()
			if hsChanged {
				a.refreshTray()
			}
			if visible {
				runtime.EventsEmit(a.ctx, "telemetry", snap)
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

func (a *App) runSteppedRecovery(reason string, triggerFailoverOnExhaust bool) {
	gen := a.recoveryGen.Add(1)
	wgbridge.ClearDnsCache()
	wgbridge.RecordDiag("RECOVERY", "START", reason)

	delays := []time.Duration{
		500 * time.Millisecond,
		1500 * time.Millisecond,
		2500 * time.Millisecond,
		3500 * time.Millisecond,
	}
	recovered := false
	for idx, wait := range delays {
		if a.bgCtx != nil && a.bgCtx.Err() != nil {
			return
		}
		if a.recoveryGen.Load() != gen {
			return
		}
		a.mu.Lock()
		isUp := a.connected
		a.mu.Unlock()
		if !isUp {
			return
		}
		if idx > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-a.bgCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if a.recoveryGen.Load() != gen {
				return
			}
		} else {
			time.Sleep(wait)
		}
		if wgbridge.ForceRebindAndHandshake() {
			recovered = true
			wgbridge.RecordDiag("RECOVERY", "OK", fmt.Sprintf("%s attempt=%d", reason, idx+1))
			a.flushPendingTelemetryAsync()
			break
		}
	}

	if !recovered && a.recoveryGen.Load() == gen {
		a.reportAnomalyAsync("STEPPED_RECOVERY_EXHAUSTED", reason)
		if triggerFailoverOnExhaust && a.failover != nil && a.bgCtx != nil {
			wgbridge.RecordDiag("RECOVERY", "FAILOVER", reason)
			a.failover.TriggerFailover(a.bgCtx)
		}
	}
	a.syncMonitoredPorts()
	a.refreshTray()
	a.emitStateChanged()
}

func (a *App) handleWakeRecovery() {
	wgbridge.ClearDnsCache()
	a.mu.Lock()
	isUp := a.connected
	on := a.state.Settings.AutoConnectOnLaunch
	busy := a.connecting
	a.mu.Unlock()
	if !isUp {
		if on && !busy && !a.manualStop.Load() && syswin.HasOutboundIPv4() {
			go a.autoConnectOnLaunch()
		}
		return
	}
	if !syswin.HasOutboundIPv4() {
		a.networkOffline.Store(true)
		return
	}
	linkMtu, outerVpn := syswin.DetectOutboundLinkMTU()
	wgbridge.SetHostLinkMTU(linkMtu, outerVpn)
	wasOffline := a.networkOffline.Swap(false)
	if wgbridge.IsTunnelHotVerified() && !wasOffline {
		wgbridge.RecordDiag("RECOVERY", "OK", "wake tunnel hot 0ms")
		a.refreshTray()
		a.emitStateChanged()
		return
	}
	if wasOffline {
		wgbridge.ResetActiveProxyConnections("win_wake")
	}
	if wgbridge.EnsureTunnelAlive(1500) {
		wgbridge.CalibrateActiveTunnelMTUAsync()
		wgbridge.RecordDiag("RECOVERY", "OK", "wake tunnel alive")
		a.refreshTray()
		a.emitStateChanged()
		return
	}
	wgbridge.ResetActiveProxyConnections("win_wake_rebound")
	a.runSteppedRecovery("wake", true)
}

func (a *App) handleNetworkSwitch() {
	if !syswin.HasOutboundIPv4() {
		a.networkOffline.Store(true)
		return
	}
	wasOffline := a.networkOffline.Swap(false)
	linkMtu, outerVpn := syswin.DetectOutboundLinkMTU()
	wgbridge.SetHostLinkMTU(linkMtu, outerVpn)

	a.mu.Lock()
	isUp := a.connected
	on := a.state.Settings.AutoConnectOnLaunch
	busy := a.connecting
	a.mu.Unlock()
	if !isUp {
		if on && !busy && !a.manualStop.Load() {
			go a.autoConnectOnLaunch()
		}
		return
	}
	wgbridge.ClearDnsCache()
	if wasOffline {
		wgbridge.ResetActiveProxyConnections("win_net_restored")
	}
	if wgbridge.EnsureTunnelAlive(1500) {
		wgbridge.CalibrateActiveTunnelMTUAsync()
		wgbridge.RecordDiag("RECOVERY", "SKIP", "net_switch tunnel healthy")
		a.refreshTray()
		a.emitStateChanged()
		return
	}
	a.runSteppedRecovery("net_switch", true)
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
	if lang == "ar" {
		tip = "نفق وايرجارد بلس - متوقف"
	}
	if conn {
		if wgbridge.IsHandshakeHealthy() {
			vis = syswin.TrayConnected
			if activeName != "" {
				if lang == "ar" {
					tip = "نفق وايرجارد بلس - " + activeName
				} else {
					tip = "WireGuard Plus - " + activeName
				}
			} else if lang == "ar" {
				tip = "نفق وايرجارد بلس - متصل"
			} else {
				tip = "WireGuard Plus - Connected"
			}
		} else {
			vis = syswin.TrayKillSwitch
			if lang == "ar" {
				tip = "نفق وايرجارد بلس - جارٍ إتمام المصافحة..."
			} else {
				tip = "WireGuard Plus - Establishing handshake..."
			}
		}
	} else if ks {
		vis = syswin.TrayKillSwitch
		if lang == "ar" {
			tip = "نفق وايرجارد بلس - مانع التسريب نشط"
		} else {
			tip = "WireGuard Plus - Kill Switch Guard"
		}
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
		snap := a.GetBootstrapState()
		runtime.EventsEmit(a.ctx, "stateChanged", snap)
		runtime.EventsEmit(a.ctx, "windowShown", snap)
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

// EnableVoipTunAdmin saves persistent Administrator preference and relaunches elevated
// (or activates Wintun directly if already running with Administrator rights).
func (a *App) EnableVoipTunAdmin() error {
	if isProcessElevated() {
		a.mu.Lock()
		a.state.Settings.AlwaysRunAsAdmin = true
		_ = a.store.Save(a.state)
		isConn := a.connected
		a.mu.Unlock()
		a.syncAutostartRegistry()
		if isConn && !wgbridge.IsWindowsVoipTunActive() {
			if dllPath, dllErr := voiptun.EnsureWintunDLLForApp(a.store.DataDir()); dllErr != nil {
				return dllErr
			} else if vtErr := wgbridge.StartWindowsVoipTun(filepath.Dir(dllPath)); vtErr != nil {
				return vtErr
			}
		}
		a.refreshTray()
		a.emitStateChanged()
		return nil
	}

	a.mu.Lock()
	prev := a.state.Settings.AlwaysRunAsAdmin
	a.state.Settings.AlwaysRunAsAdmin = true
	_ = a.store.Save(a.state)
	a.mu.Unlock()

	if err := syswin.RelaunchElevatedWithArgs(os.Getpid(), "--elevated-relaunch"); err != nil {
		a.mu.Lock()
		a.state.Settings.AlwaysRunAsAdmin = prev
		_ = a.store.Save(a.state)
		a.mu.Unlock()
		if errors.Is(err, windows.ERROR_CANCELLED) ||
			strings.Contains(strings.ToLower(err.Error()), "cancel") {
			return nil
		}
		return err
	}

	go func() {
		a.QuitApp()
		time.Sleep(1500 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}

// GetBootstrapState returns the complete initial/refreshed state snapshot for the UI.
func (a *App) GetBootstrapState() BootstrapState {
	stats := a.readBridgeStats()
	a.mu.Lock()
	defer a.mu.Unlock()

	profiles := make([]config.ServerProfile, len(a.state.Profiles))
	copy(profiles, a.state.Profiles)

	var sinceUnix int64
	if a.connected && !a.startedAt.IsZero() {
		sinceUnix = a.startedAt.Unix()
	}
	return BootstrapState{
		Settings:           a.state.Settings,
		Profiles:           profiles,
		Clients:            a.mergeClientTraffic(a.clients, stats),
		PortableMode:       a.store.IsPortable(),
		DataDir:            a.store.DataDir(),
		Connected:          a.connected,
		Connecting:         a.connecting,
		ConnectedSinceUnix: sinceUnix,
		ActiveProfileID:    a.activeID,
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

	wgbridge.ResetSocksAuthRejectCount()
	linkMtu, outerVpn := syswin.DetectOutboundLinkMTU()
	wgbridge.SetHostLinkMTU(linkMtu, outerVpn)
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
		if ks && !a.connected {
			_, _ = wgbridge.StartKillSwitchGuard()
		}
		if syswin.HasOutboundIPv4() {
			a.reportAnomalyAsync("TUNNEL_START_FAILED", err.Error())
		}
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

	if dllPath, dllErr := voiptun.EnsureWintunDLLForApp(a.store.DataDir()); dllErr != nil {
		wgbridge.RecordDiag("VOIP_TUN", "DLL_ERR", dllErr.Error())
	} else if vtErr := wgbridge.StartWindowsVoipTun(filepath.Dir(dllPath)); vtErr != nil {
		// Non-fatal fallback: keep SOCKS5 tunnel active if user launched without Administrator privileges.
		_ = vtErr
	}

	a.syncMonitoredPorts()
	a.refreshTray()
	a.emitStateChanged()
	a.flushPendingTelemetryAsync()
	go a.refreshActiveProfileLiveTelemetry(prof.ID)
	return nil
}

func (a *App) refreshActiveProfileLiveTelemetry(profileID string) {
	timer := time.NewTimer(900 * time.Millisecond)
	if a.bgCtx != nil {
		select {
		case <-a.bgCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	} else {
		<-timer.C
	}

	a.mu.Lock()
	stillSame := a.connected && a.activeID == profileID
	a.mu.Unlock()
	if !stillSame {
		return
	}

	rttMs, _ := wgbridge.ProbeActiveTunnelRttMs(2500)
	a.mu.Lock()
	stillSame = a.connected && a.activeID == profileID
	updated := false
	if stillSame && rttMs > 0 {
		for i := range a.state.Profiles {
			if a.state.Profiles[i].ID == profileID {
				a.state.Profiles[i].LastPingMs = rttMs
				updated = true
				break
			}
		}
		if updated && a.store != nil {
			_ = a.store.Save(a.state)
		}
	}
	a.mu.Unlock()

	if stillSame {
		a.refreshTray()
		a.emitStateChanged()
	}
}

func (a *App) Disconnect() error {
	a.connectMu.Lock()
	defer a.connectMu.Unlock()
	a.manualStop.Store(true)

	wgbridge.StopWindowsVoipTun()
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

// SelectProfile selects a server profile cleanly in both disconnected and connected states.
// When disconnected, it updates both activeID and ActiveProfileID so Connect uses it immediately.
// When connected, it switches the live tunnel to the chosen profile.
func (a *App) SelectProfile(profileID string) error {
	id := strings.TrimSpace(profileID)
	if id == "" {
		return errors.New("profile id is required")
	}
	a.mu.Lock()
	found := false
	for _, p := range a.state.Profiles {
		if p.ID == id {
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		return errors.New("profile not found")
	}
	isConn := a.connected
	if !isConn {
		a.activeID = id
		a.state.Settings.ActiveProfileID = id
		if err := a.store.Save(a.state); err != nil {
			a.mu.Unlock()
			return err
		}
		a.mu.Unlock()
		a.refreshTray()
		a.emitStateChanged()
		return nil
	}
	a.mu.Unlock()
	return a.Connect(id)
}

// OpenOfficialChannel opens @wgplus_official directly inside Telegram Desktop via tg://resolve
// without ever launching a web browser. Includes running/installed Desktop, Portable, and MSIX Unigram.
func (a *App) OpenOfficialChannel() (bool, error) {
	const channelURI = "tg://resolve?domain=wgplus_official"
	detected := a.ScanTelegramClients()

	// If a standard (non-portable) or MSIX client is already running and Windows has tg:// registered,
	// prefer ShellExecuteW so installed builds keep their -workdir profile arguments.
	hasNonPortableRunning := false
	for _, c := range detected {
		if c.Running && (!c.IsPortable || c.IsMsix) {
			hasNonPortableRunning = true
			break
		}
	}
	if hasNonPortableRunning && clients.HasTgProtocolHandler() {
		if err := clients.OpenTgURI(channelURI); err == nil {
			return true, nil
		}
	}

	// Prefer running desktop/portable/MSIX clients, then installed ones.
	var candidates []config.TelegramClientEntry
	for _, c := range detected {
		if c.Running && (c.IsMsix || strings.TrimSpace(c.ExePath) != "") {
			candidates = append(candidates, c)
		}
	}
	for _, c := range detected {
		if !c.Running && (c.IsMsix || strings.TrimSpace(c.ExePath) != "") {
			candidates = append(candidates, c)
		}
	}
	for _, c := range candidates {
		if res, err := clients.ApplyProxyToClient(c, channelURI); err == nil && res.Dispatched {
			return true, nil
		}
	}
	// Fallback to Windows tg:// protocol handler only if registered (never opens browser)
	if clients.HasTgProtocolHandler() {
		if err := clients.OpenTgURI(channelURI); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// AcknowledgeOfficialChannel records that the user opened or confirmed the mandatory channel modal.
func (a *App) AcknowledgeOfficialChannel() error {
	a.mu.Lock()
	a.state.Settings.ChannelInvitedV4 = true
	err := a.store.Save(a.state)
	a.mu.Unlock()
	a.emitStateChanged()
	return err
}

// EnableAwg15AndReconnect applies the strong AmneziaWG 1.5 DPI bypass preset to the active server
// profile, saves it to the vault, and reconnects the tunnel.
func (a *App) EnableAwg15AndReconnect() error {
	preset := strings.TrimSpace(wgbridge.GetAwgPreset("quic_mimicry_15"))
	if preset == "" {
		return errors.New("AWG 1.5 preset unavailable")
	}

	a.mu.Lock()
	targetID := strings.TrimSpace(a.activeID)
	if targetID == "" {
		targetID = strings.TrimSpace(a.state.Settings.ActiveProfileID)
	}
	idx := -1
	for i := range a.state.Profiles {
		if targetID == "" || a.state.Profiles[i].ID == targetID {
			idx = i
			targetID = a.state.Profiles[i].ID
			break
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return errors.New("no server profile available")
	}
	a.state.Profiles[idx].AwgParams = preset
	err := a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return a.Connect(targetID)
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
	s.ChannelInvitedV4 = prev.ChannelInvitedV4

	if s.StartWithWindows != prev.StartWithWindows || s.AlwaysRunAsAdmin != prev.AlwaysRunAsAdmin {
		exePath, _ := os.Executable()
		if err := syswin.SyncStartWithWindows(s.StartWithWindows, exePath, s.AlwaysRunAsAdmin, isProcessElevated()); err != nil {
			a.mu.Unlock()
			return prev, err
		}
	}

	a.state.Settings = s
	if !a.connected && s.ActiveProfileID != "" {
		a.activeID = s.ActiveProfileID
	}
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

// ApproveBlockedClientPath registers a custom unsigned portable client path blocked by Process Guard.
func (a *App) ApproveBlockedClientPath(exePath string) error {
	clean := filepath.Clean(strings.TrimSpace(exePath))
	if clean == "" {
		return errors.New("executable path is required")
	}
	if _, err := os.Stat(clean); err != nil {
		return err
	}
	a.mu.Lock()
	exists := false
	for i := range a.state.CustomClients {
		if strings.EqualFold(filepath.Clean(a.state.CustomClients[i].ExePath), clean) {
			a.state.CustomClients[i].Enabled = true
			exists = true
			break
		}
	}
	if !exists {
		base := filepath.Base(clean)
		a.state.CustomClients = append(a.state.CustomClients, config.TelegramClientEntry{
			ID:           fmt.Sprintf("custom_%d", time.Now().UnixNano()),
			Kind:         "custom",
			DisplayName:  strings.TrimSuffix(base, filepath.Ext(base)),
			ExePath:      clean,
			InstallDir:   filepath.Dir(clean),
			IsPortable:   true,
			Enabled:      true,
			AutoDetected: false,
		})
	}
	err := a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	a.procGuard.AllowExecutablePath(clean)
	a.ScanTelegramClients()
	a.emitStateChanged()
	return nil
}
