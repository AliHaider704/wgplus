package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"wgbridge"
	"wgplus-win/internal/clients"
	"wgplus-win/internal/config"
	"wgplus-win/internal/guard"
	"wgplus-win/internal/syswin"
)

const (
	firestoreTelemetryEndpoint = "https://firestore.googleapis.com/v1/projects/wgplus-qa/databases/(default)/documents/wgplus_diagnostics"
	maxTelemetryReportUTF8Bytes = 15800
	telemetryAutoPerTriggerSec  = 6 * 3600
	telemetryAutoDailyMax       = 4
	telemetryManualCooldownSec  = 30
	telemetryMaxPendingQueue    = 5
	telemetryMaxAnomalies       = 30
)

var (
	reWinKvSecret = regexp.MustCompile(`(?i)((?:socks_?|proxy_?|shared_?)?(?:private_?key|preshared_?key|public_?key|pass(?:word)?|secret|token)\s*[:=]\s*)([^\s,;"'\x60]+)`)
	reWinB64Key   = regexp.MustCompile(`(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{42,43}=)($|[^A-Za-z0-9+/=])`)
	reWinHex64Key = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reWinEpV4     = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b`)
	reWinEpV6     = regexp.MustCompile(`\[([0-9a-fA-F:]+)\]:(\d{1,5})`)
	reWinUserDir  = regexp.MustCompile(`(?i)([a-z]:[\\/]Users[\\/])[^\\/\r\n"'\x60]+`)
)

type telemetryPendingItem struct {
	TriggerCode string `json:"triggerCode"`
	PayloadJSON string `json:"payloadJson"`
	CreatedAt   int64  `json:"createdAt"`
}

type telemetryPersistState struct {
	LastTriggerUnix map[string]int64       `json:"lastTriggerUnix"`
	AutoSentUnix    []int64                `json:"autoSentUnix"`
	LastManualUnix  int64                  `json:"lastManualUnix"`
	Pending         []telemetryPendingItem `json:"pending"`
}

type telemetryManager struct {
	mu       sync.Mutex
	anomalies []string
	flushing bool
}

// sanitizeWindowsDiagText scrubs WireGuard/AWG secrets, SOCKS passwords, non-loopback
// endpoints, and local Windows account usernames from diagnostic text.
func sanitizeWindowsDiagText(raw string) string {
	if raw == "" {
		return ""
	}
	s := reWinKvSecret.ReplaceAllString(raw, "${1}[REDACTED]")
	s = reWinB64Key.ReplaceAllString(s, "${1}[KEY_REDACTED]${3}")
	s = reWinHex64Key.ReplaceAllString(s, "[HEX_KEY_REDACTED]")
	s = reWinEpV4.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "127.") || strings.HasPrefix(m, "0.0.0.0:") {
			return m
		}
		return "[ENDPOINT_REDACTED]"
	})
	s = reWinEpV6.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(strings.ToLower(m), "[::1]:") {
			return m
		}
		return "[ENDPOINT_V6_REDACTED]"
	})
	s = reWinUserDir.ReplaceAllString(s, "${1}[USER]")
	return s
}

func truncateUTF8Prefix(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

func truncateUTF8Suffix(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	start := len(s) - maxBytes
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[start:]
}

// capUTF8HeadTail preserves the diagnostic header/environment section and the newest
// tail events when shrinking oversized reports to <= maxBytes valid UTF-8.
func capUTF8HeadTail(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	const sep = "\n... [older events omitted to fit cloud packet limit] ...\n"
	if maxBytes <= len(sep)+32 {
		return truncateUTF8Prefix(s, maxBytes)
	}
	avail := maxBytes - len(sep)
	headBudget := (avail * 55) / 100
	tailBudget := avail - headBudget
	head := strings.TrimRight(truncateUTF8Prefix(s, headBudget), "\r\n")
	tail := strings.TrimLeft(truncateUTF8Suffix(s, tailBudget), "\r\n")
	out := head + sep + tail
	if len(out) > maxBytes {
		return truncateUTF8Prefix(out, maxBytes)
	}
	return out
}

func isProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func queryWindowsOSInfo() (osRelease string, buildNum int, deviceModel string) {
	deviceModel = fmt.Sprintf("Windows PC (%s)", goruntime.GOARCH)
	productName := "Windows"
	displayVer := ""

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if pn, _, pErr := k.GetStringValue("ProductName"); pErr == nil && strings.TrimSpace(pn) != "" {
			productName = strings.TrimSpace(pn)
		}
		if dv, _, dErr := k.GetStringValue("DisplayVersion"); dErr == nil && strings.TrimSpace(dv) != "" {
			displayVer = strings.TrimSpace(dv)
		}
		if cb, _, bErr := k.GetStringValue("CurrentBuildNumber"); bErr == nil {
			if n, nErr := strconv.Atoi(strings.TrimSpace(cb)); nErr == nil {
				buildNum = n
			}
		}
	}
	if buildNum >= 22000 && strings.Contains(productName, "Windows 10") {
		productName = strings.Replace(productName, "Windows 10", "Windows 11", 1)
	}
	var parts []string
	parts = append(parts, productName)
	if displayVer != "" {
		parts = append(parts, displayVer)
	}
	if buildNum > 0 {
		parts = append(parts, fmt.Sprintf("Build %d", buildNum))
	}
	osRelease = strings.Join(parts, " ")
	if len(osRelease) > 64 {
		osRelease = truncateUTF8Prefix(osRelease, 64)
	}
	return osRelease, buildNum, deviceModel
}

func clampFirestoreStr(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxBytes {
		return truncateUTF8Prefix(s, maxBytes)
	}
	return s
}

func buildFirestoreTelemetryPayload(
	hostPkg, hostVer, deviceModel, osRelease string, buildNum int,
	triggerCode, continuityTier, rawReport string,
) ([]byte, error) {
	sanitized := capUTF8HeadTail(sanitizeWindowsDiagText(rawReport), maxTelemetryReportUTF8Bytes)
	if len(sanitized) < 20 {
		sanitized = sanitized + "\n(windows diag minimal context)"
	}

	if strings.TrimSpace(hostPkg) == "" {
		hostPkg = "WireGuardPlus-Windows"
	}
	if strings.TrimSpace(hostVer) == "" {
		hostVer = AppVersion
	}
	cleanVer := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(hostVer), "v"), "V")
	if cleanVer == "" {
		cleanVer = AppVersion
	}
	if strings.TrimSpace(deviceModel) == "" {
		deviceModel = fmt.Sprintf("Windows PC (%s)", goruntime.GOARCH)
	}
	if strings.TrimSpace(osRelease) == "" {
		osRelease = "Windows"
	}
	if strings.TrimSpace(triggerCode) == "" {
		triggerCode = "MANUAL_USER_REPORT"
	}
	if strings.TrimSpace(continuityTier) == "" {
		continuityTier = "WINDOWS_SOCKS"
	}

	fpRaw := fmt.Sprintf("%s|%s|%s|%s",
		clampFirestoreStr(cleanVer, 32),
		clampFirestoreStr(deviceModel, 96),
		clampFirestoreStr(hostPkg, 128),
		clampFirestoreStr(triggerCode, 64),
	)
	fpHash := sha256.Sum256([]byte(fpRaw))
	fingerprint := hex.EncodeToString(fpHash[:8])

	type strVal struct {
		StringValue string `json:"stringValue"`
	}
	type intVal struct {
		IntegerValue string `json:"integerValue"`
	}
	doc := map[string]any{
		"fields": map[string]any{
			"schemaVersion":  intVal{IntegerValue: "1"},
			"createdAt":      strVal{StringValue: time.Now().UTC().Format(time.RFC3339)},
			"moduleVersion":  strVal{StringValue: clampFirestoreStr(cleanVer, 32)},
			"hostPackage":    strVal{StringValue: clampFirestoreStr(hostPkg, 128)},
			"hostVersion":    strVal{StringValue: clampFirestoreStr(cleanVer, 64)},
			"deviceModel":    strVal{StringValue: clampFirestoreStr(deviceModel, 128)},
			"androidRelease": strVal{StringValue: clampFirestoreStr(osRelease, 64)},
			"sdkInt":         intVal{IntegerValue: strconv.Itoa(buildNum)},
			"triggerCode":    strVal{StringValue: clampFirestoreStr(triggerCode, 64)},
			"continuityTier": strVal{StringValue: clampFirestoreStr(continuityTier, 64)},
			"fingerprint":    strVal{StringValue: clampFirestoreStr(fingerprint, 64)},
			"reportMarkdown": strVal{StringValue: sanitized},
		},
	}
	return json.Marshal(doc)
}

func postFirestoreDocWithClient(client *http.Client, payload []byte) (string, error) {
	req, err := http.NewRequest(http.MethodPost, firestoreTelemetryEndpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("firestore HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Name, nil
}

// postFirestoreTelemetry attempts upload through the active WireGuard SOCKS5 tunnel first,
// then falls back directly over HTTPS so tunnel/handshake failures still report cleanly.
func postFirestoreTelemetry(payload []byte, socksPort int, socksAuth bool, socksUser, socksPass string) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("empty telemetry payload")
	}
	if wgbridge.IsRunning() && socksPort > 0 {
		var auth *proxy.Auth
		if socksAuth && strings.TrimSpace(socksUser) != "" {
			auth = &proxy.Auth{User: socksUser, Password: socksPass}
		}
		if dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), auth, proxy.Direct); err == nil {
			tr := &http.Transport{
				DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				},
			}
			socksClient := &http.Client{Timeout: 6 * time.Second, Transport: tr}
			if docName, pErr := postFirestoreDocWithClient(socksClient, payload); pErr == nil {
				return docName, nil
			}
		}
	}
	directClient := &http.Client{Timeout: 8 * time.Second}
	return postFirestoreDocWithClient(directClient, payload)
}

func (a *App) telemetryStatePath() string {
	if a.store == nil {
		return ""
	}
	return filepath.Join(a.store.DataDir(), "telemetry_state.json")
}

func (a *App) loadTelemetryStateLocked() telemetryPersistState {
	st := telemetryPersistState{
		LastTriggerUnix: make(map[string]int64),
	}
	p := a.telemetryStatePath()
	if p == "" {
		return st
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(raw, &st)
	if st.LastTriggerUnix == nil {
		st.LastTriggerUnix = make(map[string]int64)
	}
	return st
}

func (a *App) saveTelemetryStateLocked(st telemetryPersistState) {
	p := a.telemetryStatePath()
	if p == "" {
		return
	}
	if b, err := json.Marshal(st); err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

func (a *App) recordAppAnomaly(code, detail string) {
	line := fmt.Sprintf("[%s] [%s] %s",
		time.Now().UTC().Format(time.RFC3339),
		code,
		sanitizeWindowsDiagText(strings.TrimSpace(detail)),
	)
	a.telemetry.mu.Lock()
	if len(a.telemetry.anomalies) >= telemetryMaxAnomalies {
		copy(a.telemetry.anomalies, a.telemetry.anomalies[1:])
		a.telemetry.anomalies[len(a.telemetry.anomalies)-1] = line
	} else {
		a.telemetry.anomalies = append(a.telemetry.anomalies, line)
	}
	a.telemetry.mu.Unlock()
}

func (a *App) snapshotAppAnomalies() []string {
	a.telemetry.mu.Lock()
	defer a.telemetry.mu.Unlock()
	out := make([]string, len(a.telemetry.anomalies))
	copy(out, a.telemetry.anomalies)
	return out
}

func (a *App) buildCloudPayload(triggerCode string) ([]byte, int, bool, string, string, error) {
	rawReport := a.GetDiagnosticReport()
	osRel, buildNum, devModel := queryWindowsOSInfo()

	a.mu.Lock()
	s := a.state.Settings
	port := wgbridge.GetActivePort()
	if port <= 0 {
		port = s.SocksPort
	}
	a.mu.Unlock()

	hostPkg := "WireGuardPlus-Windows"
	if a.store != nil && a.store.IsPortable() {
		hostPkg = "WireGuardPlus-Windows-Portable"
	}
	tier := "WINDOWS_SOCKS"
	if wgbridge.IsWindowsVoipTunActive() {
		tier = "WINDOWS_WINTUN"
	}
	payload, err := buildFirestoreTelemetryPayload(
		hostPkg, AppVersion, devModel, osRel, buildNum, triggerCode, tier, rawReport,
	)
	return payload, port, s.SocksAuthEnabled, s.SocksUser, s.SocksPass, err
}

func (a *App) enqueuePendingTelemetry(triggerCode string, payload []byte) {
	a.telemetry.mu.Lock()
	defer a.telemetry.mu.Unlock()
	st := a.loadTelemetryStateLocked()
	if len(st.Pending) >= telemetryMaxPendingQueue {
		copy(st.Pending, st.Pending[1:])
		st.Pending[len(st.Pending)-1] = telemetryPendingItem{
			TriggerCode: triggerCode,
			PayloadJSON: string(payload),
			CreatedAt:   time.Now().Unix(),
		}
	} else {
		st.Pending = append(st.Pending, telemetryPendingItem{
			TriggerCode: triggerCode,
			PayloadJSON: string(payload),
			CreatedAt:   time.Now().Unix(),
		})
	}
	a.saveTelemetryStateLocked(st)
}

// SetTelemetryConsent updates the repeat-until-enabled automatic telemetry consent choice.
func (a *App) SetTelemetryConsent(optIn bool) (config.AppSettings, error) {
	a.mu.Lock()
	a.state.Settings.TelemetryConsentDecided = true
	a.state.Settings.TelemetryOptIn = optIn
	s := a.state.Settings
	err := a.store.Save(a.state)
	a.mu.Unlock()
	if err != nil {
		return s, err
	}
	a.emitStateChanged()
	if optIn {
		a.flushPendingTelemetryAsync()
	}
	return s, nil
}

// SendDiagnosticReportNow builds a fresh sanitized report and uploads it to Cloud Firestore immediately.
// Returns "sent", "queued", or "rate_limited".
func (a *App) SendDiagnosticReportNow() (string, error) {
	now := time.Now().Unix()
	a.telemetry.mu.Lock()
	st := a.loadTelemetryStateLocked()
	if now-st.LastManualUnix < telemetryManualCooldownSec {
		a.telemetry.mu.Unlock()
		return "rate_limited", nil
	}
	st.LastManualUnix = now
	a.saveTelemetryStateLocked(st)
	a.telemetry.mu.Unlock()

	payload, port, authOn, user, pass, err := a.buildCloudPayload("MANUAL_USER_REPORT")
	if err != nil {
		return "", err
	}
	if _, postErr := postFirestoreTelemetry(payload, port, authOn, user, pass); postErr != nil {
		wgbridge.RecordDiag("TELEMETRY", "MANUAL_QUEUED", sanitizeWindowsDiagText(postErr.Error()))
		a.enqueuePendingTelemetry("MANUAL_USER_REPORT", payload)
		return "queued", nil
	}
	wgbridge.RecordDiag("TELEMETRY", "SENT_OK", "MANUAL_USER_REPORT")
	a.flushPendingTelemetryAsync()
	return "sent", nil
}

func (a *App) reportAnomalyAsync(triggerCode, detail string) {
	a.recordAppAnomaly(triggerCode, detail)

	a.mu.Lock()
	optIn := a.state.Settings.TelemetryOptIn
	a.mu.Unlock()
	if !optIn {
		return
	}

	now := time.Now().Unix()
	a.telemetry.mu.Lock()
	st := a.loadTelemetryStateLocked()
	if prev, ok := st.LastTriggerUnix[triggerCode]; ok && now-prev < telemetryAutoPerTriggerSec {
		a.telemetry.mu.Unlock()
		return
	}
	recent := make([]int64, 0, len(st.AutoSentUnix))
	for _, ts := range st.AutoSentUnix {
		if now-ts < 86400 {
			recent = append(recent, ts)
		}
	}
	if len(recent) >= telemetryAutoDailyMax {
		st.AutoSentUnix = recent
		a.saveTelemetryStateLocked(st)
		a.telemetry.mu.Unlock()
		return
	}
	recent = append(recent, now)
	st.AutoSentUnix = recent
	st.LastTriggerUnix[triggerCode] = now
	a.saveTelemetryStateLocked(st)
	a.telemetry.mu.Unlock()

	go func() {
		payload, port, authOn, user, pass, err := a.buildCloudPayload(triggerCode)
		if err != nil {
			return
		}
		if _, postErr := postFirestoreTelemetry(payload, port, authOn, user, pass); postErr != nil {
			a.enqueuePendingTelemetry(triggerCode, payload)
		} else {
			wgbridge.RecordDiag("TELEMETRY", "AUTO_SENT", triggerCode)
		}
	}()
}

func (a *App) flushPendingTelemetryAsync() {
	a.telemetry.mu.Lock()
	if a.telemetry.flushing {
		a.telemetry.mu.Unlock()
		return
	}
	st := a.loadTelemetryStateLocked()
	if len(st.Pending) == 0 {
		a.telemetry.mu.Unlock()
		return
	}
	a.telemetry.flushing = true
	a.telemetry.mu.Unlock()

	go func() {
		defer func() {
			a.telemetry.mu.Lock()
			a.telemetry.flushing = false
			a.telemetry.mu.Unlock()
		}()

		a.mu.Lock()
		optIn := a.state.Settings.TelemetryOptIn
		s := a.state.Settings
		port := wgbridge.GetActivePort()
		if port <= 0 {
			port = s.SocksPort
		}
		a.mu.Unlock()

		a.telemetry.mu.Lock()
		cur := a.loadTelemetryStateLocked()
		items := append([]telemetryPendingItem(nil), cur.Pending...)
		a.telemetry.mu.Unlock()

		var remaining []telemetryPendingItem
		for _, item := range items {
			if !optIn && item.TriggerCode != "MANUAL_USER_REPORT" {
				continue
			}
			if _, err := postFirestoreTelemetry([]byte(item.PayloadJSON), port, s.SocksAuthEnabled, s.SocksUser, s.SocksPass); err != nil {
				remaining = append(remaining, item)
			}
		}

		a.telemetry.mu.Lock()
		finalSt := a.loadTelemetryStateLocked()
		finalSt.Pending = remaining
		a.saveTelemetryStateLocked(finalSt)
		a.telemetry.mu.Unlock()
	}()
}

func (a *App) crashMarkerPath() string {
	if a.store == nil {
		return ""
	}
	return filepath.Join(a.store.DataDir(), "last_crash.txt")
}

func (a *App) recordRecoveredPanic(contextLabel string, r any) {
	if r == nil {
		return
	}
	msg := sanitizeWindowsDiagText(fmt.Sprintf("%s: %v", contextLabel, r))
	if p := a.crashMarkerPath(); p != "" {
		_ = os.WriteFile(p, []byte(msg), 0o600)
	}
	a.recordAppAnomaly("WINDOWS_UNCAUGHT_PANIC", msg)
}

func (a *App) checkPreviousCrashOnStartup() {
	p := a.crashMarkerPath()
	if p == "" {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	_ = os.Remove(p)
	a.reportAnomalyAsync("WINDOWS_UNCAUGHT_PANIC", strings.TrimSpace(string(raw)))
}

func describeWindowsEndpointShape(rawEp string) string {
	ep := strings.TrimSpace(rawEp)
	if ep == "" {
		return "unset"
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "custom"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "ipv4:" + port
		}
		return "ipv6:" + port
	}
	return "domain:" + port
}

func appendWindowsNetInterfacesMarkdown(b *strings.Builder) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var active []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aErr := ifc.Addrs()
		if aErr != nil || len(addrs) == 0 {
			continue
		}
		v4Count, v6Global := 0, 0
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP != nil {
				if ipn.IP.To4() != nil {
					v4Count++
				} else if !ipn.IP.IsLinkLocalUnicast() {
					v6Global++
				}
			}
		}
		if v4Count == 0 && v6Global == 0 {
			continue
		}
		active = append(active, fmt.Sprintf("%s(mtu=%d,v4=%d,v6=%d)", sanitizeWindowsDiagText(ifc.Name), ifc.MTU, v4Count, v6Global))
	}
	sort.Strings(active)
	if len(active) == 0 {
		b.WriteString("- **OS Network**: `OFFLINE (no active non-loopback interfaces)`\n")
		return
	}
	fmt.Fprintf(b, "- **OS Network**: `%s`\n", strings.Join(active, ", "))
}

// GetDiagnosticReport builds a sanitized Markdown report safe to share with the developer or attach to GitHub Issues.
// Never includes private keys, preshared keys, server endpoints, SOCKS credentials, or PC usernames.
func (a *App) GetDiagnosticReport() string {
	a.mu.Lock()
	s := a.state.Settings
	isConn := a.connected
	isBusy := a.connecting
	lastErr := a.lastError
	activeID := a.activeID
	startedAt := a.startedAt
	profCount := len(a.state.Profiles)
	var profSummary string
	for _, p := range a.state.Profiles {
		if p.ID == activeID {
			hasAwg := strings.TrimSpace(p.AwgParams) != ""
			profSummary = fmt.Sprintf("mtu=%d, keepAlive=%d, useDoH=%v, awg=%v, warp=%v, pingMs=%d, ep=%s",
				p.MTU, p.KeepAlive, p.UseDoH, hasAwg, p.IsWarp, p.LastPingMs, describeWindowsEndpointShape(p.Endpoint))
			break
		}
	}
	clis := append([]config.TelegramClientEntry(nil), a.clients...)
	a.mu.Unlock()

	st := a.readBridgeStats()
	mergedClis := a.mergeClientTraffic(clis, st)
	pidsMap := clients.SnapshotRunningPIDs()
	osRel, buildNum, devModel := queryWindowsOSInfo()
	uptimeSec := int64(0)
	if isConn && !startedAt.IsZero() {
		uptimeSec = int64(time.Since(startedAt).Seconds())
	}

	var b strings.Builder
	b.WriteString("### WireGuard Plus Diagnostics (Windows)\n")
	fmt.Fprintf(&b, "- **App Version**: `v%s`\n", AppVersion)
	fmt.Fprintf(&b, "- **Device / OS**: `%s` — %s (arch=%s, build=%d, portable=%v, admin=%v)\n",
		devModel, osRel, goruntime.GOARCH, buildNum, a.store.IsPortable(), isProcessElevated())
	fmt.Fprintf(&b, "- **Tunnel State**: connected=`%v`, connecting=`%v`, running=`%v`, voipTunActive=`%v`, hsHealthy=`%v`, uptimeSec=`%d`\n",
		isConn, isBusy, st.Running, st.VoipTunActive, st.HandshakeHealthy, uptimeSec)
	fmt.Fprintf(&b, "- **Security Policy**: killSwitch=`%v`, guardMode=`%s`, socksAuth=`%v`, blockIPv6=`%v`, doH=`%v`, autoFailover=`%v`, telemetryOptIn=`%v`, profiles=`%d`\n",
		s.KillSwitch, s.ProcessGuardMode, s.SocksAuthEnabled, s.BlockIPv6, s.UseDoH, s.AutoFailover, s.TelemetryOptIn, profCount)
	fmt.Fprintf(&b, "- **Ports & Stats**: socksPort=`%d`, httpPort=`%d`, rxBytes=`%d`, txBytes=`%d`, hsAgeSec=`%d`, activeTcp=`%d`, activeUdp=`%d`, socksReject=`%d`, guardBlocked=`%d`\n",
		st.SocksPort, st.HttpPort, st.RxBytes, st.TxBytes, st.HandshakeAgeSec, st.ActiveTcpConns, st.ActiveUdpAssocs, st.SocksAuthRejectCount, st.BlockedLocalAttempts)
	if profSummary != "" {
		fmt.Fprintf(&b, "- **Profile Policy**: `%s`\n", profSummary)
	}
	appendWindowsNetInterfacesMarkdown(&b)
	if strings.TrimSpace(lastErr) != "" {
		fmt.Fprintf(&b, "- **Last Error**: `%s`\n", lastErr)
	}

	b.WriteString("\n#### Per-Instance Telegram Desktop Matrix\n")
	if len(mergedClis) == 0 {
		b.WriteString("- (none detected)\n")
	} else {
		matchedLabels := make(map[string]bool, len(mergedClis))
		for _, c := range mergedClis {
			exeBase := strings.ToLower(filepath.Base(c.ExePath))
			if (exeBase == "." || exeBase == "") && c.Kind == "unigram" {
				exeBase = "unigram.exe"
			}
			instLabel := guard.ClientLabelForExe(c.ExePath, exeBase)
			matchedLabels[strings.ToLower(instLabel)] = true
			if strings.TrimSpace(c.ExePath) == "" {
				matchedLabels[exeBase] = true
			}
			var pids []uint32
			if c.ExePath != "" {
				pids = pidsMap[strings.ToLower(filepath.Clean(c.ExePath))]
			}
			if len(pids) == 0 && exeBase != "" {
				pids = pidsMap["name:"+exeBase]
			}
			dirTag := sanitizeWindowsDiagText(c.InstallDir)
			if dirTag == "" && c.IsMsix {
				dirTag = "MSIX"
			}
			fmt.Fprintf(&b, "- `%s` (kind=%s, label=`%s`, running=%v, pids=%v, enabled=%v, portable=%v, msix=%v, conns=%d, rx=%d, tx=%d, dir=`%s`)\n",
				c.DisplayName, c.Kind, instLabel, c.Running, pids, c.Enabled, c.IsPortable, c.IsMsix, c.ActiveConns, c.RxBytes, c.TxBytes, dirTag)
		}
		for _, cs := range st.Clients {
			if !matchedLabels[strings.ToLower(cs.Label)] {
				fmt.Fprintf(&b, "- (unmapped client) label=`%s`, conns=%d, rx=%d, tx=%d\n",
					cs.Label, cs.ActiveConns, cs.RxBytes, cs.TxBytes)
			}
		}
	}

	bundleRaw := wgbridge.BuildEngineDiagnosticsBundleJSON()
	var parsedBundle struct {
		UdpTelemetry json.RawMessage `json:"udpTelemetry"`
		VoipRelays   []struct {
			LocalAddr   string `json:"localAddr"`
			TargetPort  int    `json:"targetPort"`
			UdpSessions int    `json:"udpSessions"`
			UdpTxPkts   int64  `json:"udpTxPkts"`
			UdpRxPkts   int64  `json:"udpRxPkts"`
			UdpErrs     int64  `json:"udpErrs"`
			TcpConns    int64  `json:"tcpConns"`
			AgeSec      int64  `json:"ageSec"`
		} `json:"voipRelays"`
		RingBuffer []struct {
			Ts   string `json:"ts"`
			Cat  string `json:"cat"`
			Code string `json:"code"`
			Msg  string `json:"msg"`
		} `json:"ringBuffer"`
	}
	if err := json.Unmarshal([]byte(bundleRaw), &parsedBundle); err == nil && len(parsedBundle.UdpTelemetry) > 0 {
		fmt.Fprintf(&b, "\n#### UDP & Watchdog Telemetry\n```json\n%s\n```\n", string(parsedBundle.UdpTelemetry))
		if len(parsedBundle.VoipRelays) > 0 {
			b.WriteString("\n#### Active VoIP Relays\n```text\n")
			for _, r := range parsedBundle.VoipRelays {
				fmt.Fprintf(&b, "%s -> :%d sess=%d txPkts=%d rxPkts=%d errs=%d tcp=%d age=%ds\n",
					r.LocalAddr, r.TargetPort, r.UdpSessions, r.UdpTxPkts, r.UdpRxPkts, r.UdpErrs, r.TcpConns, r.AgeSec)
			}
			b.WriteString("```\n")
		}
		b.WriteString("\n#### Go Engine Ring Buffer\n```text\n")
		if len(parsedBundle.RingBuffer) == 0 {
			b.WriteString("(none)\n")
		} else {
			for _, o := range parsedBundle.RingBuffer {
				fmt.Fprintf(&b, "[%s] [%s/%s] %s\n", o.Ts, o.Cat, o.Code, o.Msg)
			}
		}
		b.WriteString("```\n")
	} else {
		fmt.Fprintf(&b, "\n#### UDP & Watchdog Telemetry\n```json\n%s\n```\n", wgbridge.GetUdpTelemetryJSON())
		fmt.Fprintf(&b, "\n#### Go Engine Ring Buffer\n```json\n%s\n```\n", wgbridge.GetDiagnosticsJSON())
	}

	anomalies := a.snapshotAppAnomalies()
	if len(anomalies) > 0 {
		b.WriteString("\n#### Windows App Anomaly Log\n```text\n")
		for _, line := range anomalies {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		b.WriteString("```\n")
	}

	guardEvents := a.procGuard.Events()
	b.WriteString("\n#### Recent Process Guard Events\n```text\n")
	if len(guardEvents) == 0 {
		b.WriteString("(none)\n")
	} else {
		start := 0
		if len(guardEvents) > 25 {
			start = len(guardEvents) - 25
		}
		for _, ev := range guardEvents[start:] {
			fmt.Fprintf(&b, "[%d] %s %s %s (pid=%d, :%d) path=%s\n",
				ev.TimestampUnix, strings.ToUpper(ev.Action), ev.Protocol, ev.ClientLabel, ev.PID, ev.PeerPort, ev.ExePath)
		}
	}
	b.WriteString("```\n")
	return capUTF8HeadTail(sanitizeWindowsDiagText(b.String()), maxTelemetryReportUTF8Bytes)
}

func (a *App) ClearDiagnostics() {
	wgbridge.ClearDiagnostics()
}

func (a *App) SaveDiagnosticReport() (string, error) {
	if a.ctx == nil {
		return "", errors.New("window context unavailable")
	}
	rep := a.GetDiagnosticReport()
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Diagnostic Report",
		DefaultFilename: "wireguard-plus-diagnostics.md",
		Filters: []runtime.FileFilter{
			{DisplayName: "Markdown Report (*.md)", Pattern: "*.md"},
		},
	})
	if err != nil || strings.TrimSpace(path) == "" {
		return "", err
	}
	if err := os.WriteFile(path, []byte(rep), 0600); err != nil {
		return "", err
	}
	return path, nil
}

func (a *App) OpenGitHubBugReport() error {
	rep := a.GetDiagnosticReport()
	_ = syswin.CopyTextToClipboard(rep)
	issueURL := "https://github.com/AliHaider704/wgplus/issues/new?template=bug_report.yml&environment=" +
		url.QueryEscape(fmt.Sprintf("Windows (%s/%s) - WireGuard Plus v%s", goruntime.GOOS, goruntime.GOARCH, AppVersion))
	if a.ctx != nil {
		runtime.BrowserOpenURL(a.ctx, issueURL)
	}
	return nil
}
