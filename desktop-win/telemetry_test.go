package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/sys/windows"
	"wgplus-win/internal/config"
	"wgplus-win/internal/guard"
	"wgplus-win/internal/vault"
)

func TestSanitizeWindowsDiagTextAndPathUserRedaction(t *testing.T) {
	privB64 := "uG8wJ5n0Y2pL9zQ3rK7mP1xV4sB6nH8jF0dM2qR5tWk="
	hex64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	raw := strings.Join([]string{
		"### WireGuard Plus Diagnostics (Windows)",
		"PrivateKey = " + privB64,
		"PresharedKey=" + hex64,
		"socksPass=my-win-pass-123",
		"Endpoint: 162.159.193.10:2408",
		"[VOIP_RELAY/OPEN] target=91.108.9.58:1400 localPort=48729",
		"[1700000000] ALLOW TCP telegram.exe#12345678 (pid=42, :48729) path=C:\\Users\\AliHaider\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
		"loopback=127.0.0.1:48729",
	}, "\n")

	clean := sanitizeWindowsDiagText(raw)
	if strings.Contains(clean, privB64) {
		t.Fatal("base64 private key must be redacted")
	}
	if strings.Contains(clean, hex64) {
		t.Fatal("64-hex key must be redacted")
	}
	if strings.Contains(clean, "my-win-pass-123") {
		t.Fatal("socksPass must be redacted")
	}
	if strings.Contains(clean, "162.159.193.10") {
		t.Fatal("public WireGuard endpoint must be redacted")
	}
	if strings.Contains(clean, "91.108.9.58") {
		t.Fatal("public VoIP relay target must be redacted")
	}
	if strings.Contains(clean, "AliHaider") {
		t.Fatal("Windows account username inside path must be redacted")
	}
	if !strings.Contains(clean, `C:\Users\[USER]\AppData\Roaming\Telegram Desktop\Telegram.exe`) {
		t.Fatalf("expected sanitized user path placeholder, got:\n%s", clean)
	}
	if !strings.Contains(clean, "127.0.0.1:48729") {
		t.Fatal("loopback proxy address must stay readable")
	}
}

func TestCapUTF8HeadTailBoundsAndValidUTF8(t *testing.T) {
	var b strings.Builder
	b.WriteString("### WireGuard Plus Diagnostics (Windows)\n- **App Version**: `v2.0.0`\n")
	for i := 0; i < 650; i++ {
		b.WriteString("[OLD/EVENT] حدث قديم مكرر في السجل رقم padded log line here.\n")
	}
	b.WriteString("[LATEST/TAIL] final_event_marker_7788\n")

	capped := capUTF8HeadTail(b.String(), maxTelemetryReportUTF8Bytes)
	if len(capped) > maxTelemetryReportUTF8Bytes {
		t.Fatalf("capped byte length %d exceeds limit %d", len(capped), maxTelemetryReportUTF8Bytes)
	}
	if !utf8.ValidString(capped) {
		t.Fatal("capped output must remain valid UTF-8")
	}
	if !strings.Contains(capped, "### WireGuard Plus Diagnostics (Windows)") {
		t.Fatal("header must be preserved")
	}
	if !strings.Contains(capped, "final_event_marker_7788") {
		t.Fatal("newest tail line must be preserved")
	}
	if !strings.Contains(capped, "[older events omitted") {
		t.Fatal("omission marker must appear")
	}
}

func TestBuildFirestoreTelemetryPayloadSchema(t *testing.T) {
	raw := "### WireGuard Plus Diagnostics (Windows)\n- socksPass=leak123 Endpoint=198.51.100.2:51820\n"
	payload, err := buildFirestoreTelemetryPayload(
		"WireGuardPlus-Windows",
		"2.0.0",
		"Windows PC (amd64)",
		"Windows 11 24H2 (Build 26100)",
		26100,
		"TUNNEL_START_FAILED",
		"WINDOWS_WINTUN",
		raw,
	)
	if err != nil {
		t.Fatalf("buildFirestoreTelemetryPayload error: %v", err)
	}
	var parsed struct {
		Fields map[string]map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	required := []string{
		"schemaVersion", "createdAt", "moduleVersion", "hostPackage",
		"hostVersion", "deviceModel", "androidRelease", "sdkInt",
		"triggerCode", "continuityTier", "fingerprint", "reportMarkdown",
	}
	if len(parsed.Fields) != len(required) {
		t.Fatalf("expected %d Firestore fields, got %d", len(required), len(parsed.Fields))
	}
	for _, k := range required {
		if _, ok := parsed.Fields[k]; !ok {
			t.Fatalf("missing Firestore field %q", k)
		}
	}
	if parsed.Fields["schemaVersion"]["integerValue"] != "1" {
		t.Fatalf("unexpected schemaVersion: %v", parsed.Fields["schemaVersion"])
	}
	if parsed.Fields["moduleVersion"]["stringValue"] != "2.0.0" {
		t.Fatalf("expected bare moduleVersion 2.0.0, got %v", parsed.Fields["moduleVersion"])
	}
	if parsed.Fields["sdkInt"]["integerValue"] != "26100" {
		t.Fatalf("unexpected sdkInt: %v", parsed.Fields["sdkInt"])
	}
	md := parsed.Fields["reportMarkdown"]["stringValue"]
	if strings.Contains(md, "leak123") || strings.Contains(md, "198.51.100.2") {
		t.Fatalf("secret or public IP leaked in reportMarkdown: %s", md)
	}
}

func TestMultiInstanceWindowsTrafficAttributionZeroBleed(t *testing.T) {
	pMain := `C:\Users\Ali\AppData\Roaming\Telegram Desktop\Telegram.exe`
	pPort1 := `D:\PortableTG1\Telegram.exe`
	pPort2 := `E:\PortableTG2\Telegram.exe`

	lMain := guard.ClientLabelForExe(pMain, "Telegram.exe")
	lPort1 := guard.ClientLabelForExe(pPort1, "Telegram.exe")
	lPort2 := guard.ClientLabelForExe(pPort2, "Telegram.exe")

	if lMain == lPort1 || lMain == lPort2 || lPort1 == lPort2 {
		t.Fatalf("expected unique per-path labels for separate Telegram.exe installs, got %q %q %q", lMain, lPort1, lPort2)
	}

	app := &App{}
	clientsList := []config.TelegramClientEntry{
		{ID: "main", Kind: "tdesktop", DisplayName: "Telegram Desktop", ExePath: pMain},
		{ID: "p1", Kind: "tdesktop_portable", DisplayName: "Telegram Portable 1", ExePath: pPort1, IsPortable: true},
		{ID: "p2", Kind: "tdesktop_portable", DisplayName: "Telegram Portable 2", ExePath: pPort2, IsPortable: true},
		{ID: "uni", Kind: "unigram", DisplayName: "Unigram (MSIX)", IsMsix: true},
	}
	stats := BridgeStats{
		Clients: []ClientTrafficStat{
			{Label: lPort1, ActiveConns: 4, RxBytes: 12000, TxBytes: 3400},
			{Label: "unigram.exe", ActiveConns: 2, RxBytes: 5000, TxBytes: 900},
		},
	}
	merged := app.mergeClientTraffic(clientsList, stats)
	if merged[0].RxBytes != 0 || merged[0].ActiveConns != 0 {
		t.Fatalf("idle main Telegram.exe must stay at 0, got %+v", merged[0])
	}
	if merged[1].RxBytes != 12000 || merged[1].ActiveConns != 4 {
		t.Fatalf("portable #1 must match exact traffic, got %+v", merged[1])
	}
	if merged[2].RxBytes != 0 || merged[2].ActiveConns != 0 {
		t.Fatalf("idle portable #2 must NOT inherit portable #1 traffic, got %+v", merged[2])
	}
	if merged[3].RxBytes != 5000 || merged[3].ActiveConns != 2 {
		t.Fatalf("MSIX Unigram fallback match failed: %+v", merged[3])
	}
}

func TestLiveWindowsFirestoreTelemetryUpload(t *testing.T) {
	if os.Getenv("WGPLUS_LIVE_TELEMETRY_TEST") != "1" {
		t.Skip("set WGPLUS_LIVE_TELEMETRY_TEST=1 to exercise live Cloud Firestore upload from Windows desktop")
	}
	payload, err := buildFirestoreTelemetryPayload(
		"WireGuardPlus-Windows",
		AppVersion,
		"Windows PC (amd64)",
		"Windows QA Live Verification",
		26100,
		"MANUAL_USER_REPORT",
		"WINDOWS_SOCKS",
		"### WireGuard Plus Diagnostics (Windows)\n- **App Version**: `v"+AppVersion+"`\n- **Per-Instance Matrix**: verified\n",
	)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	docName, err := postFirestoreTelemetry(payload, 0, false, "", "")
	if err != nil {
		t.Fatalf("live Windows Firestore upload failed: %v", err)
	}
	if !strings.Contains(docName, "wgplus_diagnostics/") {
		t.Fatalf("unexpected Firestore doc name: %q", docName)
	}
	t.Logf("Live Windows telemetry document created: %s", docName)
}

func TestReplaceBinaryFileInPlaceOverLockedOpenFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "WireGuardPlus-Windows-x64.exe")
	staged := target + ".download"

	if err := os.WriteFile(target, []byte("MZ_OLD_BINARY_V1"), 0o755); err != nil {
		t.Fatalf("write old target: %v", err)
	}
	if err := os.WriteFile(staged, []byte("MZ_NEW_BINARY_V2"), 0o755); err != nil {
		t.Fatalf("write staged target: %v", err)
	}

	// Simulate Windows PE loader handle on a running .exe: allows shared read & delete (rename)
	// while strictly blocking direct in-place write/overwrite until the process exits.
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	lockedHandle, err := windows.CreateFile(
		targetPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("CreateFile PE-style handle: %v", err)
	}
	cleanupClosed := false
	defer func() {
		if !cleanupClosed {
			_ = windows.CloseHandle(lockedHandle)
		}
	}()

	// Direct overwrite must fail while running handle is open, proving NTFS rename is necessary.
	if wErr := os.WriteFile(target, []byte("DIRECT_OVERWRITE_SHOULD_FAIL"), 0o755); wErr == nil {
		t.Fatal("expected direct write over running executable handle to fail")
	}

	if err := replaceBinaryFileInPlace(target, staged); err != nil {
		t.Fatalf("replaceBinaryFileInPlace failed over running executable handle: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read replaced target: %v", err)
	}
	if string(got) != "MZ_NEW_BINARY_V2" {
		t.Fatalf("expected new binary content at target path, got %q", string(got))
	}
	_ = windows.CloseHandle(lockedHandle)
	cleanupClosed = true
}

func TestWebviewDirElevationSeparationAndAlwaysAdminPersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStoreAt(dir, false)
	if err != nil {
		t.Fatalf("NewStoreAt: %v", err)
	}
	if store.WebviewDirForElevation(false) == store.WebviewDirForElevation(true) {
		t.Fatal("elevated and standard WebView2 directories must be isolated to avoid ACL lockouts")
	}

	st := config.PersistedState{
		SchemaVersion: 1,
		Settings:      config.DefaultSettings(),
	}
	st.Settings.AlwaysRunAsAdmin = true
	if err := store.Save(st); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if !reloaded.Settings.AlwaysRunAsAdmin {
		t.Fatal("AlwaysRunAsAdmin must persist across restarts")
	}
}
