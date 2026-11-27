package guard

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveTcpPeerPidAndStrictAllowlist(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()
	srvPort := ln.Addr().(*net.TCPAddr).Port

	pg := NewProcessGuard()
	pg.SetMonitoredPorts(srvPort)

	done := make(chan net.Addr, 1)
	go func() {
		c, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		done <- c.RemoteAddr()
		_ = c.Close()
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer cli.Close()

	remoteAddr := <-done
	tcpRemote := remoteAddr.(*net.TCPAddr)

	pid, err := pg.ResolveTcpPeerPid(uint16(tcpRemote.Port))
	if err != nil {
		t.Fatalf("ResolveTcpPeerPid failed: %v", err)
	}
	if pid != uint32(os.Getpid()) {
		t.Fatalf("expected own PID %d, got %d", os.Getpid(), pid)
	}

	// Self PID is always allowed for diagnostics/probes
	lbl, allowed := pg.CheckTcpClient(remoteAddr)
	if !allowed || lbl != "WireGuardPlus-Probe" {
		t.Fatalf("expected self PID allowed as WireGuardPlus-Probe, got lbl=%q allowed=%v", lbl, allowed)
	}

	// Verify allowlist decision helper directly on non-self PID:
	// Arbitrary paths matching a Telegram basename MUST be blocked in strict mode unless registered/signed!
	if pg.isAllowedProcess(999999, `C:\Windows\System32\curl.exe`, "curl.exe") {
		t.Fatalf("expected curl.exe to be blocked in strict mode")
	}
	if pg.isAllowedProcess(999999, `C:\Users\Victim\AppData\Local\Temp\Telegram.exe`, "Telegram.exe") {
		t.Fatalf("expected spoofed unsigned Temp\\Telegram.exe to be blocked in strict mode")
	}

	// Discovered / user-approved client paths are allowed cleanly
	pg.AllowExecutablePath(`D:\Apps\TelegramPortable\Telegram.exe`)
	pg.AllowExecutablePath(`D:\Apps\AyuGram\AyuGram.exe`)
	pg.AllowExecutablePath(`D:\Apps\64Gram\64Gram.exe`)
	pg.AllowExecutablePath(`C:\Program Files\WindowsApps\Unigram\Unigram.exe`)
	if !pg.isAllowedProcess(999999, `D:\Apps\TelegramPortable\Telegram.exe`, "Telegram.exe") {
		t.Fatalf("expected registered Telegram.exe path to be allowed")
	}
	if !pg.isAllowedProcess(999999, `D:\Apps\AyuGram\AyuGram.exe`, "AyuGram.exe") {
		t.Fatalf("expected registered AyuGram.exe path to be allowed")
	}
	if !pg.isAllowedProcess(999999, `D:\Apps\64Gram\64Gram.exe`, "64Gram.exe") {
		t.Fatalf("expected registered 64Gram.exe path to be allowed")
	}
	if !pg.isAllowedProcess(999999, `C:\Program Files\WindowsApps\Unigram\Unigram.exe`, "Unigram.exe") {
		t.Fatalf("expected registered Unigram.exe path to be allowed")
	}

	// Verify log_only permits custom tools cleanly
	pg.SetMode("log_only")
	if !pg.isAllowedProcess(999999, `C:\Windows\System32\curl.exe`, "curl.exe") {
		t.Fatalf("expected log_only mode to permit curl.exe")
	}
	if len(pg.Events()) == 0 || !strings.EqualFold(pg.Events()[0].Protocol, "TCP") {
		t.Fatalf("expected recorded guard event, got %+v", pg.Events())
	}
}

func TestResolveUdpPeerPidSupportsIPv4AndIPv6(t *testing.T) {
	pg := NewProcessGuard()

	pc4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket udp4 failed: %v", err)
	}
	defer pc4.Close()
	port4 := uint16(pc4.LocalAddr().(*net.UDPAddr).Port)
	pid4, err := pg.ResolveUdpPeerPid(port4)
	if err != nil {
		t.Fatalf("ResolveUdpPeerPid IPv4 failed: %v", err)
	}
	if pid4 != uint32(os.Getpid()) {
		t.Fatalf("IPv4 UDP owner mismatch: got %d want %d", pid4, os.Getpid())
	}

	pc6, err := net.ListenPacket("udp6", "[::]:0")
	if err == nil {
		defer pc6.Close()
		port6 := uint16(pc6.LocalAddr().(*net.UDPAddr).Port)
		pid6, err := pg.ResolveUdpPeerPid(port6)
		if err != nil {
			t.Fatalf("ResolveUdpPeerPid IPv6 dual-stack failed: %v", err)
		}
		if pid6 != uint32(os.Getpid()) {
			t.Fatalf("IPv6 UDP owner mismatch: got %d want %d", pid6, os.Getpid())
		}
	}
}

func TestStrictGuardRejectsSignedNonTelegramLolbinAndAllowsRealTelegram(t *testing.T) {
	pg := NewProcessGuard()

	const curlSrc = `C:\Windows\System32\curl.exe`
	if data, err := os.ReadFile(curlSrc); err == nil {
		spoofPath := filepath.Join(t.TempDir(), "Telegram.exe")
		if wErr := os.WriteFile(spoofPath, data, 0o755); wErr != nil {
			t.Fatalf("failed to stage spoofed binary: %v", wErr)
		}
		if pg.isAllowedProcess(99999, spoofPath, "Telegram.exe") {
			t.Fatalf("expected Microsoft-signed curl.exe copied as %q to be BLOCKED in strict mode", spoofPath)
		}
	}

	if appData := os.Getenv("APPDATA"); appData != "" {
		realTg := filepath.Join(appData, "Telegram Desktop", "Telegram.exe")
		if _, err := os.Stat(realTg); err == nil {
			signer, ok := extractAuthenticodeSignerName(realTg)
			if !ok || !strings.Contains(strings.ToLower(signer), "telegram") {
				t.Fatalf("expected Telegram.exe signer containing 'telegram', got ok=%v signer=%q", ok, signer)
			}
			if !verifyAuthenticodeFile(realTg) {
				t.Fatalf("expected real Telegram.exe at %q to pass Authenticode publisher verification", realTg)
			}
		}
	}
}

func TestDefaultAllowedTelegramForksRecognized(t *testing.T) {
	pg := NewProcessGuard()
	expected := []string{
		"telegram.exe",
		"ayugram.exe",
		"64gram.exe",
		"unigram.exe",
		"forkgram.exe",
		"kotatogram.exe",
		"materialgram.exe",
		"exteragram.exe",
		"cherrygram.exe",
		"ime.exe",
		"nicegram.exe",
	}
	for _, exe := range expected {
		if !pg.allowedNames[exe] {
			t.Fatalf("expected %q to be in default allowlisted fork names", exe)
		}
	}
	for _, pub := range []string{"exteraGram", "Cherrygram", "materialgram", "Nicegram", "iMe Messenger"} {
		if !isTrustedTelegramPublisher(pub, `C:\Apps\client.exe`) {
			t.Fatalf("expected publisher %q to be trusted", pub)
		}
	}
	for _, spoofPub := range []string{"Sublime HQ Pty Ltd", "Prime Video", "Mimecast Services", "Time Inc", "Microsoft Corporation"} {
		if isTrustedTelegramPublisher(spoofPub, `C:\Users\Victim\AppData\Local\Temp\windowsapps\Telegram.exe`) {
			t.Fatalf("expected publisher %q in spoofed path to be REJECTED", spoofPub)
		}
	}
	if !isTrustedTelegramPublisher("Microsoft Corporation", `C:\Program Files\WindowsApps\TelegramMessengerLLP.TelegramDesktop_5.0_x64__t4vj0pshhgkwm\Telegram.exe`) {
		t.Fatal("expected legitimate WindowsApps Telegram Store binary to be trusted")
	}

	const curlSrc = `C:\Windows\System32\curl.exe`
	if data, err := os.ReadFile(curlSrc); err == nil {
		fakeStoreDir := filepath.Join(t.TempDir(), "windowsapps")
		if err := os.MkdirAll(fakeStoreDir, 0o755); err == nil {
			fakeStoreExe := filepath.Join(fakeStoreDir, "Telegram.exe")
			if wErr := os.WriteFile(fakeStoreExe, data, 0o755); wErr == nil {
				if pg.isAllowedProcess(99999, fakeStoreExe, "Telegram.exe") {
					t.Fatalf("expected spoofed Temp\\windowsapps\\Telegram.exe signed by Microsoft to be BLOCKED")
				}
			}
		}
	}
}

func TestAuthenticodeCacheInvalidatesOnFileChangeAndNeverPinsPath(t *testing.T) {
	pg := NewProcessGuard()
	fPath := filepath.Join(t.TempDir(), "Telegram.exe")
	if err := os.WriteFile(fPath, []byte("unsigned-v1"), 0o755); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}
	norm := strings.ToLower(filepath.Clean(fPath))

	if pg.verifyAuthenticodeCached(fPath, norm) {
		t.Fatal("expected unsigned v1 to fail Authenticode verification")
	}
	if pg.allowedPaths[norm] {
		t.Fatal("verifyAuthenticodeCached must not mutate allowedPaths")
	}
	firstEnt, ok := pg.verifiedSigCache[norm]
	if !ok || firstEnt.valid || firstEnt.sha256Hex == "" {
		t.Fatalf("expected cached invalid entry with sha256 for v1, got ok=%v ent=%+v", ok, firstEnt)
	}

	// Simulate same-size replacement while preserving exact mtime via Chtimes (stomp bypass test).
	st1, err := os.Stat(fPath)
	if err != nil {
		t.Fatalf("Stat v1: %v", err)
	}
	if err := os.WriteFile(fPath, []byte("unsigned-vX"), 0o755); err != nil {
		t.Fatalf("WriteFile vX: %v", err)
	}
	_ = os.Chtimes(fPath, st1.ModTime(), st1.ModTime())

	if pg.verifyAuthenticodeCached(fPath, norm) {
		t.Fatal("expected same-size Chtimes-stomped file to fail")
	}
	stompedEnt := pg.verifiedSigCache[norm]
	if stompedEnt.sha256Hex == firstEnt.sha256Hex {
		t.Fatalf("expected sha256 cache entry to refresh even when size and mtime matched")
	}

	// Simulate file replacement on disk (different size and mtime)
	if err := os.WriteFile(fPath, []byte("unsigned-v2-different-size"), 0o755); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(fPath, future, future)

	if pg.verifyAuthenticodeCached(fPath, norm) {
		t.Fatal("expected modified unsigned v2 to re-evaluate and fail")
	}
	secondEnt := pg.verifiedSigCache[norm]
	if secondEnt.size == stompedEnt.size && secondEnt.modUnixNano == stompedEnt.modUnixNano {
		t.Fatalf("expected cache entry to refresh after file change: prev=%+v second=%+v", stompedEnt, secondEnt)
	}
}

