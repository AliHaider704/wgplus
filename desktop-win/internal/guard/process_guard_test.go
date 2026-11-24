package guard

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	for _, pub := range []string{"exteraGram", "Cherrygram", "materialgram", "Nicegram"} {
		if !isTrustedTelegramPublisher(pub, `C:\Apps\client.exe`) {
			t.Fatalf("expected publisher %q to be trusted", pub)
		}
	}
}
