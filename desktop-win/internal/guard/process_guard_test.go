package guard

import (
	"net"
	"os"
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

	// Verify allowlist decision helper directly on non-self PID
	if pg.isAllowedProcess(999999, `C:\Windows\System32\curl.exe`, "curl.exe") {
		t.Fatalf("expected curl.exe to be blocked in strict mode")
	}
	if !pg.isAllowedProcess(999999, `D:\Apps\TelegramPortable\Telegram.exe`, "Telegram.exe") {
		t.Fatalf("expected Telegram.exe to be allowed")
	}
	if !pg.isAllowedProcess(999999, `D:\Apps\AyuGram\AyuGram.exe`, "AyuGram.exe") {
		t.Fatalf("expected AyuGram.exe to be allowed")
	}
	if !pg.isAllowedProcess(999999, `D:\Apps\64Gram\64Gram.exe`, "64Gram.exe") {
		t.Fatalf("expected 64Gram.exe to be allowed")
	}
	if !pg.isAllowedProcess(999999, `C:\Program Files\WindowsApps\Unigram\Unigram.exe`, "Unigram.exe") {
		t.Fatalf("expected Unigram.exe to be allowed")
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
