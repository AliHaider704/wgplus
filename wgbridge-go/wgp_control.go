package wgbridge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type prependByteConn struct {
	net.Conn
	firstByte byte
	consumed  bool
}

func (c *prependByteConn) Read(p []byte) (int, error) {
	if !c.consumed {
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = c.firstByte
		c.consumed = true
		return 1, nil
	}
	return c.Conn.Read(p)
}

// ComputeProfileSigHash returns the 12-hex-char SHA-256 prefix of a normalized profileSig
// so non-secret PUBLIC_STATUS probes can confirm shared-hub profile equivalence without leaking endpoints.
func ComputeProfileSigHash(profileSig string) string {
	trimmed := strings.TrimSpace(profileSig)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])[:12]
}

func readWgpStatusSnapshot() (isUp bool, hsHealthy bool, hsSec int64, profileSig string) {
	mu.Lock()
	isUp = running
	dev := activeDev
	rawEp := strings.TrimSpace(activeRawEp)
	pubHex := strings.TrimSpace(activePeerPubHex)
	mu.Unlock()
	if isUp && dev != nil {
		_, _, hsSec = readDeviceCounters(dev)
	}
	hsHealthy = IsHandshakeHealthy()
	if rawEp != "" && len(pubHex) == 64 {
		if pubRaw, dErr := hex.DecodeString(pubHex); dErr == nil && len(pubRaw) == 32 {
			profileSig = rawEp + "|" + base64.StdEncoding.EncodeToString(pubRaw)
		}
	}
	return isUp, hsHealthy, hsSec, profileSig
}

// SendLocalWgp1Command executes a single-line WGP1 loopback control command from Go so Android
// Main UI Thread callers (such as VoIPService endpoint setup) never trigger StrictMode NetworkOnMainThreadException.
func SendLocalWgp1Command(muxPort int, socksPass string, command string, timeoutMs int) string {
	return sendLocalWgp1CommandLimit(muxPort, socksPass, command, timeoutMs, 512)
}

func sendLocalWgp1CommandLimit(muxPort int, socksPass string, command string, timeoutMs int, maxBytes int) string {
	cmd := strings.TrimSpace(command)
	if muxPort < 1 || muxPort > 65535 || cmd == "" {
		return ""
	}
	if maxBytes < 512 {
		maxBytes = 512
	}
	if timeoutMs < 80 {
		timeoutMs = 80
	} else if timeoutMs > 2000 {
		timeoutMs = 2000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	passTok := strings.TrimSpace(socksPass)
	if passTok == "" {
		passTok = "-"
	}

	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", muxPort), timeout)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	line := "WGP1 " + passTok + " " + cmd + "\n"
	if _, err := c.Write([]byte(line)); err != nil {
		return ""
	}
	out := make([]byte, 0, minInt(maxBytes, 2048))
	chunk := make([]byte, 1024)
	for len(out) < maxBytes {
		rn, rErr := c.Read(chunk)
		if rn > 0 {
			for i := 0; i < rn && len(out) < maxBytes; i++ {
				if chunk[i] == '\n' {
					return strings.TrimSpace(string(out))
				}
				out = append(out, chunk[i])
			}
		}
		if rErr != nil {
			break
		}
	}
	return strings.TrimSpace(string(out))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RequestRemoteDiagnosticsBundleJSON queries a live local mux owner over authenticated WGP1
// for its complete sanitized diagnostic bundle JSON (counters, VoIP relays, and ring buffer).
func RequestRemoteDiagnosticsBundleJSON(muxPort int, socksPass string) string {
	resp := sendLocalWgp1CommandLimit(muxPort, socksPass, "DIAG_BUNDLE", 1200, 65536)
	if !strings.HasPrefix(resp, "OK ") {
		return ""
	}
	return strings.TrimSpace(resp[3:])
}

// RequestRemoteVoipRelayAddr asks a live local mux owner over WGP1 to bind or reuse a
// port-preserving loopback relay ("ip:port") for targetHost:targetPort.
func RequestRemoteVoipRelayAddr(muxPort int, socksPass string, targetHost string, targetPort int) string {
	host := strings.TrimSpace(targetHost)
	if muxPort < 1 || muxPort > 65535 || host == "" || targetPort < 1 || targetPort > 65535 {
		return ""
	}
	resp := SendLocalWgp1Command(muxPort, socksPass, fmt.Sprintf("VOIP_RELAY_ADDR %s %d", host, targetPort), 650)
	if strings.HasPrefix(resp, "OK ") {
		addr := strings.TrimSpace(resp[3:])
		if strings.Contains(addr, ":") {
			return addr
		}
	}
	respLegacy := SendLocalWgp1Command(muxPort, socksPass, fmt.Sprintf("VOIP_RELAY %s %d", host, targetPort), 650)
	if strings.HasPrefix(respLegacy, "OK ") {
		portNum, err := strconv.Atoi(strings.TrimSpace(respLegacy[3:]))
		if err == nil && portNum > 0 && portNum <= 65535 {
			return fmt.Sprintf("127.0.0.1:%d", portNum)
		}
	}
	return ""
}

// RequestRemoteTunnelYield asks a live local mux owner over authenticated WGP1 to release
// its tunnel, kill switch guard, and local mux port for foreground takeover.
func RequestRemoteTunnelYield(muxPort int, socksPass string) bool {
	if muxPort < 1 || muxPort > 65535 {
		return false
	}
	resp := SendLocalWgp1Command(muxPort, socksPass, "YIELD", 800)
	if !strings.HasPrefix(resp, "OK") {
		return false
	}
	time.Sleep(25 * time.Millisecond)
	return true
}

func handleWgpControlConn(client net.Conn, firstByte byte) {
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	buf[0] = firstByte
	n := 1
	for n < len(buf) {
		rn, err := client.Read(buf[n : n+1])
		if rn > 0 {
			if buf[n] == '\n' {
				break
			}
			n++
		}
		if err != nil {
			break
		}
	}
	line := strings.TrimSpace(string(buf[:n]))
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "WGP1" {
		_, _ = client.Write([]byte("ERR CMD\n"))
		return
	}

	// Non-secret status metadata allows local sandboxed clients (before credential sync)
	// to detect whether port 48729 already hosts a running tunnel for the same profile hash.
	if fields[2] == "PUBLIC_STATUS" {
		isUp, hsHealthy, hsSec, profileSig := readWgpStatusSnapshot()
		sigHash := ComputeProfileSigHash(profileSig)
		if sigHash != "" {
			_, _ = fmt.Fprintf(client, "OK %t %t %d %s\n", isUp, hsHealthy, hsSec, sigHash)
		} else {
			_, _ = fmt.Fprintf(client, "OK %t %t %d -\n", isUp, hsHealthy, hsSec)
		}
		return
	}

	_, expectedPass := getSocksAuth()
	if expectedPass != "" {
		passMatch := verifySocksPassBytes([]byte(fields[1])) == 1
		if !passMatch {
			_, _ = client.Write([]byte("ERR AUTH\n"))
			return
		}
	}

	switch fields[2] {
	case "VOIP_RELAY":
		if len(fields) != 5 {
			_, _ = client.Write([]byte("ERR ARGS\n"))
			return
		}
		portNum, err := strconv.Atoi(fields[4])
		if err != nil || portNum < 1 || portNum > 65535 {
			_, _ = client.Write([]byte("ERR PORT\n"))
			return
		}
		if !IsRunning() {
			_, _ = client.Write([]byte("ERR STOPPED\n"))
			return
		}
		lp := StartVoipEndpointRelay(fields[3], portNum)
		if lp <= 0 {
			_, _ = client.Write([]byte("ERR RELAY\n"))
			return
		}
		_, _ = fmt.Fprintf(client, "OK %d\n", lp)
	case "VOIP_RELAY_ADDR":
		if len(fields) != 5 {
			_, _ = client.Write([]byte("ERR ARGS\n"))
			return
		}
		portNum, err := strconv.Atoi(fields[4])
		if err != nil || portNum < 1 || portNum > 65535 {
			_, _ = client.Write([]byte("ERR PORT\n"))
			return
		}
		if !IsRunning() {
			_, _ = client.Write([]byte("ERR STOPPED\n"))
			return
		}
		addr := StartVoipEndpointRelayAddr(fields[3], portNum)
		if addr == "" {
			_, _ = client.Write([]byte("ERR RELAY\n"))
			return
		}
		_, _ = fmt.Fprintf(client, "OK %s\n", addr)
	case "STATUS":
		isUp, hsHealthy, hsSec, profileSig := readWgpStatusSnapshot()
		if profileSig != "" {
			_, _ = fmt.Fprintf(client, "OK %t %t %d %s\n", isUp, hsHealthy, hsSec, profileSig)
		} else {
			_, _ = fmt.Fprintf(client, "OK %t %t %d\n", isUp, hsHealthy, hsSec)
		}
	case "DIAG_BUNDLE":
		_, _ = client.Write([]byte("OK " + BuildEngineDiagnosticsBundleJSON() + "\n"))
	case "YIELD":
		SetKillSwitchArmed(false)
		StopKillSwitchGuard()
		StopTunnel()
		RecordDiag("TUNNEL", "YIELDED", "released local mux on authenticated YIELD")
		_, _ = client.Write([]byte("OK YIELDED\n"))
	default:
		_, _ = client.Write([]byte("ERR CMD\n"))
	}
}

func handleMuxConn(client net.Conn) {
	defer client.Close()

	clientLabel, clientAllowed := invokeClientGuard(client.RemoteAddr())
	if !clientAllowed {
		blockedLocalAttempts.Add(1)
		return
	}

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	var first [1]byte
	if _, err := io.ReadFull(client, first[:]); err != nil {
		return
	}
	if first[0] == 'W' {
		handleWgpControlConn(client, first[0])
		return
	}

	wrapped := &prependByteConn{Conn: client, firstByte: first[0]}
	_ = wrapped.SetDeadline(time.Now().Add(20 * time.Second))

	cmd, host, dstPort, authSubLabel, ok := readSocks5HandshakeAndReqWithLabel(wrapped)
	if !ok {
		return
	}
	if authSubLabel != "" && (clientLabel == "android" || clientLabel == "local-client" || clientLabel == "") {
		clientLabel = authSubLabel
	}

	devCtx, dialer, allowed := awaitMuxRouteReady(2800 * time.Millisecond)
	if !allowed {
		// Fail closed: zero plaintext traffic leaves device when tunnel is down.
		_, _ = wrapped.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	dispatchSocks5CmdWithLabel(devCtx, wrapped, dialer, cmd, host, dstPort, clientLabel)
}
