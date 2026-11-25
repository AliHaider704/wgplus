package wgbridge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	diagMaxEntries = 256
	backupFormatV1 = "wgplus-backup-v1"
)

type diagEntry struct {
	Timestamp string `json:"ts"`
	Category  string `json:"cat"`
	Code      string `json:"code"`
	Message   string `json:"msg"`
}

var (
	diagMu      sync.Mutex
	diagEntries []diagEntry

	udpSocketsOpened     atomic.Uint64
	udpPacketsTx         atomic.Uint64
	udpPacketsRx         atomic.Uint64
	udpGuardDrops        atomic.Uint64
	udpSendErrors        atomic.Uint64
	udpIpv6DialFastFails atomic.Uint64
	watchdogRecoveries   atomic.Uint64

	diagSecretKVRe     = regexp.MustCompile(`(?i)\b((?:socks_?|proxy_?|shared_?)?(?:private_?key|preshared_?key|pass(?:word|phrase)?|secret|auth|token))\s*[:=]\s*([^\s,;]+)`)
	diagB64KeyRe       = regexp.MustCompile(`[A-Za-z0-9+/]{42,44}=`)
	diagHexKeyRe       = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	diagPublicIpPortRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b`)
)

func sanitizeDiagMessage(msg string) string {
	s := strings.TrimSpace(msg)
	if s == "" {
		return ""
	}
	s = diagSecretKVRe.ReplaceAllString(s, "$1=[REDACTED]")
	s = diagPublicIpPortRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "127.") {
			return m
		}
		return "[IP_PORT_REDACTED]"
	})
	s = diagB64KeyRe.ReplaceAllString(s, "[KEY_REDACTED]")
	s = diagHexKeyRe.ReplaceAllString(s, "[HEX_KEY_REDACTED]")
	if len(s) > 360 {
		s = s[:360] + "..."
	}
	return s
}

// RecordDiag appends a sanitized diagnostic event into the bounded in-memory ring buffer.
func RecordDiag(category, code, message string) {
	entry := diagEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Category:  strings.TrimSpace(category),
		Code:      strings.TrimSpace(code),
		Message:   sanitizeDiagMessage(message),
	}
	diagMu.Lock()
	if len(diagEntries) >= diagMaxEntries {
		copy(diagEntries, diagEntries[1:])
		diagEntries[len(diagEntries)-1] = entry
	} else {
		diagEntries = append(diagEntries, entry)
	}
	diagMu.Unlock()
}

// GetDiagnosticsJSON returns all buffered Go engine diagnostic events as a JSON array.
func GetDiagnosticsJSON() string {
	diagMu.Lock()
	snapshot := make([]diagEntry, len(diagEntries))
	copy(snapshot, diagEntries)
	diagMu.Unlock()

	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// ClearDiagnostics clears the diagnostic ring buffer and resets error/drop telemetry counters.
func ClearDiagnostics() {
	diagMu.Lock()
	diagEntries = nil
	diagMu.Unlock()
	udpGuardDrops.Store(0)
	udpSendErrors.Store(0)
	udpIpv6DialFastFails.Store(0)
	watchdogRecoveries.Store(0)
}

// GetUdpTelemetryJSON returns real-time Full-Cone UDP ASSOCIATE and watchdog counters as JSON.
func GetUdpTelemetryJSON() string {
	payload := map[string]any{
		"activeTcpConns":       activeTcpConns.Load(),
		"activeUdpAssocs":      activeUdpAssocs.Load(),
		"activeProxyStreams":   getActiveProxyStreamCount(),
		"blockedLocalAttempts": blockedLocalAttempts.Load(),
		"udpSocketsOpened":     udpSocketsOpened.Load(),
		"udpPacketsTx":         udpPacketsTx.Load(),
		"udpPacketsRx":         udpPacketsRx.Load(),
		"udpGuardDrops":        udpGuardDrops.Load(),
		"udpSendErrors":        udpSendErrors.Load(),
		"udpIpv6FastFails":     udpIpv6DialFastFails.Load(),
		"watchdogRecoveries":   watchdogRecoveries.Load(),
		"recoveryEpoch":        GetRecoveryEpoch(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// BuildEngineDiagnosticsBundleJSON returns a single privacy-safe JSON snapshot containing live
// detailed tunnel state (endpoint port only, zero raw peer IP/host), UDP & watchdog counters,
// VoIP relay packet counters, and the latest Go ring-buffer entries.
func BuildEngineDiagnosticsBundleJSON() string {
	mu.Lock()
	dev := activeDev
	isUp := running && muxListener != nil && dev != nil
	ks := muxKillSwitch
	sPort := muxPort
	hPort := httpProxyPort
	baseRx := baseRxBytes
	baseTx := baseTxBytes
	epPort := 0
	if _, portStr, err := net.SplitHostPort(strings.TrimSpace(activeResolvedEp)); err == nil {
		if p, pErr := strconv.Atoi(portStr); pErr == nil && p > 0 {
			epPort = p
		}
	}
	mtu := activeMtu
	keepAlive := activeKeepAlive
	var uptimeSec int64
	if isUp && !activeStartTime.IsZero() {
		uptimeSec = int64(time.Since(activeStartTime).Seconds())
		if uptimeSec < 0 {
			uptimeSec = 0
		}
	}
	mu.Unlock()

	var rxBytes, txBytes uint64
	var hsAge int64 = -1
	if isUp && dev != nil {
		rawRx, rawTx, hs := readDeviceCounters(dev)
		rxBytes = baseRx + rawRx
		txBytes = baseTx + rawTx
		if hs > 0 {
			hsAge = time.Now().Unix() - hs
			if hsAge < 0 {
				hsAge = 0
			}
		}
	}

	clientStatsMu.RLock()
	clients := make([]clientTrafficStat, 0, len(clientStatsMap))
	for _, ent := range clientStatsMap {
		clients = append(clients, clientTrafficStat{
			Label:        ent.label,
			ActiveConns:  ent.activeConns.Load(),
			RxBytes:      ent.rxBytes.Load(),
			TxBytes:      ent.txBytes.Load(),
			LastSeenUnix: ent.lastSeenUnix.Load(),
		})
	}
	clientStatsMu.RUnlock()

	diagMu.Lock()
	startIdx := 0
	if len(diagEntries) > 80 {
		startIdx = len(diagEntries) - 80
	}
	ringCopy := make([]diagEntry, 0, len(diagEntries)-startIdx)
	for _, entry := range diagEntries[startIdx:] {
		ringCopy = append(ringCopy, diagEntry{
			Timestamp: entry.Timestamp,
			Category:  entry.Category,
			Code:      entry.Code,
			Message:   sanitizeDiagMessage(entry.Message),
		})
	}
	diagMu.Unlock()

	bundle := map[string]any{
		"detailed": map[string]any{
			"running":              isUp,
			"killSwitch":           ks,
			"socksPort":            sPort,
			"httpPort":             hPort,
			"rxBytes":              rxBytes,
			"txBytes":              txBytes,
			"rxBps":                currentRxBps.Load(),
			"txBps":                currentTxBps.Load(),
			"hsAgeSec":             hsAge,
			"handshakeHealthy":     IsHandshakeHealthy(),
			"socksAuthRejectCount": GetSocksAuthRejectCount(),
			"activeMtu":            mtu,
			"activeKeepAlive":      keepAlive,
			"uptimeSec":            uptimeSec,
			"endpointPort":         epPort,
			"clients":              clients,
		},
		"udpTelemetry": map[string]any{
			"activeTcpConns":       activeTcpConns.Load(),
			"activeUdpAssocs":      activeUdpAssocs.Load(),
			"activeProxyStreams":   getActiveProxyStreamCount(),
			"blockedLocalAttempts": blockedLocalAttempts.Load(),
			"udpSocketsOpened":     udpSocketsOpened.Load(),
			"udpPacketsTx":         udpPacketsTx.Load(),
			"udpPacketsRx":         udpPacketsRx.Load(),
			"udpGuardDrops":        udpGuardDrops.Load(),
			"udpSendErrors":        udpSendErrors.Load(),
			"udpIpv6FastFails":     udpIpv6DialFastFails.Load(),
			"watchdogRecoveries":   watchdogRecoveries.Load(),
			"recoveryEpoch":        GetRecoveryEpoch(),
		},
		"voipRelays": getVoipRelaysDiagSnapshot(),
		"ringBuffer": ringCopy,
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

type backupV1Envelope struct {
	Format     string `json:"format"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// EncryptBackupV1 encrypts a UTF-8 JSON backup using Argon2id (t=2, m=64MB, p=4) + AES-256-GCM
// in the exact wgplus-backup-v1 format used by Windows desktop for cross-platform portability.
func EncryptBackupV1(plaintextJSON, passphrase string) (string, error) {
	if len(passphrase) < 4 {
		return "", errors.New("passphrase must be at least 4 characters")
	}
	if strings.TrimSpace(plaintextJSON) == "" {
		return "", errors.New("backup payload is empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(passphrase), salt, 2, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintextJSON), []byte(backupFormatV1))
	env := backupV1Envelope{
		Format:     backupFormatV1,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// DecryptBackupV1 decrypts a wgplus-backup-v1 Argon2id + AES-256-GCM encrypted backup envelope.
func DecryptBackupV1(envelopeJSON, passphrase string) (string, error) {
	if len(passphrase) < 1 {
		return "", errors.New("passphrase is required")
	}
	var env backupV1Envelope
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		return "", errors.New("invalid encrypted backup format")
	}
	if env.Format != backupFormatV1 {
		return "", errors.New("unsupported backup format")
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) < 8 {
		return "", errors.New("corrupt backup salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return "", errors.New("corrupt backup nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return "", errors.New("corrupt backup ciphertext")
	}
	key := argon2.IDKey([]byte(passphrase), salt, 2, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(nonce) != gcm.NonceSize() {
		return "", errors.New("invalid backup nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(backupFormatV1))
	if err != nil {
		return "", errors.New("wrong passphrase or tampered backup")
	}
	return string(plain), nil
}
