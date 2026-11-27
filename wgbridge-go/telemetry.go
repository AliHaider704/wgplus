package wgbridge

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type clientStatEntry struct {
	label        string
	activeConns  atomic.Int64
	rxBytes      atomic.Uint64
	txBytes      atomic.Uint64
	lastSeenUnix atomic.Int64
}

type clientTrafficStat struct {
	Label        string `json:"label"`
	ActiveConns  int64  `json:"activeConns"`
	RxBytes      uint64 `json:"rxBytes"`
	TxBytes      uint64 `json:"txBytes"`
	LastSeenUnix int64  `json:"lastSeenUnix"`
}

type detailedTunnelStats struct {
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
	HandshakeHealthy     bool                `json:"handshakeHealthy"`
	SocksAuthRejectCount int64               `json:"socksAuthRejectCount"`
	ResolvedEndpoint     string              `json:"resolvedEndpoint"`
	ActiveMtu            int                 `json:"activeMtu"`
	Clients              []clientTrafficStat `json:"clients"`
}

var (
	activeTcpConns       atomic.Int64
	activeUdpAssocs      atomic.Int64
	blockedLocalAttempts atomic.Uint64
	currentRxBps         atomic.Uint64
	currentTxBps         atomic.Uint64

	clientStatsMu  sync.RWMutex
	clientStatsMap = make(map[string]*clientStatEntry)
)

func normalizeClientLabel(label string) string {
	trimmed := strings.TrimSpace(label)
	if trimmed == "" {
		return "local-client"
	}
	return trimmed
}

func getOrCreateClientStat(label string) *clientStatEntry {
	key := normalizeClientLabel(label)
	clientStatsMu.RLock()
	ent, ok := clientStatsMap[key]
	clientStatsMu.RUnlock()
	if ok {
		return ent
	}

	clientStatsMu.Lock()
	ent, ok = clientStatsMap[key]
	if !ok {
		ent = &clientStatEntry{label: key}
		clientStatsMap[key] = ent
	}
	clientStatsMu.Unlock()
	return ent
}

func trackClientConnStart(label string) *clientStatEntry {
	ent := getOrCreateClientStat(label)
	ent.activeConns.Add(1)
	ent.lastSeenUnix.Store(time.Now().Unix())
	return ent
}

func trackClientConnEnd(ent *clientStatEntry) {
	if ent == nil {
		return
	}
	if v := ent.activeConns.Add(-1); v < 0 {
		ent.activeConns.Store(0)
	}
}

func recordClientRx(ent *clientStatEntry, n int) {
	if ent == nil || n <= 0 {
		return
	}
	ent.rxBytes.Add(uint64(n))
	ent.lastSeenUnix.Store(time.Now().Unix())
}

func recordClientTx(ent *clientStatEntry, n int) {
	if ent == nil || n <= 0 {
		return
	}
	ent.txBytes.Add(uint64(n))
	ent.lastSeenUnix.Store(time.Now().Unix())
}

// ResetClientTelemetry clears accumulated per-client traffic counters and blocked attempt totals.
func ResetClientTelemetry() {
	blockedLocalAttempts.Store(0)
	clientStatsMu.Lock()
	clientStatsMap = make(map[string]*clientStatEntry)
	clientStatsMu.Unlock()
}

func tunnelBandwidthSamplerLoop(ctx context.Context, dev *device.Device) {
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		ticker.Stop()
		currentRxBps.Store(0)
		currentTxBps.Store(0)
	}()

	lastRx, lastTx, _ := readActiveTotals(dev)
	lastTick := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
		if !isActiveDevice(dev) {
			return
		}
		rx, tx, _ := readActiveTotals(dev)
		elapsed := now.Sub(lastTick).Seconds()
		if elapsed > 0.05 {
			var rBps, tBps uint64
			if rx >= lastRx {
				rBps = uint64(float64(rx-lastRx) / elapsed)
			}
			if tx >= lastTx {
				tBps = uint64(float64(tx-lastTx) / elapsed)
			}
			currentRxBps.Store(rBps)
			currentTxBps.Store(tBps)
		}
		lastRx, lastTx = rx, tx
		lastTick = now
		}
	}
}

// GetDetailedStatsJSON returns a JSON snapshot of live tunnel throughput, handshake age,
// active TCP/UDP sessions, blocked loopback attempts, and per-client traffic breakdown.
func GetDetailedStatsJSON() string {
	mu.Lock()
	dev := activeDev
	isUp := running && muxListener != nil && dev != nil
	ks := muxKillSwitch
	sPort := muxPort
	hPort := httpProxyPort
	baseRx := baseRxBytes
	baseTx := baseTxBytes
	resolvedEp := activeResolvedEp
	curMtu := activeMtu
	mu.Unlock()

	var rxBytes, txBytes uint64
	var hsUnix int64
	var hsAge int64 = -1
	if isUp && dev != nil {
		rawRx, rawTx, hs := readDeviceCounters(dev)
		rxBytes = baseRx + rawRx
		txBytes = baseTx + rawTx
		hsUnix = hs
		if hs > 0 {
			age := time.Now().Unix() - hs
			if age < 0 {
				age = 0
			}
			hsAge = age
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

	sort.Slice(clients, func(i, j int) bool {
		if clients[i].ActiveConns != clients[j].ActiveConns {
			return clients[i].ActiveConns > clients[j].ActiveConns
		}
		ti := clients[i].RxBytes + clients[i].TxBytes
		tj := clients[j].RxBytes + clients[j].TxBytes
		if ti != tj {
			return ti > tj
		}
		return clients[i].Label < clients[j].Label
	})

	snap := detailedTunnelStats{
		Running:              isUp,
		KillSwitch:           ks,
		SocksPort:            sPort,
		HttpPort:             hPort,
		RxBytes:              rxBytes,
		TxBytes:              txBytes,
		RxBps:                currentRxBps.Load(),
		TxBps:                currentTxBps.Load(),
		HandshakeAgeSec:      hsAge,
		LastHandshakeUnix:    hsUnix,
		ActiveTcpConns:       activeTcpConns.Load(),
		ActiveUdpAssocs:      activeUdpAssocs.Load(),
		BlockedLocalAttempts: blockedLocalAttempts.Load(),
		HandshakeHealthy:     IsHandshakeHealthy(),
		SocksAuthRejectCount: GetSocksAuthRejectCount(),
		ResolvedEndpoint:     resolvedEp,
		ActiveMtu:            curMtu,
		Clients:              clients,
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
