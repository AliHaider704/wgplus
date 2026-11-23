package watchdog

import (
	"context"
	"sort"
	"sync"
	"time"

	"wgplus-win/internal/config"
)

// Dependencies abstracts tunnel health checks, rebinding, probing, and switching for testability.
type Dependencies struct {
	IsRunning            func() bool
	TunnelUptime         func() time.Duration
	SnapshotStats        func() (handshakeAgeSec int64, txBytes uint64)
	SnapshotTrafficStats func() (handshakeAgeSec int64, rxBytes uint64, txBytes uint64)
	ForceRebind          func() bool
	SetPending       func(pending bool)
	ListProfiles     func() (activeID string, profiles []config.ServerProfile)
	IsAutoFailover   func() bool
	ProbeProfile     func(ctx context.Context, p config.ServerProfile) (int, error)
	SwitchToProfile  func(profileID string) error
	OnFailoverSwitch func(fromID, toID, toName string, rttMs int)
	OnFailoverError  func(err error)
}

// Monitor periodically checks handshake freshness / TX progress and executes
// rebind recovery followed by lowest-latency multi-server auto-failover if needed.
type Monitor struct {
	deps          Dependencies
	checkInterval time.Duration

	mu               sync.Mutex
	lastRxBytes      uint64
	lastTxBytes      uint64
	consecutiveStall int
	lastFailoverAt   time.Time
}

// NewMonitor constructs a failover Monitor using the supplied dependencies.
func NewMonitor(deps Dependencies, checkInterval time.Duration) *Monitor {
	if checkInterval <= 0 {
		checkInterval = 5 * time.Second
	}
	return &Monitor{
		deps:          deps,
		checkInterval: checkInterval,
	}
}

// Run blocks until ctx cancels, polling tunnel health at checkInterval.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Step(ctx)
		}
	}
}

// Step evaluates one health-check cycle (exposed for deterministic unit testing).
func (m *Monitor) Step(ctx context.Context) {
	if m.deps.IsRunning == nil || !m.deps.IsRunning() {
		m.mu.Lock()
		m.consecutiveStall = 0
		m.lastRxBytes = 0
		m.lastTxBytes = 0
		m.mu.Unlock()
		return
	}

	uptime := time.Duration(0)
	if m.deps.TunnelUptime != nil {
		uptime = m.deps.TunnelUptime()
	}
	if uptime < 12*time.Second {
		return
	}

	var hsAge int64
	var rxBytes, txBytes uint64
	hasRx := false
	if m.deps.SnapshotTrafficStats != nil {
		hsAge, rxBytes, txBytes = m.deps.SnapshotTrafficStats()
		hasRx = true
	} else if m.deps.SnapshotStats != nil {
		hsAge, txBytes = m.deps.SnapshotStats()
	}

	m.mu.Lock()
	prevRx := m.lastRxBytes
	prevTx := m.lastTxBytes
	m.lastRxBytes = rxBytes
	m.lastTxBytes = txBytes
	m.mu.Unlock()

	txGrowing := txBytes > prevTx+64
	txWithoutRx := hasRx && txGrowing && rxBytes == prevRx
	needsRecovery := false
	if hsAge < 0 {
		needsRecovery = true
	} else if hsAge > 195 {
		needsRecovery = true
	} else if hsAge > 145 && txGrowing {
		needsRecovery = true
	} else if txWithoutRx {
		needsRecovery = true
	}

	if !needsRecovery {
		m.mu.Lock()
		m.consecutiveStall = 0
		m.mu.Unlock()
		return
	}

	if m.deps.ForceRebind != nil && m.deps.ForceRebind() {
		m.mu.Lock()
		m.consecutiveStall = 0
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	m.consecutiveStall++
	stalls := m.consecutiveStall
	sinceFailover := time.Since(m.lastFailoverAt)
	m.mu.Unlock()

	if stalls >= 2 && sinceFailover >= 20*time.Second {
		m.TriggerFailover(ctx)
	}
}

// TriggerFailover probes backup profiles in parallel and switches to the fastest healthy server.
func (m *Monitor) TriggerFailover(ctx context.Context) bool {
	if m.deps.IsAutoFailover != nil && !m.deps.IsAutoFailover() {
		return false
	}
	if m.deps.ListProfiles == nil || m.deps.ProbeProfile == nil || m.deps.SwitchToProfile == nil {
		return false
	}

	activeID, all := m.deps.ListProfiles()
	var candidates []config.ServerProfile
	for _, p := range all {
		if p.ID != activeID {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return false
	}

	m.mu.Lock()
	m.lastFailoverAt = time.Now()
	m.mu.Unlock()

	if m.deps.SetPending != nil {
		m.deps.SetPending(true)
		defer m.deps.SetPending(false)
	}

	type probeCandidate struct {
		profile config.ServerProfile
		rttMs   int
		err     error
	}

	probeCtx, cancel := context.WithTimeout(ctx, 4500*time.Millisecond)
	defer cancel()

	results := make([]probeCandidate, len(candidates))
	var wg sync.WaitGroup
	for i, cand := range candidates {
		wg.Add(1)
		go func(idx int, prof config.ServerProfile) {
			defer wg.Done()
			ms, err := m.deps.ProbeProfile(probeCtx, prof)
			results[idx] = probeCandidate{profile: prof, rttMs: ms, err: err}
		}(i, cand)
	}
	wg.Wait()

	var healthy []probeCandidate
	for _, r := range results {
		if r.err == nil && r.rttMs > 0 {
			healthy = append(healthy, r)
		}
	}
	if len(healthy) == 0 {
		return false
	}

	sort.Slice(healthy, func(i, j int) bool {
		return healthy[i].rttMs < healthy[j].rttMs
	})

	for _, pick := range healthy {
		if err := m.deps.SwitchToProfile(pick.profile.ID); err == nil {
			m.mu.Lock()
			m.consecutiveStall = 0
			m.mu.Unlock()
			if m.deps.OnFailoverSwitch != nil {
				m.deps.OnFailoverSwitch(activeID, pick.profile.ID, pick.profile.Name, pick.rttMs)
			}
			return true
		} else if m.deps.OnFailoverError != nil {
			m.deps.OnFailoverError(err)
		}
	}
	return false
}
