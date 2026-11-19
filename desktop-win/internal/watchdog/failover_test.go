package watchdog

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"wgplus-win/internal/config"
)

func TestMonitorSelectsFastestHealthyBackupOnStall(t *testing.T) {
	var pendingCalls atomic.Int32
	var switchedTo string

	active := "srv1"
	profiles := []config.ServerProfile{
		{ID: "srv1", Name: "Primary"},
		{ID: "srv2", Name: "Slow Backup"},
		{ID: "srv3", Name: "Fast Backup"},
		{ID: "srv4", Name: "Dead Backup"},
	}

	m := NewMonitor(Dependencies{
		IsRunning:    func() bool { return true },
		TunnelUptime: func() time.Duration { return 30 * time.Second },
		SnapshotStats: func() (int64, uint64) {
			return -1, 1024 // missing handshake past grace
		},
		ForceRebind: func() bool { return false },
		SetPending: func(p bool) {
			if p {
				pendingCalls.Add(1)
			}
		},
		ListProfiles: func() (string, []config.ServerProfile) {
			return active, profiles
		},
		IsAutoFailover: func() bool { return true },
		ProbeProfile: func(_ context.Context, p config.ServerProfile) (int, error) {
			switch p.ID {
			case "srv2":
				return 180, nil
			case "srv3":
				return 35, nil
			default:
				return 0, errors.New("timeout")
			}
		},
		SwitchToProfile: func(profileID string) error {
			switchedTo = profileID
			active = profileID
			return nil
		},
	}, time.Second)

	ctx := context.Background()
	// First stall increments counter to 1
	m.Step(ctx)
	if switchedTo != "" {
		t.Fatalf("did not expect failover after single stall, switched to %q", switchedTo)
	}
	// Second consecutive stall triggers parallel probe and picks srv3 (35ms < 180ms)
	m.Step(ctx)
	if switchedTo != "srv3" {
		t.Fatalf("expected failover to fastest healthy backup srv3, got %q", switchedTo)
	}
	if pendingCalls.Load() == 0 {
		t.Fatalf("expected SetPending(true) during failover")
	}
}

func TestMonitorSkipsFailoverWhenDisabled(t *testing.T) {
	var switched bool
	m := NewMonitor(Dependencies{
		IsRunning:     func() bool { return true },
		TunnelUptime:  func() time.Duration { return 30 * time.Second },
		SnapshotStats: func() (int64, uint64) { return 210, 2048 },
		ForceRebind:   func() bool { return false },
		ListProfiles: func() (string, []config.ServerProfile) {
			return "a", []config.ServerProfile{{ID: "a"}, {ID: "b"}}
		},
		IsAutoFailover: func() bool { return false },
		ProbeProfile:   func(_ context.Context, _ config.ServerProfile) (int, error) { return 10, nil },
		SwitchToProfile: func(_ string) error {
			switched = true
			return nil
		},
	}, time.Second)

	m.Step(context.Background())
	m.Step(context.Background())
	if switched {
		t.Fatalf("expected no failover when AutoFailover is disabled")
	}
}
