package wgbridge

import (
	"net"
	"testing"
)

func TestCryptoRandDnsTxIDNonZeroAndUnpredictable(t *testing.T) {
	seen := make(map[uint16]bool, 64)
	for i := 0; i < 64; i++ {
		id := cryptoRandDnsTxID()
		if id == 0 {
			t.Fatalf("iteration %d produced zero DNS txID", i)
		}
		seen[id] = true
	}
	if len(seen) < 50 {
		t.Fatalf("expected high entropy across 64 DNS txID samples, got only %d distinct values", len(seen))
	}
	if len(seen) == 1 && (seen[0x5747] || seen[0x5748]) {
		t.Fatalf("DNS txID appears hardcoded")
	}
}

func TestOpenFullConePacketConnFailsClosedOnNonTunnelDialer(t *testing.T) {
	if pc, err := openFullConePacketConn(nil, false); err == nil || pc != nil {
		if pc != nil {
			_ = pc.Close()
		}
		t.Fatalf("expected nil dialer to fail closed, got pc=%v err=%v", pc, err)
	}
	var stdDialer net.Dialer
	if pc, err := openFullConePacketConn(&stdDialer, false); err == nil || pc != nil {
		if pc != nil {
			_ = pc.Close()
		}
		t.Fatalf("expected clearnet net.Dialer to fail closed, got pc=%v err=%v", pc, err)
	}
	if pc, err := openFullConePacketConn(&stdDialer, true); err == nil || pc != nil {
		if pc != nil {
			_ = pc.Close()
		}
		t.Fatalf("expected clearnet IPv6 net.Dialer to fail closed, got pc=%v err=%v", pc, err)
	}
}
