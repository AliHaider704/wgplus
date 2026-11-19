package config

import (
	"strings"
	"testing"
)

func TestParseAndExportAwg15ConfRoundTrip(t *testing.T) {
	raw := `
# AmneziaWG 1.5 + WARP config
[Interface]
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 172.16.0.2/32, fd01::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1340
Jc = 4
Jmin = 40
Jmax = 120
S1 = 28
S2 = 24
H1 = 100010-100020
H4 = 400010
I1 = <b 0xc70000000108><r 8><b 0x0000449e><r 64>
Reserved = 12,34,56

[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
PresharedKey = ccccccccccccccccccccccccccccccccccccccccccc=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408 # edge
PersistentKeepalive = 25
`
	p, err := ParseWgConf(raw, "WARP AWG1.5")
	if err != nil {
		t.Fatalf("ParseWgConf failed: %v", err)
	}
	if p.Name != "WARP AWG1.5" || p.MTU != 1340 || p.KeepAlive != 25 {
		t.Fatalf("unexpected parsed fields: %+v", p)
	}
	if p.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("expected clean endpoint without comment, got %q", p.Endpoint)
	}
	if !strings.Contains(p.AwgParams, "I1=<b 0xc70000000108>") || !strings.Contains(p.AwgParams, "Reserved=12,34,56") {
		t.Fatalf("expected I1 and Reserved in AwgParams, got %q", p.AwgParams)
	}

	exported := ExportWgConf(p)
	p2, err := ParseWgConf(exported, p.Name)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if p2.PrivateKey != p.PrivateKey || p2.PeerPublicKey != p.PeerPublicKey || p2.PresharedKey != p.PresharedKey || p2.AwgParams != p.AwgParams {
		t.Fatalf("round-trip mismatch:\np1=%+v\np2=%+v", p, p2)
	}
}
