package warp

import (
	"strings"
	"testing"
)

func TestServerProfileFromWarpJSONSetsAwg15AndWarpFlag(t *testing.T) {
	raw := `{
		"name": "Cloudflare WARP (AWG 1.5)",
		"privateKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"clientIp": "172.16.0.2/32, 2606:4700:110:8::2/128",
		"dns": "1.1.1.1",
		"peerPublicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"endpoint": "engage.cloudflareclient.com:2408",
		"keepAlive": 25,
		"mtu": 1280,
		"awgParams": "Jc=4;Jmin=40;Jmax=120;I1=<b 0xc70000000108><r 8><b 0x0000449e><r 1200>;Reserved=12,34,56",
		"useDoH": true,
		"isWarp": true
	}`

	prof, err := ServerProfileFromWarpJSON(raw)
	if err != nil {
		t.Fatalf("ServerProfileFromWarpJSON failed: %v", err)
	}
	if prof.ID == "" || !prof.IsWarp || prof.MTU != 1280 || !prof.UseDoH {
		t.Fatalf("unexpected WARP defaults: %+v", prof)
	}
	if prof.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("unexpected WARP endpoint: %q", prof.Endpoint)
	}
	if !strings.Contains(prof.AwgParams, "I1=") || !strings.Contains(prof.AwgParams, "Reserved=12,34,56") {
		t.Fatalf("expected AWG 1.5 I1 + Reserved=12,34,56 in AwgParams, got %q", prof.AwgParams)
	}
}
