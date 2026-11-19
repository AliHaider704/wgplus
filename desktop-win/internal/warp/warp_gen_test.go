package warp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateWarpProfileParsesResponseAndSetsAwg15(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req warpRegRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"config": {
				"client_id": "DCI4",
				"peers": [{
					"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint": {
						"v4": "162.159.192.1:0",
						"host": "engage.cloudflareclient.com:2408"
					}
				}],
				"interface": {
					"addresses": {
						"v4": "172.16.0.2",
						"v6": "2606:4700:110:8::2"
					}
				}
			}
		}`))
	}))
	defer srv.Close()

	prof, err := generateProfileWithEndpoint(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("generateProfileWithEndpoint failed: %v", err)
	}
	if !prof.IsWarp || prof.MTU != 1280 || !prof.UseDoH {
		t.Fatalf("unexpected WARP defaults: %+v", prof)
	}
	if prof.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("unexpected WARP endpoint: %q", prof.Endpoint)
	}
	if prof.ClientIP != "172.16.0.2/32, 2606:4700:110:8::2/128" {
		t.Fatalf("unexpected client IP: %q", prof.ClientIP)
	}
	// base64 "DCI4" = 0x0c, 0x22, 0x38 = 12,34,56
	if !strings.Contains(prof.AwgParams, "I1=") || !strings.Contains(prof.AwgParams, "Reserved=12,34,56") {
		t.Fatalf("expected AWG 1.5 I1 + Reserved=12,34,56 in AwgParams, got %q", prof.AwgParams)
	}
}
