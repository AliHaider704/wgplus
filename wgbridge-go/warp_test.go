package wgbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateWarpConfigJSONParsesAndRegistersHint(t *testing.T) {
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

	rawJSON, err := generateWarpConfigJSONWithEndpoint(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("generateWarpConfigJSONWithEndpoint failed: %v", err)
	}

	var cfg warpGeneratedConfig
	if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated WARP config JSON: %v", err)
	}
	privRaw, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil || len(privRaw) != 32 {
		t.Fatalf("invalid private key length=%d err=%v", len(privRaw), err)
	}
	if cfg.Reserved != "12,34,56" {
		t.Fatalf("expected Reserved 12,34,56, got %q", cfg.Reserved)
	}
	if cfg.Endpoint != "engage.cloudflareclient.com:2408" || cfg.EndpointV4 != "162.159.192.1" {
		t.Fatalf("unexpected endpoints: %+v", cfg)
	}
	if !strings.Contains(cfg.AwgParams, "I1=") || !strings.Contains(cfg.AwgParams, "Reserved=12,34,56") {
		t.Fatalf("expected I1 and Reserved in AwgParams, got %q", cfg.AwgParams)
	}
	if !cfg.IsWarp || cfg.MTU != 1280 || !cfg.UseDoH {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}
