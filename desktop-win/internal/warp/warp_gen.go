package warp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"wgbridge"
	"wgplus-win/internal/config"
)

type warpBridgePayload struct {
	Name          string `json:"name"`
	PrivateKey    string `json:"privateKey"`
	ClientIP      string `json:"clientIp"`
	DNS           string `json:"dns"`
	PeerPublicKey string `json:"peerPublicKey"`
	Endpoint      string `json:"endpoint"`
	KeepAlive     int    `json:"keepAlive"`
	MTU           int    `json:"mtu"`
	AwgParams     string `json:"awgParams"`
	UseDoH        bool   `json:"useDoH"`
	IsWarp        bool   `json:"isWarp"`
}

// ServerProfileFromWarpJSON converts a wgbridge.GenerateWarpConfigJSON payload into a desktop ServerProfile.
func ServerProfileFromWarpJSON(rawJSON string) (config.ServerProfile, error) {
	var parsed warpBridgePayload
	if err := json.Unmarshal([]byte(rawJSON), &parsed); err != nil {
		return config.ServerProfile{}, fmt.Errorf("invalid WARP payload: %w", err)
	}
	if strings.TrimSpace(parsed.PrivateKey) == "" ||
		strings.TrimSpace(parsed.PeerPublicKey) == "" ||
		strings.TrimSpace(parsed.Endpoint) == "" {
		return config.ServerProfile{}, fmt.Errorf("incomplete WARP configuration payload")
	}
	return config.ServerProfile{
		ID:            config.NewRandomID(),
		Name:          parsed.Name,
		PrivateKey:    parsed.PrivateKey,
		ClientIP:      parsed.ClientIP,
		DNS:           parsed.DNS,
		PeerPublicKey: parsed.PeerPublicKey,
		Endpoint:      parsed.Endpoint,
		KeepAlive:     parsed.KeepAlive,
		MTU:           parsed.MTU,
		AwgParams:     parsed.AwgParams,
		UseDoH:        parsed.UseDoH,
		IsWarp:        true,
	}, nil
}

// GenerateProfile registers a fresh anonymous Cloudflare WARP WireGuard keypair via the shared wgbridge core
// and returns a ready-to-use profile pre-configured with AmneziaWG 1.5 QUIC mimicry (I1 + Jc) and Reserved bytes.
func GenerateProfile(ctx context.Context) (config.ServerProfile, error) {
	if err := ctx.Err(); err != nil {
		return config.ServerProfile{}, err
	}
	rawJSON, err := wgbridge.GenerateWarpConfigJSON()
	if err != nil {
		return config.ServerProfile{}, err
	}
	return ServerProfileFromWarpJSON(rawJSON)
}
