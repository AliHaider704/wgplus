package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"wgbridge"
	"wgplus-win/internal/config"
)

const defaultWarpRegURL = "https://api.cloudflareclient.com/v0a2158/reg"

type warpRegRequest struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Type      string `json:"type"`
	Locale    string `json:"locale"`
}

type warpRegResponse struct {
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func generateWireGuardKeypair() (privB64 string, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

func formatWarpReserved(clientID string) string {
	trimmed := strings.TrimSpace(clientID)
	if trimmed == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(trimmed, "="))
	}
	if err != nil || len(raw) != 3 {
		return ""
	}
	return fmt.Sprintf("%d,%d,%d", raw[0], raw[1], raw[2])
}

func normalizeWarpEndpoint(v4, host string) string {
	ep := strings.TrimSpace(host)
	if ep == "" {
		ep = strings.TrimSpace(v4)
	}
	if ep == "" {
		return "engage.cloudflareclient.com:2408"
	}
	if _, port, err := net.SplitHostPort(ep); err == nil && port != "" && port != "0" {
		return ep
	}
	cleaned := strings.TrimSuffix(ep, ":0")
	return net.JoinHostPort(cleaned, "2408")
}

// GenerateProfile registers a fresh anonymous Cloudflare WARP WireGuard keypair and returns
// a ready-to-use profile pre-configured with AmneziaWG 1.5 QUIC mimicry (I1 + Jc) and Reserved bytes.
func GenerateProfile(ctx context.Context) (config.ServerProfile, error) {
	return generateProfileWithEndpoint(ctx, defaultWarpRegURL, &http.Client{Timeout: 12 * time.Second})
}

func generateProfileWithEndpoint(ctx context.Context, regURL string, httpClient *http.Client) (config.ServerProfile, error) {
	privB64, pubB64, err := generateWireGuardKeypair()
	if err != nil {
		return config.ServerProfile{}, fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}

	reqBody := warpRegRequest{
		Key:    pubB64,
		Tos:    time.Now().UTC().Format(time.RFC3339),
		Model:  "PC",
		Type:   "Android",
		Locale: "en_US",
	}
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return config.ServerProfile{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return config.ServerProfile{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return config.ServerProfile{}, fmt.Errorf("WARP registration request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return config.ServerProfile{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return config.ServerProfile{}, fmt.Errorf("WARP API returned HTTP %d", resp.StatusCode)
	}

	var parsed warpRegResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return config.ServerProfile{}, fmt.Errorf("invalid WARP API JSON: %w", err)
	}
	if len(parsed.Config.Peers) == 0 || strings.TrimSpace(parsed.Config.Peers[0].PublicKey) == "" {
		return config.ServerProfile{}, errors.New("WARP API response missing peer public key")
	}
	addrV4 := strings.TrimSpace(parsed.Config.Interface.Addresses.V4)
	if addrV4 == "" {
		return config.ServerProfile{}, errors.New("WARP API response missing client IPv4")
	}
	if !strings.Contains(addrV4, "/") {
		addrV4 += "/32"
	}
	clientIP := addrV4
	if addrV6 := strings.TrimSpace(parsed.Config.Interface.Addresses.V6); addrV6 != "" {
		if !strings.Contains(addrV6, "/") {
			addrV6 += "/128"
		}
		clientIP += ", " + addrV6
	}

	awgPreset := wgbridge.GetAwgPreset("quic_mimicry_15")
	if reserved := formatWarpReserved(parsed.Config.ClientID); reserved != "" {
		if awgPreset != "" {
			awgPreset += ";Reserved=" + reserved
		} else {
			awgPreset = "Reserved=" + reserved
		}
	}

	peer := parsed.Config.Peers[0]
	if v4Trim := strings.TrimSpace(peer.Endpoint.V4); v4Trim != "" {
		v4Host := strings.TrimSuffix(v4Trim, ":0")
		if h, _, splitErr := net.SplitHostPort(v4Trim); splitErr == nil && h != "" {
			v4Host = h
		}
		if net.ParseIP(v4Host) != nil {
			wgbridge.RegisterEndpointIpHint("engage.cloudflareclient.com", v4Host)
		}
	}
	return config.ServerProfile{
		ID:            config.NewRandomID(),
		Name:          "Cloudflare WARP (AWG 1.5)",
		PrivateKey:    privB64,
		ClientIP:      clientIP,
		DNS:           "1.1.1.1",
		PeerPublicKey: strings.TrimSpace(peer.PublicKey),
		Endpoint:      normalizeWarpEndpoint(peer.Endpoint.V4, peer.Endpoint.Host),
		KeepAlive:     25,
		MTU:           1280,
		AwgParams:     awgPreset,
		UseDoH:        true,
		IsWarp:        true,
	}, nil
}
