package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const currentStateSchema = 1

var awgInterfaceKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"reserved": true,
}

// NewRandomID generates a compact 16-char hex identifier.
func NewRandomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func stripComment(val string, preserveCps bool) string {
	if preserveCps {
		return strings.TrimSpace(val)
	}
	if idx := strings.IndexByte(val, '#'); idx >= 0 {
		val = val[:idx]
	}
	if idx := strings.IndexByte(val, ';'); idx >= 0 {
		val = val[:idx]
	}
	return strings.TrimSpace(val)
}

// ParseWgConf parses a standard WireGuard or AmneziaWG (1.0 / 1.5 / 2.0) .conf string.
func ParseWgConf(raw string, defaultName string) (ServerProfile, error) {
	prof := ServerProfile{
		ID:        NewRandomID(),
		Name:      strings.TrimSpace(defaultName),
		KeepAlive: 25,
		MTU:       1280,
		DNS:       "1.1.1.1",
		UseDoH:    true,
	}

	section := ""
	var awgLines []string

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:eq]))
		rawVal := strings.TrimSpace(trimmed[eq+1:])

		switch section {
		case "interface":
			if awgInterfaceKeys[key] {
				val := stripComment(rawVal, strings.HasPrefix(key, "i"))
				if val != "" {
					awgLines = append(awgLines, fmt.Sprintf("%s=%s", canonicalAwgKey(key), val))
				}
				continue
			}
			val := stripComment(rawVal, false)
			switch key {
			case "privatekey":
				prof.PrivateKey = val
			case "address":
				prof.ClientIP = val
			case "dns":
				if val != "" {
					prof.DNS = val
				}
			case "mtu":
				if n, err := strconv.Atoi(val); err == nil && n > 0 {
					prof.MTU = n
				}
			}
		case "peer":
			val := stripComment(rawVal, false)
			switch key {
			case "publickey":
				prof.PeerPublicKey = val
			case "presharedkey":
				prof.PresharedKey = val
			case "endpoint":
				prof.Endpoint = val
			case "persistentkeepalive":
				if n, err := strconv.Atoi(val); err == nil && n >= 0 {
					prof.KeepAlive = n
				}
			}
		}
	}

	prof.AwgParams = strings.Join(awgLines, "\n")

	if strings.TrimSpace(prof.PrivateKey) == "" {
		return prof, errors.New("missing [Interface] PrivateKey")
	}
	if strings.TrimSpace(prof.ClientIP) == "" {
		return prof, errors.New("missing [Interface] Address")
	}
	if strings.TrimSpace(prof.PeerPublicKey) == "" {
		return prof, errors.New("missing [Peer] PublicKey")
	}
	if strings.TrimSpace(prof.Endpoint) == "" {
		return prof, errors.New("missing [Peer] Endpoint")
	}
	if prof.Name == "" {
		host := prof.Endpoint
		if colon := strings.LastIndexByte(host, ':'); colon > 0 {
			host = host[:colon]
		}
		prof.Name = strings.TrimSpace(host)
		if prof.Name == "" {
			prof.Name = "WireGuard Server"
		}
	}
	return prof, nil
}

func canonicalAwgKey(lowerKey string) string {
	switch lowerKey {
	case "jc":
		return "Jc"
	case "jmin":
		return "Jmin"
	case "jmax":
		return "Jmax"
	case "reserved":
		return "Reserved"
	default:
		return strings.ToUpper(lowerKey)
	}
}

// ExportWgConf formats a ServerProfile back into a standard WireGuard / AmneziaWG .conf string.
func ExportWgConf(p ServerProfile) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", strings.TrimSpace(p.PrivateKey))
	fmt.Fprintf(&b, "Address = %s\n", strings.TrimSpace(p.ClientIP))
	if strings.TrimSpace(p.DNS) != "" {
		fmt.Fprintf(&b, "DNS = %s\n", strings.TrimSpace(p.DNS))
	}
	if p.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", p.MTU)
	}
	if strings.TrimSpace(p.AwgParams) != "" {
		tokens := strings.FieldsFunc(p.AwgParams, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ';'
		})
		for _, tok := range tokens {
			t := strings.TrimSpace(tok)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if eq := strings.IndexByte(t, '='); eq > 0 {
				k := canonicalAwgKey(strings.ToLower(strings.TrimSpace(t[:eq])))
				v := strings.TrimSpace(t[eq+1:])
				if v != "" {
					fmt.Fprintf(&b, "%s = %s\n", k, v)
				}
			}
		}
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", strings.TrimSpace(p.PeerPublicKey))
	if strings.TrimSpace(p.PresharedKey) != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", strings.TrimSpace(p.PresharedKey))
	}
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", strings.TrimSpace(p.Endpoint))
	if p.KeepAlive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.KeepAlive)
	}
	return b.String()
}
