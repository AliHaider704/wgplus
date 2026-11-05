package wgbridge

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	wgMsgInitiationType  = 1
	wgMsgResponseType    = 2
	wgMsgCookieReplyType = 3
	wgMsgTransportType   = 4

	wgMsgInitiationSize  = 148
	wgMsgResponseSize    = 92
	wgMsgCookieReplySize = 64
	wgMsgTransportMin    = 32

	wgLabelMAC1 = "mac1----"

	maxAwgPadding = 512
	maxAwgJunk    = 1200
	maxAwgJc      = 15
)

// HeaderRange represents either a fixed uint32 magic header or a [Min, Max] inclusive range (AmneziaWG 1.0 / 1.5).
type HeaderRange struct {
	Min        uint32
	Max        uint32
	Configured bool
}

func (hr HeaderRange) Pick(defaultType uint32) uint32 {
	if !hr.Configured {
		return defaultType
	}
	if hr.Max <= hr.Min {
		return hr.Min
	}
	span := uint64(hr.Max-hr.Min) + 1
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(span))
	if err != nil {
		return hr.Min
	}
	return hr.Min + uint32(n.Uint64())
}

func (hr HeaderRange) Matches(val uint32, defaultType uint32) bool {
	if !hr.Configured {
		return val == defaultType
	}
	return val >= hr.Min && val <= hr.Max
}

// AwgConfig holds AmneziaWG DPI-evasion parameters.
type AwgConfig struct {
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	S3   int
	S4   int
	H1   HeaderRange
	H2   HeaderRange
	H3   HeaderRange
	H4   HeaderRange
}

func (c AwgConfig) IsActive() bool {
	return c.Jc > 0 ||
		c.S1 > 0 || c.S2 > 0 || c.S3 > 0 || c.S4 > 0 ||
		c.H1.Configured || c.H2.Configured || c.H3.Configured || c.H4.Configured
}

func parseHeaderRange(raw string) (HeaderRange, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return HeaderRange{}, nil
	}
	if dash := strings.IndexByte(s, '-'); dash > 0 {
		loStr := strings.TrimSpace(s[:dash])
		hiStr := strings.TrimSpace(s[dash+1:])
		lo, err1 := strconv.ParseUint(loStr, 10, 32)
		hi, err2 := strconv.ParseUint(hiStr, 10, 32)
		if err1 != nil || err2 != nil {
			return HeaderRange{}, fmt.Errorf("invalid header range %q", raw)
		}
		if hi < lo {
			lo, hi = hi, lo
		}
		return HeaderRange{Min: uint32(lo), Max: uint32(hi), Configured: true}, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return HeaderRange{}, fmt.Errorf("invalid header value %q", raw)
	}
	return HeaderRange{Min: uint32(v), Max: uint32(v), Configured: true}, nil
}

func parseAwgConfig(raw string) (AwgConfig, error) {
	var cfg AwgConfig
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return cfg, nil
	}

	tokens := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	for _, tok := range tokens {
		line := strings.TrimSpace(tok)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:eq]))
		v := strings.TrimSpace(line[eq+1:])
		if v == "" {
			continue
		}

		switch k {
		case "jc":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid Jc %q", v)
			}
			if n > maxAwgJc {
				n = maxAwgJc
			}
			cfg.Jc = n
		case "jmin":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid Jmin %q", v)
			}
			cfg.Jmin = clampInt(n, 0, maxAwgJunk)
		case "jmax":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid Jmax %q", v)
			}
			cfg.Jmax = clampInt(n, 0, maxAwgJunk)
		case "s1":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid S1 %q", v)
			}
			cfg.S1 = clampInt(n, 0, maxAwgPadding)
		case "s2":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid S2 %q", v)
			}
			cfg.S2 = clampInt(n, 0, maxAwgPadding)
		case "s3":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid S3 %q", v)
			}
			cfg.S3 = clampInt(n, 0, maxAwgPadding)
		case "s4":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("invalid S4 %q", v)
			}
			cfg.S4 = clampInt(n, 0, maxAwgPadding)
		case "h1":
			hr, err := parseHeaderRange(v)
			if err != nil {
				return cfg, err
			}
			cfg.H1 = hr
		case "h2":
			hr, err := parseHeaderRange(v)
			if err != nil {
				return cfg, err
			}
			cfg.H2 = hr
		case "h3":
			hr, err := parseHeaderRange(v)
			if err != nil {
				return cfg, err
			}
			cfg.H3 = hr
		case "h4":
			hr, err := parseHeaderRange(v)
			if err != nil {
				return cfg, err
			}
			cfg.H4 = hr
		}
	}

	if cfg.Jc > 0 {
		if cfg.Jmin <= 0 {
			cfg.Jmin = 40
		}
		if cfg.Jmax < cfg.Jmin {
			cfg.Jmax = cfg.Jmin + 90
		}
		if cfg.Jmax > maxAwgJunk {
			cfg.Jmax = maxAwgJunk
		}
	}
	return cfg, nil
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func derivePublicKeyFromHex(privHex string) ([32]byte, error) {
	var pub [32]byte
	raw, err := hex.DecodeString(privHex)
	if err != nil || len(raw) != 32 {
		return pub, fmt.Errorf("invalid 32-byte hex key")
	}
	var clamped [32]byte
	copy(clamped[:], raw)
	clamped[0] &= 248
	clamped[31] = (clamped[31] & 127) | 64
	curve25519.ScalarBaseMult(&pub, &clamped)
	return pub, nil
}

func decodeHexKey32(hexKey string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("invalid 32-byte hex key")
	}
	copy(out[:], raw)
	return out, nil
}

func computeMac1Key(pub [32]byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte(wgLabelMAC1))
	h.Write(pub[:])
	var key [32]byte
	h.Sum(key[:0])
	return key
}

func recomputeMac1(msg []byte, mac1Offset int, mac1Key [32]byte) {
	mac, _ := blake2s.New128(mac1Key[:])
	mac.Write(msg[:mac1Offset])
	mac.Sum(msg[mac1Offset:mac1Offset])
}

func verifyMac1(msg []byte, mac1Offset int, mac1Key [32]byte) bool {
	var expected [16]byte
	mac, _ := blake2s.New128(mac1Key[:])
	mac.Write(msg[:mac1Offset])
	mac.Sum(expected[:0])
	return hmac.Equal(expected[:], msg[mac1Offset:mac1Offset+16])
}

// awgBind wraps a conn.Bind to apply AmneziaWG packet padding (S1..S4), magic header replacement (H1..H4),
// BLAKE2s-128 MAC1 recalculation/verification, and pre-handshake decoy junk bursts (Jc, Jmin, Jmax).
type awgBind struct {
	inner       conn.Bind
	cfg         AwgConfig
	localMacKey [32]byte
	peerMacKey  [32]byte
}

func newAwgBind(inner conn.Bind, cfg AwgConfig, privHex string, peerPubHex string) (conn.Bind, error) {
	if !cfg.IsActive() {
		return inner, nil
	}
	localPub, err := derivePublicKeyFromHex(privHex)
	if err != nil {
		return nil, err
	}
	peerPub, err := decodeHexKey32(peerPubHex)
	if err != nil {
		return nil, err
	}
	return &awgBind{
		inner:       inner,
		cfg:         cfg,
		localMacKey: computeMac1Key(localPub),
		peerMacKey:  computeMac1Key(peerPub),
	}, nil
}

func (b *awgBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for idx, fn := range fns {
		origFn := fn
		wrapped[idx] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, rErr := origFn(packets, sizes, eps)
			for i := 0; i < n; i++ {
				sz := sizes[i]
				if sz <= 0 || sz > len(packets[i]) {
					sizes[i] = 0
					continue
				}
				newSz := b.deobfuscateInbound(packets[i], sz)
				sizes[i] = newSz
			}
			return n, rErr
		}
	}
	return wrapped, actualPort, nil
}

func (b *awgBind) Close() error {
	return b.inner.Close()
}

func (b *awgBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *awgBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *awgBind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *awgBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	var out [][]byte
	for _, pkt := range bufs {
		if len(pkt) < 4 {
			out = append(out, pkt)
			continue
		}
		msgType := binary.LittleEndian.Uint32(pkt[0:4])

		// Inject decoy junk burst immediately before Handshake Initiation
		if msgType == wgMsgInitiationType && len(pkt) == wgMsgInitiationSize && b.cfg.Jc > 0 {
			for j := 0; j < b.cfg.Jc; j++ {
				jLen := b.cfg.Jmin
				if b.cfg.Jmax > b.cfg.Jmin {
					span := uint64(b.cfg.Jmax-b.cfg.Jmin) + 1
					if rBig, rErr := rand.Int(rand.Reader, new(big.Int).SetUint64(span)); rErr == nil {
						jLen += int(rBig.Uint64())
					}
				}
				if jLen < 1 {
					jLen = 40
				}
				junk := make([]byte, jLen)
				_, _ = rand.Read(junk)
				out = append(out, junk)
			}
		}

		obf := b.obfuscateOutbound(pkt)
		out = append(out, obf)
	}

	batchCap := b.inner.BatchSize()
	if batchCap <= 0 {
		batchCap = 1
	}
	for start := 0; start < len(out); start += batchCap {
		end := start + batchCap
		if end > len(out) {
			end = len(out)
		}
		if err := b.inner.Send(out[start:end], ep); err != nil {
			return err
		}
	}
	return nil
}

func (b *awgBind) obfuscateOutbound(pkt []byte) []byte {
	if len(pkt) < 4 {
		return pkt
	}
	msgType := binary.LittleEndian.Uint32(pkt[0:4])

	switch {
	case msgType == wgMsgInitiationType && len(pkt) == wgMsgInitiationSize:
		pad := b.cfg.S1
		hVal := b.cfg.H1.Pick(wgMsgInitiationType)
		if pad == 0 && hVal == wgMsgInitiationType {
			return pkt
		}
		res := make([]byte, pad+wgMsgInitiationSize)
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		if hVal != wgMsgInitiationType {
			binary.LittleEndian.PutUint32(inner[0:4], hVal)
			recomputeMac1(inner, 116, b.peerMacKey)
			// Clear MAC2 if header changed (cookie is recomputed if server requests one)
			for i := 132; i < 148; i++ {
				inner[i] = 0
			}
		}
		return res

	case msgType == wgMsgResponseType && len(pkt) == wgMsgResponseSize:
		pad := b.cfg.S2
		hVal := b.cfg.H2.Pick(wgMsgResponseType)
		if pad == 0 && hVal == wgMsgResponseType {
			return pkt
		}
		res := make([]byte, pad+wgMsgResponseSize)
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		if hVal != wgMsgResponseType {
			binary.LittleEndian.PutUint32(inner[0:4], hVal)
			recomputeMac1(inner, 60, b.peerMacKey)
			for i := 76; i < 92; i++ {
				inner[i] = 0
			}
		}
		return res

	case msgType == wgMsgCookieReplyType && len(pkt) == wgMsgCookieReplySize:
		pad := b.cfg.S3
		hVal := b.cfg.H3.Pick(wgMsgCookieReplyType)
		if pad == 0 && hVal == wgMsgCookieReplyType {
			return pkt
		}
		res := make([]byte, pad+wgMsgCookieReplySize)
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		binary.LittleEndian.PutUint32(inner[0:4], hVal)
		return res

	case msgType == wgMsgTransportType && len(pkt) >= wgMsgTransportMin:
		pad := b.cfg.S4
		hVal := b.cfg.H4.Pick(wgMsgTransportType)
		if pad == 0 && hVal == wgMsgTransportType {
			return pkt
		}
		res := make([]byte, pad+len(pkt))
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		binary.LittleEndian.PutUint32(inner[0:4], hVal)
		return res

	default:
		return pkt
	}
}

func (b *awgBind) deobfuscateInbound(buf []byte, sz int) int {
	raw := buf[:sz]

	// 1. Check Handshake Response (S2 + 92)
	if sz == b.cfg.S2+wgMsgResponseSize {
		cand := raw[b.cfg.S2:]
		hdr := binary.LittleEndian.Uint32(cand[0:4])
		if b.cfg.H2.Matches(hdr, wgMsgResponseType) && verifyMac1(cand, 60, b.localMacKey) {
			if b.cfg.S2 > 0 {
				copy(buf[:wgMsgResponseSize], cand)
			}
			if hdr != wgMsgResponseType {
				binary.LittleEndian.PutUint32(buf[0:4], wgMsgResponseType)
				recomputeMac1(buf[:wgMsgResponseSize], 60, b.localMacKey)
			}
			return wgMsgResponseSize
		}
	}

	// 2. Check Handshake Initiation (S1 + 148)
	if sz == b.cfg.S1+wgMsgInitiationSize {
		cand := raw[b.cfg.S1:]
		hdr := binary.LittleEndian.Uint32(cand[0:4])
		if b.cfg.H1.Matches(hdr, wgMsgInitiationType) && verifyMac1(cand, 116, b.localMacKey) {
			if b.cfg.S1 > 0 {
				copy(buf[:wgMsgInitiationSize], cand)
			}
			if hdr != wgMsgInitiationType {
				binary.LittleEndian.PutUint32(buf[0:4], wgMsgInitiationType)
				recomputeMac1(buf[:wgMsgInitiationSize], 116, b.localMacKey)
			}
			return wgMsgInitiationSize
		}
	}

	// 3. Check Cookie Reply (S3 + 64)
	if sz == b.cfg.S3+wgMsgCookieReplySize {
		cand := raw[b.cfg.S3:]
		hdr := binary.LittleEndian.Uint32(cand[0:4])
		if b.cfg.H3.Matches(hdr, wgMsgCookieReplyType) {
			if b.cfg.S3 > 0 {
				copy(buf[:wgMsgCookieReplySize], cand)
			}
			binary.LittleEndian.PutUint32(buf[0:4], wgMsgCookieReplyType)
			return wgMsgCookieReplySize
		}
	}

	// 4. Check Transport Data (>= S4 + 32)
	if sz >= b.cfg.S4+wgMsgTransportMin {
		cand := raw[b.cfg.S4:]
		hdr := binary.LittleEndian.Uint32(cand[0:4])
		if b.cfg.H4.Matches(hdr, wgMsgTransportType) {
			innerLen := sz - b.cfg.S4
			if b.cfg.S4 > 0 {
				copy(buf[:innerLen], cand)
			}
			binary.LittleEndian.PutUint32(buf[0:4], wgMsgTransportType)
			return innerLen
		}
	}

	// Drop unrecognized or decoy junk datagrams cleanly
	return 0
}
