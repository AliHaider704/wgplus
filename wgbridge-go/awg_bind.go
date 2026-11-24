package wgbridge

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

const (
	awgPresetUniversalJunk = "Jc=4;Jmin=40;Jmax=120"
	awgPresetQuicMimicry15 = "Jc=4;Jmin=40;Jmax=120;I1=<b 0xc70000000108><r 8><b 0x0000449e><r 1200>"
)

// GetAwgPreset returns a built-in AmneziaWG obfuscation preset string compatible with
// standard WireGuard servers and Cloudflare WARP endpoints.
func GetAwgPreset(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "universal_junk":
		return awgPresetUniversalJunk
	case "quic_mimicry_15", "awg15_quic":
		return awgPresetQuicMimicry15
	default:
		return ""
	}
}

// AwgConfig holds AmneziaWG 1.0 / 1.5 / 2.0 DPI-evasion parameters and optional WARP reserved bytes.
type AwgConfig struct {
	Jc          int
	Jmin        int
	Jmax        int
	S1          int
	S2          int
	S3          int
	S4          int
	H1          HeaderRange
	H2          HeaderRange
	H3          HeaderRange
	H4          HeaderRange
	I1          string
	I2          string
	I3          string
	I4          string
	I5          string
	Reserved    [3]byte
	HasReserved bool
}

func (c AwgConfig) IsActive() bool {
	return c.Jc > 0 ||
		c.S1 > 0 || c.S2 > 0 || c.S3 > 0 || c.S4 > 0 ||
		c.H1.Configured || c.H2.Configured || c.H3.Configured || c.H4.Configured ||
		c.I1 != "" || c.I2 != "" || c.I3 != "" || c.I4 != "" || c.I5 != "" ||
		c.HasReserved
}

func (c AwgConfig) SignatureSpecs() []string {
	var specs []string
	for _, s := range []string{c.I1, c.I2, c.I3, c.I4, c.I5} {
		if strings.TrimSpace(s) != "" {
			specs = append(specs, s)
		}
	}
	return specs
}

func parseReservedBytes(raw string) ([3]byte, error) {
	var out [3]byte
	s := strings.TrimSpace(raw)
	if s == "" {
		return out, fmt.Errorf("empty reserved value")
	}
	// Format 1: comma- or whitespace-separated decimal bytes (e.g. "12,34,56")
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(parts) == 3 {
		for i, p := range parts {
			v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
			if err != nil {
				return out, fmt.Errorf("invalid reserved byte %q", p)
			}
			out[i] = byte(v)
		}
		return out, nil
	}
	// Format 2: base64-encoded 3-byte client_id (e.g. Cloudflare WARP API client_id)
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	}
	if err == nil && len(decoded) == 3 {
		copy(out[:], decoded)
		return out, nil
	}
	return out, fmt.Errorf("invalid Reserved %q: expected 3 bytes or base64", raw)
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
		case "i1":
			if _, err := renderCpsPacket(v, nil); err != nil {
				return cfg, fmt.Errorf("invalid I1: %w", err)
			}
			cfg.I1 = v
		case "i2":
			if _, err := renderCpsPacket(v, nil); err != nil {
				return cfg, fmt.Errorf("invalid I2: %w", err)
			}
			cfg.I2 = v
		case "i3":
			if _, err := renderCpsPacket(v, nil); err != nil {
				return cfg, fmt.Errorf("invalid I3: %w", err)
			}
			cfg.I3 = v
		case "i4":
			if _, err := renderCpsPacket(v, nil); err != nil {
				return cfg, fmt.Errorf("invalid I4: %w", err)
			}
			cfg.I4 = v
		case "i5":
			if _, err := renderCpsPacket(v, nil); err != nil {
				return cfg, fmt.Errorf("invalid I5: %w", err)
			}
			cfg.I5 = v
		case "reserved":
			rb, err := parseReservedBytes(v)
			if err != nil {
				return cfg, err
			}
			cfg.Reserved = rb
			cfg.HasReserved = true
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

const (
	cpsLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	cpsDigits  = "0123456789"
)

// renderCpsPacket compiles and renders an AmneziaWG 1.5 CPS signature packet specification
// supporting <b 0xHEX>, <r N>, <rc N>, <rd N>, <t>, and <c> tags.
func renderCpsPacket(spec string, counter *atomic.Uint32) ([]byte, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, nil
	}
	var out []byte
	i := 0
	for i < len(s) {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		if s[i] != '<' {
			out = append(out, s[i])
			i++
			continue
		}
		closeIdx := strings.IndexByte(s[i:], '>')
		if closeIdx <= 1 {
			return nil, fmt.Errorf("unclosed or empty CPS tag near %q", s[i:])
		}
		tagBody := strings.TrimSpace(s[i+1 : i+closeIdx])
		i += closeIdx + 1

		fields := strings.Fields(tagBody)
		if len(fields) == 0 {
			return nil, errors.New("empty CPS tag")
		}
		op := strings.ToLower(fields[0])
		switch op {
		case "b":
			if len(fields) < 2 {
				return nil, errors.New("CPS <b> tag missing hex payload")
			}
			hexArg := strings.Join(fields[1:], "")
			hexArg = strings.TrimPrefix(strings.TrimPrefix(hexArg, "0x"), "0X")
			if hexArg == "" || len(hexArg)%2 != 0 {
				return nil, fmt.Errorf("CPS <b> tag invalid hex length %q", hexArg)
			}
			raw, err := hex.DecodeString(hexArg)
			if err != nil {
				return nil, fmt.Errorf("CPS <b> tag invalid hex: %w", err)
			}
			out = append(out, raw...)
		case "r":
			n, err := parseCpsLength(fields)
			if err != nil {
				return nil, fmt.Errorf("CPS <r>: %w", err)
			}
			buf := make([]byte, n)
			_, _ = rand.Read(buf)
			out = append(out, buf...)
		case "rc":
			n, err := parseCpsLength(fields)
			if err != nil {
				return nil, fmt.Errorf("CPS <rc>: %w", err)
			}
			buf := make([]byte, n)
			_, _ = rand.Read(buf)
			for idx := range buf {
				buf[idx] = cpsLetters[int(buf[idx])%len(cpsLetters)]
			}
			out = append(out, buf...)
		case "rd":
			n, err := parseCpsLength(fields)
			if err != nil {
				return nil, fmt.Errorf("CPS <rd>: %w", err)
			}
			buf := make([]byte, n)
			_, _ = rand.Read(buf)
			for idx := range buf {
				buf[idx] = cpsDigits[int(buf[idx])%len(cpsDigits)]
			}
			out = append(out, buf...)
		case "t":
			var ts [4]byte
			binary.BigEndian.PutUint32(ts[:], uint32(time.Now().Unix()))
			out = append(out, ts[:]...)
		case "c":
			var seq uint32 = 1
			if counter != nil {
				seq = counter.Add(1)
			}
			var cb [4]byte
			binary.BigEndian.PutUint32(cb[:], seq)
			out = append(out, cb[:]...)
		default:
			return nil, fmt.Errorf("unsupported CPS tag <%s>", op)
		}
		if len(out) > 1472 {
			out = out[:1472]
			break
		}
	}
	return out, nil
}

func parseCpsLength(fields []string) (int, error) {
	if len(fields) != 2 {
		return 0, errors.New("expected length argument")
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("invalid length %q", fields[1])
	}
	return clampInt(n, 1, maxAwgJunk), nil
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

func verifyMac1ZeroedReserved(msg []byte, mac1Offset int, mac1Key [32]byte) bool {
	if len(msg) < mac1Offset+16 || mac1Offset < 4 {
		return false
	}
	var hdr [4]byte
	hdr[0] = msg[0]
	var expected [16]byte
	mac, _ := blake2s.New128(mac1Key[:])
	mac.Write(hdr[:])
	mac.Write(msg[4:mac1Offset])
	mac.Sum(expected[:0])
	return hmac.Equal(expected[:], msg[mac1Offset:mac1Offset+16])
}

// awgBind wraps a conn.Bind to apply AmneziaWG packet padding (S1..S4), magic header replacement (H1..H4),
// AWG 1.5 CPS signature packets (I1..I5), WARP Reserved bytes, BLAKE2s-128 MAC1 recalculation/verification,
// and pre-handshake decoy junk bursts (Jc, Jmin, Jmax).
type awgBind struct {
	inner       conn.Bind
	cfg         AwgConfig
	localMacKey [32]byte
	peerMacKey  [32]byte
	cpsCounter  atomic.Uint32
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

var awgOutFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func (b *awgBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	var stackOut [64][]byte
	out := stackOut[:0]
	if len(bufs) > len(stackOut) {
		out = make([][]byte, 0, len(bufs))
	}
	var borrowed []*[]byte
	defer func() {
		for _, p := range borrowed {
			awgOutFramePool.Put(p)
		}
	}()

	for _, pkt := range bufs {
		if len(pkt) < 4 {
			out = append(out, pkt)
			continue
		}
		msgType := binary.LittleEndian.Uint32(pkt[0:4])

		// Inject AmneziaWG 1.5 CPS signature packets (I1..I5) and paced random junk bursts (Jc)
		// before Handshake Initiation so DPI sees realistic QUIC/HTTP3/decoy traffic first.
		if msgType == wgMsgInitiationType && len(pkt) == wgMsgInitiationSize {
			specs := b.cfg.SignatureSpecs()
			emittedPreBurst := false
			for sIdx, spec := range specs {
				if sigPkt, sErr := renderCpsPacket(spec, &b.cpsCounter); sErr == nil && len(sigPkt) > 0 {
					_ = b.inner.Send([][]byte{sigPkt}, ep)
					emittedPreBurst = true
					if sIdx+1 < len(specs) || b.cfg.Jc > 0 {
						time.Sleep(2 * time.Millisecond)
					}
				}
			}
			if b.cfg.Jc > 0 {
				emittedPreBurst = true
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
					_ = b.inner.Send([][]byte{junk}, ep)
					if j+1 < b.cfg.Jc {
						time.Sleep(2 * time.Millisecond)
					}
				}
			}
			if emittedPreBurst {
				time.Sleep(2 * time.Millisecond)
			}
		}

		obf, pooledPtr := b.obfuscateOutboundPooled(pkt)
		if pooledPtr != nil {
			borrowed = append(borrowed, pooledPtr)
		}
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
	obf, _ := b.obfuscateOutboundWithAlloc(pkt, nil)
	return obf
}

func (b *awgBind) obfuscateOutboundPooled(pkt []byte) ([]byte, *[]byte) {
	return b.obfuscateOutboundWithAlloc(pkt, &awgOutFramePool)
}

func allocAwgBuf(totalLen int, pool *sync.Pool) ([]byte, *[]byte) {
	if pool != nil && totalLen <= 2048 {
		ptr := pool.Get().(*[]byte)
		return (*ptr)[:totalLen], ptr
	}
	return make([]byte, totalLen), nil
}

func matchesHeaderWithReserved(hr HeaderRange, cand []byte, defaultType uint32, hasReserved bool, reserved [3]byte) bool {
	if len(cand) < 4 {
		return false
	}
	if hr.Configured {
		return hr.Matches(binary.LittleEndian.Uint32(cand[0:4]), defaultType)
	}
	if hasReserved {
		if cand[0] != byte(defaultType) {
			return false
		}
		isZero := cand[1] == 0 && cand[2] == 0 && cand[3] == 0
		isRes := cand[1] == reserved[0] && cand[2] == reserved[1] && cand[3] == reserved[2]
		return isZero || isRes
	}
	return binary.LittleEndian.Uint32(cand[0:4]) == defaultType
}

func (b *awgBind) obfuscateOutboundWithAlloc(pkt []byte, pool *sync.Pool) ([]byte, *[]byte) {
	if len(pkt) < 4 {
		return pkt, nil
	}
	msgType := binary.LittleEndian.Uint32(pkt[0:4])

	switch {
	case msgType == wgMsgInitiationType && len(pkt) == wgMsgInitiationSize:
		pad := b.cfg.S1
		hVal := b.cfg.H1.Pick(wgMsgInitiationType)
		stampReserved := b.cfg.HasReserved && !b.cfg.H1.Configured
		if pad == 0 && hVal == wgMsgInitiationType && !stampReserved {
			return pkt, nil
		}
		res, pPtr := allocAwgBuf(pad+wgMsgInitiationSize, pool)
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		if hVal != wgMsgInitiationType {
			binary.LittleEndian.PutUint32(inner[0:4], hVal)
			recomputeMac1(inner, 116, b.peerMacKey)
			// Clear MAC2 if magic header changed (cookie is recomputed if server requests one)
			for i := 132; i < 148; i++ {
				inner[i] = 0
			}
		} else if stampReserved {
			// Cloudflare WARP Reserved bytes (bytes 1..3) are stamped outside Noise framing
			// without modifying MAC1 or MAC2 (edge strips them before MAC1 verification).
			copy(inner[1:4], b.cfg.Reserved[:])
		}
		return res, pPtr

	case msgType == wgMsgResponseType && len(pkt) == wgMsgResponseSize:
		pad := b.cfg.S2
		hVal := b.cfg.H2.Pick(wgMsgResponseType)
		stampReserved := b.cfg.HasReserved && !b.cfg.H2.Configured
		if pad == 0 && hVal == wgMsgResponseType && !stampReserved {
			return pkt, nil
		}
		res, pPtr := allocAwgBuf(pad+wgMsgResponseSize, pool)
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
		} else if stampReserved {
			copy(inner[1:4], b.cfg.Reserved[:])
		}
		return res, pPtr

	case msgType == wgMsgCookieReplyType && len(pkt) == wgMsgCookieReplySize:
		pad := b.cfg.S3
		hVal := b.cfg.H3.Pick(wgMsgCookieReplyType)
		stampReserved := b.cfg.HasReserved && !b.cfg.H3.Configured
		if pad == 0 && hVal == wgMsgCookieReplyType && !stampReserved {
			return pkt, nil
		}
		res, pPtr := allocAwgBuf(pad+wgMsgCookieReplySize, pool)
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		if hVal != wgMsgCookieReplyType {
			binary.LittleEndian.PutUint32(inner[0:4], hVal)
		} else if stampReserved {
			copy(inner[1:4], b.cfg.Reserved[:])
		}
		return res, pPtr

	case msgType == wgMsgTransportType && len(pkt) >= wgMsgTransportMin:
		pad := b.cfg.S4
		hVal := b.cfg.H4.Pick(wgMsgTransportType)
		stampReserved := b.cfg.HasReserved && !b.cfg.H4.Configured
		if pad == 0 && hVal == wgMsgTransportType && !stampReserved {
			return pkt, nil
		}
		res, pPtr := allocAwgBuf(pad+len(pkt), pool)
		if pad > 0 {
			_, _ = rand.Read(res[:pad])
		}
		inner := res[pad:]
		copy(inner, pkt)
		if hVal != wgMsgTransportType {
			binary.LittleEndian.PutUint32(inner[0:4], hVal)
		} else if stampReserved {
			copy(inner[1:4], b.cfg.Reserved[:])
		}
		return res, pPtr

	default:
		return pkt, nil
	}
}

func (b *awgBind) tryDeobfuscateHandshake(buf, raw []byte, sz, pad int, hr HeaderRange, msgType uint32, msgSize, mac1Offset int) (int, bool) {
	if sz != pad+msgSize {
		return 0, false
	}
	cand := raw[pad:]
	if !matchesHeaderWithReserved(hr, cand, msgType, b.cfg.HasReserved, b.cfg.Reserved) {
		return 0, false
	}
	var macValid bool
	switch {
	case hr.Configured:
		macValid = verifyMac1(cand, mac1Offset, b.localMacKey)
	case b.cfg.HasReserved:
		macValid = verifyMac1ZeroedReserved(cand, mac1Offset, b.localMacKey)
	default:
		macValid = verifyMac1(cand, mac1Offset, b.localMacKey)
	}
	if !macValid {
		return 0, false
	}
	if pad > 0 {
		copy(buf[:msgSize], cand)
	}
	if hr.Configured {
		hdr := binary.LittleEndian.Uint32(buf[0:4])
		if hdr != msgType {
			binary.LittleEndian.PutUint32(buf[0:4], msgType)
			recomputeMac1(buf[:msgSize], mac1Offset, b.localMacKey)
		}
	} else if b.cfg.HasReserved {
		// Strip Cloudflare WARP Reserved octets without altering MAC1/MAC2.
		buf[1], buf[2], buf[3] = 0, 0, 0
	}
	return msgSize, true
}

func (b *awgBind) deobfuscateInbound(buf []byte, sz int) int {
	raw := buf[:sz]

	// 1. Check Handshake Response (S2 + 92)
	if n, ok := b.tryDeobfuscateHandshake(buf, raw, sz, b.cfg.S2, b.cfg.H2, wgMsgResponseType, wgMsgResponseSize, 60); ok {
		return n
	}

	// 2. Check Handshake Initiation (S1 + 148)
	if n, ok := b.tryDeobfuscateHandshake(buf, raw, sz, b.cfg.S1, b.cfg.H1, wgMsgInitiationType, wgMsgInitiationSize, 116); ok {
		return n
	}

	// 3. Check Cookie Reply (S3 + 64)
	if sz == b.cfg.S3+wgMsgCookieReplySize {
		cand := raw[b.cfg.S3:]
		if matchesHeaderWithReserved(b.cfg.H3, cand, wgMsgCookieReplyType, b.cfg.HasReserved, b.cfg.Reserved) {
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
		if matchesHeaderWithReserved(b.cfg.H4, cand, wgMsgTransportType, b.cfg.HasReserved, b.cfg.Reserved) {
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
