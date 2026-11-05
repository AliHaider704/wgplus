package wgbridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dnsMimeType = "application/dns-message"
	dohCacheTTL = 90 * time.Second
)

type dohCacheEntry struct {
	ip        string
	expiresAt time.Time
}

type dohUpstream struct {
	dialAddr   string
	serverName string
	url        string
}

var (
	dohUpstreams = []dohUpstream{
		{
			dialAddr:   "1.1.1.1:443",
			serverName: "cloudflare-dns.com",
			url:        "https://cloudflare-dns.com/dns-query",
		},
		{
			dialAddr:   "1.0.0.1:443",
			serverName: "cloudflare-dns.com",
			url:        "https://cloudflare-dns.com/dns-query",
		},
		{
			dialAddr:   "8.8.8.8:443",
			serverName: "dns.google",
			url:        "https://dns.google/dns-query",
		},
	}

	dohMu    sync.Mutex
	dohCache = make(map[string]dohCacheEntry)
)

// ClearDnsCache flushes cached DoH endpoint resolutions (used on network handoff / roaming).
func ClearDnsCache() {
	dohMu.Lock()
	dohCache = make(map[string]dohCacheEntry)
	dohMu.Unlock()
}

func getCachedDoH(host string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(host))
	dohMu.Lock()
	defer dohMu.Unlock()
	ent, ok := dohCache[key]
	if !ok || time.Now().After(ent.expiresAt) {
		delete(dohCache, key)
		return "", false
	}
	return ent.ip, true
}

func putCachedDoH(host, ip string) {
	key := strings.ToLower(strings.TrimSpace(host))
	dohMu.Lock()
	dohCache[key] = dohCacheEntry{
		ip:        ip,
		expiresAt: time.Now().Add(dohCacheTTL),
	}
	dohMu.Unlock()
}

func encodeDnsQueryA(host string) ([]byte, error) {
	clean := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if clean == "" || len(clean) > 253 {
		return nil, fmt.Errorf("invalid DNS hostname %q", host)
	}
	labels := strings.Split(clean, ".")
	var buf bytes.Buffer
	// RFC 8484 Section 4.1: ID=0x0000, Flags=0x0100 (RD), QDCOUNT=1
	buf.Write([]byte{
		0x00, 0x00,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	})
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", host)
		}
		buf.WriteByte(byte(len(lbl)))
		buf.WriteString(lbl)
	}
	buf.WriteByte(0x00)
	// QTYPE=A (1), QCLASS=IN (1)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})
	return buf.Bytes(), nil
}

func skipDnsName(msg []byte, offset int) (int, error) {
	cur := offset
	hops := 0
	for {
		if cur >= len(msg) {
			return 0, errors.New("truncated DNS name")
		}
		b := msg[cur]
		if b == 0 {
			return cur + 1, nil
		}
		// Compression pointer (top two bits 11)
		if (b & 0xC0) == 0xC0 {
			if cur+1 >= len(msg) {
				return 0, errors.New("truncated DNS compression pointer")
			}
			return cur + 2, nil
		}
		if (b & 0xC0) != 0 {
			return 0, errors.New("unsupported DNS label flags")
		}
		cur += 1 + int(b)
		hops++
		if hops > 128 {
			return 0, errors.New("excessive DNS label count")
		}
	}
}

func isSinkholeIPv4(addr netip.Addr, allowLoopback bool) bool {
	if !addr.IsValid() || !addr.Is4() {
		return true
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return true
	}
	if !allowLoopback && addr.IsLoopback() {
		return true
	}
	b := addr.As4()
	// 0.0.0.0/8 sinkhole block
	if b[0] == 0 {
		return true
	}
	return false
}

func parseDnsResponseA(msg []byte, allowLoopback bool) (netip.Addr, error) {
	if len(msg) < 12 {
		return netip.Addr{}, errors.New("short DNS response")
	}
	rcode := msg[3] & 0x0F
	if rcode != 0 {
		return netip.Addr{}, fmt.Errorf("DNS response RCODE=%d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return netip.Addr{}, errors.New("DNS response has zero answer records")
	}

	offset := 12
	for q := 0; q < qdCount; q++ {
		nextOff, err := skipDnsName(msg, offset)
		if err != nil {
			return netip.Addr{}, err
		}
		if nextOff+4 > len(msg) {
			return netip.Addr{}, errors.New("truncated DNS question")
		}
		offset = nextOff + 4
	}

	for a := 0; a < anCount; a++ {
		nextOff, err := skipDnsName(msg, offset)
		if err != nil {
			return netip.Addr{}, err
		}
		if nextOff+10 > len(msg) {
			return netip.Addr{}, errors.New("truncated DNS resource record header")
		}
		rrType := binary.BigEndian.Uint16(msg[nextOff : nextOff+2])
		rrClass := binary.BigEndian.Uint16(msg[nextOff+2 : nextOff+4])
		rdLen := int(binary.BigEndian.Uint16(msg[nextOff+8 : nextOff+10]))
		rdataStart := nextOff + 10
		rdataEnd := rdataStart + rdLen
		if rdataEnd > len(msg) {
			return netip.Addr{}, errors.New("truncated DNS RDATA")
		}
		if rrType == 1 && rrClass == 1 && rdLen == 4 {
			var v4 [4]byte
			copy(v4[:], msg[rdataStart:rdataEnd])
			cand := netip.AddrFrom4(v4)
			if isSinkholeIPv4(cand, allowLoopback) {
				return netip.Addr{}, fmt.Errorf("rejected sinkhole/bogon DNS answer %s", cand.String())
			}
			return cand, nil
		}
		offset = rdataEnd
	}
	return netip.Addr{}, errors.New("no valid IPv4 A record in DNS response")
}

func resolveHostViaDoHEndpoint(
	ctx context.Context,
	client *http.Client,
	dohURL string,
	host string,
	allowLoopback bool,
) (netip.Addr, error) {
	wireQuery, err := encodeDnsQueryA(host)
	if err != nil {
		return netip.Addr{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(wireQuery))
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("Content-Type", dnsMimeType)
	req.Header.Set("Accept", dnsMimeType)

	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return netip.Addr{}, err
	}
	return parseDnsResponseA(body, allowLoopback)
}

func newDirectDoHClient(up dohUpstream) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			rawConn, err := d.DialContext(ctx, "tcp", up.dialAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName: up.serverName,
				MinVersion: tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	return &http.Client{Transport: tr}
}

// ResolveEndpointDoH resolves a host:port WireGuard endpoint using encrypted RFC 8484 DNS-over-HTTPS
// (Cloudflare 1.1.1.1 / 1.0.0.1 and Google 8.8.8.8) with bogon/sinkhole filtering, falling back to system DNS if unavailable.
func ResolveEndpointDoH(rawEndpoint string, useDoH bool) (string, error) {
	ep := strings.TrimSpace(rawEndpoint)
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q (expected host:port): %w", ep, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid endpoint port %q", portStr)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(portNum)), nil
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(portNum)), nil
	}

	if useDoH {
		if cachedIP, ok := getCachedDoH(host); ok {
			return net.JoinHostPort(cachedIP, strconv.Itoa(portNum)), nil
		}
		for _, up := range dohUpstreams {
			ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
			client := newDirectDoHClient(up)
			addr, dohErr := resolveHostViaDoHEndpoint(ctx, client, up.url, host, false)
			cancel()
			if dohErr == nil && addr.IsValid() {
				ipStr := addr.String()
				putCachedDoH(host, ipStr)
				return net.JoinHostPort(ipStr, strconv.Itoa(portNum)), nil
			}
		}
	}

	return resolveEndpointSystem(host, portNum)
}

func resolveEndpointSystem(host string, portNum int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("failed to resolve endpoint host %q: %w", host, err)
	}
	chosen := ips[0].Unmap()
	for _, candidate := range ips {
		c := candidate.Unmap()
		if c.Is4() && !isSinkholeIPv4(c, false) {
			chosen = c
			break
		}
	}
	return net.JoinHostPort(chosen.String(), strconv.Itoa(portNum)), nil
}
