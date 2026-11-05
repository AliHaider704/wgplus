package wgbridge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultMTU        = 1280
	minMTU            = 1280
	maxMTU            = 1420
	maxUdpSessionsCap = 64
)

var (
	mu               sync.Mutex
	activeDev        *device.Device
	activeListener   net.Listener
	activeCancel     context.CancelFunc
	activePort       int
	activePeerPubHex string
	activeUseDoH     bool
	running          bool
)

func normalizeHexKey(raw string) (string, error) {
	k := strings.TrimSpace(raw)
	if len(k) == 64 {
		if _, err := hex.DecodeString(k); err == nil {
			return strings.ToLower(k), nil
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(k, "="))
	}
	if err == nil && len(decoded) == 32 {
		return hex.EncodeToString(decoded), nil
	}
	return "", errors.New("invalid WireGuard key: expected 64-char hex or 32-byte base64 key")
}

func parseAddresses(raw string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("invalid address prefix %q: %w", s, err)
			}
			out = append(out, pfx.Addr().Unmap())
		} else {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", s, err)
			}
			out = append(out, addr.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one client IP address is required")
	}
	return out, nil
}

func parseDNS(raw string) ([]netip.Addr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		trimmed = "1.1.1.1"
	}
	var out []netip.Addr
	for _, part := range strings.Split(trimmed, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			if pfx, err := netip.ParsePrefix(s); err == nil {
				out = append(out, pfx.Addr().Unmap())
				continue
			}
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS server %q: %w", s, err)
		}
		out = append(out, addr.Unmap())
	}
	if len(out) == 0 {
		out = append(out, netip.MustParseAddr("1.1.1.1"))
	}
	return out, nil
}

func normalizeMTU(mtu int) int {
	if mtu <= 0 {
		return defaultMTU
	}
	if mtu < minMTU {
		return minMTU
	}
	if mtu > maxMTU {
		return maxMTU
	}
	return mtu
}

// StartTunnel starts the userspace WireGuard tunnel with default MTU (1280) and no PresharedKey.
func StartTunnel(privateKeyHex string, clientIP string, dnsServer string, peerPublicKeyHex string, endpoint string, keepAlive int) (int, error) {
	return StartTunnelWithOptions(privateKeyHex, "", clientIP, dnsServer, peerPublicKeyHex, endpoint, keepAlive, defaultMTU)
}

// StartTunnelWithOptions starts the userspace WireGuard tunnel and local RFC 1928 SOCKS5 (TCP CONNECT + UDP ASSOCIATE) server on 127.0.0.1:0.
func StartTunnelWithOptions(
	privateKey string,
	presharedKey string,
	clientIP string,
	dnsServer string,
	peerPublicKey string,
	endpoint string,
	keepAlive int,
	mtu int,
) (int, error) {
	return StartTunnelAdvanced(privateKey, presharedKey, clientIP, dnsServer, peerPublicKey, endpoint, keepAlive, mtu, "", false)
}

// StartTunnelAdvanced starts the userspace WireGuard / AmneziaWG tunnel with optional DPI obfuscation (awgParams)
// and optional encrypted RFC 8484 DNS-over-HTTPS endpoint resolution (useDoH).
func StartTunnelAdvanced(
	privateKey string,
	presharedKey string,
	clientIP string,
	dnsServer string,
	peerPublicKey string,
	endpoint string,
	keepAlive int,
	mtu int,
	awgParams string,
	useDoH bool,
) (int, error) {
	privHex, err := normalizeHexKey(privateKey)
	if err != nil {
		return 0, fmt.Errorf("private key error: %w", err)
	}
	pubHex, err := normalizeHexKey(peerPublicKey)
	if err != nil {
		return 0, fmt.Errorf("peer public key error: %w", err)
	}
	var pskHex string
	if strings.TrimSpace(presharedKey) != "" {
		pskHex, err = normalizeHexKey(presharedKey)
		if err != nil {
			return 0, fmt.Errorf("preshared key error: %w", err)
		}
	}
	awgCfg, err := parseAwgConfig(awgParams)
	if err != nil {
		return 0, fmt.Errorf("AmneziaWG config error: %w", err)
	}
	clientAddrs, err := parseAddresses(clientIP)
	if err != nil {
		return 0, err
	}
	dnsAddrs, err := parseDNS(dnsServer)
	if err != nil {
		return 0, err
	}
	resolvedEndpoint, err := ResolveEndpointDoH(endpoint, useDoH)
	if err != nil {
		return 0, err
	}
	effectiveMTU := normalizeMTU(mtu)

	mu.Lock()
	defer mu.Unlock()

	stopLocked()

	tunDev, tnet, err := netstack.CreateNetTUN(clientAddrs, dnsAddrs, effectiveMTU)
	if err != nil {
		return 0, fmt.Errorf("failed to create netstack TUN: %w", err)
	}

	bindImpl, err := newAwgBind(conn.NewDefaultBind(), awgCfg, privHex, pubHex)
	if err != nil {
		return 0, fmt.Errorf("failed to initialize tunnel bind: %w", err)
	}

	dev := device.NewDevice(tunDev, bindImpl, device.NewLogger(device.LogLevelSilent, ""))

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", privHex)
	fmt.Fprintf(&uapi, "public_key=%s\n", pubHex)
	if pskHex != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&uapi, "endpoint=%s\n", resolvedEndpoint)
	uapi.WriteString("allowed_ip=0.0.0.0/0\n")
	uapi.WriteString("allowed_ip=::/0\n")
	if keepAlive > 0 {
		fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", keepAlive)
	}

	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return 0, fmt.Errorf("failed to apply WireGuard UAPI config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return 0, fmt.Errorf("failed to bring WireGuard device up: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		dev.Close()
		return 0, fmt.Errorf("failed to bind local SOCKS5 listener: %w", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())

	activeDev = dev
	activeListener = ln
	activeCancel = cancel
	activePort = port
	activePeerPubHex = pubHex
	activeUseDoH = useDoH
	running = true

	go acceptLoop(ctx, ln, tnet)

	return port, nil
}

// UpdatePeerEndpoint updates the WireGuard peer endpoint dynamically on network handoff without restarting the local SOCKS5 listener.
func UpdatePeerEndpoint(endpoint string) error {
	mu.Lock()
	useDoH := activeUseDoH
	mu.Unlock()

	ClearDnsCache()
	resolved, err := ResolveEndpointDoH(endpoint, useDoH)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if !running || activeDev == nil || activePeerPubHex == "" {
		return errors.New("tunnel is not running")
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "public_key=%s\n", activePeerPubHex)
	fmt.Fprintf(&uapi, "endpoint=%s\n", resolved)
	return activeDev.IpcSet(uapi.String())
}

// SetPeerKeepalive dynamically adjusts persistent_keepalive_interval on the active peer (0 pauses background keepalives for battery saving).
func SetPeerKeepalive(keepAlive int) error {
	if keepAlive < 0 {
		keepAlive = 0
	}
	if keepAlive > 600 {
		keepAlive = 600
	}
	mu.Lock()
	defer mu.Unlock()
	if !running || activeDev == nil || activePeerPubHex == "" {
		return errors.New("tunnel is not running")
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "public_key=%s\n", activePeerPubHex)
	fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", keepAlive)
	return activeDev.IpcSet(uapi.String())
}

// GetTunnelStats returns UAPI telemetry lines (rx_bytes, tx_bytes, last_handshake_time_sec) for the active peer.
func GetTunnelStats() string {
	mu.Lock()
	dev := activeDev
	isUp := running
	mu.Unlock()

	if !isUp || dev == nil {
		return ""
	}
	ipcOut, err := dev.IpcGet()
	if err != nil || ipcOut == "" {
		return ""
	}

	var rx, tx, hs string
	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "rx_bytes=") {
			rx = strings.TrimPrefix(line, "rx_bytes=")
		} else if strings.HasPrefix(line, "tx_bytes=") {
			tx = strings.TrimPrefix(line, "tx_bytes=")
		} else if strings.HasPrefix(line, "last_handshake_time_sec=") {
			hs = strings.TrimPrefix(line, "last_handshake_time_sec=")
		}
	}
	if rx == "" {
		rx = "0"
	}
	if tx == "" {
		tx = "0"
	}
	if hs == "" {
		hs = "0"
	}
	return fmt.Sprintf("rx_bytes=%s\ntx_bytes=%s\nlast_handshake_time_sec=%s", rx, tx, hs)
}

// StopTunnel stops the active SOCKS5 listener and closes the WireGuard device.
func StopTunnel() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

func stopLocked() {
	if activeCancel != nil {
		activeCancel()
		activeCancel = nil
	}
	if activeListener != nil {
		_ = activeListener.Close()
		activeListener = nil
	}
	if activeDev != nil {
		activeDev.Close()
		activeDev = nil
	}
	activePort = 0
	activePeerPubHex = ""
	activeUseDoH = false
	running = false
}

// IsRunning returns true if the tunnel and SOCKS5 listener are active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running && activeListener != nil && activeDev != nil
}

// GetActivePort returns the active local SOCKS5 port, or 0 if stopped.
func GetActivePort() int {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return 0
	}
	return activePort
}

func acceptLoop(ctx context.Context, ln net.Listener, tnet *netstack.Net) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		go handleSocks5Client(ctx, c, tnet)
	}
}

type udpDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func readSocks5Target(r io.Reader, atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err = io.ReadFull(r, ipBuf); err != nil {
			return "", 0, err
		}
		host = net.IP(ipBuf).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(r, lenBuf); err != nil {
			return "", 0, err
		}
		domBuf := make([]byte, int(lenBuf[0]))
		if _, err = io.ReadFull(r, domBuf); err != nil {
			return "", 0, err
		}
		host = string(domBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err = io.ReadFull(r, ipBuf); err != nil {
			return "", 0, err
		}
		host = net.IP(ipBuf).String()
	default:
		return "", 0, errors.New("unsupported SOCKS5 ATYP")
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	port = binary.BigEndian.Uint16(portBuf)
	return host, port, nil
}

func handleSocks5Client(ctx context.Context, client net.Conn, dialer udpDialer) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(20 * time.Second))

	// 1. Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	if nMethods > 0 {
		methods := make([]byte, nMethods)
		if _, err := io.ReadFull(client, methods); err != nil {
			return
		}
	}
	// Reply: SOCKS5, NO AUTHENTICATION REQUIRED (0x00)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		return
	}

	cmd := reqHdr[1]
	host, dstPort, err := readSocks5Target(client, reqHdr[3])
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	switch cmd {
	case 0x01: // TCP CONNECT (MTProto signaling, channels, media, VoIP TCP fallback)
		handleTcpConnect(ctx, client, dialer, host, dstPort)
	case 0x03: // UDP ASSOCIATE (Telegram VoIP / tgcalls voice & video RTP/STUN media)
		handleUdpAssociate(ctx, client, dialer)
	default:
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func handleTcpConnect(ctx context.Context, client net.Conn, dialer udpDialer, host string, dstPort uint16) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	remote, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Clear handshake deadline before streaming
	_ = client.SetDeadline(time.Time{})

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	stopDone := make(chan struct{})
	defer close(stopDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = remote.Close()
		case <-stopDone:
		}
	}()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, client)
		_ = remote.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, remote)
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
}

type udpRemoteSession struct {
	remoteConn net.Conn
	replyHdr   []byte
	clientAddr atomic.Value // stores *net.UDPAddr
}

func parseSocks5UdpDatagram(pkt []byte) (targetAddr string, replyHdr []byte, payload []byte, err error) {
	if len(pkt) < 10 {
		return "", nil, nil, errors.New("short SOCKS5 UDP packet")
	}
	// RSV must be 0x0000 and FRAG must be 0x00 (RFC 1928 Section 7)
	if pkt[2] != 0x00 {
		return "", nil, nil, errors.New("fragmented SOCKS5 UDP not supported")
	}

	atyp := pkt[3]
	var host string
	var hdrEnd int

	switch atyp {
	case 0x01: // IPv4: 4 + 4 + 2 = 10
		if len(pkt) < 10 {
			return "", nil, nil, errors.New("truncated IPv4 UDP header")
		}
		host = net.IP(pkt[4:8]).String()
		hdrEnd = 10
	case 0x03: // Domain: 4 + 1 + L + 2
		domLen := int(pkt[4])
		hdrEnd = 4 + 1 + domLen + 2
		if domLen == 0 || len(pkt) < hdrEnd {
			return "", nil, nil, errors.New("truncated domain UDP header")
		}
		host = string(pkt[5 : 5+domLen])
	case 0x04: // IPv6: 4 + 16 + 2 = 22
		if len(pkt) < 22 {
			return "", nil, nil, errors.New("truncated IPv6 UDP header")
		}
		host = net.IP(pkt[4:20]).String()
		hdrEnd = 22
	default:
		return "", nil, nil, errors.New("unsupported UDP ATYP")
	}

	dstPort := binary.BigEndian.Uint16(pkt[hdrEnd-2 : hdrEnd])
	targetAddr = net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	hdrCopy := make([]byte, hdrEnd)
	hdrCopy[0] = 0x00
	hdrCopy[1] = 0x00
	hdrCopy[2] = 0x00
	copy(hdrCopy[3:], pkt[3:hdrEnd])

	return targetAddr, hdrCopy, pkt[hdrEnd:], nil
}

func handleUdpAssociate(ctx context.Context, tcpControl net.Conn, dialer udpDialer) {
	udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = tcpControl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	relayPort := udpLn.LocalAddr().(*net.UDPAddr).Port

	// Clear deadline on TCP control connection so calls stay alive indefinitely until closed by Telegram
	_ = tcpControl.SetDeadline(time.Time{})

	reply := []byte{
		0x05, 0x00, 0x00, 0x01,
		127, 0, 0, 1,
		byte(relayPort >> 8), byte(relayPort & 0xff),
	}
	if _, err := tcpControl.Write(reply); err != nil {
		_ = udpLn.Close()
		return
	}

	assocCtx, assocCancel := context.WithCancel(ctx)
	var sessMu sync.Mutex
	sessions := make(map[string]*udpRemoteSession)

	cleanupAll := func() {
		assocCancel()
		_ = udpLn.Close()
		_ = tcpControl.Close()
		sessMu.Lock()
		for k, s := range sessions {
			_ = s.remoteConn.Close()
			delete(sessions, k)
		}
		sessMu.Unlock()
	}
	defer cleanupAll()

	// Tear down immediately if parent tunnel context cancels
	go func() {
		<-assocCtx.Done()
		_ = udpLn.Close()
		_ = tcpControl.Close()
	}()

	// Pump local UDP frames from tgcalls into WireGuard netstack UDP sockets
	go func() {
		buf := make([]byte, 65535)
		for {
			n, srcAddr, rErr := udpLn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			if srcAddr == nil || !srcAddr.IP.IsLoopback() {
				continue
			}

			targetAddr, replyHdr, payload, pErr := parseSocks5UdpDatagram(buf[:n])
			if pErr != nil || len(payload) == 0 {
				continue
			}

			sessMu.Lock()
			sess, exists := sessions[targetAddr]
			if !exists {
				if len(sessions) >= maxUdpSessionsCap {
					sessMu.Unlock()
					continue
				}
				dialCtx, cancel := context.WithTimeout(assocCtx, 8*time.Second)
				rConn, dErr := dialer.DialContext(dialCtx, "udp", targetAddr)
				cancel()
				if dErr != nil {
					sessMu.Unlock()
					continue
				}
				sess = &udpRemoteSession{
					remoteConn: rConn,
					replyHdr:   replyHdr,
				}
				sess.clientAddr.Store(srcAddr)
				sessions[targetAddr] = sess
				sessMu.Unlock()

				// Pump return UDP packets from WireGuard netstack back to local client with RFC 1928 UDP header
				go func(key string, s *udpRemoteSession) {
					respBuf := make([]byte, 65535)
					for {
						rn, readErr := s.remoteConn.Read(respBuf)
						if readErr != nil {
							sessMu.Lock()
							delete(sessions, key)
							sessMu.Unlock()
							_ = s.remoteConn.Close()
							return
						}
						cAddrAny := s.clientAddr.Load()
						if cAddr, ok := cAddrAny.(*net.UDPAddr); ok && cAddr != nil {
							outPkt := make([]byte, len(s.replyHdr)+rn)
							copy(outPkt, s.replyHdr)
							copy(outPkt[len(s.replyHdr):], respBuf[:rn])
							_, _ = udpLn.WriteToUDP(outPkt, cAddr)
						}
					}
				}(targetAddr, sess)
			} else {
				sess.clientAddr.Store(srcAddr)
				sessMu.Unlock()
			}

			_, _ = sess.remoteConn.Write(payload)
		}
	}()

	// RFC 1928 Section 7: UDP association stays alive until TCP control socket closes
	ctrlBuf := make([]byte, 16)
	for {
		if _, err := tcpControl.Read(ctrlBuf); err != nil {
			return
		}
	}
}
