package wgbridge

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dcProbeResult struct {
	DC    string `json:"dc"`
	Addr  string `json:"addr"`
	RttMs int64  `json:"rttMs"`
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type routeAndCallsReport struct {
	Ok          bool            `json:"ok"`
	ExitIP      string          `json:"exitIp"`
	Country     string          `json:"country"`
	ExitRttMs   int64           `json:"exitRttMs"`
	ExitError   string          `json:"exitError,omitempty"`
	UdpOk       bool            `json:"udpOk"`
	UdpRttMs    int64           `json:"udpRttMs"`
	UdpError    string          `json:"udpError,omitempty"`
	DcLatencies []dcProbeResult `json:"dcLatencies"`
	Error       string          `json:"error,omitempty"`
}

type verifyTargets struct {
	traceDialAddr   string
	traceServerName string
	traceUseTLS     bool
	udpDnsTarget    netip.AddrPort
	dcs             []struct {
		name string
		addr string
	}
}

func defaultVerifyTargets() verifyTargets {
	return verifyTargets{
		traceDialAddr:   "1.0.0.1:443",
		traceServerName: "one.one.one.one",
		traceUseTLS:     true,
		udpDnsTarget:    netip.MustParseAddrPort("1.1.1.1:53"),
		dcs: []struct {
			name string
			addr string
		}{
			{name: "DC1", addr: "149.154.175.53:443"},
			{name: "DC2", addr: "149.154.167.51:443"},
			{name: "DC4", addr: "149.154.167.91:443"},
			{name: "DC5", addr: "91.108.56.130:443"},
		},
	}
}

func performSocks5Handshake(c net.Conn, username, password string, cmd byte, dstHost string, dstPort uint16) (relayIP net.IP, relayPort uint16, err error) {
	if username == "" && password == "" {
		if _, err = c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return nil, 0, err
		}
		var greet [2]byte
		if _, err = io.ReadFull(c, greet[:]); err != nil {
			return nil, 0, err
		}
		if greet[0] != 0x05 || greet[1] != 0x00 {
			return nil, 0, fmt.Errorf("SOCKS5 auth method rejected: 0x%02x", greet[1])
		}
	} else {
		if _, err = c.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return nil, 0, err
		}
		var greet [2]byte
		if _, err = io.ReadFull(c, greet[:]); err != nil {
			return nil, 0, err
		}
		if greet[0] != 0x05 || greet[1] != 0x02 {
			return nil, 0, fmt.Errorf("SOCKS5 server did not accept user/pass auth: 0x%02x", greet[1])
		}
		if len(username) > 255 || len(password) > 255 {
			return nil, 0, errors.New("SOCKS5 credentials exceed 255 bytes")
		}
		authReq := make([]byte, 0, 3+len(username)+len(password))
		authReq = append(authReq, 0x01, byte(len(username)))
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)
		if _, err = c.Write(authReq); err != nil {
			return nil, 0, err
		}
		var authResp [2]byte
		if _, err = io.ReadFull(c, authResp[:]); err != nil {
			return nil, 0, err
		}
		if authResp[1] != 0x00 {
			return nil, 0, errors.New("SOCKS5 authentication failed")
		}
	}

	req := make([]byte, 0, 32)
	req = append(req, 0x05, cmd, 0x00)
	if ip, pErr := netip.ParseAddr(dstHost); pErr == nil {
		unmapped := ip.Unmap()
		if unmapped.Is4() {
			req = append(req, 0x01)
			v4 := unmapped.As4()
			req = append(req, v4[:]...)
		} else {
			req = append(req, 0x04)
			v6 := unmapped.As16()
			req = append(req, v6[:]...)
		}
	} else {
		if len(dstHost) == 0 || len(dstHost) > 255 {
			return nil, 0, errors.New("invalid SOCKS5 target host")
		}
		req = append(req, 0x03, byte(len(dstHost)))
		req = append(req, []byte(dstHost)...)
	}
	req = append(req, byte(dstPort>>8), byte(dstPort&0xff))
	if _, err = c.Write(req); err != nil {
		return nil, 0, err
	}

	var respHdr [4]byte
	if _, err = io.ReadFull(c, respHdr[:]); err != nil {
		return nil, 0, err
	}
	if respHdr[0] != 0x05 || respHdr[1] != 0x00 {
		return nil, 0, fmt.Errorf("SOCKS5 request rejected with code 0x%02x", respHdr[1])
	}
	bndHost, bndPort, err := readSocks5Target(c, respHdr[3])
	if err != nil {
		return nil, 0, err
	}
	return net.ParseIP(bndHost), bndPort, nil
}

func dialViaLocalSocks5(socksPort int, user, pass, targetAddr string, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return nil, errors.New("invalid target port")
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), timeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, _, err := performSocks5Handshake(c, user, pass, 0x01, host, uint16(p)); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// VerifyRouteAndCallsJSON runs an end-to-end verification through the local SOCKS5 listener:
// exit IP + country lookup, parallel Telegram DC latency probes, and real RFC 1928 UDP ASSOCIATE call readiness.
func VerifyRouteAndCallsJSON(socksPort int, username, password string) string {
	return verifyRouteAndCallsWithTargets(socksPort, username, password, defaultVerifyTargets())
}

func probeExitTrace(socksPort int, username, password, dialAddr, serverName string, useTLS bool) (exitIP, country string, rttMs int64, errStr string) {
	start := time.Now()
	c, err := dialViaLocalSocks5(socksPort, username, password, dialAddr, 3500*time.Millisecond)
	if err != nil {
		return "", "", 0, err.Error()
	}
	defer c.Close()

	// Measure pure 1-RTT tunnel connect latency to match DC probes and Android,
	// excluding TLS handshake and HTTP connection teardown waits.
	connectRtt := time.Since(start).Milliseconds()
	if connectRtt < 1 {
		connectRtt = 1
	}
	_ = c.SetDeadline(time.Now().Add(3500 * time.Millisecond))

	var rw io.ReadWriter = c
	if useTLS {
		tlsConn := tls.Client(c, &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		})
		if hErr := tlsConn.Handshake(); hErr != nil {
			return "", "", 0, hErr.Error()
		}
		rw = tlsConn
	}

	req := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: WireGuardPlus/1.5\r\nConnection: close\r\n\r\n", serverName)
	if _, wErr := io.WriteString(rw, req); wErr != nil {
		return "", "", 0, wErr.Error()
	}

	scanner := bufio.NewScanner(io.LimitReader(rw, 8192))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ip=") {
			exitIP = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			country = strings.TrimPrefix(line, "loc=")
		}
		if exitIP != "" && country != "" {
			break
		}
	}
	if exitIP == "" {
		if sErr := scanner.Err(); sErr != nil {
			return "", "", 0, sErr.Error()
		}
		return "", "", 0, "missing ip field in trace response"
	}
	return exitIP, country, connectRtt, ""
}

func probeUdpDnsOnce(socksPort int, username, password string, target netip.AddrPort) (int64, string) {
	start := time.Now()
	ctrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 4*time.Second)
	if err != nil {
		return 0, err.Error()
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))

	_, relayPort, err := performSocks5Handshake(ctrl, username, password, 0x03, "0.0.0.0", 0)
	if err != nil || relayPort == 0 {
		if err == nil {
			err = errors.New("relay port is 0")
		}
		return 0, err.Error()
	}

	uConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)})
	if err != nil {
		return 0, err.Error()
	}
	defer uConn.Close()
	_ = uConn.SetDeadline(time.Now().Add(4 * time.Second))

	dnsQuery, qErr := encodeDnsQueryA("telegram.org")
	if qErr != nil {
		return 0, qErr.Error()
	}
	txID := cryptoRandDnsTxID()
	binary.BigEndian.PutUint16(dnsQuery[0:2], txID)

	v4 := target.Addr().As4()
	udpPkt := make([]byte, 10+len(dnsQuery))
	udpPkt[3] = 0x01
	copy(udpPkt[4:8], v4[:])
	binary.BigEndian.PutUint16(udpPkt[8:10], target.Port())
	copy(udpPkt[10:], dnsQuery)

	if _, wErr := uConn.Write(udpPkt); wErr != nil {
		return 0, wErr.Error()
	}

	respBuf := make([]byte, 1500)
	rn, rErr := uConn.Read(respBuf)
	if rErr != nil {
		return 0, rErr.Error()
	}
	_, _, payload, pErr := parseSocks5UdpDatagram(respBuf[:rn])
	if pErr != nil || len(payload) < 12 {
		if pErr == nil {
			pErr = errors.New("short UDP DNS reply")
		}
		return 0, pErr.Error()
	}
	if binary.BigEndian.Uint16(payload[0:2]) != txID {
		return 0, "UDP DNS txid mismatch"
	}
	if _, parseErr := parseDnsResponseA(payload, true); parseErr != nil {
		return 0, parseErr.Error()
	}
	rtt := time.Since(start).Milliseconds()
	if rtt < 1 {
		rtt = 1
	}
	return rtt, ""
}

func verifyRouteAndCallsWithTargets(socksPort int, username, password string, tgt verifyTargets) string {
	if socksPort <= 0 {
		socksPort = GetActivePort()
	}
	var report routeAndCallsReport
	if socksPort <= 0 {
		report.Error = "tunnel is not running"
		raw, _ := json.Marshal(report)
		return string(raw)
	}

	var wg sync.WaitGroup

	// 1. Exit IP + Country via trace endpoint (fall back across 1.0.0.1 / 162.159.36.1 / 1.1.1.1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var addrs []string
		addrs = append(addrs, tgt.traceDialAddr)
		if tgt.traceDialAddr == "1.0.0.1:443" || tgt.traceDialAddr == "1.1.1.1:443" {
			for _, alt := range []string{"1.0.0.1:443", "162.159.36.1:443", "1.1.1.1:443"} {
				if alt != tgt.traceDialAddr {
					addrs = append(addrs, alt)
				}
			}
		}
		var ip, cc string
		var rtt int64
		var errStr string
		for _, addr := range addrs {
			ip, cc, rtt, errStr = probeExitTrace(socksPort, username, password, addr, tgt.traceServerName, tgt.traceUseTLS)
			if errStr == "" {
				break
			}
		}
		report.ExitIP = ip
		report.Country = cc
		report.ExitRttMs = rtt
		report.ExitError = errStr
	}()

	// 2. Parallel Telegram DC TCP latencies
	dcResults := make([]dcProbeResult, len(tgt.dcs))
	for i, dc := range tgt.dcs {
		wg.Add(1)
		go func(idx int, name, addr string) {
			defer wg.Done()
			start := time.Now()
			c, err := dialViaLocalSocks5(socksPort, username, password, addr, 4500*time.Millisecond)
			if err != nil {
				dcResults[idx] = dcProbeResult{DC: name, Addr: addr, Ok: false, Error: err.Error()}
				return
			}
			_ = c.Close()
			rtt := time.Since(start).Milliseconds()
			if rtt < 1 {
				rtt = 1
			}
			dcResults[idx] = dcProbeResult{DC: name, Addr: addr, Ok: true, RttMs: rtt}
		}(i, dc.name, dc.addr)
	}

	// 3. Real RFC 1928 UDP ASSOCIATE call readiness check (with 8.8.8.8:53 fallback)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rtt, errStr := probeUdpDnsOnce(socksPort, username, password, tgt.udpDnsTarget)
		if errStr != "" && tgt.udpDnsTarget == netip.MustParseAddrPort("1.1.1.1:53") {
			rtt2, errStr2 := probeUdpDnsOnce(socksPort, username, password, netip.MustParseAddrPort("8.8.8.8:53"))
			if errStr2 == "" {
				rtt, errStr = rtt2, ""
			} else {
				errStr = errStr2
			}
		}
		if errStr != "" {
			report.UdpError = errStr
			return
		}
		report.UdpOk = true
		report.UdpRttMs = rtt
	}()

	wg.Wait()
	report.DcLatencies = dcResults
	report.Ok = report.ExitIP != "" && report.UdpOk

	raw, _ := json.Marshal(report)
	return string(raw)
}
