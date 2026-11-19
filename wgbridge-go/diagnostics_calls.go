package wgbridge

import (
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
		traceDialAddr:   "1.1.1.1:443",
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

	// 1. Exit IP + Country via trace endpoint
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		c, err := dialViaLocalSocks5(socksPort, username, password, tgt.traceDialAddr, 6*time.Second)
		if err != nil {
			report.ExitError = err.Error()
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(6 * time.Second))

		var rw io.ReadWriter = c
		if tgt.traceUseTLS {
			tlsConn := tls.Client(c, &tls.Config{
				ServerName: tgt.traceServerName,
				MinVersion: tls.VersionTLS12,
			})
			if hErr := tlsConn.Handshake(); hErr != nil {
				report.ExitError = hErr.Error()
				return
			}
			rw = tlsConn
		}

		req := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: WireGuardPlus/1.5\r\nConnection: close\r\n\r\n", tgt.traceServerName)
		if _, wErr := io.WriteString(rw, req); wErr != nil {
			report.ExitError = wErr.Error()
			return
		}
		bodyBytes, rErr := io.ReadAll(io.LimitReader(rw, 8192))
		if rErr != nil && len(bodyBytes) == 0 {
			report.ExitError = rErr.Error()
			return
		}
		body := string(bodyBytes)
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ip=") {
				report.ExitIP = strings.TrimPrefix(line, "ip=")
			} else if strings.HasPrefix(line, "loc=") {
				report.Country = strings.TrimPrefix(line, "loc=")
			}
		}
		if report.ExitIP == "" {
			report.ExitError = "missing ip field in trace response"
			return
		}
		rtt := time.Since(start).Milliseconds()
		if rtt < 1 {
			rtt = 1
		}
		report.ExitRttMs = rtt
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

	// 3. Real RFC 1928 UDP ASSOCIATE call readiness check
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		ctrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 4*time.Second)
		if err != nil {
			report.UdpError = err.Error()
			return
		}
		defer ctrl.Close()
		_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))

		_, relayPort, err := performSocks5Handshake(ctrl, username, password, 0x03, "0.0.0.0", 0)
		if err != nil || relayPort == 0 {
			if err == nil {
				err = errors.New("relay port is 0")
			}
			report.UdpError = err.Error()
			return
		}

		uConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)})
		if err != nil {
			report.UdpError = err.Error()
			return
		}
		defer uConn.Close()
		_ = uConn.SetDeadline(time.Now().Add(4 * time.Second))

		dnsQuery, qErr := encodeDnsQueryA("telegram.org")
		if qErr != nil {
			report.UdpError = qErr.Error()
			return
		}
		dnsQuery[0] = 0x57
		dnsQuery[1] = 0x48

		v4 := tgt.udpDnsTarget.Addr().As4()
		udpPkt := make([]byte, 10+len(dnsQuery))
		udpPkt[3] = 0x01
		copy(udpPkt[4:8], v4[:])
		binary.BigEndian.PutUint16(udpPkt[8:10], tgt.udpDnsTarget.Port())
		copy(udpPkt[10:], dnsQuery)

		if _, wErr := uConn.Write(udpPkt); wErr != nil {
			report.UdpError = wErr.Error()
			return
		}

		respBuf := make([]byte, 1500)
		rn, rErr := uConn.Read(respBuf)
		if rErr != nil {
			report.UdpError = rErr.Error()
			return
		}
		_, _, payload, pErr := parseSocks5UdpDatagram(respBuf[:rn])
		if pErr != nil || len(payload) < 12 {
			if pErr == nil {
				pErr = errors.New("short UDP DNS reply")
			}
			report.UdpError = pErr.Error()
			return
		}
		if payload[0] != 0x57 || payload[1] != 0x48 {
			report.UdpError = "UDP DNS txid mismatch"
			return
		}
		if _, parseErr := parseDnsResponseA(payload, true); parseErr != nil {
			report.UdpError = parseErr.Error()
			return
		}
		rtt := time.Since(start).Milliseconds()
		if rtt < 1 {
			rtt = 1
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
