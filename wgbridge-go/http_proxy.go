package wgbridge

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const preferredHttpProxyPort = 48739

var (
	httpProxyListener net.Listener
	httpProxyPort     int
)

// StartHttpProxy binds a loopback-only HTTP CONNECT proxy on 127.0.0.1 sharing
// the active WireGuard netstack, strict Kill Switch, Process Guard, and auth policy.
func StartHttpProxy(port int) (int, error) {
	mu.Lock()
	if httpProxyListener != nil && httpProxyPort > 0 {
		if port <= 0 || port == httpProxyPort {
			existing := httpProxyPort
			mu.Unlock()
			return existing, nil
		}
		_ = httpProxyListener.Close()
		httpProxyListener = nil
		httpProxyPort = 0
	}

	var candidates []int
	if port > 0 && port <= 65535 {
		candidates = []int{port, 0}
	} else {
		candidates = []int{preferredHttpProxyPort, 0}
	}

	var ln net.Listener
	var err error
	for _, p := range candidates {
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			break
		}
	}
	if err != nil {
		mu.Unlock()
		return 0, fmt.Errorf("failed to bind local HTTP CONNECT proxy: %w", err)
	}

	httpProxyListener = ln
	httpProxyPort = ln.Addr().(*net.TCPAddr).Port
	boundPort := httpProxyPort
	mu.Unlock()

	go httpProxyAcceptLoop(ln)
	return boundPort, nil
}

// StopHttpProxy closes the optional local HTTP CONNECT listener if active.
func StopHttpProxy() {
	mu.Lock()
	if httpProxyListener != nil {
		_ = httpProxyListener.Close()
		httpProxyListener = nil
		httpProxyPort = 0
	}
	mu.Unlock()
}

// GetHttpProxyPort returns the active local HTTP CONNECT port, or 0 if disabled.
func GetHttpProxyPort() int {
	mu.Lock()
	defer mu.Unlock()
	if httpProxyListener == nil {
		return 0
	}
	return httpProxyPort
}

func httpProxyAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			return
		}
		tuneLocalTcpSocket(c)
		go handleHttpConnectClient(c)
	}
}

func writeHttpErrorAndClose(c net.Conn, statusLine string, extraHeaders string) {
	msg := statusLine + "\r\n" + extraHeaders + "Connection: close\r\nContent-Length: 0\r\n\r\n"
	_, _ = io.WriteString(c, msg)
}

func verifyBasicProxyAuth(authHeader string, expectedUser string, expectedPass string) bool {
	return verifyBasicProxyAuthInternal(authHeader, expectedUser, expectedPass, false)
}

func verifyBasicProxyAuthWithExtras(authHeader string, expectedUser string, expectedPass string) bool {
	return verifyBasicProxyAuthInternal(authHeader, expectedUser, expectedPass, true)
}

func verifyBasicProxyAuthInternal(authHeader string, expectedUser string, expectedPass string, allowExtras bool) bool {
	if expectedUser == "" && expectedPass == "" {
		return true
	}
	fields := strings.Fields(strings.TrimSpace(authHeader))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	pair := string(decoded)
	colonIdx := strings.IndexByte(pair, ':')
	if colonIdx < 0 {
		return false
	}
	gotUser := pair[:colonIdx]
	gotPass := pair[colonIdx+1:]
	if subtle.ConstantTimeCompare([]byte(gotUser), []byte(expectedUser)) != 1 {
		return false
	}
	if allowExtras {
		return verifySocksPassBytes([]byte(gotPass)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(gotPass), []byte(expectedPass)) == 1
}

func handleHttpConnectClient(client net.Conn) {
	defer client.Close()

	clientLabel, allowed := invokeClientGuard(client.RemoteAddr())
	if !allowed {
		blockedLocalAttempts.Add(1)
		return
	}

	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReaderSize(io.LimitReader(client, 16*1024), 4096)

	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	reqLine = strings.TrimRight(reqLine, "\r\n")
	parts := strings.Fields(reqLine)
	if len(parts) < 3 {
		writeHttpErrorAndClose(client, "HTTP/1.1 400 Bad Request", "")
		return
	}
	method, target := parts[0], parts[1]

	var proxyAuthHeader string
	sawBlankLine := false
	for headerLines := 0; headerLines < 64; headerLines++ {
		line, hErr := br.ReadString('\n')
		if hErr != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			sawBlankLine = true
			break
		}
		if colon := strings.IndexByte(trimmed, ':'); colon > 0 {
			name := strings.TrimSpace(trimmed[:colon])
			if strings.EqualFold(name, "Proxy-Authorization") {
				proxyAuthHeader = strings.TrimSpace(trimmed[colon+1:])
			}
		}
	}
	if !sawBlankLine {
		writeHttpErrorAndClose(client, "HTTP/1.1 431 Request Header Fields Too Large", "")
		return
	}

	if !strings.EqualFold(method, http.MethodConnect) {
		writeHttpErrorAndClose(client, "HTTP/1.1 405 Method Not Allowed", "")
		return
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil || strings.TrimSpace(host) == "" {
		writeHttpErrorAndClose(client, "HTTP/1.1 400 Bad Request", "")
		return
	}
	portNum, pErr := strconv.Atoi(portStr)
	if pErr != nil || portNum < 1 || portNum > 65535 {
		writeHttpErrorAndClose(client, "HTTP/1.1 400 Bad Request", "")
		return
	}

	expectedUser, expectedPass := getSocksAuth()
	if !verifyBasicProxyAuthWithExtras(proxyAuthHeader, expectedUser, expectedPass) {
		writeHttpErrorAndClose(client, "HTTP/1.1 407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"WireGuard Plus\"\r\n")
		return
	}

	devCtx, dialer, routeAllowed := awaitMuxRouteReady(2800 * time.Millisecond)
	if !routeAllowed {
		writeHttpErrorAndClose(client, "HTTP/1.1 503 Service Unavailable", "")
		return
	}

	dialCtx, cancel := context.WithTimeout(devCtx, 12*time.Second)
	remote, dErr := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(portNum)))
	cancel()
	if dErr != nil {
		writeHttpErrorAndClose(client, "HTTP/1.1 502 Bad Gateway", "")
		return
	}
	defer remote.Close()

	_ = client.SetDeadline(time.Time{})
	if _, wErr := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); wErr != nil {
		return
	}

	activeTcpConns.Add(1)
	defer activeTcpConns.Add(-1)
	statEnt := trackClientConnStart(clientLabel)
	defer trackClientConnEnd(statEnt)

	stopDone := make(chan struct{})
	defer close(stopDone)
	go func() {
		select {
		case <-devCtx.Done():
			_ = client.Close()
			_ = remote.Close()
		case <-stopDone:
		}
	}()

	// Re-wrap client body reader if buffered bytes remain after headers, then stream raw client
	var clientSrc io.Reader = client
	if br.Buffered() > 0 {
		bufferedBytes := make([]byte, br.Buffered())
		n, _ := br.Read(bufferedBytes)
		if n > 0 {
			if _, wErr := remote.Write(bufferedBytes[:n]); wErr != nil {
				return
			}
			recordClientTx(statEnt, n)
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		copyWithPooledBufTracked(remote, clientSrc, statEnt, true)
		closeWriteOrConn(remote)
		done <- struct{}{}
	}()
	go func() {
		copyWithPooledBufTracked(client, remote, statEnt, false)
		closeWriteOrConn(client)
		done <- struct{}{}
	}()
	<-done
}
