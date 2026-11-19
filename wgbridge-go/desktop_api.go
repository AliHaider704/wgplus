//go:build !android

package wgbridge

import (
	"net"
	"sync"
)

// ClientGuardFunc inspects the incoming loopback peer address and returns
// a human-readable client label (e.g., "Telegram.exe") and whether it is allowed.
type ClientGuardFunc func(remoteAddr net.Addr) (clientLabel string, allowed bool)

// UdpPeerGuardFunc verifies an incoming loopback UDP packet sender against the
// owning SOCKS5 control client identity.
type UdpPeerGuardFunc func(remoteAddr *net.UDPAddr, expectedLabel string) bool

var (
	guardHooksMu sync.RWMutex
	clientGuard  ClientGuardFunc
	udpPeerGuard UdpPeerGuardFunc
)

// SetClientGuard registers a local process firewall callback for incoming TCP connections
// on the loopback SOCKS5 and HTTP CONNECT listeners.
func SetClientGuard(fn ClientGuardFunc) {
	guardHooksMu.Lock()
	clientGuard = fn
	guardHooksMu.Unlock()
}

// SetUdpPeerGuard registers a local process verification callback for UDP packets arriving
// on loopback SOCKS5 UDP ASSOCIATE relay sockets.
func SetUdpPeerGuard(fn UdpPeerGuardFunc) {
	guardHooksMu.Lock()
	udpPeerGuard = fn
	guardHooksMu.Unlock()
}

func invokeClientGuard(remoteAddr net.Addr) (string, bool) {
	guardHooksMu.RLock()
	fn := clientGuard
	guardHooksMu.RUnlock()
	if fn == nil {
		return "local-client", true
	}
	return fn(remoteAddr)
}

func invokeUdpPeerGuard(remoteAddr *net.UDPAddr, expectedLabel string) bool {
	guardHooksMu.RLock()
	fn := udpPeerGuard
	guardHooksMu.RUnlock()
	if fn == nil {
		return true
	}
	return fn(remoteAddr, expectedLabel)
}
