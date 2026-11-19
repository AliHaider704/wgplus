//go:build android

package wgbridge

import "net"

func invokeClientGuard(_ net.Addr) (string, bool) {
	return "android", true
}

func invokeUdpPeerGuard(_ *net.UDPAddr, _ string) bool {
	return true
}
