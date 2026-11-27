package syswin

import (
	"net"
	"testing"
)

func TestShouldIncludeInterfaceInFingerprintExcludesWintunAndLoopback(t *testing.T) {
	if shouldIncludeInterfaceInFingerprint("WireGuardPlusCalls", net.FlagUp) {
		t.Fatalf("expected WireGuardPlusCalls adapter to be excluded from network fingerprint")
	}
	if shouldIncludeInterfaceInFingerprint(" wireguardpluscalls ", net.FlagUp) {
		t.Fatalf("expected case-insensitive WireGuardPlusCalls adapter to be excluded")
	}
	if shouldIncludeInterfaceInFingerprint("Loopback Pseudo-Interface 1", net.FlagUp|net.FlagLoopback) {
		t.Fatalf("expected loopback interface to be excluded")
	}
	if shouldIncludeInterfaceInFingerprint("Ethernet 3", 0) {
		t.Fatalf("expected down interface to be excluded")
	}
	if !shouldIncludeInterfaceInFingerprint("Ethernet 3", net.FlagUp) {
		t.Fatalf("expected active Ethernet 3 adapter to be included")
	}
	for _, virt := range []string{
		"VMware Network Adapter VMnet1",
		"VMware Network Adapter VMnet8",
		"VirtualBox Host-Only Ethernet Adapter",
		"vEthernet (Default Switch)",
		"Teredo Tunneling Pseudo-Interface",
	} {
		if shouldIncludeInterfaceInFingerprint(virt, net.FlagUp) {
			t.Fatalf("expected isolated virtual adapter %q to be excluded", virt)
		}
	}
	if !isOuterVpnAdapter("Radmin VPN") || !isOuterVpnAdapter("WireGuard Tunnel") || isOuterVpnAdapter("WireGuardPlusCalls") {
		t.Fatalf("unexpected isOuterVpnAdapter classification")
	}
}
