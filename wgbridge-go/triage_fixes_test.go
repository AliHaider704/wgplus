package wgbridge

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSetSocksExtraPasswordsAcceptedAcrossSocks5HttpAndWgp1(t *testing.T) {
	SetSocksAuth("", "")
	ResetSocksAuthRejectCount()
	defer func() {
		SetSocksAuth("", "")
		ResetSocksAuthRejectCount()
	}()

	SetSocksAuth("wg", "primary-pass-1")
	SetSocksExtraPasswords("alt-pass-2, alt-pass-3,alt-pass-2,,")

	runSocksCheck := func(user, pass string, expectOK bool) {
		t.Helper()
		cConn, sConn := net.Pipe()
		defer cConn.Close()

		type res struct {
			sub string
			ok  bool
		}
		ch := make(chan res, 1)
		go func() {
			defer sConn.Close()
			_, _, _, sub, ok := readSocks5HandshakeAndReqWithLabel(sConn)
			ch <- res{sub: sub, ok: ok}
		}()

		if _, err := cConn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		meth := make([]byte, 2)
		if _, err := io.ReadFull(cConn, meth); err != nil || meth[1] != 0x02 {
			t.Fatalf("read method = %v err=%v", meth, err)
		}
		authPkt := []byte{0x01, byte(len(user))}
		authPkt = append(authPkt, []byte(user)...)
		authPkt = append(authPkt, byte(len(pass)))
		authPkt = append(authPkt, []byte(pass)...)
		if _, err := cConn.Write(authPkt); err != nil {
			t.Fatalf("write auth: %v", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(cConn, authResp); err != nil {
			t.Fatalf("read auth resp: %v", err)
		}
		if expectOK {
			if authResp[1] != 0x00 {
				t.Fatalf("expected auth accept for %q, got status=0x%02x", pass, authResp[1])
			}
			// Send valid CONNECT 1.1.1.1:443
			_, _ = cConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB})
			got := <-ch
			if !got.ok || got.sub != "org.telegram.plus" {
				t.Fatalf("unexpected parse result: %+v", got)
			}
		} else {
			if authResp[1] == 0x00 {
				t.Fatalf("expected auth reject for %q", pass)
			}
			got := <-ch
			if got.ok {
				t.Fatalf("expected handshake failure for wrong pass")
			}
		}
	}

	runSocksCheck("wg:org.telegram.plus", "primary-pass-1", true)
	runSocksCheck("wg:org.telegram.plus", "alt-pass-2", true)
	runSocksCheck("wg:org.telegram.plus", "alt-pass-3", true)
	if cnt := GetSocksAuthRejectCount(); cnt != 0 {
		t.Fatalf("expected 0 rejects for allowed passes, got %d", cnt)
	}
	runSocksCheck("wg:org.telegram.plus", "bad-pass", false)
	if cnt := GetSocksAuthRejectCount(); cnt != 1 {
		t.Fatalf("expected 1 reject for bad pass, got %d", cnt)
	}

	// Verify HTTP Basic auth helper and WGP1 control also honor extra passes
	hdrAlt := "Basic " + base64.StdEncoding.EncodeToString([]byte("wg:alt-pass-2"))
	if !verifyBasicProxyAuthWithExtras(hdrAlt, "wg", "primary-pass-1") {
		t.Fatalf("verifyBasicProxyAuthWithExtras rejected valid extra pass")
	}

	runWgp1 := func(cmd string) string {
		t.Helper()
		cConn, sConn := net.Pipe()
		go func() {
			defer sConn.Close()
			handleWgpControlConn(sConn, cmd[0])
		}()
		_, _ = io.WriteString(cConn, cmd[1:])
		line, _ := bufio.NewReader(cConn).ReadString('\n')
		_ = cConn.Close()
		return strings.TrimSpace(line)
	}
	if resp := runWgp1("WGP1 alt-pass-3 PUBLIC_STATUS\n"); !strings.HasPrefix(resp, "OK ") {
		t.Fatalf("PUBLIC_STATUS failed: %q", resp)
	}
	if resp := runWgp1("WGP1 alt-pass-2 STATUS\n"); !strings.HasPrefix(resp, "OK ") {
		t.Fatalf("STATUS with extra pass failed: %q", resp)
	}
	if resp := runWgp1("WGP1 wrong STATUS\n"); resp != "ERR AUTH" {
		t.Fatalf("expected ERR AUTH for wrong WGP1 pass, got %q", resp)
	}

	// Empty SetSocksAuth must clear extra passwords
	SetSocksAuth("", "")
	if len(socksExtraPasses) != 0 {
		t.Fatalf("expected SetSocksAuth(\"\", \"\") to clear extra passes")
	}
}

func TestNextWarpFallbackEndpointRotatesOnlyUnhandshakedWarp(t *testing.T) {
	warpPub := cloudflareWarpPeerPubHex
	otherPub := strings.Repeat("a", 64)

	if ep, ok := nextWarpFallbackEndpoint("162.159.192.1:2408", warpPub, 1700000000); ok || ep != "" {
		t.Fatalf("must not rotate when handshake already succeeded: %q %v", ep, ok)
	}
	if ep, ok := nextWarpFallbackEndpoint("162.159.192.1:2408", otherPub, 0); ok || ep != "" {
		t.Fatalf("must not rotate non-WARP pubkey: %q %v", ep, ok)
	}
	if ep, ok := nextWarpFallbackEndpoint("162.159.192.1:51820", warpPub, 0); ok || ep != "" {
		t.Fatalf("must not rotate custom port: %q %v", ep, ok)
	}

	seen := map[string]bool{}
	cur := "162.159.192.1:2408"
	for i := 0; i < 6; i++ {
		next, ok := nextWarpFallbackEndpoint(cur, warpPub, 0)
		if !ok || next == "" || next == cur {
			t.Fatalf("expected distinct rotated endpoint from %q, got %q ok=%v", cur, next, ok)
		}
		_, port, _ := net.SplitHostPort(next)
		seen[port] = true
		cur = next
	}
	for _, wantPort := range []string{"2408", "4500", "500", "1701"} {
		if !seen[wantPort] {
			t.Fatalf("expected port %s to be visited during rotation, seen=%v", wantPort, seen)
		}
	}
}

func TestNestedVpnLinkMtuSensorClampsAndRestoresInPlace(t *testing.T) {
	SetHostLinkMTU(0, false)
	defer SetHostLinkMTU(0, false)

	if got := computeNestedCapMTU(1280, true); got != nestedMinMTU {
		t.Fatalf("expected outerVpn cap 1200, got %d", got)
	}
	if got := computeNestedCapMTU(1360, false); got != nestedMinMTU {
		t.Fatalf("expected low linkMtu cap 1200, got %d", got)
	}
	if got := computeNestedCapMTU(1500, false); got != maxMTU {
		t.Fatalf("expected normal linkMtu cap 1420, got %d", got)
	}
}

func TestIsolatedVirtualInterfaceFilter(t *testing.T) {
	for _, virt := range []string{
		"VMware Network Adapter VMnet1",
		"VMware Network Adapter VMnet8",
		"VirtualBox Host-Only Ethernet Adapter",
		"vEthernet (Default Switch)",
		"Teredo Tunneling Pseudo-Interface",
		"WireGuardPlusCalls",
	} {
		if !isIsolatedVirtualInterfaceName(virt) {
			t.Fatalf("expected %q to be classified as isolated virtual adapter", virt)
		}
	}
	for _, real := range []string{"wlan0", "rmnet_data2", "tun1", "Wi-Fi", "Ethernet 3", "Беспроводная сеть"} {
		if isIsolatedVirtualInterfaceName(real) {
			t.Fatalf("did not expect real adapter %q to be filtered", real)
		}
	}
}

func TestVoipBackupRelaySuppressesFalseLowTrafficWhenSiblingCarriedMedia(t *testing.T) {
	baseLow := voipLowTrafficCloses.Load()
	lastVoipMediaRelayActiveUnix.Store(0)

	voipRelaysMu.Lock()
	mediaRelay := &voipRelay{
		targetKey:     "p|149.154.167.50:1400",
		targetHost:    "149.154.167.50",
		targetPort:    1400,
		createdAtUnix: time.Now().Unix() - 45,
	}
	mediaRelay.udpPktsTx.Store(200)
	mediaRelay.udpPktsRx.Store(190)

	backupRelay := &voipRelay{
		targetKey:     "p|149.154.167.50:597",
		targetHost:    "149.154.167.50",
		targetPort:    597,
		createdAtUnix: time.Now().Unix() - 55,
	}
	backupRelay.udpPktsTx.Store(3)
	backupRelay.udpPktsRx.Store(2)

	voipRelays[mediaRelay.targetKey] = mediaRelay
	voipRelays[backupRelay.targetKey] = backupRelay
	voipRelaysMu.Unlock()

	defer func() {
		voipRelaysMu.Lock()
		delete(voipRelays, mediaRelay.targetKey)
		delete(voipRelays, backupRelay.targetKey)
		voipRelaysMu.Unlock()
		lastVoipMediaRelayActiveUnix.Store(0)
	}()

	// Closing backup relay while sibling carries >=100 packets must NOT count as LOW_TRAFFIC
	backupRelay.close()
	if got := voipLowTrafficCloses.Load(); got != baseLow {
		t.Fatalf("expected backup close not to increment voipLowTrafficCloses (got %d vs %d)", got, baseLow)
	}
	mediaRelay.close()
}

func TestIsTunnelHotVerifiedTracksRxAndStallState(t *testing.T) {
	mu.Lock()
	origRun := running
	origDev := activeDev
	origEp := activeResolvedEp
	mu.Unlock()
	if origRun || origDev != nil {
		t.Skip("unexpected running global tunnel during unit test")
	}
	if IsTunnelHotVerified() {
		t.Fatalf("expected IsTunnelHotVerified false when tunnel stopped (ep=%s)", origEp)
	}
}
