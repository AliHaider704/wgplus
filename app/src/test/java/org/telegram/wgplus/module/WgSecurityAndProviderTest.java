package org.telegram.wgplus.module;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Security & trust-boundary regression tests covering IPC caller certificate pinning,
 * daemon token handoff without CLI argv leakage, shell argument quoting, updater URL checks,
 * atomic multi-field snapshots, and critical catch handling.
 */
public class WgSecurityAndProviderTest {

    @Test
    public void testExplicitApprovalReplacesSilentTofuAndBlocksCertChange() {
        String[] verifiedOfficialHashes = new String[]{
                "496b68c0f0e38839e141ef48b636260b8215c255a0e7aa80147f9bb2e149c173", // Telegram Google Play
                "49c1522548ebacd46ce322b6fd47f6092bb745d0f88082145caf35e14dcc38e1", // Telegram Direct/Web/Beta
                "6ebb622268aad319dbe8a1f414837d2843a9b35856aefb7dee2971a3d493f276", // Plus Messenger
                "b577c8d6f67d2eb1e837e89695993055fd9b9f5fc47f2a0fa5d9de2fb489a385", // Telegram X
                "bce0abdcc35da8b05c8824dc602811717cf9e8facf470ad6b2e4c049a7f3a0ca", // Nicegram
                "e7d5ad736aeecd2fe237679e4deaf2a40bb32fc07837fe48778a5b41c0418862", // Telegraph / Graph Messenger
                "5ce932b970199fbda2aae7bf21e1ad9e70b0809a7b1ac94c0699f5d5ada83313", // Nekogram
                "88a8afe3ccbee080c13b73832aab8c98a9f19d1c65f3bcfd50b8d01c0bc80e9e", // Nagram
                "f1a56d605801a6a73d7270f7ce5a9b126e6669955d2536011dfb20f5f15bf754", // exteraGram
                "a9d5ba4a1aa06b969bfec97b557183160c856f1e1401d756a043af110dddc71f", // Cherrygram
                "9bd25f08e031a7c878f468336795191adb23ad8044c1ace4c7cf0f34cdf8d4cd", // OctoGram
                "0880f186d777f3cb6d82a66d02bd58850e3a270a26b678175459a95511235ae5"  // Forkgram
        };
        for (String h : verifiedOfficialHashes) {
            assertEquals("Official cert must be allowed: " + h,
                    1, KeepaliveStatusProvider.evaluateCallerTrustDecision("org.telegram.plus", h, "own", ""));
        }
        assertEquals(1, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "org.telegram.messenger.web",
                "49c1522548ebacd46ce322b6fd47f6092bb745d0f88082145caf35e14dcc38e1",
                "own", ""));
        assertEquals(1, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "org.telegram.messenger.beta",
                "49c1522548ebacd46ce322b6fd47f6092bb745d0f88082145caf35e14dcc38e1",
                "own", ""));
        assertEquals(1, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "app.nicegram",
                "bce0abdcc35da8b05c8824dc602811717cf9e8facf470ad6b2e4c049a7f3a0ca",
                "own", ""));
        assertEquals(1, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "ir.ilmili.telegraph",
                "e7d5ad736aeecd2fe237679e4deaf2a40bb32fc07837fe48778a5b41c0418862",
                "own", ""));

        // Same cert as module itself (local LSPatch re-sign) allowed
        assertEquals(1, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "org.telegram.plus", "ownCertHex", "ownCertHex", ""));

        // Unapproved Play/F-Droid/unknown cert must DENY (no silent TOFU)
        assertEquals(0, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "com.radolyn.ayugram", "unknownCertHash123", "ownCertHex", ""));

        // Explicitly user-approved cert is allowed
        assertEquals(1, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "com.radolyn.ayugram", "userApproved123", "ownCertHex", "userApproved123"));

        // Different cert on an already-approved package must DENY (no silent auto-repin)
        assertEquals(0, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "com.radolyn.ayugram", "replacedAttackerCert", "ownCertHex", "userApproved123"));

        // Unsupported package or empty cert must DENY regardless of approval
        assertEquals(0, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "com.evil.stealer", verifiedOfficialHashes[0], "ownCertHex", verifiedOfficialHashes[0]));
        assertEquals(0, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                "org.telegram.plus", "", "ownCertHex", "userApproved123"));
        assertEquals(0, KeepaliveStatusProvider.evaluateCallerTrustDecision(
                null, verifiedOfficialHashes[0], "ownCertHex", ""));

        assertEquals("org.telegram.plus", KeepaliveStatusProvider.sanitizePackageName(" org.telegram.plus "));
        assertEquals("", KeepaliveStatusProvider.sanitizePackageName("org.telegram.plus;id"));
        assertEquals("", KeepaliveStatusProvider.sanitizePackageName("org.telegram.plus > /tmp/x"));
        assertEquals("", KeepaliveStatusProvider.sanitizePackageName(""));
    }

    @Test
    public void testDaemonTokenExtractionAndZeroArgvExposure() throws Exception {
        String sample64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String stdout = "Result: Bundle[{registered=true, token=" + sample64.toUpperCase() + "}]";
        assertEquals(sample64, DaemonProcessHelper.extractTokenFromContentCallOutput(stdout));
        assertEquals("", DaemonProcessHelper.extractTokenFromContentCallOutput("Result: Bundle[{registered=false}]"));
        assertEquals("", DaemonProcessHelper.extractTokenFromContentCallOutput("token=tooshort"));
        assertEquals("", DaemonProcessHelper.extractTokenFromContentCallOutput(null));

        Path helperPath = resolveModuleJavaFile("DaemonProcessHelper.java");
        String helperSrc = new String(Files.readAllBytes(helperPath), StandardCharsets.UTF_8);
        assertFalse("Daemon token must never be passed via /system/bin/content CLI argv",
                helperSrc.contains("token:s:"));
    }

    @Test
    public void testShellQuotingAndSafeTokens() {
        assertEquals("'/data/app/base.apk'", DaemonProcessHelper.shellQuoteSingle("/data/app/base.apk"));
        assertEquals("'/data/app/my app/base'\"'\"'1.apk'",
                DaemonProcessHelper.shellQuoteSingle("/data/app/my app/base'1.apk"));
        assertEquals("", DaemonProcessHelper.shellQuoteSingle(""));
        assertEquals("", DaemonProcessHelper.shellQuoteSingle(null));
        assertEquals("", DaemonProcessHelper.shellQuoteSingle("/data/bad\nrm -rf /"));
        assertEquals("", DaemonProcessHelper.shellQuoteSingle("/data/bad\r;id"));
        assertEquals("", DaemonProcessHelper.shellQuoteSingle("/data/bad\0null"));

        assertTrue(DaemonProcessHelper.isSafeToken("org.telegram.messenger.web"));
        assertFalse(DaemonProcessHelper.isSafeToken("org.telegram.plus$(id)"));
        assertFalse(DaemonProcessHelper.isSafeComponent("org.telegram.plus/Bad;Cmd"));
    }

    @Test
    public void testUpdateGateTrustedReleaseUrlValidation() {
        assertTrue(UpdateGate.isTrustedReleaseUrl(
                "https://github.com/AliHaider704/wgplus/releases/download/v2.0.3/WireGuardPlus-2.0.3-arm64-v8a.apk"));
        assertTrue(UpdateGate.isTrustedReleaseUrl(
                "https://github.com/AliHaider704/wgplus/releases/latest"));

        assertFalse(UpdateGate.isTrustedReleaseUrl(
                "http://github.com/AliHaider704/wgplus/releases/download/v2.0.3/app.apk"));
        assertFalse(UpdateGate.isTrustedReleaseUrl(
                "https://evil.com/AliHaider704/wgplus/releases/download/v2.0.3/app.apk"));
        assertFalse(UpdateGate.isTrustedReleaseUrl(
                "https://github.com/AliHaider704/wgplus/releases/download/../evil.apk"));
        assertFalse(UpdateGate.isTrustedReleaseUrl(
                "https://github.com/user@evil.com/AliHaider704/wgplus/releases/download/v2.0.3/app.apk"));
        assertFalse(UpdateGate.isTrustedReleaseUrl("javascript:alert(1)"));
        assertFalse(UpdateGate.isTrustedReleaseUrl(""));
        assertFalse(UpdateGate.isTrustedReleaseUrl(null));
    }

    @Test
    public void testAtomicSnapshotsAndCriticalCatchHandler() {
        try {
            WireGuardManager.updateLocalSocksCreds("wg", "p1");
            WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
            assertEquals("wg", creds.user);
            assertEquals("p1", creds.pass);

            WireGuardManager.updateSharedHubOwner(48729, "wg", "p1");
            WireGuardManager.SharedHubSnapshot ownerSnap = WireGuardManager.sSharedHub;
            assertTrue(ownerSnap.isOwner);
            assertEquals(48729, ownerSnap.port);

            WireGuardManager.updateSharedHubClient(48730, "wg", "sharedSecret", 1700000000L, true);
            WireGuardManager.SharedHubSnapshot clientSnap = WireGuardManager.sSharedHub;
            assertFalse(clientSnap.isOwner);
            assertEquals(48730, clientSnap.port);
            assertEquals("sharedSecret", clientSnap.pass);
            assertTrue(clientSnap.hsHealthy);

            WireGuardManager.clearSharedHubState();
            assertSame(WireGuardManager.SharedHubSnapshot.NONE, WireGuardManager.sSharedHub);
            assertEquals(-1, WireGuardManager.sSharedHub.port);
            assertFalse(WireGuardManager.sSharedHub.isOwner);
        } finally {
            WireGuardManager.clearSharedHubState();
            WireGuardManager.updateLocalSocksCreds("", "");
        }

        // VirtualMachineError subclasses must always propagate
        try {
            WgDiagnosticsLog.handleCriticalCatch("TEST", "OOM", new OutOfMemoryError("oom"));
            fail("OutOfMemoryError must be rethrown");
        } catch (OutOfMemoryError expected) {
            assertEquals("oom", expected.getMessage());
        }

        // InterruptedException must restore thread interrupt status
        try {
            WgDiagnosticsLog.handleCriticalCatch("TEST", "INT", new InterruptedException("stop"));
            assertTrue("Thread interrupt flag must be restored", Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }

        // Regular exceptions must record sanitized diagnostic event
        WgDiagnosticsLog.clear();
        WgDiagnosticsLog.handleCriticalCatch("SYNC", "TEST_CATCH",
                new IllegalStateException("fail socksPass=supersecret99"));
        String ex = WgDiagnosticsLog.snapshotExceptions().get(0);
        assertNotNull(ex);
        assertTrue(ex.contains("[SYNC/TEST_CATCH]"));
        assertFalse("Secret must be redacted in handleCriticalCatch", ex.contains("supersecret99"));
    }

    private static Path resolveModuleJavaFile(String name) {
        Path p = Paths.get("src", "main", "java", "org", "telegram", "wgplus", "module", name);
        if (!Files.exists(p)) {
            p = Paths.get("app", "src", "main", "java", "org", "telegram", "wgplus", "module", name);
        }
        assertTrue("Expected file to exist: " + p.toAbsolutePath(), Files.exists(p));
        return p;
    }
}
