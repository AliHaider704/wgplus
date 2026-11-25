package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import wgbridge.Wgbridge;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Instrumentation smoke suite verifying JNI native bridge loading, loopback kill-switch
 * listener behavior, ContentProvider IPC, non-root privilege checks, and companion UI launch
 * across Android API levels (emulators and physical devices).
 */
@RunWith(AndroidJUnit4.class)
public class WgPlusSmokeInstrumentedTest {

    private static String runUiShellCommandBestEffort(String cmd) {
        try (ParcelFileDescriptor pfd = InstrumentationRegistry.getInstrumentation()
                .getUiAutomation().executeShellCommand(cmd);
             InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(pfd)) {
            byte[] buf = new byte[1024];
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = in.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    @Test(timeout = 30_000L)
    public void nativeBridgeLoadsAndInitialStateIsClean() {
        Context ctx = ApplicationProvider.getApplicationContext();
        assertNotNull(ctx);

        String sourceApk = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
        NativeBridgeLoader.ensureLoaded(ctx, sourceApk);
        assertTrue("NativeBridgeLoader must report loaded", NativeBridgeLoader.isLoaded());

        Wgbridge.stopTunnel();
        assertFalse("Tunnel must not be running after stopTunnel()", Wgbridge.isRunning());
        assertFalse("Stopped tunnel must report handshakeHealthy=false", Wgbridge.isHandshakeHealthy());
        assertTrue("socksAuthRejectCount must be non-negative", Wgbridge.getSocksAuthRejectCount() >= 0L);
    }

    @Test(timeout = 30_000L)
    public void killSwitchLoopbackGuardAndTelemetryJsonAreValid() throws Exception {
        Context ctx = ApplicationProvider.getApplicationContext();
        String sourceApk = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
        NativeBridgeLoader.ensureLoaded(ctx, sourceApk);

        long ksPort = Wgbridge.startKillSwitchGuard();
        try {
            assertTrue("Kill switch mux port must be bound (> 0)", ksPort > 0);
            assertEquals("Active kill switch port must match", ksPort, Wgbridge.getKillSwitchPort());

            JSONObject detailed = new JSONObject(Wgbridge.getDetailedStatsJSON());
            assertTrue(detailed.has("activeTcpConns"));
            assertTrue(detailed.has("activeUdpAssocs"));
            assertTrue(detailed.has("handshakeHealthy"));
            assertTrue(detailed.has("socksAuthRejectCount"));
            assertTrue(detailed.has("killSwitch"));
            assertTrue(detailed.getBoolean("killSwitch"));

            JSONObject udpTel = new JSONObject(Wgbridge.getUdpTelemetryJSON());
            assertTrue(udpTel.has("watchdogRecoveries"));
            assertTrue(udpTel.has("udpSocketsOpened"));
            assertTrue(udpTel.has("udpPacketsTx"));
            assertTrue(udpTel.has("udpPacketsRx"));
        } finally {
            Wgbridge.stopKillSwitchGuard();
        }
    }

    @Test(timeout = 30_000L)
    public void keepaliveStatusProviderRespondsGracefully() {
        Context ctx = ApplicationProvider.getApplicationContext();
        Uri providerUri = Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY);

        Bundle status = ctx.getContentResolver().call(
                providerUri,
                KeepaliveStatusProvider.METHOD_QUERY_STATUS,
                null,
                null
        );
        assertNotNull("METHOD_QUERY_STATUS must return a non-null Bundle", status);
        String tier = status.getString(KeepaliveStatusProvider.RESULT_TIER, "");
        assertFalse("Continuity tier must be non-empty", tier.isEmpty());

        Bundle shared = ctx.getContentResolver().call(
                providerUri,
                KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                null,
                null
        );
        assertNotNull("METHOD_QUERY_SHARED_TUNNEL must return a non-null Bundle", shared);
        assertTrue("Shared tunnel Bundle must contain port key", shared.containsKey("port"));
    }

    @Test(timeout = 30_000L)
    public void continuityAndPrivilegeChecksDoNotCrashOnUnprivilegedDevice() {
        Context ctx = ApplicationProvider.getApplicationContext();
        boolean rootPassive = PrivilegeBridge.isRootAvailablePassive(ctx);
        assertFalse("Uninitialized test process should not crash on passive root check",
                rootPassive && !PrivilegeBridge.hasRootBinaryOnDisk());

        ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(ctx);
        assertNotNull("StealthSnapshot must never be null", snap);
        assertNotNull("Continuity tier must never be null", snap.tier);

        String mode = ContinuityBridgeManager.getActivePrivilegeMode(ctx);
        assertNotNull("Active privilege mode string must be non-null", mode);
        assertFalse("Active privilege mode string must be non-empty", mode.isEmpty());
    }

    @Test(timeout = 30_000L)
    public void moduleLauncherActivityLaunchesAndResumes() throws Exception {
        Application app = (Application) ApplicationProvider.getApplicationContext();
        final CountDownLatch resumedLatch = new CountDownLatch(1);
        final AtomicReference<ModuleLauncherActivity> resumedActivity = new AtomicReference<>();
        Application.ActivityLifecycleCallbacks cb = new Application.ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity a, Bundle b) {}
            @Override public void onActivityStarted(Activity a) {}
            @Override public void onActivityResumed(Activity a) {
                if (a instanceof ModuleLauncherActivity) {
                    resumedActivity.set((ModuleLauncherActivity) a);
                    resumedLatch.countDown();
                }
            }
            @Override public void onActivityPaused(Activity a) {}
            @Override public void onActivityStopped(Activity a) {}
            @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
            @Override public void onActivityDestroyed(Activity a) {}
        };
        app.registerActivityLifecycleCallbacks(cb);
        try {
            runUiShellCommandBestEffort("input keyevent KEYCODE_WAKEUP");
            runUiShellCommandBestEffort("wm dismiss-keyguard");
            runUiShellCommandBestEffort("appops set org.telegram.wgplus.module 10021 allow");
            runUiShellCommandBestEffort("am start -W --activity-clear-task -n org.telegram.wgplus.module/.ModuleLauncherActivity");
            assertTrue("ModuleLauncherActivity must reach onResume within 15s",
                    resumedLatch.await(15, TimeUnit.SECONDS));
            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                ModuleLauncherActivity act = resumedActivity.get();
                assertNotNull(act);
                assertFalse(act.isFinishing());
                assertNotNull(act.getWindow());
                assertNotNull(act.getWindow().getDecorView());
                act.finish();
            });
        } finally {
            app.unregisterActivityLifecycleCallbacks(cb);
        }
    }

    @Test(timeout = 30_000L)
    public void simulationXiaomiUnrootedOwnerYieldAndVoipContinuity() throws Exception {
        Context ctx = ApplicationProvider.getApplicationContext();
        String sourceApk = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
        NativeBridgeLoader.ensureLoaded(ctx, sourceApk);

        assertTrue("Unrooted companion owner must yield to foreground Telegram Web",
                WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                        "org.telegram.messenger.web", "org.telegram.wgplus.module", false));
        assertFalse("Daemon/root companion must keep hosting shared hub",
                WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                        "org.telegram.messenger.web", "org.telegram.wgplus.module", true));

        Uri providerUri = Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY);
        Bundle yieldBundle = ctx.getContentResolver().call(
                providerUri,
                KeepaliveStatusProvider.METHOD_REQUEST_YIELD_TUNNEL,
                null,
                null
        );
        assertNotNull("METHOD_REQUEST_YIELD_TUNNEL must return a Bundle", yieldBundle);
        assertTrue("Yield response Bundle must include yielded flag", yieldBundle.containsKey("yielded"));

        try {
            Wgbridge.setSocksAuth("wgtest", "yieldpass123");
            long ksPort = Wgbridge.startKillSwitchGuard();
            assertTrue("Kill switch mux port must bind before yield test", ksPort > 0L);

            assertFalse("Wrong password must be rejected on WGP1 YIELD",
                    Wgbridge.requestRemoteTunnelYield(ksPort, "wrongpass"));
            assertEquals("Failed YIELD must leave active mux intact", ksPort, Wgbridge.getKillSwitchPort());

            assertTrue("Authenticated WGP1 YIELD must succeed",
                    Wgbridge.requestRemoteTunnelYield(ksPort, "yieldpass123"));
            assertEquals("Authenticated YIELD must release mux port", 0L, Wgbridge.getKillSwitchPort());
        } finally {
            Wgbridge.stopKillSwitchGuard();
            Wgbridge.setSocksAuth("", "");
        }
    }

    @Test(timeout = 30_000L)
    public void simulationSamsungNineHourOfflineZombieTcpReset() throws Exception {
        Context ctx = ApplicationProvider.getApplicationContext();
        String sourceApk = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
        NativeBridgeLoader.ensureLoaded(ctx, sourceApk);

        JSONObject before = new JSONObject(Wgbridge.getUdpTelemetryJSON());
        long epochBefore = before.optLong("recoveryEpoch", 0L);

        long resetCount = Wgbridge.resetActiveProxyConnections("test_9h_sleep");
        assertTrue("Reset proxy count must be non-negative", resetCount >= 0L);

        JSONObject after = new JSONObject(Wgbridge.getUdpTelemetryJSON());
        long epochAfter = after.optLong("recoveryEpoch", 0L);
        assertTrue("Recovery epoch must increment after proxy reset", epochAfter >= epochBefore + 1L);
    }

    @Test(timeout = 30_000L)
    public void firstRunTelemetryConsentPersistenceAndLauncherRender() throws Exception {
        final Context ctx = ApplicationProvider.getApplicationContext();
        Application app = (Application) ctx;
        final CountDownLatch resumedLatch = new CountDownLatch(1);
        final AtomicReference<ModuleLauncherActivity> resumedActivity = new AtomicReference<>();
        Application.ActivityLifecycleCallbacks cb = new Application.ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity a, Bundle b) {}
            @Override public void onActivityStarted(Activity a) {}
            @Override public void onActivityResumed(Activity a) {
                if (a instanceof ModuleLauncherActivity) {
                    resumedActivity.set((ModuleLauncherActivity) a);
                    resumedLatch.countDown();
                }
            }
            @Override public void onActivityPaused(Activity a) {}
            @Override public void onActivityStopped(Activity a) {}
            @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
            @Override public void onActivityDestroyed(Activity a) {}
        };

        WireGuardManager.getPrefs(ctx).edit()
                .remove(WgTelemetryReporter.KEY_TELEMETRY_DECIDED)
                .remove(WgTelemetryReporter.KEY_TELEMETRY_OPT_IN)
                .commit();
        assertFalse(WgTelemetryReporter.isConsentDecided(ctx));
        assertFalse(WgTelemetryReporter.isOptedIn(ctx));

        app.registerActivityLifecycleCallbacks(cb);
        try {
            runUiShellCommandBestEffort("input keyevent KEYCODE_WAKEUP");
            runUiShellCommandBestEffort("wm dismiss-keyguard");
            runUiShellCommandBestEffort("am start -W --activity-clear-task -n org.telegram.wgplus.module/.ModuleLauncherActivity");
            assertTrue("ModuleLauncherActivity must resume cleanly with first-run consent modal",
                    resumedLatch.await(15, TimeUnit.SECONDS));

            InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
                ModuleLauncherActivity act = resumedActivity.get();
                assertNotNull(act);
                assertFalse(act.isFinishing());
                TelemetryConsentDialog.dismissActiveIfShowing();
                act.finish();
            });

            WgTelemetryReporter.setConsentDecision(ctx, true);
            assertTrue("Consent decided must persist", WgTelemetryReporter.isConsentDecided(ctx));
            assertTrue("Opt-in choice must persist", WgTelemetryReporter.isOptedIn(ctx));
        } finally {
            app.unregisterActivityLifecycleCallbacks(cb);
            try {
                InstrumentationRegistry.getInstrumentation().runOnMainSync(TelemetryConsentDialog::dismissActiveIfShowing);
            } catch (Throwable ignored) {
            }
            WgTelemetryReporter.setConsentDecision(ctx, false);
        }
    }
}
