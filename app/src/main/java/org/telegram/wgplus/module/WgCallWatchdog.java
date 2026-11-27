package org.telegram.wgplus.module;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import wgbridge.Wgbridge;

/**
 * Detects calls whose VoIP relays stay (almost) silent and triggers an automatic opt-in anomaly report,
 * so a failed call is reported without the user having to press "send".
 */
final class WgCallWatchdog {

    private static final long FIRST_CHECK_MS = 25_000L;
    private static final long SECOND_CHECK_MS = 55_000L;
    private static final long MIN_GAP_BETWEEN_ARMS_MS = 40_000L;
    private static final long LOW_TRAFFIC_PKTS = 60L;
    private static volatile long sLastArmMs = 0L;

    private WgCallWatchdog() {
    }

    static void arm(final Context ctx, final String moduleApkPath) {
        if (ctx == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - sLastArmMs < MIN_GAP_BETWEEN_ARMS_MS) {
            return;
        }
        sLastArmMs = now;
        final Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(FIRST_CHECK_MS);
                String first = evaluate(appCtx, moduleApkPath);
                if (first != null && first.startsWith("DEAD")) {
                    WgDiagnosticsLog.record("VOIP", "CALL_WATCHDOG", first);
                    WgTelemetryReporter.reportAnomalyAsync(appCtx, moduleApkPath, "VOIP_CALL_NO_MEDIA", first);
                    return;
                }
                Thread.sleep(SECOND_CHECK_MS - FIRST_CHECK_MS);
                String second = evaluate(appCtx, moduleApkPath);
                if (second != null) {
                    WgDiagnosticsLog.record("VOIP", "CALL_WATCHDOG", second);
                    WgTelemetryReporter.reportAnomalyAsync(appCtx, moduleApkPath, "VOIP_CALL_NO_MEDIA", second);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Throwable ignored) {
            }
        }, "wgplus-call-watchdog");
        t.setDaemon(true);
        t.start();
    }

    /** Returns null when media looks healthy, otherwise a short summary starting with DEAD or LOW. */
    private static String evaluate(Context ctx, String moduleApkPath) {
        String json = "";
        try {
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                json = Wgbridge.buildEngineDiagnosticsBundleJSON();
            } else {
                int port = WireGuardManager.getEffectiveProxyPort(ctx, moduleApkPath);
                if (port > 0) {
                    json = WireGuardManager.fetchRemoteEngineDiagnosticsBundle(ctx, moduleApkPath, port);
                }
            }
        } catch (Throwable ignored) {
        }
        if (json == null || !json.trim().startsWith("{")) {
            return null;
        }
        return evaluateDiagnosticsJson(json);
    }

    static String evaluateDiagnosticsJson(String json) {
        if (json == null || !json.trim().startsWith("{")) {
            return null;
        }
        try {
            JSONObject root = new JSONObject(json);
            JSONArray relays = root.optJSONArray("voipRelays");
            if (relays == null || relays.length() == 0) {
                return null;
            }
            long tx = 0L;
            long rx = 0L;
            long errs = 0L;
            long tcp = 0L;
            long oldest = 0L;
            long minIdle = Long.MAX_VALUE;
            long maxActiveSpan = 0L;
            int validCount = 0;
            for (int i = 0; i < relays.length(); i++) {
                JSONObject r = relays.optJSONObject(i);
                if (r == null) {
                    continue;
                }
                validCount++;
                tx += r.optLong("udpTxPkts");
                rx += r.optLong("udpRxPkts");
                errs += r.optLong("udpErrs");
                tcp += r.optLong("tcpConns");
                long ageSec = r.optLong("ageSec");
                long idleSec = r.optLong("idleSec");
                oldest = Math.max(oldest, ageSec);
                minIdle = Math.min(minIdle, idleSec);
                maxActiveSpan = Math.max(maxActiveSpan, Math.max(0L, ageSec - idleSec));
            }
            if (validCount == 0 || oldest < 20L) {
                return null;
            }
            String summary = " relays=" + validCount + " udpTx=" + tx + " udpRx=" + rx
                    + " errs=" + errs + " tcpConns=" + tcp + " oldestAgeSec=" + oldest + " minIdleSec=" + minIdle;
            if (tx > 0L && rx == 0L && (minIdle <= 15L || maxActiveSpan >= 10L)) {
                return "DEAD(no return traffic)" + summary;
            }
            if (tx == 0L && tcp == 0L && oldest <= 40L) {
                return "DEAD(no outbound packets reached relay)" + summary;
            }
            if (tx + rx < LOW_TRAFFIC_PKTS && oldest >= 50L && (minIdle <= 15L || maxActiveSpan >= 20L)) {
                return "LOW(call never carried media)" + summary;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
