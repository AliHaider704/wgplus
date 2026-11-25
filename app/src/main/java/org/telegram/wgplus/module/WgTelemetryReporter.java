package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Privacy-preserving automatic and manual diagnostic reporter backed by a write-only
 * Cloud Firestore endpoint (anonymous create only, zero public read, zero secrets in APK).
 */
public final class WgTelemetryReporter {

    private static final String TAG = "WGPlusTelemetry";
    public static final String FIRESTORE_PROJECT = "wgplus-qa";
    public static final String FIRESTORE_COLLECTION = "wgplus_diagnostics";
    public static final String FIRESTORE_HOST = "firestore.googleapis.com";
    public static final String FIRESTORE_PATH =
            "/v1/projects/" + FIRESTORE_PROJECT + "/databases/(default)/documents/" + FIRESTORE_COLLECTION;
    public static final String FIRESTORE_ENDPOINT_URL = "https://" + FIRESTORE_HOST + FIRESTORE_PATH;

    public static final String KEY_TELEMETRY_DECIDED = "wg_telemetry_consent_decided";
    public static final String KEY_TELEMETRY_OPT_IN = "wg_telemetry_opt_in";
    private static final String KEY_LAST_TRIGGER_MAP_JSON = "wg_telemetry_last_trigger_ms";
    private static final String KEY_DAILY_TIMESTAMPS_JSON = "wg_telemetry_daily_ts";
    private static final String KEY_PENDING_PAYLOAD_JSON = "wg_telemetry_pending_payload";

    private static final long AUTO_TRIGGER_COOLDOWN_MS = 6L * 60L * 60L * 1000L;
    private static final long DAILY_WINDOW_MS = 24L * 60L * 60L * 1000L;
    private static final int MAX_AUTO_REPORTS_PER_DAY = 4;
    private static final long MANUAL_COOLDOWN_MS = 30_000L;
    private static final int MAX_REPORT_CHARS = 14000;

    public static final int STATUS_SENT = 0;
    public static final int STATUS_RATE_LIMITED = 1;
    public static final int STATUS_FAILED = 2;

    public interface ManualSendCallback {
        void onComplete(int statusCode);
    }

    private static final ExecutorService TELEMETRY_EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "wgplus-telemetry");
        t.setDaemon(true);
        return t;
    });
    private static final AtomicBoolean sAutoSendInFlight = new AtomicBoolean(false);
    private static volatile long sLastManualSendElapsedMs = 0L;

    private WgTelemetryReporter() {
    }

    public static boolean isConsentDecided(Context context) {
        if (context == null) {
            return false;
        }
        return WireGuardManager.getPrefs(context).getBoolean(KEY_TELEMETRY_DECIDED, false);
    }

    public static boolean isOptedIn(Context context) {
        if (context == null) {
            return false;
        }
        return WireGuardManager.getPrefs(context).getBoolean(KEY_TELEMETRY_OPT_IN, false);
    }

    public static void setConsentDecision(Context context, boolean optIn) {
        if (context == null) {
            return;
        }
        SharedPreferences.Editor ed = WireGuardManager.getPrefs(context).edit()
                .putBoolean(KEY_TELEMETRY_DECIDED, true)
                .putBoolean(KEY_TELEMETRY_OPT_IN, optIn);
        if (!optIn) {
            ed.remove(KEY_PENDING_PAYLOAD_JSON);
        }
        ed.commit();
        WireGuardManager.scheduleSyncPushToProvider(context);
    }

    public static void setOptIn(Context context, boolean optIn) {
        setConsentDecision(context, optIn);
    }

    public static void reportAnomalyAsync(
            final Context context,
            final String moduleApkPath,
            final String triggerCode,
            final String detail
    ) {
        if (context == null || !isOptedIn(context)) {
            return;
        }
        final String safeTrigger = normalizeToken(triggerCode, "ANOMALY", 64);
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        if (!sAutoSendInFlight.compareAndSet(false, true)) {
            return;
        }
        TELEMETRY_EXEC.execute(() -> {
            try {
                if (!isOptedIn(appCtx) || !checkAndReserveAutoQuota(appCtx, safeTrigger)) {
                    return;
                }
                String report = WgDiagnosticsLog.buildMarkdownReport(appCtx, moduleApkPath);
                if (detail != null && !detail.trim().isEmpty()) {
                    report = report + "\nTrigger Detail: " + WgDiagnosticsLog.sanitize(detail) + "\n";
                }
                String jsonBody = buildFirestoreDocumentJson(appCtx, safeTrigger, report);
                if (!postJson(appCtx, moduleApkPath, jsonBody)) {
                    storePendingPayload(appCtx, jsonBody);
                }
            } catch (Throwable t) {
                Log.w(TAG, "Auto telemetry skipped: " + t.getMessage());
            } finally {
                sAutoSendInFlight.set(false);
            }
        });
    }

    public static void flushPendingIfOnlineAsync(final Context context, final String moduleApkPath) {
        if (context == null || !isOptedIn(context)) {
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        TELEMETRY_EXEC.execute(() -> {
            try {
                SharedPreferences sp = WireGuardManager.getPrefs(appCtx);
                String pending = sp.getString(KEY_PENDING_PAYLOAD_JSON, "");
                if (pending == null || pending.isEmpty()) {
                    return;
                }
                if (!sp.getBoolean(KEY_TELEMETRY_OPT_IN, false)) {
                    sp.edit().remove(KEY_PENDING_PAYLOAD_JSON).apply();
                    return;
                }
                if (postJson(appCtx, moduleApkPath, pending)) {
                    sp.edit().remove(KEY_PENDING_PAYLOAD_JSON).apply();
                }
            } catch (Throwable ignored) {
            }
        });
    }

    public static void sendManualReportAsync(
            final Context context,
            final String moduleApkPath,
            final String reportMarkdown,
            final ManualSendCallback callback
    ) {
        if (context == null) {
            if (callback != null) {
                callback.onComplete(STATUS_FAILED);
            }
            return;
        }
        long nowElapsed = SystemClock.elapsedRealtime();
        if (sLastManualSendElapsedMs > 0L && (nowElapsed - sLastManualSendElapsedMs) < MANUAL_COOLDOWN_MS) {
            if (callback != null) {
                callback.onComplete(STATUS_RATE_LIMITED);
            }
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        TELEMETRY_EXEC.execute(() -> {
            int result = STATUS_FAILED;
            try {
                String effective = (reportMarkdown != null && !reportMarkdown.trim().isEmpty())
                        ? reportMarkdown
                        : WgDiagnosticsLog.buildMarkdownReport(appCtx, moduleApkPath);
                String jsonBody = buildFirestoreDocumentJson(appCtx, "MANUAL_USER_REPORT", effective);
                if (postJson(appCtx, moduleApkPath, jsonBody)) {
                    sLastManualSendElapsedMs = SystemClock.elapsedRealtime();
                    result = STATUS_SENT;
                }
            } catch (Throwable t) {
                Log.w(TAG, "Manual telemetry failed: " + t.getMessage());
            }
            if (callback != null) {
                callback.onComplete(result);
            }
        });
    }

    public static String buildFirestoreDocumentJson(Context ctx, String triggerCode, String rawReportMarkdown) {
        String pkg = ctx != null ? ctx.getPackageName() : "unknown";
        String modVer = WgStrings.VERSION_LABEL;
        String hostVer = "";
        String tier = ContinuityBridgeManager.ContinuityTier.STANDARD_FGS.name();
        if (ctx != null) {
            try {
                PackageInfo modPi = ctx.getPackageManager().getPackageInfo("org.telegram.wgplus.module", 0);
                if (modPi != null && modPi.versionName != null) {
                    modVer = modPi.versionName;
                }
            } catch (Throwable ignored) {
            }
            try {
                PackageInfo hostPi = ctx.getPackageManager().getPackageInfo(pkg, 0);
                if (hostPi != null && hostPi.versionName != null) {
                    hostVer = hostPi.versionName;
                }
            } catch (Throwable ignored) {
            }
            try {
                tier = ContinuityBridgeManager.captureStatusSnapshot(ctx).tier.name();
            } catch (Throwable ignored) {
            }
        }
        String deviceModel = (Build.MANUFACTURER != null ? Build.MANUFACTURER : "unknown")
                + " " + (Build.MODEL != null ? Build.MODEL : "unknown");
        String androidRel = Build.VERSION.RELEASE != null ? Build.VERSION.RELEASE : "unknown";
        return buildFirestoreDocumentJsonFromParts(
                modVer,
                pkg,
                hostVer,
                deviceModel,
                androidRel,
                Build.VERSION.SDK_INT,
                triggerCode,
                tier,
                rawReportMarkdown
        );
    }

    public static String buildFirestoreDocumentJsonFromParts(
            String moduleVersion,
            String hostPackage,
            String hostVersion,
            String deviceModel,
            String androidRelease,
            int sdkInt,
            String triggerCode,
            String continuityTier,
            String rawReportMarkdown
    ) {
        try {
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            String nowIso = fmt.format(new Date());

            String safeModVer = normalizeToken(moduleVersion, WgStrings.VERSION_LABEL, 32);
            String safePkg = normalizeToken(hostPackage, "unknown", 128);
            String safeHostVer = normalizeToken(hostVersion, "unknown", 48);
            String safeModel = normalizeToken(deviceModel, "unknown", 96);
            String safeRelease = normalizeToken(androidRelease, "unknown", 32);
            String safeTrigger = normalizeToken(triggerCode, "ANOMALY", 64);
            String safeTier = normalizeToken(continuityTier, "STANDARD_FGS", 48);
            String sanitizedMd = WgDiagnosticsLog.sanitizeReportText(rawReportMarkdown, MAX_REPORT_CHARS);
            if (sanitizedMd.length() < 20) {
                sanitizedMd = "### WireGuard Plus Diagnostics\n- Trigger: " + safeTrigger;
            }
            String fingerprint = computeShortHash(safeModVer + "|" + safeModel + "|" + safePkg + "|" + safeTrigger);

            JSONObject fields = new JSONObject();
            fields.put("schemaVersion", intField(1));
            fields.put("createdAt", strField(nowIso));
            fields.put("moduleVersion", strField(safeModVer));
            fields.put("hostPackage", strField(safePkg));
            fields.put("hostVersion", strField(safeHostVer));
            fields.put("deviceModel", strField(safeModel));
            fields.put("androidRelease", strField(safeRelease));
            fields.put("sdkInt", intField(sdkInt));
            fields.put("triggerCode", strField(safeTrigger));
            fields.put("continuityTier", strField(safeTier));
            fields.put("fingerprint", strField(fingerprint));
            fields.put("reportMarkdown", strField(sanitizedMd));

            JSONObject doc = new JSONObject();
            doc.put("fields", fields);
            return doc.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    private static JSONObject strField(String val) throws Exception {
        JSONObject o = new JSONObject();
        o.put("stringValue", val != null ? val : "");
        return o;
    }

    private static JSONObject intField(long val) throws Exception {
        JSONObject o = new JSONObject();
        o.put("integerValue", String.valueOf(val));
        return o;
    }

    private static String normalizeToken(String raw, String fallback, int maxLen) {
        String clean = raw == null ? "" : WgDiagnosticsLog.sanitize(raw).replaceAll("[\\r\\n]+", " ").trim();
        if (clean.isEmpty()) {
            clean = fallback;
        }
        if (clean.length() > maxLen) {
            clean = clean.substring(0, maxLen);
        }
        return clean;
    }

    private static String computeShortHash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8 && i < dig.length; i++) {
                sb.append(String.format(Locale.US, "%02x", dig[i] & 0xff));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "00000000";
        }
    }

    private static synchronized boolean checkAndReserveAutoQuota(Context ctx, String triggerCode) {
        try {
            SharedPreferences sp = WireGuardManager.getPrefs(ctx);
            long now = System.currentTimeMillis();

            JSONObject trigMap;
            String rawMap = sp.getString(KEY_LAST_TRIGGER_MAP_JSON, "{}");
            try {
                trigMap = new JSONObject(rawMap);
            } catch (Throwable ignored) {
                trigMap = new JSONObject();
            }
            long lastSame = trigMap.optLong(triggerCode, 0L);
            if (lastSame > 0L && (now - lastSame) < AUTO_TRIGGER_COOLDOWN_MS) {
                return false;
            }

            JSONArray arr;
            String rawDaily = sp.getString(KEY_DAILY_TIMESTAMPS_JSON, "[]");
            try {
                arr = new JSONArray(rawDaily);
            } catch (Throwable ignored) {
                arr = new JSONArray();
            }
            JSONArray pruned = new JSONArray();
            for (int i = 0; i < arr.length(); i++) {
                long ts = arr.optLong(i, 0L);
                if (ts > 0L && (now - ts) < DAILY_WINDOW_MS) {
                    pruned.put(ts);
                }
            }
            if (pruned.length() >= MAX_AUTO_REPORTS_PER_DAY) {
                return false;
            }

            trigMap.put(triggerCode, now);
            pruned.put(now);
            sp.edit()
                    .putString(KEY_LAST_TRIGGER_MAP_JSON, trigMap.toString())
                    .putString(KEY_DAILY_TIMESTAMPS_JSON, pruned.toString())
                    .apply();
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void storePendingPayload(Context ctx, String jsonBody) {
        if (ctx == null || jsonBody == null || jsonBody.isEmpty()) {
            return;
        }
        try {
            WireGuardManager.getPrefs(ctx).edit().putString(KEY_PENDING_PAYLOAD_JSON, jsonBody).apply();
        } catch (Throwable ignored) {
        }
    }

    private static boolean postJson(Context ctx, String moduleApkPath, String jsonBody) {
        if (jsonBody == null || jsonBody.isEmpty()) {
            return false;
        }
        byte[] payload = jsonBody.getBytes(StandardCharsets.UTF_8);
        int activePort = 0;
        try {
            if (WireGuardManager.isTunnelRunning(ctx, moduleApkPath)) {
                activePort = WireGuardManager.getActivePort(ctx, moduleApkPath);
            }
        } catch (Throwable ignored) {
        }

        if (activePort > 0) {
            String user = WireGuardManager.getActiveSocksUser(ctx);
            String pass = WireGuardManager.getActiveSocksPass(ctx);
            if (postHttpsThroughSocks5(activePort, user, pass, payload)) {
                return true;
            }
        }

        // Strict Kill Switch compliance: never bypass directly to ISP when Kill Switch is armed while disconnected
        if (WireGuardManager.isKillSwitchEnabled(ctx)) {
            return false;
        }
        return postHttpsDirect(payload);
    }

    private static boolean postHttpsThroughSocks5(int port, String user, String pass, byte[] payload) {
        try (Socket sock = WireGuardManager.openSocks5HostSocket(port, user, pass, FIRESTORE_HOST, 443, 6000)) {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket ssl = (SSLSocket) factory.createSocket(sock, FIRESTORE_HOST, 443, true)) {
                ssl.setSoTimeout(7000);
                ssl.startHandshake();
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(FIRESTORE_HOST, ssl.getSession())) {
                    throw new SSLHandshakeException("TLS hostname mismatch for Firestore");
                }
                OutputStream os = ssl.getOutputStream();
                String headers = "POST " + FIRESTORE_PATH + " HTTP/1.1\r\n"
                        + "Host: " + FIRESTORE_HOST + "\r\n"
                        + "User-Agent: WireGuardPlus-Android/" + WgStrings.VERSION_LABEL + "\r\n"
                        + "Content-Type: application/json; charset=utf-8\r\n"
                        + "Content-Length: " + payload.length + "\r\n"
                        + "Connection: close\r\n\r\n";
                os.write(headers.getBytes(StandardCharsets.US_ASCII));
                os.write(payload);
                os.flush();

                BufferedReader br = new BufferedReader(new InputStreamReader(ssl.getInputStream(), StandardCharsets.US_ASCII));
                String statusLine = br.readLine();
                if (statusLine != null) {
                    String[] parts = statusLine.split("\\s+", 3);
                    if (parts.length >= 2) {
                        int code = Integer.parseInt(parts[1].trim());
                        return code >= 200 && code < 300;
                    }
                }
            }
        } catch (Throwable t) {
            Log.d(TAG, "SOCKS5 Firestore post failed: " + t.getMessage());
        }
        return false;
    }

    private static boolean postHttpsDirect(byte[] payload) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(FIRESTORE_ENDPOINT_URL).openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(6000);
            conn.setReadTimeout(7000);
            conn.setDoOutput(true);
            conn.setFixedLengthStreamingMode(payload.length);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("User-Agent", "WireGuardPlus-Android/" + WgStrings.VERSION_LABEL);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload);
                os.flush();
            }
            int code = conn.getResponseCode();
            try (InputStream ignored = (code >= 400 ? conn.getErrorStream() : conn.getInputStream())) {
                if (ignored != null) {
                    byte[] tmp = new byte[256];
                    // Drain briefly for clean keepalive close
                    ignored.read(tmp);
                }
            } catch (Throwable ignored) {
            }
            return code >= 200 && code < 300;
        } catch (Throwable t) {
            Log.d(TAG, "Direct Firestore post failed: " + t.getMessage());
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
}
