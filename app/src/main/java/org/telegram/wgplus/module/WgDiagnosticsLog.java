package org.telegram.wgplus.module;

import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import wgbridge.Wgbridge;

/**
 * Thread-safe bounded ring buffers, exception/crash capture, and privacy-safe diagnostic
 * report builder spanning Android power/network/hook/Telegram state and Go engine telemetry.
 */
public final class WgDiagnosticsLog {

    private static final int MAX_EVENTS = 160;
    private static final int MAX_EXCEPTIONS = 20;
    private static final String KEY_LAST_UNCAUGHT_CRASH = "wg_last_uncaught_crash";
    private static final long PROCESS_START_ELAPSED_MS = safeElapsedRealtime();

    private static final List<String> EVENTS = new ArrayList<>(MAX_EVENTS);
    private static final List<String> EXCEPTIONS = new ArrayList<>(MAX_EXCEPTIONS);
    private static final AtomicBoolean CRASH_HANDLER_INSTALLED = new AtomicBoolean(false);

    private static final Pattern KV_SECRET_RE = Pattern.compile(
            "(?i)\\b((?:socks_?|proxy_?|shared_?)?(?:private_?key|preshared_?key|pass(?:word|phrase)?|secret|auth|token))\\s*[:=]\\s*([^\\s,;]+)"
    );
    private static final Pattern B64_KEY_RE = Pattern.compile("(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{42,44}=(?![A-Za-z0-9+/=])");
    private static final Pattern HEX_KEY_RE = Pattern.compile("\\b[0-9a-fA-F]{64}\\b");
    private static final Pattern ENDPOINT_RE = Pattern.compile(
            "(?i)(endpoint\\s*[:=]\\s*)([^\\s,;]+)"
    );
    private static final Pattern IP_PORT_RE = Pattern.compile(
            "\\b(?!127\\.)(?:\\d{1,3}\\.){3}\\d{1,3}:\\d{1,5}\\b"
    );

    private WgDiagnosticsLog() {
    }

    private static long safeElapsedRealtime() {
        try {
            return SystemClock.elapsedRealtime();
        } catch (Throwable ignored) {
            return 0L;
        }
    }

    private static String formatUtcNow() {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        return fmt.format(new Date());
    }

    private static String sanitizeCore(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        String s = raw.trim();
        s = KV_SECRET_RE.matcher(s).replaceAll("$1=[REDACTED]");
        s = ENDPOINT_RE.matcher(s).replaceAll("$1[ENDPOINT_REDACTED]");
        s = IP_PORT_RE.matcher(s).replaceAll("[IP_PORT_REDACTED]");
        s = B64_KEY_RE.matcher(s).replaceAll("[KEY_REDACTED]");
        s = HEX_KEY_RE.matcher(s).replaceAll("[HEX_KEY_REDACTED]");
        return s;
    }

    public static String sanitize(String raw) {
        String s = sanitizeCore(raw);
        if (s.length() > 360) {
            return s.substring(0, 360) + "...";
        }
        return s;
    }

    public static String sanitizeReportText(String raw, int maxUtf8Bytes) {
        String s = sanitizeCore(raw);
        if (s.isEmpty()) {
            return "";
        }
        int limit = Math.max(128, maxUtf8Bytes);
        byte[] all = s.getBytes(StandardCharsets.UTF_8);
        if (all.length <= limit) {
            return s;
        }
        String marker = "\n...[older events omitted]...\n";
        int markerBytes = marker.getBytes(StandardCharsets.UTF_8).length;
        if (limit <= markerBytes + 64) {
            return utf8Prefix(s, limit);
        }
        int headBudget = Math.min(9000, Math.max(64, (limit - markerBytes) * 58 / 100));
        int tailBudget = Math.max(64, limit - headBudget - markerBytes - 8);
        String head = utf8Prefix(s, headBudget);
        String tail = utf8Suffix(s, tailBudget);
        String combined = head + marker + tail;
        while (combined.getBytes(StandardCharsets.UTF_8).length > limit && tail.length() > 16) {
            tail = tail.substring(Math.min(tail.length() - 1, 64));
            combined = head + marker + tail;
        }
        return combined;
    }

    private static String utf8Prefix(String s, int maxBytes) {
        int bytes = 0;
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            int charCount = Character.charCount(cp);
            int cpBytes = s.substring(i, i + charCount).getBytes(StandardCharsets.UTF_8).length;
            if (bytes + cpBytes > maxBytes) {
                break;
            }
            bytes += cpBytes;
            i += charCount;
        }
        return s.substring(0, i);
    }

    private static String utf8Suffix(String s, int maxBytes) {
        int bytes = 0;
        int i = s.length();
        while (i > 0) {
            int cp = s.codePointBefore(i);
            int charCount = Character.charCount(cp);
            int cpBytes = s.substring(i - charCount, i).getBytes(StandardCharsets.UTF_8).length;
            if (bytes + cpBytes > maxBytes) {
                break;
            }
            bytes += cpBytes;
            i -= charCount;
        }
        return s.substring(i);
    }

    public static void record(String category, String code, String message) {
        String cat = category == null ? "APP" : category.trim();
        String cd = code == null ? "INFO" : code.trim();
        String msg = sanitize(message);
        String line = "[" + formatUtcNow() + "] [" + cat + "/" + cd + "] " + msg;
        synchronized (EVENTS) {
            if (EVENTS.size() >= MAX_EVENTS) {
                EVENTS.remove(0);
            }
            EVENTS.add(line);
        }
    }

    public static void recordException(String category, String code, Throwable t) {
        if (t == null) {
            return;
        }
        String cat = category == null ? "ERR" : category.trim();
        String cd = code == null ? "EXCEPTION" : code.trim();
        String formatted = formatThrowableSummary(t);
        synchronized (EXCEPTIONS) {
            if (EXCEPTIONS.size() >= MAX_EXCEPTIONS) {
                EXCEPTIONS.remove(0);
            }
            EXCEPTIONS.add("[" + formatUtcNow() + "] [" + cat + "/" + cd + "] " + formatted);
        }
        record(cat, cd, t.getClass().getSimpleName() + ": " + sanitize(t.getMessage()));
    }

    private static String formatThrowableSummary(Throwable t) {
        StringBuilder sb = new StringBuilder();
        sb.append(t.getClass().getName());
        if (t.getMessage() != null && !t.getMessage().isEmpty()) {
            sb.append(": ").append(sanitize(t.getMessage()));
        }
        int added = 0;
        for (StackTraceElement el : t.getStackTrace()) {
            String cn = el.getClassName();
            if (added < 2 || cn.startsWith("org.telegram.wgplus") || cn.startsWith("wgbridge")) {
                sb.append(" @ ").append(cn).append(".").append(el.getMethodName())
                        .append(":").append(el.getLineNumber());
                added++;
                if (added >= 5) {
                    break;
                }
            }
        }
        return sanitizeCore(sb.toString());
    }

    public static void installCrashRecorder(final Context context, final String moduleApkPath) {
        if (context == null) {
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        if (!CRASH_HANDLER_INSTALLED.compareAndSet(false, true)) {
            return;
        }
        try {
            SharedPreferences sp = WireGuardManager.getPrefs(appCtx);
            String pendingCrash = sp.getString(KEY_LAST_UNCAUGHT_CRASH, "");
            if (pendingCrash != null && !pendingCrash.isEmpty()) {
                sp.edit().remove(KEY_LAST_UNCAUGHT_CRASH).apply();
                synchronized (EXCEPTIONS) {
                    EXCEPTIONS.add(pendingCrash);
                }
                record("CRASH", "PREV_UNCAUGHT", pendingCrash);
                WgTelemetryReporter.reportAnomalyAsync(appCtx, moduleApkPath, "UNCAUGHT_MODULE_CRASH", pendingCrash);
            }
        } catch (Throwable ignored) {
        }

        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            try {
                if (mentionsModuleOrBridge(throwable)) {
                    String summary = "[" + formatUtcNow() + "] [UNCAUGHT/" + thread.getName() + "] "
                            + sanitizeReportText(formatThrowableSummary(throwable), 2400);
                    WireGuardManager.getPrefs(appCtx).edit()
                            .putString(KEY_LAST_UNCAUGHT_CRASH, summary)
                            .commit();
                }
            } catch (Throwable ignored) {
            }
            if (prev != null) {
                prev.uncaughtException(thread, throwable);
            }
        });
    }

    private static boolean mentionsModuleOrBridge(Throwable t) {
        int depth = 0;
        Throwable cur = t;
        while (cur != null && depth < 5) {
            String msg = cur.getMessage();
            if (msg != null && (msg.contains("wgplus") || msg.contains("wgbridge") || msg.contains("libgojni"))) {
                return true;
            }
            for (StackTraceElement el : cur.getStackTrace()) {
                String cn = el.getClassName();
                if (cn.startsWith("org.telegram.wgplus") || cn.startsWith("wgbridge.")) {
                    return true;
                }
            }
            cur = cur.getCause();
            depth++;
        }
        return false;
    }

    public static void clear() {
        synchronized (EVENTS) {
            EVENTS.clear();
        }
        synchronized (EXCEPTIONS) {
            EXCEPTIONS.clear();
        }
        try {
            if (NativeBridgeLoader.isLoaded()) {
                Wgbridge.clearDiagnostics();
            }
        } catch (Throwable ignored) {
        }
    }

    public static List<String> snapshotEvents() {
        synchronized (EVENTS) {
            return new ArrayList<>(EVENTS);
        }
    }

    public static List<String> snapshotExceptions() {
        synchronized (EXCEPTIONS) {
            return new ArrayList<>(EXCEPTIONS);
        }
    }

    public static String buildMarkdownReport(Context context, String moduleApkPath) {
        StringBuilder sb = new StringBuilder();
        sb.append("### WireGuard Plus Diagnostics (Android)\n");

        String pkg = context != null ? context.getPackageName() : "unknown";
        boolean inModule = "org.telegram.wgplus.module".equals(pkg);
        String moduleVer = WgStrings.VERSION_LABEL;
        String hostVer = "";
        int targetSdk = 0;
        if (context != null) {
            try {
                PackageInfo modPi = context.getPackageManager().getPackageInfo("org.telegram.wgplus.module", 0);
                if (modPi != null && modPi.versionName != null) {
                    moduleVer = modPi.versionName;
                }
            } catch (Throwable ignored) {
            }
            try {
                PackageInfo hostPi = context.getPackageManager().getPackageInfo(pkg, 0);
                if (hostPi != null) {
                    hostVer = hostPi.versionName != null ? hostPi.versionName : "";
                    if (hostPi.applicationInfo != null) {
                        targetSdk = hostPi.applicationInfo.targetSdkVersion;
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        long uptimeSec = Math.max(0L, (safeElapsedRealtime() - PROCESS_START_ELAPSED_MS) / 1000L);
        String abi = (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) ? Build.SUPPORTED_ABIS[0] : Build.CPU_ABI;
        String romExtra = buildRomTag();

        sb.append("- **Module Version**: `v").append(moduleVer).append("`\n");
        sb.append("- **Device / OS**: `").append(Build.MANUFACTURER).append(" ").append(Build.MODEL)
                .append("` (Android ").append(Build.VERSION.RELEASE)
                .append(" / API ").append(Build.VERSION.SDK_INT)
                .append(", abi=").append(abi);
        if (!romExtra.isEmpty()) {
            sb.append(", ").append(romExtra);
        }
        sb.append(")\n");
        sb.append("- **Process Context**: `").append(pkg).append("` (inModule=").append(inModule)
                .append(", mode=").append(WireGuardManager.detectInjectionMode(context))
                .append(", hostVer=").append(hostVer.isEmpty() ? "?" : hostVer)
                .append(", targetSdk=").append(targetSdk)
                .append(", uptimeSec=").append(uptimeSec).append(")\n");

        if (context != null) {
            appendPowerAndNetworkSections(sb, context);

            boolean localRunning = NativeBridgeLoader.isLoaded() && safeBridgeIsRunning();
            boolean running = WireGuardManager.isTunnelRunning(context, moduleApkPath);
            int port = WireGuardManager.getEffectiveProxyPort(context, moduleApkPath);
            boolean ks = WireGuardManager.isKillSwitchEnabled(context);
            boolean auto = WireGuardManager.isAutoConnectEnabled(context);
            boolean calls = WireGuardManager.isRouteCallsEnabled(context);
            boolean doh = WireGuardManager.isDohEnabled(context);
            WireGuardManager.TunnelConfig cfg = WireGuardManager.loadConfig(context);

            sb.append("- **Tunnel Policy**: running=`").append(running)
                    .append("`, activePort=`").append(port)
                    .append("`, killSwitch=`").append(ks)
                    .append("`, autoConnect=`").append(auto)
                    .append("`, routeCalls=`").append(calls)
                    .append("`, doH=`").append(doh).append("`\n");
            sb.append("- **Profile Policy**: mtu=`").append(cfg.mtu)
                    .append("`, keepAlive=`").append(cfg.keepAlive)
                    .append("`, awg=`").append(cfg.hasAwgConfigured())
                    .append("` (").append(describeAwgShape(cfg)).append(")")
                    .append(", warp=`").append(cfg.isWarp)
                    .append("`, ep=").append(describeEndpointShape(cfg.endpoint)).append("\n");
            sb.append("- **Manager State**: `").append(WireGuardManager.getDiagnosticsInternalStateSummary(context)).append("`\n");

            Bundle sharedInfo = WireGuardManager.fetchSharedHubInfoBundle(context);
            if (sharedInfo != null) {
                sb.append("- **Shared Hub**: owner=`").append(sharedInfo.getString("owner", "?"))
                        .append("`, port=`").append(sharedInfo.getInt("port", -1))
                        .append("`, hsHealthy=`").append(sharedInfo.getBoolean("hsHealthy", false))
                        .append("`, daemonOrRoot=`").append(sharedInfo.getBoolean("daemonOrRootActive", false))
                        .append("`, usingShared=`").append(WireGuardManager.isUsingSharedHub()).append("`\n");
            }

            try {
                ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(context);
                sb.append("- **Continuity**: tier=`").append(snap.tier.name())
                        .append("`, stealth=`").append(snap.stealthProtected)
                        .append("`, daemon=`").append(snap.daemonActive)
                        .append("`, root=`").append(snap.rootActive)
                        .append("`, selfPriv=`").append(snap.selfPrivileged)
                        .append("`, listener=`").append(snap.listenerConnected).append("`\n");
            } catch (Throwable ignored) {
            }

            appendClientsAndHooksSummary(sb, context, inModule);

            if (!inModule) {
                sb.append("- **Telegram Proxy Health**: `")
                        .append(WireGuardManager.inspectTelegramProxyHealthSummary(context))
                        .append("`\n");
            }

            String engineBundleJson = "";
            if (localRunning) {
                try {
                    engineBundleJson = Wgbridge.buildEngineDiagnosticsBundleJSON();
                } catch (Throwable ignored) {
                }
            } else if (port > 0) {
                engineBundleJson = WireGuardManager.fetchRemoteEngineDiagnosticsBundle(context, moduleApkPath, port);
            }

            if (engineBundleJson != null && !engineBundleJson.isEmpty() && engineBundleJson.trim().startsWith("{")) {
                appendEngineBundleMarkdown(sb, engineBundleJson, localRunning ? "local" : "remote_shared_hub");
            } else {
                WireGuardManager.TunnelStats st = WireGuardManager.getLiveStats(context, moduleApkPath);
                long hsAgeSec = st.lastHandshakeSec > 0L
                        ? Math.max(0L, (System.currentTimeMillis() / 1000L) - st.lastHandshakeSec)
                        : -1L;
                sb.append("- **Live Counters**: rxBytes=`").append(st.rxBytes)
                        .append("`, txBytes=`").append(st.txBytes)
                        .append("`, hsAgeSec=`").append(hsAgeSec)
                        .append("` (nativeLoaded=").append(NativeBridgeLoader.isLoaded())
                        .append(", localEngine=").append(localRunning).append(")\n");
                appendLocalBridgeFallbackSections(sb);
            }
        } else {
            appendLocalBridgeFallbackSections(sb);
        }

        List<String> exList = snapshotExceptions();
        if (!exList.isEmpty()) {
            sb.append("\n#### Recent Module Exceptions\n```text\n");
            for (String line : exList) {
                sb.append(line).append("\n");
            }
            sb.append("```\n");
        }

        List<String> evs = snapshotEvents();
        sb.append("\n#### Android Diagnostic Log\n```text\n");
        if (evs.isEmpty()) {
            sb.append("(none)\n");
        } else {
            for (String line : evs) {
                sb.append(line).append("\n");
            }
        }
        sb.append("```\n");
        return sb.toString();
    }

    private static boolean safeBridgeIsRunning() {
        try {
            return Wgbridge.isRunning();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String buildRomTag() {
        StringBuilder sb = new StringBuilder();
        String miui = getSysProp("ro.miui.ui.version.name");
        if (!miui.isEmpty()) {
            sb.append("miui=").append(miui);
        }
        String hyper = getSysProp("ro.mi.os.version.name");
        if (!hyper.isEmpty()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append("hyperOS=").append(hyper);
        }
        String oneUi = getSysProp("ro.build.version.oneui");
        if (!oneUi.isEmpty()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append("oneUI=").append(oneUi);
        }
        return sb.toString();
    }

    private static String getSysProp(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Object v = sp.getMethod("get", String.class, String.class).invoke(null, key, "");
            return v instanceof String ? ((String) v).trim() : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String describeAwgShape(WireGuardManager.TunnelConfig cfg) {
        if (cfg == null) {
            return "none";
        }
        int sigCount = 0;
        if (!cfg.i1.trim().isEmpty()) sigCount++;
        if (!cfg.i2.trim().isEmpty()) sigCount++;
        if (!cfg.i3.trim().isEmpty()) sigCount++;
        if (!cfg.i4.trim().isEmpty()) sigCount++;
        if (!cfg.i5.trim().isEmpty()) sigCount++;
        return "jc=" + cfg.jc + ",j=" + cfg.jmin + "-" + cfg.jmax
                + ",s=" + cfg.s1 + "/" + cfg.s2 + "/" + cfg.s3 + "/" + cfg.s4
                + ",cps=" + sigCount + ",rsv=" + (!cfg.reserved.trim().isEmpty());
    }

    private static String describeEndpointShape(String rawEp) {
        if (rawEp == null || rawEp.trim().isEmpty()) {
            return "unset";
        }
        String ep = rawEp.trim();
        int port = 0;
        String host = ep;
        int colon = ep.lastIndexOf(':');
        if (colon > 0 && colon < ep.length() - 1) {
            host = ep.substring(0, colon);
            try {
                port = Integer.parseInt(ep.substring(colon + 1));
            } catch (NumberFormatException ignored) {
            }
        }
        String kind = host.contains(":") ? "ipv6" : (host.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$") ? "ipv4" : "domain");
        return kind + ":" + port;
    }

    private static void appendPowerAndNetworkSections(StringBuilder sb, Context ctx) {
        try {
            PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            boolean ignoreBatt = false;
            boolean dozeIdle = false;
            boolean powerSave = false;
            if (pm != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    ignoreBatt = pm.isIgnoringBatteryOptimizations(ctx.getPackageName());
                    dozeIdle = pm.isDeviceIdleMode();
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    powerSave = pm.isPowerSaveMode();
                }
            }
            String bucket = "n/a";
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    UsageStatsManager usm = (UsageStatsManager) ctx.getSystemService(Context.USAGE_STATS_SERVICE);
                    if (usm != null) {
                        int b = usm.getAppStandbyBucket();
                        bucket = standbyBucketLabel(b);
                    }
                } catch (Throwable ignored) {
                }
            }
            String bgData = "n/a";
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                try {
                    int s = cm.getRestrictBackgroundStatus();
                    bgData = s == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED ? "ENABLED(restricted)"
                            : (s == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED ? "WHITELISTED" : "DISABLED");
                } catch (Throwable ignored) {
                }
            }
            sb.append("- **Power Policy**: battOptIgnored=`").append(ignoreBatt)
                    .append("`, standbyBucket=`").append(bucket)
                    .append("`, dozeIdle=`").append(dozeIdle)
                    .append("`, powerSave=`").append(powerSave)
                    .append("`, dataSaver=`").append(bgData).append("`\n");

            if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = cm.getActiveNetwork();
                if (active == null) {
                    sb.append("- **OS Network**: `OFFLINE (no active default network)`\n");
                } else {
                    NetworkCapabilities nc = cm.getNetworkCapabilities(active);
                    LinkProperties lp = cm.getLinkProperties(active);
                    StringBuilder trans = new StringBuilder();
                    boolean internet = false;
                    boolean validated = false;
                    boolean notMetered = false;
                    boolean captive = false;
                    boolean otherVpn = false;
                    if (nc != null) {
                        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) trans.append("WIFI+");
                        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) trans.append("CELLULAR+");
                        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) trans.append("ETHERNET+");
                        otherVpn = nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                        if (otherVpn) trans.append("VPN+");
                        internet = nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
                        validated = nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                        notMetered = nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
                        captive = nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL);
                    }
                    String tStr = trans.length() > 0 ? trans.substring(0, trans.length() - 1) : "UNKNOWN";
                    String ifName = lp != null && lp.getInterfaceName() != null ? lp.getInterfaceName() : "?";
                    boolean hasV4 = false;
                    boolean hasV6 = false;
                    int dnsCnt = lp != null && lp.getDnsServers() != null ? lp.getDnsServers().size() : 0;
                    int linkMtu = (lp != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) ? lp.getMtu() : 0;
                    if (lp != null && lp.getLinkAddresses() != null) {
                        for (LinkAddress la : lp.getLinkAddresses()) {
                            if (la.getAddress() instanceof java.net.Inet4Address) hasV4 = true;
                            if (la.getAddress() instanceof java.net.Inet6Address && !la.getAddress().isLinkLocalAddress()) hasV6 = true;
                        }
                    }
                    sb.append("- **OS Network**: `").append(tStr)
                            .append("` (iface=").append(ifName)
                            .append(", internet=").append(internet)
                            .append(", validated=").append(validated)
                            .append(", notMetered=").append(notMetered)
                            .append(", captive=").append(captive)
                            .append(", otherVpn=").append(otherVpn)
                            .append(", ipv4=").append(hasV4)
                            .append(", ipv6=").append(hasV6)
                            .append(", dns=").append(dnsCnt)
                            .append(", linkMtu=").append(linkMtu).append(")\n");
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static String standbyBucketLabel(int b) {
        if (b <= 10) return "ACTIVE(" + b + ")";
        if (b <= 20) return "WORKING_SET(" + b + ")";
        if (b <= 30) return "FREQUENT(" + b + ")";
        if (b <= 40) return "RARE(" + b + ")";
        if (b <= 45) return "RESTRICTED(" + b + ")";
        return String.valueOf(b);
    }

    static String formatInstancesMatrixMarkdown(String instancesJson) {
        if (instancesJson == null || instancesJson.trim().isEmpty() || "[]".equals(instancesJson.trim())) {
            return "";
        }
        try {
            JSONArray arr = new JSONArray(instancesJson);
            if (arr.length() == 0) {
                return "";
            }
            StringBuilder out = new StringBuilder("\n#### Per-App Telegram Instance Matrix\n");
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o == null) continue;
                String pkg = sanitize(o.optString("pkg", "?"));
                String ver = sanitize(o.optString("ver", "?"));
                String mode = sanitize(o.optString("mode", "?"));
                String role = sanitize(o.optString("role", "?"));
                boolean running = o.optBoolean("running", false);
                int port = o.optInt("port", -1);
                long ageSec = o.optLong("ageSec", -1L);
                String tgState = sanitize(o.optString("tgState", ""));
                String lastEv = sanitize(o.optString("lastEvent", ""));
                out.append("- `").append(pkg).append("` | ver=`").append(ver)
                        .append("` | mode=`").append(mode)
                        .append("` | role=`").append(role)
                        .append("` | up=`").append(running)
                        .append("` | port=`").append(port)
                        .append("` | age=`").append(ageSec).append("s`");
                if (!tgState.isEmpty()) {
                    out.append(" | tg=`").append(tgState).append("`");
                }
                if (!lastEv.isEmpty()) {
                    out.append(" | ev=`").append(lastEv).append("`");
                }
                out.append("\n");
            }
            return out.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static void appendClientsAndHooksSummary(StringBuilder sb, Context ctx, boolean inModule) {
        try {
            List<String> installed = ContinuityBridgeManager.getInstalledTargetPackages(ctx);
            sb.append("- **Installed Clients**: `").append(installed.isEmpty() ? "none" : String.join(", ", installed)).append("`\n");
            String instancesJson = "";
            if (!inModule) {
                Bundle hook = ctx.getContentResolver().call(
                        Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                        KeepaliveStatusProvider.METHOD_QUERY_HOOK_STATUS,
                        null,
                        null
                );
                if (hook != null) {
                    String lastPkg = hook.getString(KeepaliveStatusProvider.RESULT_HOOK_PKG, "");
                    long lastMs = hook.getLong(KeepaliveStatusProvider.RESULT_HOOK_LAST_MS, 0L);
                    long ageSec = lastMs > 0L ? Math.max(0L, (System.currentTimeMillis() - lastMs) / 1000L) : -1L;
                    sb.append("- **Hook Telemetry**: lastPkg=`").append(lastPkg.isEmpty() ? "none" : lastPkg)
                            .append("`, lastSeenAgeSec=`").append(ageSec).append("`\n");
                    instancesJson = hook.getString(KeepaliveStatusProvider.RESULT_INSTANCES_JSON, "");
                }
            } else {
                Bundle hook = KeepaliveStatusProvider.readHookTelemetryBundle(ctx);
                if (hook != null) {
                    instancesJson = hook.getString(KeepaliveStatusProvider.RESULT_INSTANCES_JSON, "");
                }
                Bundle auto = ctx.getContentResolver().call(
                        Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                        KeepaliveStatusProvider.METHOD_AUTOMATION_STATUS,
                        null,
                        null
                );
                if (auto != null) {
                    String raw = auto.getString(KeepaliveStatusProvider.EXTRA_JSON, "");
                    if (!raw.isEmpty()) {
                        JSONObject j = new JSONObject(raw);
                        JSONArray hp = j.optJSONArray("hookPackages");
                        sb.append("- **Hooked Packages**: `").append(hp != null ? hp.toString() : "[]").append("`\n");
                        if (instancesJson.isEmpty()) {
                            JSONArray inst = j.optJSONArray("hookInstances");
                            if (inst != null) {
                                instancesJson = inst.toString();
                            }
                        }
                    }
                }
            }
            String matrixMd = formatInstancesMatrixMarkdown(instancesJson);
            if (!matrixMd.isEmpty()) {
                sb.append(matrixMd);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void appendEngineBundleMarkdown(StringBuilder sb, String bundleJson, String sourceTag) {
        try {
            JSONObject root = new JSONObject(bundleJson);
            JSONObject d = root.optJSONObject("detailed");
            if (d != null) {
                sb.append("- **Live Counters (").append(sourceTag).append(")**: rxBytes=`").append(d.optLong("rxBytes", 0L))
                        .append("`, txBytes=`").append(d.optLong("txBytes", 0L))
                        .append("`, rxBps=`").append(d.optLong("rxBps", 0L))
                        .append("`, txBps=`").append(d.optLong("txBps", 0L))
                        .append("`, hsAgeSec=`").append(d.optLong("hsAgeSec", -1L))
                        .append("`, activeMtu=`").append(d.optInt("activeMtu", 0))
                        .append("`, epPort=`").append(d.optInt("endpointPort", 0))
                        .append("`, uptimeSec=`").append(d.optLong("uptimeSec", 0L))
                        .append("`, socksAuthReject=`").append(d.optLong("socksAuthRejectCount", 0L)).append("`\n");
                JSONArray clients = d.optJSONArray("clients");
                if (clients != null && clients.length() > 0) {
                    sb.append("- **Mux Clients**: `").append(clients.toString()).append("`\n");
                }
            }
            JSONObject udp = root.optJSONObject("udpTelemetry");
            if (udp != null) {
                sb.append("\n#### UDP & Watchdog Telemetry\n```json\n").append(udp.toString()).append("\n```\n");
            }
            JSONArray relays = root.optJSONArray("voipRelays");
            if (relays != null && relays.length() > 0) {
                sb.append("\n#### Active VoIP Relays\n```text\n");
                for (int i = 0; i < relays.length(); i++) {
                    JSONObject r = relays.optJSONObject(i);
                    if (r != null) {
                        sb.append(r.optString("localAddr")).append(" -> :").append(r.optInt("targetPort"))
                                .append(" sess=").append(r.optInt("udpSessions"))
                                .append(" txPkts=").append(r.optLong("udpTxPkts"))
                                .append(" rxPkts=").append(r.optLong("udpRxPkts"))
                                .append(" errs=").append(r.optLong("udpErrs"))
                                .append(" tcp=").append(r.optLong("tcpConns"))
                                .append(" age=").append(r.optLong("ageSec")).append("s\n");
                    }
                }
                sb.append("```\n");
            }
            JSONArray ring = root.optJSONArray("ringBuffer");
            if (ring != null && ring.length() > 0) {
                sb.append("\n#### Go Engine Ring Buffer\n```text\n");
                for (int i = 0; i < ring.length(); i++) {
                    JSONObject o = ring.optJSONObject(i);
                    if (o != null) {
                        sb.append("[").append(o.optString("ts")).append("] [")
                                .append(o.optString("cat")).append("/").append(o.optString("code")).append("] ")
                                .append(sanitize(o.optString("msg"))).append("\n");
                    }
                }
                sb.append("```\n");
            }
        } catch (Throwable t) {
            sb.append("- **Engine Bundle ParseError**: ").append(sanitize(t.getMessage())).append("\n");
        }
    }

    private static void appendLocalBridgeFallbackSections(StringBuilder sb) {
        if (!NativeBridgeLoader.isLoaded()) {
            return;
        }
        try {
            String udpTel = Wgbridge.getUdpTelemetryJSON();
            if (udpTel != null && !udpTel.isEmpty()) {
                sb.append("\n#### UDP & Watchdog Telemetry\n```json\n").append(udpTel).append("\n```\n");
            }
        } catch (Throwable ignored) {
        }
        try {
            String goDiag = Wgbridge.getDiagnosticsJSON();
            if (goDiag != null && !goDiag.isEmpty() && !"[]".equals(goDiag.trim())) {
                JSONArray arr = new JSONArray(goDiag);
                sb.append("\n#### Go Engine Ring Buffer\n```text\n");
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.optJSONObject(i);
                    if (o != null) {
                        sb.append("[").append(o.optString("ts")).append("] [")
                                .append(o.optString("cat")).append("/").append(o.optString("code")).append("] ")
                                .append(sanitize(o.optString("msg"))).append("\n");
                    }
                }
                sb.append("```\n");
            }
        } catch (Throwable ignored) {
        }
    }
}
