package org.telegram.wgplus.module;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Pattern;

import wgbridge.Wgbridge;

/**
 * Thread-safe bounded ring buffer and sanitized GitHub Markdown diagnostic report builder.
 * Strictly strips PrivateKeys, PresharedKeys, server endpoints, and SOCKS5 credentials.
 */
public final class WgDiagnosticsLog {

    private static final int MAX_EVENTS = 160;
    private static final List<String> EVENTS = new ArrayList<>(MAX_EVENTS);
    private static final Pattern KV_SECRET_RE = Pattern.compile(
            "(?i)\\b(private_?key|preshared_?key|pass(?:word|phrase)?|secret|auth|token)\\s*[:=]\\s*([^\\s,;]+)"
    );
    private static final Pattern B64_KEY_RE = Pattern.compile("\\b[A-Za-z0-9+/]{42,44}=\\b");
    private static final Pattern ENDPOINT_RE = Pattern.compile(
            "(?i)(endpoint\\s*[:=]\\s*)([^\\s,;]+)"
    );

    private WgDiagnosticsLog() {
    }

    public static String sanitize(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        String s = raw.trim();
        s = KV_SECRET_RE.matcher(s).replaceAll("$1=[REDACTED]");
        s = ENDPOINT_RE.matcher(s).replaceAll("$1[ENDPOINT_REDACTED]");
        s = B64_KEY_RE.matcher(s).replaceAll("[KEY_REDACTED]");
        if (s.length() > 360) {
            s = s.substring(0, 360) + "...";
        }
        return s;
    }

    public static void record(String category, String code, String message) {
        String cat = category == null ? "APP" : category.trim();
        String cd = code == null ? "INFO" : code.trim();
        String msg = sanitize(message);
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        String line = "[" + fmt.format(new Date()) + "] [" + cat + "/" + cd + "] " + msg;
        synchronized (EVENTS) {
            if (EVENTS.size() >= MAX_EVENTS) {
                EVENTS.remove(0);
            }
            EVENTS.add(line);
        }
    }

    public static void clear() {
        synchronized (EVENTS) {
            EVENTS.clear();
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

        sb.append("- **Module Version**: `v").append(moduleVer).append("`\n");
        sb.append("- **Device / OS**: `").append(Build.MANUFACTURER).append(" ").append(Build.MODEL)
                .append("` (Android ").append(Build.VERSION.RELEASE)
                .append(" / API ").append(Build.VERSION.SDK_INT).append(")\n");
        sb.append("- **Process Context**: `").append(pkg).append("` (inModule=").append(inModule)
                .append(", hostVer=").append(hostVer.isEmpty() ? "?" : hostVer)
                .append(", targetSdk=").append(targetSdk).append(")\n");

        if (context != null) {
            boolean running = WireGuardManager.isTunnelRunning(context, moduleApkPath);
            int port = WireGuardManager.getEffectiveProxyPort(context, moduleApkPath);
            boolean ks = WireGuardManager.isKillSwitchEnabled(context);
            boolean auto = WireGuardManager.isAutoConnectEnabled(context);
            boolean calls = WireGuardManager.isRouteCallsEnabled(context);
            boolean doh = WireGuardManager.isDohEnabled(context);
            WireGuardManager.TunnelConfig cfg = WireGuardManager.loadConfig(context);
            WireGuardManager.TunnelStats st = WireGuardManager.getLiveStats(context, moduleApkPath);

            sb.append("- **Tunnel State**: running=`").append(running)
                    .append("`, activePort=`").append(port)
                    .append("`, killSwitch=`").append(ks)
                    .append("`, autoConnect=`").append(auto)
                    .append("`, routeCalls=`").append(calls)
                    .append("`, doH=`").append(doh).append("`\n");
            sb.append("- **Profile Policy**: mtu=`").append(cfg.mtu)
                    .append("`, keepAlive=`").append(cfg.keepAlive)
                    .append("`, awg=`").append(cfg.hasAwgConfigured())
                    .append("`, warp=`").append(cfg.isWarp).append("`\n");
            long hsAgeSec = st.lastHandshakeSec > 0L
                    ? Math.max(0L, (System.currentTimeMillis() / 1000L) - st.lastHandshakeSec)
                    : -1L;
            sb.append("- **Live Counters**: rxBytes=`").append(st.rxBytes)
                    .append("`, txBytes=`").append(st.txBytes)
                    .append("`, hsAgeSec=`").append(hsAgeSec).append("`\n");

            try {
                ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(context);
                sb.append("- **Continuity**: tier=`").append(snap.tier.name())
                        .append("`, stealth=`").append(snap.stealthProtected)
                        .append("`, daemon=`").append(snap.daemonActive)
                        .append("`, root=`").append(snap.rootActive)
                        .append("`, listener=`").append(snap.listenerConnected).append("`\n");
            } catch (Throwable ignored) {
            }
        }

        if (NativeBridgeLoader.isLoaded()) {
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
}
