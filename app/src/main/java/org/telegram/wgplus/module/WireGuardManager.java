package org.telegram.wgplus.module;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import de.robv.android.xposed.XposedHelpers;
import wgbridge.Wgbridge;

public final class WireGuardManager {
    private static final String TAG = "WGPlusManager";
    public static final String PREFS_NAME = "wg_plus_isolated_prefs";
    public static final String BACKUP_SCHEMA = "wgplus-backup-v1";
    private static final String TG_MAINCONFIG = "mainconfig";

    public static final String KEY_ENABLED = "wg_enabled";
    public static final String KEY_ROUTE_CALLS = "wg_route_calls";
    public static final String KEY_KILL_SWITCH = "wg_strict_kill_switch";
    public static final String KEY_AUTO_FAILOVER = "wg_auto_failover";
    public static final String KEY_DOH_ENABLED = "wg_doh_enabled";
    public static final String KEY_SMART_KEEPALIVE = "wg_smart_keepalive";
    public static final String KEY_PROFILES_JSON = "wg_profiles_v2_json";
    public static final String KEY_ACTIVE_PROFILE_ID = "wg_active_profile_id";
    public static final String KEY_CONNECTED_PROFILE_ID = "wg_connected_profile_id";
    private static final String KEY_DNS_LKG_CACHE_JSON = "wg_dns_lkg_cache_json";
    private static final String KEY_MIGRATED_FORCED_CONTINUITY_V1 = "wg_migrated_forced_continuity_v1";

    public static final String EXTRA_STOP_FOREGROUND_KEEPALIVE = "wgplus_stop_fg_keepalive";
    public static final String EXTRA_EXPECT_FOREGROUND_PROMOTE = "wgplus_expect_fg_promote";
    public static final String ACTION_KEEPALIVE_BRIDGE = "org.telegram.wgplus.ACTION_KEEPALIVE_BRIDGE";
    public static final String ACTION_SYNC_CONTINUITY = "org.telegram.wgplus.ACTION_SYNC_CONTINUITY";
    private static final Uri STATUS_PROVIDER_URI = Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY);
    public static final String FG_NOTIFICATION_CHANNEL_ID = "wgplus_keepalive_silent_channel";
    public static final int FG_NOTIFICATION_ID = 49107;
    private static final String FG_SERVICE_CLASS = "org.telegram.messenger.NotificationsService";

    private static volatile long sLastStealthQueryMs;
    private static volatile boolean sLastStealthProtected;
    private static volatile boolean sLastStealthWantsAwake;
    private static volatile long sTunnelStartedAtMs;
    public static final long HANDSHAKE_HEALTHY_WINDOW_SEC = 210L;
    public static final long PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC = 120L;
    private static final java.util.concurrent.atomic.AtomicBoolean sHandshakeNudgeInFlight = new java.util.concurrent.atomic.AtomicBoolean(false);
    private static volatile long sLastHandshakeNudgeMs = 0L;
    private static volatile long sLastSharedTunnelHeartbeatMs = 0L;
    private static volatile long sLastRemoteHygieneCheckMs;
    private static volatile long sLastHandledHygieneReqMs;
    private static final String KEY_SHARED_STATE_REV = "wg_shared_state_rev";
    private static final ExecutorService SYNC_EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "wgplus-shared-sync");
        t.setDaemon(true);
        return t;
    });
    private static volatile Context sSyncContext;
    private static volatile boolean sSuppressSyncPush;
    private static volatile long sLastSyncPullMs;

    // Legacy v1.1.0 single-profile keys (transparently migrated once)
    public static final String KEY_PRIVATE_KEY = "wg_private_key";
    public static final String KEY_ADDRESS = "wg_address";
    public static final String KEY_DNS = "wg_dns";
    public static final String KEY_PUBLIC_KEY = "wg_public_key";
    public static final String KEY_ENDPOINT = "wg_endpoint";
    public static final String KEY_KEEPALIVE = "wg_keepalive";

    public static final String KEY_UI_LANG = "wg_ui_lang";
    public static final String KEY_UI_DARK = "wg_ui_dark";
    public static final String OFFICIAL_CHANNEL_URL = "https://t.me/wgplus_official";
    private static final String KEY_CHANNEL_INVITED_V2 = "wg_channel_invited_v2";

    static String patchVoipConfigJsonForProxy(String rawJson) {
        if (rawJson == null) {
            return null;
        }
        String trimmed = rawJson.trim();
        if (trimmed.isEmpty() || !trimmed.startsWith("{")) {
            return rawJson;
        }
        try {
            JSONObject obj = new JSONObject(trimmed);
            obj.put("force_tcp", true);
            obj.put("use_tcp", true);
            return obj.toString();
        } catch (Throwable ignored) {
            return rawJson
                    .replace("\"force_tcp\":false", "\"force_tcp\":true")
                    .replace("\"force_tcp\": false", "\"force_tcp\": true")
                    .replace("\"use_tcp\":false", "\"use_tcp\":true")
                    .replace("\"use_tcp\": false", "\"use_tcp\": true");
        }
    }

    interface EndpointRelayStarter {
        int startRelay(String host, int port);
    }

    interface EndpointAddrRelayStarter {
        String startRelayAddr(String host, int port);
    }

    /**
     * Rewrites ICE/TURN transport candidate endpoints inside tgcalls group/conference call
     * {@code setJoinResponsePayload(String)} JSON so media routes via local WireGuard relays.
     */
    static String rewriteGroupCallJoinPayload(
            String payloadJson,
            EndpointRelayStarter relayStarter,
            boolean killSwitchBlackhole
    ) {
        if (relayStarter == null) {
            return payloadJson;
        }
        return rewriteGroupCallJoinPayloadAddr(
                payloadJson,
                (host, port) -> {
                    int lp = relayStarter.startRelay(host, port);
                    return lp > 0 ? ("127.0.0.1:" + lp) : "";
                },
                killSwitchBlackhole
        );
    }

    static String rewriteGroupCallJoinPayloadAddr(
            String payloadJson,
            EndpointAddrRelayStarter relayStarter,
            boolean killSwitchBlackhole
    ) {
        if (payloadJson == null || payloadJson.isEmpty() || relayStarter == null) {
            return payloadJson;
        }
        String trimmed = payloadJson.trim();
        if (!trimmed.startsWith("{")) {
            return payloadJson;
        }
        try {
            JSONObject root = new JSONObject(trimmed);
            JSONObject transport = root.optJSONObject("transport");
            JSONArray candidates = transport != null ? transport.optJSONArray("candidates") : null;
            if (candidates == null) {
                candidates = root.optJSONArray("candidates");
            }
            if (candidates == null || candidates.length() == 0) {
                return payloadJson;
            }
            boolean changed = false;
            for (int i = 0; i < candidates.length(); i++) {
                JSONObject cand = candidates.optJSONObject(i);
                if (cand == null) {
                    continue;
                }
                String ipField = cand.has("ip") ? "ip" : (cand.has("address") ? "address" : "ip");
                String host = cand.optString(ipField, "").trim();
                Object portObj = cand.opt("port");
                int rawPort = -1;
                if (portObj instanceof Number) {
                    rawPort = ((Number) portObj).intValue();
                } else if (portObj instanceof String) {
                    try {
                        rawPort = Integer.parseInt(((String) portObj).trim());
                    } catch (NumberFormatException ignored) {
                    }
                }
                if (host.isEmpty() || rawPort < 1 || rawPort > 65535) {
                    continue;
                }
                if (host.startsWith("127.") || "::1".equals(host)) {
                    continue;
                }

                String relayAddr = relayStarter.startRelayAddr(host, rawPort);
                String relayIp = parseIpFromHostPort(relayAddr);
                int localPort = parsePortFromHostPort(relayAddr);
                if (localPort <= 0 && killSwitchBlackhole) {
                    relayIp = "127.0.0.1";
                    localPort = 9;
                }
                if (!relayIp.isEmpty() && localPort > 0) {
                    cand.put(ipField, relayIp);
                    if (portObj instanceof Number) {
                        cand.put("port", localPort);
                    } else {
                        cand.put("port", String.valueOf(localPort));
                    }
                    changed = true;
                }
            }
            return changed ? root.toString() : payloadJson;
        } catch (Throwable ignored) {
            return payloadJson;
        }
    }

    private static final String KEY_PERSISTED_SOCKS_USER = "wg_socks_user_v2";
    private static final String KEY_PERSISTED_SOCKS_PASS = "wg_socks_pass_v2";
    private static volatile Context sSocksPrefsCtx = null;
    private static volatile String sSocksUser = "";
    private static volatile String sSocksPass = "";
    private static volatile String sSharedSocksUser = "";
    private static volatile String sSharedSocksPass = "";
    private static volatile long sSharedLastHsSec = 0L;
    private static volatile boolean sSharedHsHealthy = false;

    /**
     * Derives deterministic 128-bit loopback SOCKS/WGP1 credentials from the active WireGuard
     * private key via HMAC-SHA256 so every local Telegram app configured with the same profile
     * authenticates identically without cross-sandbox race conditions or package-visibility failures.
     */
    static String deriveProfileSocksPass(String privateKey) {
        String trimmed = safeTrim(privateKey);
        if (trimmed.isEmpty()) {
            return "";
        }
        try {
            String privHex = normalizeKeyToHex(trimmed);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec("wgplus-loopback-socks-v2".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(privHex.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(32);
            for (int i = 0; i < 16 && i < digest.length; i++) {
                hex.append(String.format(Locale.US, "%02x", digest[i] & 0xff));
            }
            return hex.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    static String computeProfileSigHash(String profileSig) {
        String trimmed = safeTrim(profileSig);
        if (trimmed.isEmpty()) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(trimmed.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(12);
            for (int i = 0; i < 6 && i < digest.length; i++) {
                hex.append(String.format(Locale.US, "%02x", digest[i] & 0xff));
            }
            return hex.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static synchronized void syncDeterministicSocksCredentialsForProfile(Context context, TunnelConfig cfg) {
        if (context != null) {
            Context app = context.getApplicationContext();
            sSocksPrefsCtx = app != null ? app : context;
        }
        String detPass = cfg != null ? deriveProfileSocksPass(cfg.privateKey) : "";
        if (detPass.isEmpty()) {
            ensureSessionSocksCredentials(context);
            return;
        }
        boolean changed = !"wg".equals(sSocksUser) || !detPass.equals(sSocksPass);
        sSocksUser = "wg";
        sSocksPass = detPass;
        Context eff = context != null ? context : sSocksPrefsCtx;
        if (eff != null && changed) {
            try {
                getPrefs(eff).edit()
                        .putString(KEY_PERSISTED_SOCKS_USER, sSocksUser)
                        .putString(KEY_PERSISTED_SOCKS_PASS, sSocksPass)
                        .commit();
            } catch (Throwable ignored) {
            }
        }
        if (changed) {
            try {
                if (NativeBridgeLoader.isLoaded()) {
                    Wgbridge.setSocksAuth(sSocksUser, sSocksPass);
                    Wgbridge.resetSocksAuthRejectCount();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static synchronized void ensureSessionSocksCredentials() {
        ensureSessionSocksCredentials(sSocksPrefsCtx);
    }

    private static synchronized void ensureSessionSocksCredentials(Context context) {
        if (context != null) {
            Context app = context.getApplicationContext();
            sSocksPrefsCtx = app != null ? app : context;
        }
        Context eff = context != null ? context : sSocksPrefsCtx;
        if (eff == null) {
            // Never mint an unpersisted ephemeral password in memory before Application Context exists;
            // otherwise mainconfig/proxyList desyncs from wg_plus_isolated_prefs.
            return;
        }
        try {
            TunnelConfig activeCfg = loadConfig(eff);
            String detPass = deriveProfileSocksPass(activeCfg != null ? activeCfg.privateKey : "");
            if (!detPass.isEmpty()) {
                boolean changed = !"wg".equals(sSocksUser) || !detPass.equals(sSocksPass);
                sSocksUser = "wg";
                sSocksPass = detPass;
                if (changed) {
                    getPrefs(eff).edit()
                            .putString(KEY_PERSISTED_SOCKS_USER, sSocksUser)
                            .putString(KEY_PERSISTED_SOCKS_PASS, sSocksPass)
                            .commit();
                }
                return;
            }
        } catch (Throwable ignored) {
        }
        if (!sSocksUser.isEmpty() && !sSocksPass.isEmpty()) {
            return;
        }
        try {
            SharedPreferences sp = getPrefs(eff);
            String u = sp.getString(KEY_PERSISTED_SOCKS_USER, "");
            String p = sp.getString(KEY_PERSISTED_SOCKS_PASS, "");
            if (u != null && !u.isEmpty() && p != null && !p.isEmpty()) {
                sSocksUser = u;
                sSocksPass = p;
                return;
            }
        } catch (Throwable ignored) {
        }
        byte[] raw = new byte[16];
        new SecureRandom().nextBytes(raw);
        sSocksUser = "wg";
        sSocksPass = android.util.Base64.encodeToString(raw, android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING);
        try {
            getPrefs(eff).edit()
                    .putString(KEY_PERSISTED_SOCKS_USER, sSocksUser)
                    .putString(KEY_PERSISTED_SOCKS_PASS, sSocksPass)
                    .commit();
        } catch (Throwable ignored) {
        }
    }

    public static String getActiveSocksUser() {
        return getActiveSocksUser(sSocksPrefsCtx);
    }

    public static String getActiveSocksUser(Context context) {
        if (!sIsSharedHubOwner) {
            if ((sSharedHubPort <= 0 || sSharedSocksUser.isEmpty()) && context != null) {
                queryAnyLiveSharedTunnelPort(context);
            }
            if (sSharedHubPort > 0 && !sSharedSocksUser.isEmpty()) {
                return sSharedSocksUser;
            }
        }
        ensureSessionSocksCredentials(context);
        return sSocksUser;
    }

    public static String getActiveSocksPass() {
        return getActiveSocksPass(sSocksPrefsCtx);
    }

    public static String getActiveSocksPass(Context context) {
        if (!sIsSharedHubOwner) {
            if ((sSharedHubPort <= 0 || sSharedSocksPass.isEmpty()) && context != null) {
                queryAnyLiveSharedTunnelPort(context);
            }
            if (sSharedHubPort > 0 && !sSharedSocksPass.isEmpty()) {
                return sSharedSocksPass;
            }
        }
        ensureSessionSocksCredentials(context);
        return sSocksPass;
    }

    public static boolean openOfficialChannel(final Context ctx, final Runnable onBeforeRedirect) {
        if (ctx == null) {
            return false;
        }
        final Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        android.app.Activity resolvedAct = null;
        Context cur = ctx;
        for (int depth = 0; depth < 8 && cur != null; depth++) {
            if (cur instanceof android.app.Activity) {
                resolvedAct = (android.app.Activity) cur;
                break;
            }
            if (cur instanceof android.content.ContextWrapper) {
                cur = ((android.content.ContextWrapper) cur).getBaseContext();
            } else {
                break;
            }
        }
        if (resolvedAct != null && resolvedAct.isFinishing()) {
            resolvedAct = null;
        }

        if (onBeforeRedirect != null) {
            try {
                onBeforeRedirect.run();
            } catch (Throwable ignored) {
            }
        }

        final String channelUri = "tg://resolve?domain=wgplus_official";
        final String pkg = resolvedAct != null ? resolvedAct.getPackageName() : appCtx.getPackageName();
        final boolean inModuleApp = "org.telegram.wgplus.module".equals(pkg);
        if (!inModuleApp) {
            if (resolvedAct != null) {
                // Primary path inside hooked Telegram: invoke Telegram's internal Browser.openUrl directly
                try {
                    Class<?> browserCls = XposedHelpers.findClassIfExists(
                            "org.telegram.messenger.browser.Browser",
                            resolvedAct.getClassLoader()
                    );
                    if (browserCls != null) {
                        XposedHelpers.callStaticMethod(browserCls, "openUrl", resolvedAct, channelUri);
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
            try {
                Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(channelUri));
                if (pkg != null && !pkg.isEmpty()) {
                    i.setPackage(pkg);
                }
                if (resolvedAct != null) {
                    i.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                    resolvedAct.startActivity(i);
                } else {
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    appCtx.startActivity(i);
                }
                return true;
            } catch (Throwable ignored) {
            }
            return false;
        }

        // Inside companion app: target installed Telegram clients directly (never launch a web browser)
        PackageManager pm = appCtx.getPackageManager();
        for (String tgPkg : ContinuityBridgeManager.DEFAULT_TARGET_PACKAGES) {
            try {
                Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(channelUri));
                i.setPackage(tgPkg);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                if (pm != null && i.resolveActivity(pm) != null) {
                    appCtx.startActivity(i);
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(channelUri));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            appCtx.startActivity(i);
            return true;
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static void maybeInviteToOfficialChannel(final Context ctx, final boolean isAr) {
        maybeInviteToOfficialChannel(ctx, isAr, null);
    }

    public static void maybeInviteToOfficialChannel(
            final Context ctx,
            final boolean isAr,
            final Runnable onBeforeRedirect
    ) {
        if (ctx == null) {
            return;
        }
        try {
            if (getPrefs(ctx).getBoolean(KEY_CHANNEL_INVITED_V2, false)) {
                return;
            }
            final Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
            android.app.Activity resolvedAct = null;
            Context cur = ctx;
            for (int depth = 0; depth < 8 && cur != null; depth++) {
                if (cur instanceof android.app.Activity) {
                    resolvedAct = (android.app.Activity) cur;
                    break;
                }
                if (cur instanceof android.content.ContextWrapper) {
                    cur = ((android.content.ContextWrapper) cur).getBaseContext();
                } else {
                    break;
                }
            }
            if (resolvedAct == null || resolvedAct.isFinishing()) {
                return;
            }
            final android.app.Activity act = resolvedAct;
            final Runnable openChannel = () -> {
                getPrefs(appCtx).edit().putBoolean(KEY_CHANNEL_INVITED_V2, true).apply();
                openOfficialChannel(act, onBeforeRedirect);
            };
            final WgTheme th = WgTheme.of(isDarkTheme(ctx));
            final android.app.Dialog d = new android.app.Dialog(act);
            d.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE);
            d.setCancelable(false);
            d.setCanceledOnTouchOutside(false);

            int p = WgTheme.dp(act, 20);
            android.widget.LinearLayout card = new android.widget.LinearLayout(act);
            card.setOrientation(android.widget.LinearLayout.VERTICAL);
            card.setPadding(p, p, p, p);
            card.setBackground(WgTheme.cardBackground(act, th.surfaceCard, th.borderSubtle, 16));
            card.setLayoutDirection(isAr ? android.view.View.LAYOUT_DIRECTION_RTL : android.view.View.LAYOUT_DIRECTION_LTR);

            android.widget.TextView badge = new android.widget.TextView(act);
            badge.setText("@wgplus_official");
            badge.setTextSize(12);
            badge.setTextColor(th.accentPrimary);
            badge.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            badge.setPadding(WgTheme.dp(act, 10), WgTheme.dp(act, 3), WgTheme.dp(act, 10), WgTheme.dp(act, 3));
            badge.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 99));
            card.addView(badge, new android.widget.LinearLayout.LayoutParams(-2, -2));

            android.widget.TextView title = new android.widget.TextView(act);
            title.setText(isAr ? "القناة الرسمية لـ وايرجارد بلس" : "Official WireGuard Plus Channel");
            title.setTextSize(18);
            title.setTextColor(th.textPrimary);
            title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
            title.setPadding(0, WgTheme.dp(act, 12), 0, WgTheme.dp(act, 6));
            card.addView(title);

            android.widget.TextView body = new android.widget.TextView(act);
            body.setText(isAr
                    ? "انضم إلى قناة تيليجرام الرسمية للحصول على أحدث الإصدارات وإصلاحات الاتصال.\n\nهل أنت مشترك في القناة حالي\u064B\u0627؟"
                    : "Join our official Telegram channel for the latest releases and connection updates.\n\nAre you subscribed to the channel?");
            body.setTextSize(13.5f);
            body.setTextColor(th.textSecondary);
            body.setPadding(0, 0, 0, WgTheme.dp(act, 14));
            card.addView(body);

            android.widget.Button openBtn = new android.widget.Button(act);
            openBtn.setAllCaps(false);
            openBtn.setTextColor(th.onAccent);
            openBtn.setText(isAr ? "فتح القناة على تيليجرام" : "Open Channel on Telegram");
            openBtn.setBackground(WgTheme.cardBackground(act, th.accentPrimary, th.accentPrimary, 10));
            openBtn.setOnClickListener(v -> {
                d.dismiss();
                openChannel.run();
            });
            android.widget.LinearLayout.LayoutParams openLp = new android.widget.LinearLayout.LayoutParams(-1, WgTheme.dp(act, 46));
            openLp.bottomMargin = WgTheme.dp(act, 8);
            card.addView(openBtn, openLp);

            android.widget.LinearLayout row = new android.widget.LinearLayout(act);
            row.setOrientation(android.widget.LinearLayout.HORIZONTAL);

            android.widget.Button yesBtn = new android.widget.Button(act);
            yesBtn.setAllCaps(false);
            yesBtn.setTextColor(th.textPrimary);
            yesBtn.setText(isAr ? "نعم، مشترك" : "Yes, subscribed");
            yesBtn.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 10));
            yesBtn.setOnClickListener(v -> {
                getPrefs(appCtx).edit().putBoolean(KEY_CHANNEL_INVITED_V2, true).apply();
                d.dismiss();
            });
            android.widget.LinearLayout.LayoutParams yLp = new android.widget.LinearLayout.LayoutParams(0, WgTheme.dp(act, 44), 1f);
            yLp.setMarginEnd(WgTheme.dp(act, 6));
            row.addView(yesBtn, yLp);

            android.widget.Button noBtn = new android.widget.Button(act);
            noBtn.setAllCaps(false);
            noBtn.setTextColor(th.textSecondary);
            noBtn.setText(isAr ? "لا، ليس بعد" : "No, not yet");
            noBtn.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 10));
            noBtn.setOnClickListener(v -> {
                Toast.makeText(
                        act,
                        isAr ? "يرجى الاشتراك في القناة أول\u064B\u0627 للمتابعة" : "Please subscribe to the channel first to continue",
                        Toast.LENGTH_SHORT
                ).show();
                d.dismiss();
                openChannel.run();
            });
            row.addView(noBtn, new android.widget.LinearLayout.LayoutParams(0, WgTheme.dp(act, 44), 1f));
            card.addView(row, new android.widget.LinearLayout.LayoutParams(-1, -2));

            d.setContentView(card);
            android.view.Window w = d.getWindow();
            if (w != null) {
                w.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(0));
                w.setLayout((int) (act.getResources().getDisplayMetrics().widthPixels * 0.90f),
                        android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
                w.setGravity(android.view.Gravity.CENTER);
                w.setDimAmount(0.75f);
            }
            d.show();
        } catch (Throwable t) {
            Log.e(TAG, "maybeInviteToOfficialChannel failed", t);
        }
    }

    // Snapshot keys to cleanly restore any pre-existing user proxy in Telegram's mainconfig
    private static final String KEY_MC_SNAPSHOT_TAKEN = "wg_mc_snapshot_taken";
    private static final String KEY_MC_PREV_ENABLED = "wg_mc_prev_enabled";
    private static final String KEY_MC_PREV_CALLS = "wg_mc_prev_calls";
    private static final String KEY_MC_PREV_IP = "wg_mc_prev_ip";
    private static final String KEY_MC_PREV_PORT = "wg_mc_prev_port";
    private static final String KEY_MC_PREV_USER = "wg_mc_prev_user";
    private static final String KEY_MC_PREV_PASS = "wg_mc_prev_pass";
    private static final String KEY_MC_PREV_SECRET = "wg_mc_prev_secret";

    private static final Object WATCHDOG_LOCK = new Object();
    private static ConnectivityManager.NetworkCallback sNetworkCallback = null;
    private static volatile String sWatchdogRawEndpoint = "";
    private static volatile String sConnectedProfileId = "";
    private static volatile long sLastRoamingUpdateMs = 0L;
    private static volatile boolean sUserManuallyStopped = false;
    private static volatile String sLastActiveNetworkSignature = "";
    private static volatile int sActiveTunnelMtu = 1280;
    private static volatile int sSharedHubPort = -1;
    private static volatile boolean sIsSharedHubOwner = false;
    private static volatile Boolean sLastBoundEnabled = null;
    private static volatile int sLastBoundPort = -1;
    private static volatile boolean sLastBoundRouteCalls = false;
    private static volatile String sLastBoundUser = "";
    private static volatile String sLastBoundPass = "";
    private static volatile Boolean sLastBoundHsHealthy = null;
    private static volatile long sLastHardRestartMs = 0L;
    private static volatile boolean sAutoMtuDowngraded = false;
    private static volatile boolean sLastReportedHsHealthy = false;
    private static volatile int sRoamRetryCount = 0;
    private static final int MAX_ROAM_RETRIES = 3;
    private static volatile boolean sApplyingProxyBindings = false;

    public static boolean isApplyingProxyBindings() {
        return sApplyingProxyBindings;
    }

    // Live Ping RTT cache (profileId -> ms, or -1 on timeout)
    private static final Map<String, Integer> sPingCacheMs = new ConcurrentHashMap<>();

    // 24/7 Forced Continuity Locks, Guardian Executor & Smart Keepalive background state
    private static final Object LOCK_SYNC = new Object();
    private static PowerManager.WakeLock sForcedWakeLock = null;
    private static WifiManager.WifiLock sForcedWifiLock = null;
    private static ScheduledExecutorService sGuardianExecutor = null;
    private static ScheduledFuture<?> sGuardianFuture = null;
    private static ScheduledFuture<?> sRoamingDebounceFuture = null;
    private static Handler sMainHandler = null;
    private static volatile boolean sAppInForeground = true;
    private static volatile boolean sKeepalivePausedForIdle = false;
    private static Runnable sPendingIdleSaverTask = null;
    private static volatile int sConsecutiveHealthFailures = 0;
    private static volatile boolean sFailoverCheckRunning = false;

    private static synchronized ScheduledExecutorService getGuardianExecutor() {
        if (sGuardianExecutor == null || sGuardianExecutor.isShutdown()) {
            sGuardianExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "wg-plus-24x7-guardian");
                t.setDaemon(true);
                t.setPriority(Thread.NORM_PRIORITY + 1);
                return t;
            });
        }
        return sGuardianExecutor;
    }

    private static synchronized Handler getMainHandler() {
        if (sMainHandler == null) {
            Looper main = Looper.getMainLooper();
            if (main != null) {
                sMainHandler = new Handler(main);
            }
        }
        return sMainHandler;
    }

    private WireGuardManager() {
    }

    public static final class TunnelConfig {
        public String id = UUID.randomUUID().toString();
        public String name = "";
        public boolean enabled = false;
        public boolean routeCalls = true;
        public String privateKey = "";
        public String presharedKey = "";
        public String address = "10.0.0.2/32";
        public String dns = "1.1.1.1";
        public String publicKey = "";
        public String endpoint = "";
        public int keepAlive = 25;
        public int mtu = 1280;

        // AmneziaWG DPI obfuscation parameters
        public int jc = 0;
        public int jmin = 0;
        public int jmax = 0;
        public int s1 = 0;
        public int s2 = 0;
        public int s3 = 0;
        public int s4 = 0;
        public String h1 = "";
        public String h2 = "";
        public String h3 = "";
        public String h4 = "";
        public String i1 = "";
        public String i2 = "";
        public String i3 = "";
        public String i4 = "";
        public String i5 = "";
        public String reserved = "";
        public boolean isWarp = false;

        public TunnelConfig copy() {
            TunnelConfig c = new TunnelConfig();
            c.id = this.id;
            c.name = this.name;
            c.enabled = this.enabled;
            c.routeCalls = this.routeCalls;
            c.privateKey = this.privateKey;
            c.presharedKey = this.presharedKey;
            c.address = this.address;
            c.dns = this.dns;
            c.publicKey = this.publicKey;
            c.endpoint = this.endpoint;
            c.keepAlive = this.keepAlive;
            c.mtu = this.mtu;
            c.jc = this.jc;
            c.jmin = this.jmin;
            c.jmax = this.jmax;
            c.s1 = this.s1;
            c.s2 = this.s2;
            c.s3 = this.s3;
            c.s4 = this.s4;
            c.h1 = this.h1;
            c.h2 = this.h2;
            c.h3 = this.h3;
            c.h4 = this.h4;
            c.i1 = this.i1;
            c.i2 = this.i2;
            c.i3 = this.i3;
            c.i4 = this.i4;
            c.i5 = this.i5;
            c.reserved = this.reserved;
            c.isWarp = this.isWarp;
            return c;
        }

        public boolean hasPeerConfigured() {
            return !safeTrim(privateKey).isEmpty()
                    && !safeTrim(publicKey).isEmpty()
                    && !safeTrim(endpoint).isEmpty();
        }

        public boolean hasAwgConfigured() {
            return jc > 0
                    || s1 > 0 || s2 > 0 || s3 > 0 || s4 > 0
                    || !safeTrim(h1).isEmpty()
                    || !safeTrim(h2).isEmpty()
                    || !safeTrim(h3).isEmpty()
                    || !safeTrim(h4).isEmpty()
                    || !safeTrim(i1).isEmpty()
                    || !safeTrim(i2).isEmpty()
                    || !safeTrim(i3).isEmpty()
                    || !safeTrim(i4).isEmpty()
                    || !safeTrim(i5).isEmpty()
                    || !safeTrim(reserved).isEmpty();
        }

        public String toAwgParamsString() {
            if (!hasAwgConfigured()) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            if (jc > 0) {
                sb.append("Jc=").append(jc).append('\n');
                if (jmin > 0) {
                    sb.append("Jmin=").append(jmin).append('\n');
                }
                if (jmax > 0) {
                    sb.append("Jmax=").append(jmax).append('\n');
                }
            }
            if (s1 > 0) sb.append("S1=").append(s1).append('\n');
            if (s2 > 0) sb.append("S2=").append(s2).append('\n');
            if (s3 > 0) sb.append("S3=").append(s3).append('\n');
            if (s4 > 0) sb.append("S4=").append(s4).append('\n');
            if (!safeTrim(h1).isEmpty()) sb.append("H1=").append(safeTrim(h1)).append('\n');
            if (!safeTrim(h2).isEmpty()) sb.append("H2=").append(safeTrim(h2)).append('\n');
            if (!safeTrim(h3).isEmpty()) sb.append("H3=").append(safeTrim(h3)).append('\n');
            if (!safeTrim(h4).isEmpty()) sb.append("H4=").append(safeTrim(h4)).append('\n');
            if (!safeTrim(i1).isEmpty()) sb.append("I1=").append(safeTrim(i1)).append('\n');
            if (!safeTrim(i2).isEmpty()) sb.append("I2=").append(safeTrim(i2)).append('\n');
            if (!safeTrim(i3).isEmpty()) sb.append("I3=").append(safeTrim(i3)).append('\n');
            if (!safeTrim(i4).isEmpty()) sb.append("I4=").append(safeTrim(i4)).append('\n');
            if (!safeTrim(i5).isEmpty()) sb.append("I5=").append(safeTrim(i5)).append('\n');
            if (!safeTrim(reserved).isEmpty()) sb.append("Reserved=").append(safeTrim(reserved)).append('\n');
            return sb.toString();
        }

        /**
         * Returns the runtime AmneziaWG parameters passed to the native bridge.
         * For standard (vanilla) WireGuard configs where no AWG parameters are set,
         * injects a lightweight 3-packet micro-paced UDP wakeup burst (Jc=3, Jmin=48, Jmax=108)
         * before every Handshake Initiation. Standard WireGuard servers silently discard
         * unrecognized UDP packets, while mobile carriers' 4G/5G RRC state machines, CGNAT
         * tables, and first-packet DPI filters wake up cleanly without dropping the real
         * 148-byte WireGuard Handshake Initiation packet.
         */
        public String toEffectiveAwgParamsString() {
            String explicit = toAwgParamsString();
            if (!explicit.isEmpty()) {
                return explicit;
            }
            return "";
        }

        public String summaryLabel() {
            String ep = safeTrim(endpoint);
            if (ep.isEmpty()) {
                return "";
            }
            String addr = safeTrim(address);
            return addr.isEmpty() ? ep : (ep + " • " + addr);
        }
    }

    public static final class TunnelStats {
        public long rxBytes = 0L;
        public long txBytes = 0L;
        public long lastHandshakeSec = 0L;
    }

    public static final class TunnelVerifyResult {
        public String exitIp = "";
        public String countryCode = "";
        public String colo = "";
        public long tunnelPingMs = 0L;
        public boolean telegramDcReachable = false;
        public long telegramDcPingMs = 0L;
        public boolean udpCallsReady = false;
        public long udpPingMs = 0L;
    }

    public static final class PingWinnerResult {
        public TunnelConfig winner;
        public int bestMs;
        public boolean switchedLive;
        public int livePort;
    }

    public static final class QuickWarpResult {
        public TunnelConfig profile;
        public int localPort;
        public boolean createdNew;
    }

    public static SharedPreferences getPrefs(Context context) {
        if (context != null) {
            WgKeystoreCrypto.init(context);
            if (sSyncContext == null) {
                Context app = context.getApplicationContext();
                sSyncContext = app != null ? app : context;
            }
        }
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static synchronized String exportSharedSyncBundleJson(Context context) {
        return exportSharedSyncBundleJson(context, true);
    }

    private static synchronized String exportSharedSyncBundleJson(Context context, boolean includeSecrets) {
        if (context == null) {
            return "{}";
        }
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        JSONObject root = new JSONObject();
        try {
            root.put("stateRev", prefs.getLong(KEY_SHARED_STATE_REV, 0L));
            root.put("hasSecrets", includeSecrets);
            root.put("activeProfileId", prefs.getString(KEY_ACTIVE_PROFILE_ID, ""));
            root.put("enabled", isAutoConnectEnabled(context));
            root.put("routeCalls", isRouteCallsEnabled(context));
            root.put("killSwitch", isKillSwitchEnabled(context));
            root.put("autoFailover", isAutoFailoverEnabled(context));
            root.put("dohEnabled", isDohEnabled(context));
            root.put("smartKeepalive", isSmartKeepaliveEnabled(context));
            root.put("uiLang", prefs.getString(KEY_UI_LANG, ""));
            root.put("uiDark", prefs.contains(KEY_UI_DARK) ? (prefs.getBoolean(KEY_UI_DARK, true) ? 1 : 0) : -1);
            if (includeSecrets) {
                ensureSessionSocksCredentials(context);
                if (!sSocksUser.isEmpty() && !sSocksPass.isEmpty()) {
                    root.put("socksUser", sSocksUser);
                    root.put("socksPass", sSocksPass);
                }
            }
            JSONArray arr = new JSONArray();
            for (TunnelConfig cfg : profiles) {
                JSONObject obj = configToJsonObject(cfg, false);
                if (!includeSecrets) {
                    obj.remove("privateKey");
                    obj.remove("presharedKey");
                }
                arr.put(obj);
            }
            root.put("profiles", arr);
        } catch (Throwable ignored) {
        }
        return root.toString();
    }

    public static synchronized long importSharedSyncBundleJson(Context context, String rawJson, boolean keepIncomingRev) {
        if (context == null || rawJson == null || rawJson.trim().isEmpty()) {
            return -1L;
        }
        try {
            JSONObject root = new JSONObject(rawJson);
            SharedPreferences prefs = getPrefs(context);
            long localRev = prefs.getLong(KEY_SHARED_STATE_REV, 0L);
            long incomingRev = root.optLong("stateRev", 0L);
            String localActiveId = prefs.getString(KEY_ACTIVE_PROFILE_ID, "").trim();
            String incomingActiveId = root.optString("activeProfileId", "").trim();
            boolean equalRevProfileDrift = (incomingRev == localRev)
                    && !incomingActiveId.isEmpty() && !incomingActiveId.equals(localActiveId);
            if (keepIncomingRev && incomingRev <= localRev && !equalRevProfileDrift && hasAnyConfiguredProfile(context)) {
                return localRev;
            }
            JSONArray arr = root.optJSONArray("profiles");
            List<TunnelConfig> profiles = new ArrayList<>();
            boolean hasKeyedProfile = false;
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject item = arr.optJSONObject(i);
                    if (item != null) {
                        TunnelConfig cfg = configFromJsonObject(item, false);
                        if (cfg != null) {
                            profiles.add(cfg);
                            if (!safeTrim(cfg.privateKey).isEmpty()) {
                                hasKeyedProfile = true;
                            }
                        }
                    }
                }
            }
            boolean hasSecrets = root.optBoolean("hasSecrets", hasKeyedProfile);
            if (keepIncomingRev && !hasSecrets && !profiles.isEmpty() && hasAnyConfiguredProfile(context)) {
                return localRev;
            }
            long nextRev = keepIncomingRev ? incomingRev : Math.max(localRev + 1L, incomingRev + 1L);
            sSuppressSyncPush = true;
            try {
                boolean enabled = root.optBoolean("enabled", isAutoConnectEnabled(context));
                boolean routeCalls = root.optBoolean("routeCalls", isRouteCallsEnabled(context));
                String activeId = root.optString("activeProfileId", "");
                if (activeId.isEmpty() && !profiles.isEmpty()) {
                    activeId = profiles.get(0).id;
                }
                if (hasSecrets || !profiles.isEmpty()) {
                    persistProfilesLocked(prefs, profiles, activeId, enabled, routeCalls);
                }
                SharedPreferences.Editor ed = prefs.edit()
                        .putBoolean(KEY_ENABLED, enabled)
                        .putBoolean(KEY_ROUTE_CALLS, routeCalls)
                        .putBoolean(KEY_KILL_SWITCH, root.optBoolean("killSwitch", false))
                        .putBoolean(KEY_AUTO_FAILOVER, root.optBoolean("autoFailover", false))
                        .putBoolean(KEY_DOH_ENABLED, root.optBoolean("dohEnabled", true))
                        .putBoolean(KEY_SMART_KEEPALIVE, root.optBoolean("smartKeepalive", false))
                        .putBoolean(KEY_MIGRATED_FORCED_CONTINUITY_V1, true);
                if (!keepIncomingRev || hasSecrets || profiles.isEmpty()) {
                    ed.putLong(KEY_SHARED_STATE_REV, nextRev);
                }
                if (hasSecrets) {
                    TunnelConfig selectedActive = null;
                    for (TunnelConfig p : profiles) {
                        if (activeId.equals(p.id)) {
                            selectedActive = p;
                            break;
                        }
                    }
                    if (selectedActive == null && !profiles.isEmpty()) {
                        selectedActive = profiles.get(0);
                    }
                    String detPass = selectedActive != null ? deriveProfileSocksPass(selectedActive.privateKey) : "";
                    String syncUser = !detPass.isEmpty() ? "wg" : root.optString("socksUser", "").trim();
                    String syncPass = !detPass.isEmpty() ? detPass : root.optString("socksPass", "").trim();
                    if (!syncUser.isEmpty() && !syncPass.isEmpty()) {
                        sSocksUser = syncUser;
                        sSocksPass = syncPass;
                        ed.putString(KEY_PERSISTED_SOCKS_USER, syncUser);
                        ed.putString(KEY_PERSISTED_SOCKS_PASS, syncPass);
                        try {
                            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                                Wgbridge.setSocksAuth(syncUser, syncPass);
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                }
                String uiLang = root.optString("uiLang", "");
                if (!uiLang.isEmpty()) {
                    ed.putString(KEY_UI_LANG, uiLang);
                }
                int uiDark = root.optInt("uiDark", -1);
                if (uiDark == 0 || uiDark == 1) {
                    ed.putBoolean(KEY_UI_DARK, uiDark == 1);
                }
                ed.commit();
            } finally {
                sSuppressSyncPush = false;
            }
            return nextRev;
        } catch (Throwable ignored) {
            return -1L;
        }
    }

    public static boolean syncPullSharedStateFromProvider(Context context, boolean force) {
        if (context == null || "org.telegram.wgplus.module".equals(context.getPackageName())) {
            return false;
        }
        long now = SystemClock.elapsedRealtime();
        if (!force && now - sLastSyncPullMs < 8_000L) {
            return false;
        }
        sLastSyncPullMs = now;
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            String json = null;
            try {
                Bundle res = appCtx.getContentResolver().call(
                        STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_SYNC_PULL_STATE,
                        appCtx.getPackageName(),
                        null
                );
                if (res != null) {
                    json = res.getString(KeepaliveStatusProvider.RESULT_JSON, "");
                }
            } catch (Throwable ignored) {
            }
            // Prefer full-secret local root mirror BEFORE XSharedPreferences (which strips keys).
            if (json == null || json.isEmpty()) {
                json = readSyncBundleFromLocalMirrorFile(appCtx);
            }
            if (json == null || json.isEmpty()) {
                json = readSyncBundleFromXSharedPrefs();
            }
            if (json == null || json.isEmpty()) {
                return false;
            }
            JSONObject obj = new JSONObject(json);
            long remoteRev = obj.optLong("stateRev", 0L);
            long localRev = getPrefs(appCtx).getLong(KEY_SHARED_STATE_REV, 0L);
            String remoteActiveId = obj.optString("activeProfileId", "").trim();
            String localActiveId = getPrefs(appCtx).getString(KEY_ACTIVE_PROFILE_ID, "").trim();
            boolean equalRevProfileDrift = (remoteRev == localRev)
                    && !remoteActiveId.isEmpty() && !remoteActiveId.equals(localActiveId);
            JSONArray remoteProfiles = obj.optJSONArray("profiles");
            boolean remoteHasPeer = false;
            if (remoteProfiles != null) {
                for (int i = 0; i < remoteProfiles.length(); i++) {
                    JSONObject p = remoteProfiles.optJSONObject(i);
                    if (p != null && !p.optString("endpoint", "").trim().isEmpty()) {
                        remoteHasPeer = true;
                        break;
                    }
                }
            }
            if (remoteRev > localRev || equalRevProfileDrift || (remoteHasPeer && !hasAnyConfiguredProfile(appCtx))) {
                long applied = importSharedSyncBundleJson(appCtx, json, true);
                return applied >= 0L;
            }
            if (localRev > remoteRev && hasAnyConfiguredProfile(appCtx)) {
                scheduleSyncPushToProvider(appCtx);
            } else if (remoteRev == 0L && !remoteHasPeer && hasAnyConfiguredProfile(appCtx)) {
                scheduleSyncPushToProvider(appCtx);
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static void scheduleSyncPushToProvider(Context context) {
        if (sSuppressSyncPush) {
            return;
        }
        final Context appCtx = context != null
                ? (context.getApplicationContext() != null ? context.getApplicationContext() : context)
                : sSyncContext;
        if (appCtx == null) {
            return;
        }
        SharedPreferences prefs = getPrefs(appCtx);
        long nextRev = prefs.getLong(KEY_SHARED_STATE_REV, 0L) + 1L;
        prefs.edit().putLong(KEY_SHARED_STATE_REV, nextRev).apply();
        if ("org.telegram.wgplus.module".equals(appCtx.getPackageName())) {
            publishWorldReadableSyncBundle(appCtx);
            return;
        }
        SYNC_EXEC.execute(() -> {
            try {
                Bundle extras = new Bundle();
                extras.putString(KeepaliveStatusProvider.EXTRA_JSON, exportSharedSyncBundleJson(appCtx));
                Bundle res = appCtx.getContentResolver().call(
                        STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_SYNC_PUSH_STATE,
                        appCtx.getPackageName(),
                        extras
                );
                if (res != null) {
                    long canonicalRev = res.getLong("stateRev", -1L);
                    if (canonicalRev > 0L) {
                        getPrefs(appCtx).edit().putLong(KEY_SHARED_STATE_REV, canonicalRev).apply();
                    }
                }
            } catch (Throwable ignored) {
            }
            publishWorldReadableSyncBundle(appCtx);
        });
    }

    @SuppressWarnings("deprecation")
    public static void publishWorldReadableSyncBundle(Context appCtx) {
        if (appCtx == null) {
            return;
        }
        final String fullJson = exportSharedSyncBundleJson(appCtx, true);
        final String safeMetadataJson = exportSharedSyncBundleJson(appCtx, false);
        try {
            // Never write PrivateKey/PresharedKey into MODE_WORLD_READABLE storage;
            // secrets sync exclusively over authenticated Binder IPC and 0600 UID-owned mirrors.
            SharedPreferences sp = appCtx.getSharedPreferences("wg_plus_xshared_sync", Context.MODE_WORLD_READABLE);
            sp.edit().putString("bundle_json", safeMetadataJson).apply();
        } catch (SecurityException ignored) {
            // MODE_WORLD_READABLE is only allowed when LSPosed/Vector hooks ContextImpl for this module
        } catch (Throwable ignored) {
        }
        mirrorSyncBundleToClientsAsync(appCtx, fullJson);
    }

    private static void mirrorSyncBundleToClientsAsync(final Context appCtx, final String json) {
        if (appCtx == null || json == null || json.isEmpty()) {
            return;
        }
        SYNC_EXEC.execute(() -> {
            try {
                if (!PrivilegeBridge.hasRootAccess()) {
                    return;
                }
                List<String> targets = ContinuityBridgeManager.getInstalledTargetPackages(appCtx);
                if (targets == null || targets.isEmpty()) {
                    return;
                }
                String b64 = android.util.Base64.encodeToString(
                        json.getBytes(StandardCharsets.UTF_8),
                        android.util.Base64.NO_WRAP
                );
                StringBuilder cmd = new StringBuilder();
                for (String pkg : targets) {
                    if (pkg == null || !pkg.matches("[a-zA-Z0-9._]+") || "org.telegram.wgplus.module".equals(pkg)) {
                        continue;
                    }
                    int uid;
                    try {
                        uid = appCtx.getPackageManager().getPackageUid(pkg, 0);
                    } catch (Throwable ignored) {
                        continue;
                    }
                    String dir = "/data/data/" + pkg + "/files";
                    String path = dir + "/wg_plus_sync_mirror.json";
                    cmd.append("mkdir -p ").append(dir)
                            .append(" && printf '%s' '").append(b64).append("' | base64 -d > ").append(path)
                            .append(" && chown ").append(uid).append(':').append(uid).append(' ').append(path)
                            .append(" && chmod 600 ").append(path).append("; ");
                }
                if (cmd.length() > 0) {
                    PrivilegeBridge.runRootCommand(cmd.toString(), 4000);
                }
            } catch (Throwable ignored) {
            }
        });
    }

    private static String readSyncBundleFromLocalMirrorFile(Context appCtx) {
        if (appCtx == null) {
            return "";
        }
        try {
            java.io.File file = new java.io.File(appCtx.getFilesDir(), "wg_plus_sync_mirror.json");
            if (!file.isFile() || file.length() <= 0 || file.length() > 1_048_576L) {
                return "";
            }
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String readSyncBundleFromXSharedPrefs() {
        try {
            ClassLoader xposedCl = de.robv.android.xposed.XposedBridge.class.getClassLoader();
            Class<?> xspClass = xposedCl != null
                    ? xposedCl.loadClass("de.robv.android.xposed.XSharedPreferences")
                    : Class.forName("de.robv.android.xposed.XSharedPreferences");
            Object xsp = xspClass.getConstructor(String.class, String.class)
                    .newInstance("org.telegram.wgplus.module", "wg_plus_xshared_sync");
            try {
                xspClass.getMethod("reload").invoke(xsp);
            } catch (Throwable ignored) {
            }
            Object val = xspClass.getMethod("getString", String.class, String.class)
                    .invoke(xsp, "bundle_json", "");
            return val instanceof String ? (String) val : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    public static Integer getCachedPingMs(String profileId) {
        if (profileId == null || profileId.isEmpty()) {
            return null;
        }
        return sPingCacheMs.get(profileId);
    }

    public static void clearRuntimePingCache() {
        sPingCacheMs.clear();
    }

    public static long getTunnelStartedAtMs() {
        return sTunnelStartedAtMs;
    }

    public static void reportHookActiveToProvider(Context context, String hostPkg) {
        if (context == null || hostPkg == null || hostPkg.isEmpty()) {
            return;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            appCtx.getContentResolver().call(
                    STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_REPORT_HOOK_ACTIVE,
                    hostPkg,
                    null
            );
        } catch (Throwable ignored) {
        }
    }

    public static Bundle queryHookStatusFromProvider(Context context) {
        if (context == null || Looper.myLooper() == Looper.getMainLooper()) {
            return null;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            return appCtx.getContentResolver().call(
                    STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_QUERY_HOOK_STATUS,
                    appCtx.getPackageName(),
                    null
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static void pollAndRunRemoteHygieneIfRequested(Context context) {
        if (context == null || Looper.myLooper() == Looper.getMainLooper()) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        if (now - sLastRemoteHygieneCheckMs < 15_000L) {
            return;
        }
        sLastRemoteHygieneCheckMs = now;
        try {
            Bundle b = queryHookStatusFromProvider(context);
            if (b != null) {
                long reqTs = b.getLong(KeepaliveStatusProvider.RESULT_HYGIENE_REQ_MS, 0L);
                if (reqTs > 0L && reqTs > sLastHandledHygieneReqMs) {
                    sLastHandledHygieneReqMs = reqTs;
                    ModuleHygieneManager.cleanCachesSafely(context, true);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    public static boolean isArabic(Context context) {
        SharedPreferences prefs = getPrefs(context);
        String saved = prefs.getString(KEY_UI_LANG, null);
        if (saved != null) {
            return WgStrings.LANG_AR.equals(saved);
        }
        String sysLang = Locale.getDefault().getLanguage();
        return sysLang != null && sysLang.toLowerCase(Locale.ROOT).startsWith("ar");
    }

    public static void setArabic(Context context, boolean arabic) {
        getPrefs(context).edit()
                .putString(KEY_UI_LANG, arabic ? WgStrings.LANG_AR : WgStrings.LANG_EN)
                .apply();
        scheduleSyncPushToProvider(context);
    }

    public static boolean isDarkTheme(Context context) {
        SharedPreferences prefs = getPrefs(context);
        if (prefs.contains(KEY_UI_DARK)) {
            return prefs.getBoolean(KEY_UI_DARK, true);
        }
        try {
            int nightMask = context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
            if (nightMask == Configuration.UI_MODE_NIGHT_NO) {
                return false;
            }
        } catch (Throwable ignored) {
        }
        return true;
    }

    public static void setDarkTheme(Context context, boolean dark) {
        getPrefs(context).edit().putBoolean(KEY_UI_DARK, dark).apply();
        scheduleSyncPushToProvider(context);
    }

    public static boolean isAutoConnectEnabled(Context context) {
        return getPrefs(context).getBoolean(KEY_ENABLED, false);
    }

    public static void setEnabled(Context context, boolean enabled) {
        getPrefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply();
        scheduleSyncPushToProvider(context);
    }

    public static boolean isRouteCallsEnabled(Context context) {
        return getPrefs(context).getBoolean(KEY_ROUTE_CALLS, true);
    }

    public static void setRouteCallsEnabled(Context context, boolean routeCalls) {
        getPrefs(context).edit().putBoolean(KEY_ROUTE_CALLS, routeCalls).apply();
        scheduleSyncPushToProvider(context);
    }

    public static boolean isKillSwitchEnabled(Context context) {
        return context != null && getPrefs(context).getBoolean(KEY_KILL_SWITCH, false);
    }

    public static void setKillSwitchEnabled(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader,
            boolean enabled
    ) {
        if (context == null) {
            return;
        }
        getPrefs(context).edit().putBoolean(KEY_KILL_SWITCH, enabled).commit();
        scheduleSyncPushToProvider(context);
        if (isTunnelRunning(context, moduleApkPath)) {
            return;
        }
        if (enabled) {
            enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
        } else {
            releaseKillSwitchGuard(context, moduleApkPath, telegramClassLoader);
        }
    }

    public static boolean isAutoFailoverEnabled(Context context) {
        return context != null && getPrefs(context).getBoolean(KEY_AUTO_FAILOVER, false);
    }

    public static void setAutoFailoverEnabled(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader,
            boolean enabled
    ) {
        if (context == null) {
            return;
        }
        getPrefs(context).edit().putBoolean(KEY_AUTO_FAILOVER, enabled).commit();
        scheduleSyncPushToProvider(context);
        if (isTunnelRunning(context, moduleApkPath)) {
            startFailoverMonitor(context, moduleApkPath, telegramClassLoader);
        }
    }

    public static boolean isDohEnabled(Context context) {
        return context == null || getPrefs(context).getBoolean(KEY_DOH_ENABLED, true);
    }

    public static void setDohEnabled(Context context, boolean enabled) {
        if (context != null) {
            getPrefs(context).edit().putBoolean(KEY_DOH_ENABLED, enabled).apply();
            scheduleSyncPushToProvider(context);
        }
    }

    public static boolean isSmartKeepaliveEnabled(Context context) {
        if (context == null) {
            return false;
        }
        SharedPreferences prefs = getPrefs(context);
        if (!prefs.getBoolean(KEY_MIGRATED_FORCED_CONTINUITY_V1, false)) {
            prefs.edit()
                    .putBoolean(KEY_SMART_KEEPALIVE, false)
                    .putBoolean(KEY_MIGRATED_FORCED_CONTINUITY_V1, true)
                    .commit();
            return false;
        }
        return prefs.getBoolean(KEY_SMART_KEEPALIVE, false);
    }

    public static void setSmartKeepaliveEnabled(Context context, String moduleApkPath, boolean enabled) {
        if (context == null) {
            return;
        }
        getPrefs(context).edit()
                .putBoolean(KEY_SMART_KEEPALIVE, enabled)
                .putBoolean(KEY_MIGRATED_FORCED_CONTINUITY_V1, true)
                .apply();
        scheduleSyncPushToProvider(context);
        if (!enabled && sKeepalivePausedForIdle) {
            restoreActiveKeepaliveNow(context, moduleApkPath);
        }
    }

    /**
     * Returns true when Telegram's native tgnet sockets should be forced awake 24/7
     * (blocking setAppPaused(true) and native_pauseNetwork) so background delivery,
     * messages, and incoming calls stay live across cellular and Wi-Fi.
     */
    public static boolean shouldForceTelegramAlwaysAwake(Context context, String moduleApkPath) {
        if (context == null) {
            return false;
        }
        if (!sConnectedProfileId.isEmpty()) {
            return true;
        }
        try {
            if (isAutoConnectEnabled(context) || isKillSwitchEnabled(context)) {
                return true;
            }
            String savedConn = getPrefs(context).getString(KEY_CONNECTED_PROFILE_ID, "");
            if (savedConn != null && !savedConn.isEmpty()) {
                return true;
            }
        } catch (Throwable ignored) {
        }
        return isTunnelRunning(context, moduleApkPath);
    }

    private static void acquireForcedContinuityLocks(Context context) {
        if (context == null) {
            return;
        }
        synchronized (LOCK_SYNC) {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            try {
                if (sForcedWakeLock == null) {
                    PowerManager pm = (PowerManager) appCtx.getSystemService(Context.POWER_SERVICE);
                    if (pm != null) {
                        sForcedWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "WireGuardPlus::ForcedContinuityWakeLock");
                        sForcedWakeLock.setReferenceCounted(false);
                    }
                }
                if (sForcedWakeLock != null && !sForcedWakeLock.isHeld()) {
                    sForcedWakeLock.acquire();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (sForcedWifiLock == null) {
                    WifiManager wm = (WifiManager) appCtx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                    if (wm != null) {
                        int lockMode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                                ? WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                                : WifiManager.WIFI_MODE_FULL_HIGH_PERF;
                        sForcedWifiLock = wm.createWifiLock(lockMode, "WireGuardPlus::ForcedContinuityWifiLock");
                        sForcedWifiLock.setReferenceCounted(false);
                    }
                }
                if (sForcedWifiLock != null && !sForcedWifiLock.isHeld()) {
                    sForcedWifiLock.acquire();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static void releaseForcedContinuityLocks() {
        synchronized (LOCK_SYNC) {
            try {
                if (sForcedWakeLock != null && sForcedWakeLock.isHeld()) {
                    sForcedWakeLock.release();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (sForcedWifiLock != null && sForcedWifiLock.isHeld()) {
                    sForcedWifiLock.release();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static boolean isCellularNetworkActive(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false;
        }
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return false;
            }
            Network active = cm.getActiveNetwork();
            if (active == null) {
                return false;
            }
            NetworkCapabilities caps = cm.getNetworkCapabilities(active);
            return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static int effectiveKeepAlive(Context context, int configuredKeepAlive) {
        int clamped = clampKeepAlive(configuredKeepAlive);
        return isCellularNetworkActive(context) ? Math.min(18, clamped) : clamped;
    }

    /**
     * Queries the companion module's {@link KeepaliveStatusProvider} to apply elevated
     * {@code setProcessImportant} + silent {@link KeepaliveBridgeListenerService} protection
     * for this host process before falling back to a standard foreground service notification.
     */
    public static boolean queryAndSyncStealthContinuity(Context context, boolean wantsAwake, boolean forceFresh) {
        if (context == null) {
            return false;
        }
        long now = SystemClock.elapsedRealtime();
        if (!forceFresh && wantsAwake == sLastStealthWantsAwake && (now - sLastStealthQueryMs) < 60_000L) {
            return sLastStealthProtected;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        // Never block the host app UI thread on synchronous ContentProvider Binder IPC
        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (now - sLastStealthQueryMs >= 10_000L) {
                sLastStealthQueryMs = now;
                getGuardianExecutor().execute(() -> queryAndSyncStealthContinuity(appCtx, wantsAwake, true));
            }
            return sLastStealthProtected;
        }
        try {
            Bundle extras = new Bundle();
            extras.putInt(KeepaliveStatusProvider.EXTRA_PID, Process.myPid());
            extras.putBoolean(KeepaliveStatusProvider.EXTRA_WANTS_ALWAYS_AWAKE, wantsAwake);
            Bundle res = appCtx.getContentResolver().call(
                    STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_ENSURE_STEALTH,
                    appCtx.getPackageName(),
                    extras
            );
            boolean stealth = res != null && res.getBoolean(KeepaliveStatusProvider.RESULT_STEALTH_PROTECTED, false);
            sLastStealthWantsAwake = wantsAwake;
            sLastStealthProtected = stealth;
            sLastStealthQueryMs = now;
            return stealth;
        } catch (Throwable ignored) {
            sLastStealthWantsAwake = wantsAwake;
            sLastStealthProtected = false;
            sLastStealthQueryMs = now;
            return false;
        }
    }

    public static void syncForegroundKeepaliveService(Context context, boolean active) {
        if (context == null) {
            return;
        }
        if (TelegramXBridge.PACKAGE_NAME.equals(context.getPackageName())) {
            return;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            Intent intent = new Intent();
            intent.setClassName(appCtx.getPackageName(), FG_SERVICE_CLASS);
            if (!active) {
                queryAndSyncStealthContinuity(appCtx, false, true);
                intent.putExtra(EXTRA_STOP_FOREGROUND_KEEPALIVE, true);
                try {
                    appCtx.startService(intent);
                } catch (Throwable ignored) {
                }
                return;
            }
            if (queryAndSyncStealthContinuity(appCtx, true, true)) {
                // Stealth protection active (elevated force-imp and/or silent NotificationListener bind):
                // Do NOT call startForegroundService (avoids 5s timer crash and removes any old FG notification).
                intent.setAction(ACTION_SYNC_CONTINUITY);
                try {
                    appCtx.startService(intent);
                } catch (Throwable ignored) {
                }
                return;
            }
            intent.putExtra(EXTRA_EXPECT_FOREGROUND_PROMOTE, true);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    && canPromoteNotificationsServiceToForeground(appCtx)) {
                appCtx.startForegroundService(intent);
            } else {
                appCtx.startService(intent);
            }
        } catch (Throwable ignored) {
            // Android 12+ may restrict background startForegroundService; NotificationsService.onStartCommand
            // still promotes on next foreground transition or Telegram push tick.
        }
    }

    private static boolean canPromoteNotificationsServiceToForeground(Context context) {
        if (context == null) {
            return false;
        }
        try {
            PackageManager pm = context.getPackageManager();
            if (pm == null) {
                return false;
            }
            ServiceInfo si = pm.getServiceInfo(new ComponentName(context.getPackageName(), FG_SERVICE_CLASS), 0);
            if (si == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= 34
                    && context.getApplicationInfo() != null
                    && context.getApplicationInfo().targetSdkVersion >= 34
                    && si.getForegroundServiceType() == 0) {
                return false;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String computeActiveNetworkSignature(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return "";
        }
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return "";
            }
            Network active = cm.getActiveNetwork();
            if (active == null) {
                return "";
            }
            NetworkCapabilities caps = cm.getNetworkCapabilities(active);
            if (caps == null) {
                return "";
            }
            StringBuilder transport = new StringBuilder(4);
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                transport.append('C');
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                transport.append('W');
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                transport.append('E');
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                transport.append('V');
            }

            String ifName = "";
            List<String> addrs = new ArrayList<>();
            LinkProperties lp = cm.getLinkProperties(active);
            if (lp != null) {
                ifName = safeTrim(lp.getInterfaceName());
                for (LinkAddress la : lp.getLinkAddresses()) {
                    if (la == null || la.getAddress() == null) {
                        continue;
                    }
                    InetAddress addr = la.getAddress();
                    if (addr.isLinkLocalAddress() || addr.isLoopbackAddress()) {
                        continue;
                    }
                    // Track IPv4 and at most one non-local IPv6 fallback so temporary IPv6 privacy rotation
                    // never causes spurious socket teardowns on carrier/Wi-Fi networks.
                    if (addr instanceof Inet4Address || addrs.isEmpty()) {
                        addrs.add(addr.getHostAddress() + "/" + la.getPrefixLength());
                    }
                }
                Collections.sort(addrs);
            }
            return active.toString() + "|" + transport + "|" + ifName + "|" + String.join(",", addrs);
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static void syncEndpointDnsHintsToNative(Context context, String rawEndpoint) {
        if (context == null) {
            return;
        }
        try {
            SharedPreferences prefs = getPrefs(context);
            String rawCache = prefs.getString(KEY_DNS_LKG_CACHE_JSON, "");
            if (NativeBridgeLoader.isLoaded() && rawCache != null && !rawCache.isEmpty()) {
                JSONObject obj = new JSONObject(rawCache);
                Iterator<String> keys = obj.keys();
                while (keys.hasNext()) {
                    String host = keys.next();
                    String ip = obj.optString(host, "");
                    if (!host.isEmpty() && !ip.isEmpty()) {
                        Wgbridge.registerEndpointIpHint(host, ip);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        String host = extractEndpointHost(rawEndpoint);
        if (host.isEmpty()) {
            return;
        }
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            if (addrs != null && addrs.length > 0) {
                InetAddress chosen = addrs[0];
                for (InetAddress cand : addrs) {
                    if (cand instanceof Inet4Address) {
                        chosen = cand;
                        break;
                    }
                }
                String ip = chosen.getHostAddress();
                if (ip != null && !ip.isEmpty()) {
                    if (NativeBridgeLoader.isLoaded()) {
                        Wgbridge.registerEndpointIpHint(host, ip);
                    }
                    persistEndpointDnsHint(context, host, ip);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void persistEndpointDnsHint(Context context, String host, String ip) {
        if (context == null || host == null || host.isEmpty() || ip == null || ip.isEmpty()) {
            return;
        }
        try {
            SharedPreferences prefs = getPrefs(context);
            String rawCache = prefs.getString(KEY_DNS_LKG_CACHE_JSON, "");
            JSONObject obj = (rawCache != null && !rawCache.isEmpty()) ? new JSONObject(rawCache) : new JSONObject();
            obj.put(host.toLowerCase(Locale.ROOT), ip);
            prefs.edit().putString(KEY_DNS_LKG_CACHE_JSON, obj.toString()).apply();
        } catch (Throwable ignored) {
        }
    }

    private static String extractEndpointHost(String rawEndpoint) {
        String ep = safeTrim(rawEndpoint);
        if (ep.isEmpty() || ep.startsWith("[")) {
            return "";
        }
        int lastColon = ep.lastIndexOf(':');
        if (lastColon <= 0 || lastColon == ep.length() - 1) {
            return "";
        }
        String host = ep.substring(0, lastColon).trim();
        if (host.indexOf(':') >= 0) {
            return "";
        }
        return host;
    }

    public static synchronized List<TunnelConfig> loadProfiles(Context context) {
        SharedPreferences prefs = getPrefs(context);
        boolean globalEnabled = prefs.getBoolean(KEY_ENABLED, false);
        boolean globalCalls = prefs.getBoolean(KEY_ROUTE_CALLS, true);
        boolean isAr = isArabic(context);

        List<TunnelConfig> list = new ArrayList<>();
        String rawJson = prefs.getString(KEY_PROFILES_JSON, null);

        if (rawJson != null && !rawJson.trim().isEmpty()) {
            try {
                JSONArray arr = new JSONArray(rawJson);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject obj = arr.optJSONObject(i);
                    if (obj == null) {
                        continue;
                    }
                    TunnelConfig cfg = configFromJsonObject(obj, true);
                    cfg.enabled = globalEnabled;
                    cfg.routeCalls = globalCalls;
                    if (cfg.name.isEmpty()) {
                        cfg.name = deriveProfileName(cfg.endpoint, isAr, i + 1);
                    }
                    list.add(cfg);
                }
            } catch (Throwable t) {
                Log.w(TAG, "Failed parsing profiles JSON: " + t.getMessage());
            }
        }

        if (list.isEmpty()) {
            TunnelConfig migrated = new TunnelConfig();
            migrated.id = UUID.randomUUID().toString();
            migrated.enabled = globalEnabled;
            migrated.routeCalls = globalCalls;
            migrated.privateKey = WgKeystoreCrypto.decrypt(prefs.getString(KEY_PRIVATE_KEY, ""));
            migrated.address = prefs.getString(KEY_ADDRESS, "10.0.0.2/32");
            migrated.dns = prefs.getString(KEY_DNS, "1.1.1.1");
            migrated.publicKey = prefs.getString(KEY_PUBLIC_KEY, "");
            migrated.endpoint = prefs.getString(KEY_ENDPOINT, "");
            migrated.keepAlive = clampKeepAlive(prefs.getInt(KEY_KEEPALIVE, 25));
            migrated.mtu = 1280;
            migrated.name = deriveProfileName(migrated.endpoint, isAr, 1);
            list.add(migrated);

            persistProfilesLocked(prefs, list, migrated.id, globalEnabled, globalCalls);
            if (prefs.contains(KEY_PRIVATE_KEY)) {
                prefs.edit().remove(KEY_PRIVATE_KEY).apply();
            }
        }

        return list;
    }

    private static TunnelConfig configFromJsonObject(JSONObject obj, boolean decryptKeystore) {
        TunnelConfig cfg = new TunnelConfig();
        cfg.id = safeTrim(obj.optString("id", UUID.randomUUID().toString()));
        if (cfg.id.isEmpty()) {
            cfg.id = UUID.randomUUID().toString();
        }
        cfg.name = safeTrim(obj.optString("name", ""));
        String rawPriv = obj.optString("privateKey", "");
        String rawPsk = obj.optString("presharedKey", "");
        cfg.privateKey = decryptKeystore ? WgKeystoreCrypto.decrypt(rawPriv) : safeTrim(rawPriv);
        cfg.presharedKey = decryptKeystore ? WgKeystoreCrypto.decrypt(rawPsk) : safeTrim(rawPsk);
        cfg.address = safeTrim(obj.optString("address", "10.0.0.2/32"));
        cfg.dns = safeTrim(obj.optString("dns", "1.1.1.1"));
        cfg.publicKey = safeTrim(obj.optString("publicKey", ""));
        cfg.endpoint = safeTrim(obj.optString("endpoint", ""));
        cfg.keepAlive = clampKeepAlive(obj.optInt("keepAlive", 25));
        cfg.mtu = clampMtu(obj.optInt("mtu", 1280));
        cfg.jc = Math.max(0, Math.min(15, obj.optInt("jc", 0)));
        cfg.jmin = Math.max(0, Math.min(1200, obj.optInt("jmin", 0)));
        cfg.jmax = Math.max(0, Math.min(1200, obj.optInt("jmax", 0)));
        cfg.s1 = Math.max(0, Math.min(512, obj.optInt("s1", 0)));
        cfg.s2 = Math.max(0, Math.min(512, obj.optInt("s2", 0)));
        cfg.s3 = Math.max(0, Math.min(512, obj.optInt("s3", 0)));
        cfg.s4 = Math.max(0, Math.min(512, obj.optInt("s4", 0)));
        cfg.h1 = safeTrim(obj.optString("h1", ""));
        cfg.h2 = safeTrim(obj.optString("h2", ""));
        cfg.h3 = safeTrim(obj.optString("h3", ""));
        cfg.h4 = safeTrim(obj.optString("h4", ""));
        cfg.i1 = safeTrim(obj.optString("i1", ""));
        cfg.i2 = safeTrim(obj.optString("i2", ""));
        cfg.i3 = safeTrim(obj.optString("i3", ""));
        cfg.i4 = safeTrim(obj.optString("i4", ""));
        cfg.i5 = safeTrim(obj.optString("i5", ""));
        cfg.reserved = safeTrim(obj.optString("reserved", ""));
        cfg.isWarp = obj.optBoolean("isWarp", false);
        return cfg;
    }

    private static JSONObject configToJsonObject(TunnelConfig cfg, boolean encryptKeystore) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("id", cfg.id);
        obj.put("name", safeTrim(cfg.name));
        String priv = safeTrim(cfg.privateKey);
        String psk = safeTrim(cfg.presharedKey);
        obj.put("privateKey", encryptKeystore ? WgKeystoreCrypto.encrypt(priv) : priv);
        obj.put("presharedKey", encryptKeystore ? WgKeystoreCrypto.encrypt(psk) : psk);
        obj.put("address", safeTrim(cfg.address).isEmpty() ? "10.0.0.2/32" : safeTrim(cfg.address));
        obj.put("dns", safeTrim(cfg.dns).isEmpty() ? "1.1.1.1" : safeTrim(cfg.dns));
        obj.put("publicKey", safeTrim(cfg.publicKey));
        obj.put("endpoint", safeTrim(cfg.endpoint));
        obj.put("keepAlive", clampKeepAlive(cfg.keepAlive));
        obj.put("mtu", clampMtu(cfg.mtu));
        obj.put("jc", Math.max(0, Math.min(15, cfg.jc)));
        obj.put("jmin", Math.max(0, Math.min(1200, cfg.jmin)));
        obj.put("jmax", Math.max(0, Math.min(1200, cfg.jmax)));
        obj.put("s1", Math.max(0, Math.min(512, cfg.s1)));
        obj.put("s2", Math.max(0, Math.min(512, cfg.s2)));
        obj.put("s3", Math.max(0, Math.min(512, cfg.s3)));
        obj.put("s4", Math.max(0, Math.min(512, cfg.s4)));
        obj.put("h1", safeTrim(cfg.h1));
        obj.put("h2", safeTrim(cfg.h2));
        obj.put("h3", safeTrim(cfg.h3));
        obj.put("h4", safeTrim(cfg.h4));
        obj.put("i1", safeTrim(cfg.i1));
        obj.put("i2", safeTrim(cfg.i2));
        obj.put("i3", safeTrim(cfg.i3));
        obj.put("i4", safeTrim(cfg.i4));
        obj.put("i5", safeTrim(cfg.i5));
        obj.put("reserved", safeTrim(cfg.reserved));
        obj.put("isWarp", cfg.isWarp);
        return obj;
    }

    /**
     * Pure-Java multi-profile backup serializer (portable JSON bundle including AmneziaWG fields).
     */
    public static String serializeProfilesBackupJson(List<TunnelConfig> profiles) throws WgStrings.WgException {
        try {
            JSONObject root = new JSONObject();
            root.put("schema", BACKUP_SCHEMA);
            root.put("version", WgStrings.VERSION_LABEL);
            JSONArray arr = new JSONArray();
            if (profiles != null) {
                for (TunnelConfig cfg : profiles) {
                    if (cfg != null && cfg.hasPeerConfigured()) {
                        arr.put(configToJsonObject(cfg, false));
                    }
                }
            }
            if (arr.length() == 0 && profiles != null && !profiles.isEmpty()) {
                arr.put(configToJsonObject(profiles.get(0), false));
            }
            root.put("profiles", arr);
            return root.toString(2);
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID, t.getMessage(), t);
        }
    }

    /**
     * Pure-Java multi-profile backup deserializer.
     */
    public static List<TunnelConfig> deserializeProfilesBackupJson(String rawJson) throws WgStrings.WgException {
        if (rawJson == null || rawJson.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
        }
        try {
            JSONObject root = new JSONObject(rawJson.trim());
            if (!BACKUP_SCHEMA.equals(root.optString("schema", ""))) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID);
            }
            JSONArray arr = root.optJSONArray("profiles");
            if (arr == null || arr.length() == 0) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID);
            }
            List<TunnelConfig> out = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject item = arr.optJSONObject(i);
                if (item != null) {
                    TunnelConfig cfg = configFromJsonObject(item, false);
                    cfg.id = UUID.randomUUID().toString();
                    out.add(cfg);
                }
            }
            if (out.isEmpty()) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID);
            }
            return out;
        } catch (WgStrings.WgException we) {
            throw we;
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID, t.getMessage(), t);
        }
    }

    public static synchronized String exportAllProfilesBackupJson(Context context) throws WgStrings.WgException {
        List<TunnelConfig> profiles = loadProfiles(context);
        return serializeProfilesBackupJson(profiles);
    }

    public static boolean isEncryptedBackupEnvelope(String raw) {
        if (raw == null) {
            return false;
        }
        String t = raw.trim();
        if (!t.startsWith("{")) {
            return false;
        }
        try {
            JSONObject obj = new JSONObject(t);
            return BACKUP_SCHEMA.equals(obj.optString("format", ""));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static synchronized String exportEncryptedBackupV1(
            Context context,
            String moduleApkPath,
            String passphrase
    ) throws WgStrings.WgException {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            String plainJson = exportAllProfilesBackupJson(context);
            return Wgbridge.encryptBackupV1(plainJson, passphrase == null ? "" : passphrase);
        } catch (WgStrings.WgException we) {
            throw we;
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID, t.getMessage(), t);
        }
    }

    public static synchronized int importEncryptedBackupV1(
            Context context,
            String moduleApkPath,
            String envelopeJson,
            String passphrase
    ) throws WgStrings.WgException {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            String plainJson = Wgbridge.decryptBackupV1(envelopeJson, passphrase == null ? "" : passphrase);
            return importProfilesBackupJson(context, plainJson);
        } catch (WgStrings.WgException we) {
            throw we;
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID, t.getMessage(), t);
        }
    }

    public static synchronized int importProfilesBackupJson(Context context, String rawJson) throws WgStrings.WgException {
        List<TunnelConfig> incoming = deserializeProfilesBackupJson(rawJson);
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> existing = loadProfiles(context);
        boolean isAr = isArabic(context);
        boolean autoStart = prefs.getBoolean(KEY_ENABLED, false);
        boolean routeCalls = prefs.getBoolean(KEY_ROUTE_CALLS, true);

        if (existing.size() == 1 && !existing.get(0).hasPeerConfigured()) {
            existing.clear();
        }

        String lastImportedId = "";
        int addedCount = 0;
        for (int i = 0; i < incoming.size(); i++) {
            TunnelConfig item = incoming.get(i);
            item.enabled = autoStart;
            item.routeCalls = routeCalls;
            String baseName = safeTrim(item.name);
            if (baseName.isEmpty()) {
                baseName = deriveProfileName(item.endpoint, isAr, existing.size() + 1);
            }
            item.name = uniqueProfileName(baseName, existing, item.id);
            existing.add(item);
            lastImportedId = item.id;
            addedCount++;
        }

        if (!existing.isEmpty()) {
            String activeId = lastImportedId.isEmpty() ? existing.get(0).id : lastImportedId;
            persistProfilesLocked(prefs, existing, activeId, autoStart, routeCalls);
        }
        return addedCount;
    }

    public static synchronized boolean hasAnyConfiguredProfile(Context context) {
        if (context == null) {
            return false;
        }
        List<TunnelConfig> profiles = loadProfiles(context);
        for (TunnelConfig p : profiles) {
            if (p != null && p.hasPeerConfigured()) {
                return true;
            }
        }
        return false;
    }

    public static synchronized TunnelConfig loadConfig(Context context) {
        List<TunnelConfig> profiles = loadProfiles(context);
        String activeId = getPrefs(context).getString(KEY_ACTIVE_PROFILE_ID, "");
        for (TunnelConfig p : profiles) {
            if (p.id.equals(activeId)) {
                return p.copy();
            }
        }
        return profiles.get(0).copy();
    }

    public static synchronized void saveConfig(Context context, TunnelConfig updated) {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        boolean isAr = isArabic(context);

        if (updated.id == null || updated.id.trim().isEmpty()) {
            updated.id = UUID.randomUUID().toString();
        }
        if (safeTrim(updated.name).isEmpty()) {
            updated.name = deriveProfileName(updated.endpoint, isAr, profiles.size() + 1);
        }

        boolean replaced = false;
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).id.equals(updated.id)) {
                profiles.set(i, updated.copy());
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            profiles.add(updated.copy());
        }

        persistProfilesLocked(prefs, profiles, updated.id, updated.enabled, updated.routeCalls);
        syncDeterministicSocksCredentialsForProfile(context, updated);
    }

    public static synchronized TunnelConfig selectProfile(Context context, String profileId) {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        for (TunnelConfig p : profiles) {
            if (p.id.equals(profileId)) {
                prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, p.id).commit();
                syncDeterministicSocksCredentialsForProfile(context, p);
                scheduleSyncPushToProvider(context);
                return p.copy();
            }
        }
        return profiles.get(0).copy();
    }

    public static synchronized TunnelConfig createNewProfile(Context context) {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        boolean isAr = isArabic(context);

        TunnelConfig fresh = new TunnelConfig();
        fresh.id = UUID.randomUUID().toString();
        String baseName = WgStrings.defaultProfileName(isAr, profiles.size() + 1);
        fresh.name = uniqueProfileName(baseName, profiles, fresh.id);
        fresh.enabled = prefs.getBoolean(KEY_ENABLED, false);
        fresh.routeCalls = prefs.getBoolean(KEY_ROUTE_CALLS, true);
        fresh.address = "10.0.0.2/32";
        fresh.dns = "1.1.1.1";
        fresh.keepAlive = 25;
        fresh.mtu = 1280;

        profiles.add(fresh);
        persistProfilesLocked(prefs, profiles, fresh.id, fresh.enabled, fresh.routeCalls);
        return fresh.copy();
    }

    public static synchronized TunnelConfig importConfAsProfile(
            Context context,
            String confText,
            String suggestedName,
            boolean autoStart,
            boolean routeCalls
    ) throws WgStrings.WgException {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        boolean isAr = isArabic(context);

        TunnelConfig parsed = parseConfText(confText, null);
        parsed.enabled = autoStart;
        parsed.routeCalls = routeCalls;

        boolean reuseSingleEmptySlot = (profiles.size() == 1 && !profiles.get(0).hasPeerConfigured());
        if (reuseSingleEmptySlot) {
            parsed.id = profiles.get(0).id;
        } else {
            parsed.id = UUID.randomUUID().toString();
        }

        String candidateName = sanitizeSuggestedName(suggestedName);
        if (candidateName.isEmpty()) {
            candidateName = deriveProfileName(parsed.endpoint, isAr, reuseSingleEmptySlot ? 1 : (profiles.size() + 1));
        }
        parsed.name = uniqueProfileName(candidateName, profiles, parsed.id);

        if (reuseSingleEmptySlot) {
            profiles.set(0, parsed.copy());
        } else {
            profiles.add(parsed.copy());
        }

        persistProfilesLocked(prefs, profiles, parsed.id, autoStart, routeCalls);
        return parsed.copy();
    }

    public static synchronized TunnelConfig deleteProfile(Context context, String profileId) {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        String currentActiveId = prefs.getString(KEY_ACTIVE_PROFILE_ID, "");

        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).id.equals(profileId)) {
                profiles.remove(i);
                break;
            }
        }
        if (profileId != null) {
            sPingCacheMs.remove(profileId);
            if (profileId.equals(sConnectedProfileId)) {
                sConnectedProfileId = "";
                prefs.edit().remove(KEY_CONNECTED_PROFILE_ID).commit();
            }
        }
        if (profiles.isEmpty()) {
            TunnelConfig fallback = new TunnelConfig();
            fallback.id = UUID.randomUUID().toString();
            fallback.name = WgStrings.defaultProfileName(isArabic(context), 1);
            fallback.enabled = prefs.getBoolean(KEY_ENABLED, false);
            fallback.routeCalls = prefs.getBoolean(KEY_ROUTE_CALLS, true);
            profiles.add(fallback);
        }

        TunnelConfig nextActive = profiles.get(0);
        for (TunnelConfig p : profiles) {
            if (p.id.equals(currentActiveId)) {
                nextActive = p;
                break;
            }
        }
        persistProfilesLocked(prefs, profiles, nextActive.id, nextActive.enabled, nextActive.routeCalls);
        return nextActive.copy();
    }

    public static synchronized String getConnectedProfileId(Context context, String moduleApkPath) {
        if (!isTunnelRunning(context, moduleApkPath)) {
            return "";
        }
        String memId = sConnectedProfileId;
        if (memId != null && !memId.isEmpty()) {
            return memId;
        }
        String savedId = getPrefs(context).getString(KEY_CONNECTED_PROFILE_ID, "");
        return savedId == null ? "" : savedId;
    }

    public static synchronized TunnelConfig getConnectedProfile(Context context, String moduleApkPath) {
        String connId = getConnectedProfileId(context, moduleApkPath);
        if (connId.isEmpty()) {
            return null;
        }
        List<TunnelConfig> profiles = loadProfiles(context);
        for (TunnelConfig p : profiles) {
            if (p.id.equals(connId)) {
                return p.copy();
            }
        }
        return null;
    }

    private static void persistProfilesLocked(
            SharedPreferences prefs,
            List<TunnelConfig> profiles,
            String activeId,
            boolean enabled,
            boolean routeCalls
    ) {
        JSONArray arr = new JSONArray();
        for (TunnelConfig cfg : profiles) {
            try {
                arr.put(configToJsonObject(cfg, true));
            } catch (Throwable ignored) {
            }
        }
        prefs.edit()
                .putString(KEY_PROFILES_JSON, arr.toString())
                .putString(KEY_ACTIVE_PROFILE_ID, activeId)
                .putBoolean(KEY_ENABLED, enabled)
                .putBoolean(KEY_ROUTE_CALLS, routeCalls)
                .commit();
        scheduleSyncPushToProvider(null);
    }

    private static String sanitizeSuggestedName(String raw) {
        String s = safeTrim(raw);
        if (s.isEmpty()) {
            return "";
        }
        int slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
        if (slash >= 0 && slash < s.length() - 1) {
            s = s.substring(slash + 1).trim();
        }
        String lower = s.toLowerCase(Locale.ROOT);
        String[] exts = new String[]{".conf", ".txt", ".png", ".jpg", ".jpeg", ".webp"};
        for (String ext : exts) {
            if (lower.endsWith(ext) && s.length() > ext.length()) {
                s = s.substring(0, s.length() - ext.length()).trim();
                break;
            }
        }
        if (s.length() > 32) {
            s = s.substring(0, 32).trim();
        }
        return s;
    }

    private static String uniqueProfileName(String desired, List<TunnelConfig> existing, String excludeId) {
        String base = safeTrim(desired);
        if (base.isEmpty()) {
            base = "WireGuard";
        }
        if (!nameExists(base, existing, excludeId)) {
            return base;
        }
        for (int n = 2; n <= 99; n++) {
            String candidate = base + " (" + n + ")";
            if (!nameExists(candidate, existing, excludeId)) {
                return candidate;
            }
        }
        return base + " (" + UUID.randomUUID().toString().substring(0, 4) + ")";
    }

    private static boolean nameExists(String candidate, List<TunnelConfig> existing, String excludeId) {
        for (TunnelConfig item : existing) {
            if (excludeId != null && excludeId.equals(item.id)) {
                continue;
            }
            if (candidate.equalsIgnoreCase(safeTrim(item.name))) {
                return true;
            }
        }
        return false;
    }

    private static String deriveProfileName(String endpoint, boolean isAr, int fallbackIndex) {
        String ep = safeTrim(endpoint);
        if (!ep.isEmpty()) {
            int colon = ep.lastIndexOf(':');
            String host = colon > 0 ? ep.substring(0, colon) : ep;
            if (host.length() > 24) {
                int dot = host.indexOf('.');
                if (dot > 0) {
                    host = host.substring(0, dot);
                }
            }
            if (!host.isEmpty()) {
                return host;
            }
        }
        return WgStrings.defaultProfileName(isAr, fallbackIndex);
    }

    public static String normalizeKeyToHex(String inputKey) throws WgStrings.WgException {
        if (inputKey == null || inputKey.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_FORMAT);
        }
        String trimmed = inputKey.trim();
        if (trimmed.length() == 64 && trimmed.matches("^[0-9a-fA-F]{64}$")) {
            return trimmed.toLowerCase(Locale.ROOT);
        }
        byte[] decoded = null;
        try {
            decoded = android.util.Base64.decode(trimmed, android.util.Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_FORMAT, "", e);
        } catch (Throwable ignored) {
        }
        if (decoded == null) {
            try {
                decoded = java.util.Base64.getDecoder().decode(trimmed);
            } catch (IllegalArgumentException e) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_FORMAT, "", e);
            }
        }
        if (decoded == null || decoded.length != 32) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_LENGTH);
        }
        StringBuilder sb = new StringBuilder(64);
        for (byte b : decoded) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static TunnelConfig parseConfText(String confText, TunnelConfig base) throws WgStrings.WgException {
        if (confText == null || confText.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
        }
        TunnelConfig cfg = base != null ? base.copy() : new TunnelConfig();
        String section = "";
        boolean foundAny = false;

        String[] lines = confText.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length() - 1).trim().toLowerCase(Locale.ROOT);
                continue;
            }
            int eqIdx = line.indexOf('=');
            if (eqIdx <= 0) {
                continue;
            }
            String key = line.substring(0, eqIdx).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(eqIdx + 1).trim();
            int commentIdx = value.indexOf('#');
            if (commentIdx >= 0) {
                value = value.substring(0, commentIdx).trim();
            }

            switch (key) {
                case "privatekey":
                    cfg.privateKey = value;
                    foundAny = true;
                    break;
                case "presharedkey":
                    cfg.presharedKey = value;
                    foundAny = true;
                    break;
                case "address":
                    cfg.address = value;
                    foundAny = true;
                    break;
                case "dns":
                    cfg.dns = value;
                    foundAny = true;
                    break;
                case "mtu":
                    cfg.mtu = clampMtu(parseIntSafe(value, 1280));
                    foundAny = true;
                    break;
                case "jc":
                    cfg.jc = Math.max(0, Math.min(15, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "jmin":
                    cfg.jmin = Math.max(0, Math.min(1200, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "jmax":
                    cfg.jmax = Math.max(0, Math.min(1200, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s1":
                    cfg.s1 = Math.max(0, Math.min(512, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s2":
                    cfg.s2 = Math.max(0, Math.min(512, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s3":
                    cfg.s3 = Math.max(0, Math.min(512, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s4":
                    cfg.s4 = Math.max(0, Math.min(512, parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "h1":
                    cfg.h1 = value;
                    foundAny = true;
                    break;
                case "h2":
                    cfg.h2 = value;
                    foundAny = true;
                    break;
                case "h3":
                    cfg.h3 = value;
                    foundAny = true;
                    break;
                case "h4":
                    cfg.h4 = value;
                    foundAny = true;
                    break;
                case "i1":
                    cfg.i1 = value;
                    foundAny = true;
                    break;
                case "i2":
                    cfg.i2 = value;
                    foundAny = true;
                    break;
                case "i3":
                    cfg.i3 = value;
                    foundAny = true;
                    break;
                case "i4":
                    cfg.i4 = value;
                    foundAny = true;
                    break;
                case "i5":
                    cfg.i5 = value;
                    foundAny = true;
                    break;
                case "reserved":
                    cfg.reserved = value;
                    foundAny = true;
                    break;
                case "publickey":
                    if (!"interface".equals(section)) {
                        cfg.publicKey = value;
                        foundAny = true;
                    }
                    break;
                case "endpoint":
                    cfg.endpoint = value;
                    foundAny = true;
                    break;
                case "persistentkeepalive":
                    cfg.keepAlive = clampKeepAlive(parseIntSafe(value, 25));
                    foundAny = true;
                    break;
                default:
                    break;
            }
        }

        if (!foundAny) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_CONF);
        }

        if (!safeTrim(cfg.endpoint).isEmpty()) {
            String currentName = safeTrim(cfg.name);
            if (currentName.isEmpty() || WgStrings.isDefaultProfileName(currentName)) {
                cfg.name = deriveProfileName(cfg.endpoint, false, 1);
            }
        }
        return cfg;
    }

    public static String exportConfText(TunnelConfig cfg) {
        StringBuilder sb = new StringBuilder();
        sb.append("[Interface]\n");
        sb.append("PrivateKey = ").append(safeTrim(cfg.privateKey)).append('\n');
        sb.append("Address = ").append(safeTrim(cfg.address).isEmpty() ? "10.0.0.2/32" : safeTrim(cfg.address)).append('\n');
        sb.append("DNS = ").append(safeTrim(cfg.dns).isEmpty() ? "1.1.1.1" : safeTrim(cfg.dns)).append('\n');
        if (cfg.mtu > 0 && cfg.mtu != 1280) {
            sb.append("MTU = ").append(clampMtu(cfg.mtu)).append('\n');
        }
        if (cfg.jc > 0) {
            sb.append("Jc = ").append(cfg.jc).append('\n');
            if (cfg.jmin > 0) sb.append("Jmin = ").append(cfg.jmin).append('\n');
            if (cfg.jmax > 0) sb.append("Jmax = ").append(cfg.jmax).append('\n');
        }
        if (cfg.s1 > 0) sb.append("S1 = ").append(cfg.s1).append('\n');
        if (cfg.s2 > 0) sb.append("S2 = ").append(cfg.s2).append('\n');
        if (cfg.s3 > 0) sb.append("S3 = ").append(cfg.s3).append('\n');
        if (cfg.s4 > 0) sb.append("S4 = ").append(cfg.s4).append('\n');
        if (!safeTrim(cfg.h1).isEmpty()) sb.append("H1 = ").append(safeTrim(cfg.h1)).append('\n');
        if (!safeTrim(cfg.h2).isEmpty()) sb.append("H2 = ").append(safeTrim(cfg.h2)).append('\n');
        if (!safeTrim(cfg.h3).isEmpty()) sb.append("H3 = ").append(safeTrim(cfg.h3)).append('\n');
        if (!safeTrim(cfg.h4).isEmpty()) sb.append("H4 = ").append(safeTrim(cfg.h4)).append('\n');
        if (!safeTrim(cfg.i1).isEmpty()) sb.append("I1 = ").append(safeTrim(cfg.i1)).append('\n');
        if (!safeTrim(cfg.i2).isEmpty()) sb.append("I2 = ").append(safeTrim(cfg.i2)).append('\n');
        if (!safeTrim(cfg.i3).isEmpty()) sb.append("I3 = ").append(safeTrim(cfg.i3)).append('\n');
        if (!safeTrim(cfg.i4).isEmpty()) sb.append("I4 = ").append(safeTrim(cfg.i4)).append('\n');
        if (!safeTrim(cfg.i5).isEmpty()) sb.append("I5 = ").append(safeTrim(cfg.i5)).append('\n');
        if (!safeTrim(cfg.reserved).isEmpty()) sb.append("Reserved = ").append(safeTrim(cfg.reserved)).append('\n');

        sb.append("\n[Peer]\n");
        sb.append("PublicKey = ").append(safeTrim(cfg.publicKey)).append('\n');
        if (!safeTrim(cfg.presharedKey).isEmpty()) {
            sb.append("PresharedKey = ").append(safeTrim(cfg.presharedKey)).append('\n');
        }
        sb.append("Endpoint = ").append(safeTrim(cfg.endpoint)).append('\n');
        sb.append("AllowedIPs = 0.0.0.0/0, ::/0\n");
        sb.append("PersistentKeepalive = ").append(clampKeepAlive(cfg.keepAlive)).append('\n');
        return sb.toString();
    }

    private static String preResolveEndpoint(String rawEndpoint) {
        String ep = safeTrim(rawEndpoint);
        if (ep.isEmpty() || ep.startsWith("[")) {
            return ep;
        }
        int lastColon = ep.lastIndexOf(':');
        if (lastColon <= 0 || lastColon == ep.length() - 1) {
            return ep;
        }
        String host = ep.substring(0, lastColon).trim();
        String port = ep.substring(lastColon + 1).trim();
        if (host.indexOf(':') >= 0) {
            return ep;
        }
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            if (addrs != null && addrs.length > 0) {
                InetAddress chosen = addrs[0];
                for (InetAddress candidate : addrs) {
                    if (candidate instanceof Inet4Address) {
                        chosen = candidate;
                        break;
                    }
                }
                String ip = chosen.getHostAddress();
                if (ip != null && !ip.isEmpty()) {
                    return chosen instanceof Inet4Address ? (ip + ":" + port) : ("[" + ip + "]:" + port);
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Java DNS pre-resolve fallback to Go resolver for " + host + ": " + t.getMessage());
        }
        return ep;
    }

    public static TunnelConfig parseWarpGeneratedJson(String rawJson, String[] outEndpointV4) throws Exception {
        JSONObject obj = new JSONObject(rawJson);
        TunnelConfig cfg = new TunnelConfig();
        cfg.id = UUID.randomUUID().toString();
        cfg.name = safeTrim(obj.optString("name", "Cloudflare WARP (AWG 1.5)"));
        cfg.privateKey = safeTrim(obj.optString("privateKey", ""));
        cfg.address = safeTrim(obj.optString("clientIp", "172.16.0.2/32"));
        cfg.dns = safeTrim(obj.optString("dns", "1.1.1.1"));
        cfg.publicKey = safeTrim(obj.optString("peerPublicKey", ""));
        cfg.endpoint = safeTrim(obj.optString("endpoint", "engage.cloudflareclient.com:2408"));
        cfg.keepAlive = clampKeepAlive(obj.optInt("keepAlive", 25));
        cfg.mtu = clampMtu(obj.optInt("mtu", 1280));
        cfg.jc = Math.max(0, Math.min(15, obj.optInt("jc", 4)));
        cfg.jmin = Math.max(0, Math.min(1200, obj.optInt("jmin", 40)));
        cfg.jmax = Math.max(0, Math.min(1200, obj.optInt("jmax", 120)));
        cfg.i1 = safeTrim(obj.optString("i1", ""));
        cfg.reserved = safeTrim(obj.optString("reserved", ""));
        cfg.isWarp = true;
        cfg.enabled = true;
        cfg.routeCalls = true;
        if (!cfg.hasPeerConfigured()) {
            throw new IllegalStateException("Generated WARP payload incomplete");
        }
        if (outEndpointV4 != null && outEndpointV4.length > 0) {
            outEndpointV4[0] = safeTrim(obj.optString("endpointV4", ""));
        }
        return cfg;
    }

    /**
     * Provisions or reuses a free Cloudflare WARP + AmneziaWG 1.5 profile, activates it,
     * connects the Go WireGuard tunnel, and binds Telegram's local SOCKS5 + call routing in one tap.
     */
    public static QuickWarpResult quickConnectFreeWarp(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader,
            boolean forceNewProfile
    ) throws Exception {
        NativeBridgeLoader.ensureLoaded(context, moduleApkPath);

        TunnelConfig target = null;
        boolean createdNew = false;

        synchronized (WireGuardManager.class) {
            SharedPreferences prefs = getPrefs(context);
            List<TunnelConfig> profiles = loadProfiles(context);

            if (!forceNewProfile) {
                for (TunnelConfig p : profiles) {
                    if ((p.isWarp || !safeTrim(p.reserved).isEmpty()) && p.hasPeerConfigured()) {
                        target = p.copy();
                        break;
                    }
                }
            }

            if (target == null) {
                String rawJson = Wgbridge.generateWarpConfigJSON();
                String[] epV4 = new String[1];
                target = parseWarpGeneratedJson(rawJson, epV4);
                boolean reuseSingleEmptySlot = (profiles.size() == 1 && !profiles.get(0).hasPeerConfigured());
                if (reuseSingleEmptySlot) {
                    target.id = profiles.get(0).id;
                }
                target.name = uniqueProfileName(
                        safeTrim(target.name).isEmpty() ? "Cloudflare WARP (AWG 1.5)" : target.name,
                        profiles,
                        target.id
                );
                if (reuseSingleEmptySlot) {
                    profiles.set(0, target.copy());
                } else {
                    profiles.add(target.copy());
                }
                if (epV4[0] != null && !epV4[0].isEmpty()) {
                    persistEndpointDnsHint(context, "engage.cloudflareclient.com", epV4[0]);
                    try {
                        Wgbridge.registerEndpointIpHint("engage.cloudflareclient.com", epV4[0]);
                    } catch (Throwable ignored) {
                    }
                }
                persistProfilesLocked(prefs, profiles, target.id, true, true);
                createdNew = true;
            } else {
                target.enabled = true;
                target.routeCalls = true;
                for (int i = 0; i < profiles.size(); i++) {
                    if (profiles.get(i).id.equals(target.id)) {
                        profiles.set(i, target.copy());
                        break;
                    }
                }
                persistProfilesLocked(prefs, profiles, target.id, true, true);
            }
        }

        int port = startAndBindProfile(context, target, moduleApkPath, telegramClassLoader);
        QuickWarpResult res = new QuickWarpResult();
        res.profile = target.copy();
        res.localPort = port;
        res.createdNew = createdNew;
        return res;
    }

    public static int applyAwg15AndReconnect(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) throws Exception {
        TunnelConfig cfg = getConnectedProfile(context, moduleApkPath);
        if (cfg == null || !cfg.hasPeerConfigured()) {
            cfg = loadConfig(context);
        }
        if (cfg == null || !cfg.hasPeerConfigured()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ENDPOINT);
        }
        cfg.jc = 4;
        cfg.jmin = 40;
        cfg.jmax = 120;
        cfg.i1 = "<b 0xc70000000108><r 8><b 0x0000449e><r 1200>";
        saveConfig(context, cfg);
        return startAndBindProfile(context, cfg, moduleApkPath, telegramClassLoader);
    }

    public static int startAndBind(Context context, String moduleApkPath, ClassLoader telegramClassLoader) throws Exception {
        TunnelConfig cfg = loadConfig(context);
        return startAndBindProfile(context, cfg, moduleApkPath, telegramClassLoader);
    }

    public static int startAndBindProfile(
            Context context,
            TunnelConfig cfg,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) throws Exception {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.NATIVE_BRIDGE_FAILED, t.getMessage(), t);
        }

        if (safeTrim(cfg.privateKey).isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_PRIVATE_KEY);
        }
        if (safeTrim(cfg.publicKey).isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_PUBLIC_KEY);
        }
        if (safeTrim(cfg.endpoint).isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ENDPOINT);
        }
        if (safeTrim(cfg.address).isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ADDRESS);
        }

        sUserManuallyStopped = false;
        acquireForcedContinuityLocks(context);
        syncDeterministicSocksCredentialsForProfile(context, cfg);

        // Reuse an already-running WireGuard tunnel hosted by another local Telegram client or module app
        // so multiple open Telegram clients share ONE WireGuard session with zero PrivateKey collisions.
        String profileSig = safeTrim(cfg.endpoint) + "|" + safeTrim(cfg.publicKey);
        int sharedPort = queryLiveSharedTunnelPort(context, profileSig);
        if (sharedPort > 0) {
            try {
                Wgbridge.setKillSwitchArmed(false);
                Wgbridge.stopKillSwitchGuard();
                if (Wgbridge.isRunning()) {
                    Wgbridge.stopTunnel();
                }
            } catch (Throwable ignored) {
            }
            sSharedHubPort = sharedPort;
            sIsSharedHubOwner = false;
            sConnectedProfileId = cfg.id;
            sTunnelStartedAtMs = SystemClock.elapsedRealtime();
            sActiveTunnelMtu = clampMtu(cfg.mtu);
            sLastActiveNetworkSignature = computeActiveNetworkSignature(context);
            sLastRoamingUpdateMs = System.currentTimeMillis();
            sKeepalivePausedForIdle = false;
            sConsecutiveHealthFailures = 0;
            String prevActiveId = getPrefs(context).getString(KEY_ACTIVE_PROFILE_ID, "");
            getPrefs(context).edit()
                    .putString(KEY_CONNECTED_PROFILE_ID, cfg.id)
                    .putString(KEY_ACTIVE_PROFILE_ID, cfg.id)
                    .commit();
            if (cfg.id != null && !cfg.id.isEmpty() && !cfg.id.equals(prevActiveId)) {
                scheduleSyncPushToProvider(context);
            }
            sWatchdogRawEndpoint = cfg.endpoint;
            if (telegramClassLoader != null) {
                postBindTelegramProxy(context, telegramClassLoader, true, sharedPort, isRouteCallsEnabled(context), true);
                registerNetworkWatchdog(context, moduleApkPath, telegramClassLoader);
            }
            return sharedPort;
        }

        syncEndpointDnsHintsToNative(context, cfg.endpoint);

        ensureSessionSocksCredentials(context);
        try {
            Wgbridge.setSocksAuth(sSocksUser, sSocksPass);
            Wgbridge.resetSocksAuthRejectCount();
        } catch (Throwable ignored) {
        }

        String privHex = normalizeKeyToHex(cfg.privateKey);
        String pubHex = normalizeKeyToHex(cfg.publicKey);
        String pskHex = safeTrim(cfg.presharedKey).isEmpty() ? "" : normalizeKeyToHex(cfg.presharedKey);
        String dns = safeTrim(cfg.dns).isEmpty() ? "1.1.1.1" : safeTrim(cfg.dns);
        boolean onCellular = isCellularNetworkActive(context);
        int keepAlive = effectiveKeepAlive(context, cfg.keepAlive);
        String awgParams = cfg.toEffectiveAwgParamsString();
        boolean warpOrAwg = isWarpOrAwgConfig(cfg, awgParams);
        int mtu = (onCellular || warpOrAwg || sAutoMtuDowngraded) ? 1280 : clampMtu(cfg.mtu);
        boolean useDoH = isDohEnabled(context);
        // When DoH is enabled, pass raw hostname straight to Go so zero plaintext port-53 DNS leaks occur!
        String endpointForGo = useDoH ? safeTrim(cfg.endpoint) : preResolveEndpoint(cfg.endpoint);

        try {
            Wgbridge.setTunnelStartupPending(true);
        } catch (Throwable ignored) {
        }
        long portLong;
        try {
            portLong = Wgbridge.startTunnelAdvanced(
                    privHex,
                    pskHex,
                    safeTrim(cfg.address),
                    dns,
                    pubHex,
                    endpointForGo,
                    keepAlive,
                    mtu,
                    awgParams,
                    useDoH
            );
        } catch (Exception firstErr) {
            // If DoH failed on a captive network and host was a domain, attempt system fallback once
            String sysResolved = preResolveEndpoint(cfg.endpoint);
            if (useDoH && !sysResolved.equals(endpointForGo)) {
                try {
                    portLong = Wgbridge.startTunnelAdvanced(
                            privHex,
                            pskHex,
                            safeTrim(cfg.address),
                            dns,
                            pubHex,
                            sysResolved,
                            keepAlive,
                            mtu,
                            awgParams,
                            false
                    );
                } catch (Exception retryErr) {
                    try {
                        Wgbridge.setTunnelStartupPending(false);
                    } catch (Throwable ignored) {
                    }
                    if (isKillSwitchEnabled(context)) {
                        enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
                    }
                    throw retryErr;
                }
            } else {
                try {
                    Wgbridge.setTunnelStartupPending(false);
                } catch (Throwable ignored) {
                }
                if (isKillSwitchEnabled(context)) {
                    enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
                }
                throw firstErr;
            }
        } finally {
            try {
                Wgbridge.setTunnelStartupPending(false);
            } catch (Throwable ignored) {
            }
        }
        int localPort = (int) portLong;
        sSharedHubPort = localPort;
        sIsSharedHubOwner = true;
        registerSharedTunnel(context, localPort, profileSig, cfg.id, cfg.name, sSocksUser, sSocksPass);

        sConnectedProfileId = cfg.id;
        sTunnelStartedAtMs = SystemClock.elapsedRealtime();
        sActiveTunnelMtu = mtu;
        sLastActiveNetworkSignature = computeActiveNetworkSignature(context);
        sLastRoamingUpdateMs = System.currentTimeMillis();
        sRoamRetryCount = 0;
        sKeepalivePausedForIdle = false;
        sConsecutiveHealthFailures = 0;
        sLastReportedHsHealthy = isHandshakeHealthyNow(context, moduleApkPath);
        String prevOwnerActiveId = getPrefs(context).getString(KEY_ACTIVE_PROFILE_ID, "");
        getPrefs(context).edit()
                .putString(KEY_CONNECTED_PROFILE_ID, cfg.id)
                .putString(KEY_ACTIVE_PROFILE_ID, cfg.id)
                .commit();
        if (cfg.id != null && !cfg.id.isEmpty() && !cfg.id.equals(prevOwnerActiveId)) {
            scheduleSyncPushToProvider(context);
        }
        sWatchdogRawEndpoint = cfg.endpoint;
        WgDiagnosticsLog.record("TUNNEL", "STARTED", "port=" + localPort + " mtu=" + mtu + " cellular=" + onCellular);

        if (telegramClassLoader != null) {
            postBindTelegramProxy(context, telegramClassLoader, true, localPort, isRouteCallsEnabled(context), true);
            registerNetworkWatchdog(context, moduleApkPath, telegramClassLoader);
        }
        syncForegroundKeepaliveService(context, true);
        // Keep muxKillSwitch armed if Kill Switch is enabled so unexpected tunnel death fails closed immediately.
        try {
            Wgbridge.setKillSwitchArmed(isKillSwitchEnabled(context));
        } catch (Throwable ignored) {
        }
        // Always start the 24/7 Forced Continuity & Auto-Failover Guardian while connected
        startFailoverMonitor(context, moduleApkPath, telegramClassLoader);
        return localPort;
    }

    private static volatile long sLastSharedHubCheckMs = 0L;
    private static volatile int sCachedExternalSharedPort = -1;
    private static volatile boolean sSharedHubProbeInFlight = false;

    private static boolean isUsingSharedHub() {
        if (sIsSharedHubOwner || sSharedHubPort <= 0) {
            return false;
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return true;
        }
        return isLocalLoopbackPortOpen(sSharedHubPort, 120);
    }

    public static int queryAnyLiveSharedTunnelPort(Context context) {
        if (context == null) {
            return isUsingSharedHub() ? sSharedHubPort : -1;
        }
        if (sIsSharedHubOwner) {
            return -1;
        }
        long now = SystemClock.elapsedRealtime();
        boolean onMain = (Looper.myLooper() == Looper.getMainLooper());
        if (now - sLastSharedHubCheckMs < 2000L && sCachedExternalSharedPort > 0) {
            if (onMain || isLocalLoopbackPortOpen(sCachedExternalSharedPort, 120)) {
                return sCachedExternalSharedPort;
            }
        }
        try {
            int port = -1;
            String owner = "";
            String sharedUser = "";
            String sharedPass = "";
            long updatedAt = 0L;
            long lastHsSec = 0L;
            boolean hsHealthy = false;
            String myPkg = context.getPackageName();
            if ("org.telegram.wgplus.module".equals(myPkg)) {
                SharedPreferences sp = context.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                port = sp.getInt("port", -1);
                owner = sp.getString("owner", "");
                sharedUser = sp.getString("socksUser", "");
                sharedPass = sp.getString("socksPass", "");
                updatedAt = sp.getLong("updatedAt", 0L);
                lastHsSec = sp.getLong("lastHsSec", 0L);
                hsHealthy = sp.getBoolean("hsHealthy", false);
            } else {
                Bundle out = context.getContentResolver().call(
                        Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                        KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                        null,
                        null
                );
                if (out != null) {
                    port = out.getInt("port", -1);
                    owner = out.getString("owner", "");
                    sharedUser = out.getString("socksUser", "");
                    sharedPass = out.getString("socksPass", "");
                    updatedAt = out.getLong("updatedAt", 0L);
                    lastHsSec = out.getLong("lastHsSec", 0L);
                    hsHealthy = out.getBoolean("hsHealthy", false);
                }
            }
            if (port > 0 && (myPkg == null || !myPkg.equals(owner))) {
                boolean recent = updatedAt <= 0L || Math.abs(System.currentTimeMillis() - updatedAt) < 300_000L;
                Wgp1StatusResult liveRes = queryLiveStatusWithFallback(context, null, port, sharedPass, null);
                if (liveRes != null && liveRes.running) {
                    sSharedSocksUser = sharedUser != null ? sharedUser : "";
                    sSharedSocksPass = sharedPass != null ? sharedPass : "";
                    sSharedLastHsSec = liveRes.hsSec > 0L ? liveRes.hsSec : (liveRes.hsHealthy ? lastHsSec : 0L);
                    sSharedHsHealthy = liveRes.hsHealthy;
                    sSharedHubPort = port;
                    sCachedExternalSharedPort = port;
                    sLastSharedHubCheckMs = now;
                    return port;
                }
                if (!onMain && !NativeBridgeLoader.isLoaded() && isLocalLoopbackPortOpen(port, 160)) {
                    sSharedSocksUser = sharedUser != null ? sharedUser : "";
                    sSharedSocksPass = sharedPass != null ? sharedPass : "";
                    sSharedLastHsSec = lastHsSec;
                    sSharedHsHealthy = hsHealthy;
                    sSharedHubPort = port;
                    sCachedExternalSharedPort = port;
                    sLastSharedHubCheckMs = now;
                    return port;
                }
                if (onMain && recent && !sSharedHubProbeInFlight) {
                    final int probePort = port;
                    final String candUser = sharedUser != null ? sharedUser : "";
                    final String candPass = sharedPass != null ? sharedPass : "";
                    final long candHsSec = lastHsSec;
                    final boolean candHsHealthy = hsHealthy;
                    sSharedHubProbeInFlight = true;
                    SYNC_EXEC.execute(() -> {
                        try {
                            Wgp1StatusResult bgRes = queryLiveStatusWithFallback(context, null, probePort, candPass, null);
                            sLastSharedHubCheckMs = SystemClock.elapsedRealtime();
                            if (bgRes != null && bgRes.running) {
                                sSharedSocksUser = candUser;
                                sSharedSocksPass = candPass;
                                sSharedLastHsSec = bgRes.hsSec > 0L ? bgRes.hsSec : candHsSec;
                                sSharedHsHealthy = bgRes.hsHealthy || candHsHealthy;
                                sSharedHubPort = probePort;
                                sCachedExternalSharedPort = probePort;
                            } else {
                                sCachedExternalSharedPort = -1;
                            }
                        } finally {
                            sSharedHubProbeInFlight = false;
                        }
                    });
                }
            }
        } catch (Throwable ignored) {
        }
        // Fallback when package-visibility restrictions block ContentResolver IPC:
        // probe localhost WGP1 mux ports directly via Go (safe on Main Thread too once libgojni is loaded).
        int wgpPort = probeSharedTunnelOverWgp1(context, null);
        if (wgpPort > 0) {
            return wgpPort;
        }
        sLastSharedHubCheckMs = now;
        sCachedExternalSharedPort = -1;
        return -1;
    }

    public static boolean isSharedTunnelObserved(Context context, String moduleApkPath) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (Wgbridge.isRunning()) {
                return false;
            }
        } catch (Throwable ignored) {
        }
        return queryAnyLiveSharedTunnelPort(context) > 0;
    }

    private static boolean isLocalLoopbackPortOpen(int port, int timeoutMs) {
        if (port <= 0 || port > 65535) return false;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return false;
        }
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", port), timeoutMs);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    static String parseIpFromHostPort(String hostPort) {
        if (hostPort == null) {
            return "";
        }
        String s = hostPort.trim();
        int idx = s.lastIndexOf(':');
        if (idx <= 0 || idx >= s.length() - 1) {
            return "";
        }
        return s.substring(0, idx).trim();
    }

    static int parsePortFromHostPort(String hostPort) {
        if (hostPort == null) {
            return 0;
        }
        String s = hostPort.trim();
        int idx = s.lastIndexOf(':');
        if (idx < 0 || idx >= s.length() - 1) {
            return 0;
        }
        try {
            int p = Integer.parseInt(s.substring(idx + 1).trim());
            return (p > 0 && p <= 65535) ? p : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    /** Starts a local VoIP relay socket inside this process if its own Go tunnel is active. */
    public static int startLocalVoipEndpointRelay(Context ctx, String targetHost, int targetPort) {
        return parsePortFromHostPort(startLocalVoipEndpointRelayAddr(ctx, targetHost, targetPort));
    }

    public static String startLocalVoipEndpointRelayAddr(Context ctx, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, null);
            if (!Wgbridge.isRunning()) {
                return "";
            }
            String addr = Wgbridge.startVoipEndpointRelayAddr(host, targetPort);
            return addr != null ? addr.trim() : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Sends a single-line WGP1 control command over loopback via Go JNI (immune to NetworkOnMainThreadException). */
    private static String sendWgp1ControlCommand(int muxPort, String socksPass, String command) {
        if (muxPort < 1 || muxPort > 65535 || command == null || command.isEmpty()) {
            return "";
        }
        String passTok = (socksPass != null && !socksPass.trim().isEmpty()) ? socksPass.trim() : "-";
        try {
            if (NativeBridgeLoader.isLoaded()) {
                String resp = Wgbridge.sendLocalWgp1Command(muxPort, passTok, command, 350L);
                if (resp != null) {
                    return resp.trim();
                }
            }
        } catch (Throwable ignored) {
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return "";
        }
        String line = "WGP1 " + passTok + " " + command + "\n";
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress("127.0.0.1", muxPort), 350);
            sock.setSoTimeout(450);
            OutputStream os = sock.getOutputStream();
            os.write(line.getBytes(StandardCharsets.UTF_8));
            os.flush();
            BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            String resp = br.readLine();
            return resp != null ? resp.trim() : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Opens or reuses a local VoIP relay socket directly inside whichever local process owns {@code muxPort}. */
    static int requestVoipRelayOverWgp1(int muxPort, String socksPass, String targetHost, int targetPort) {
        return parsePortFromHostPort(requestVoipRelayOverWgp1Addr(muxPort, socksPass, targetHost, targetPort));
    }

    static String requestVoipRelayOverWgp1Addr(int muxPort, String socksPass, String targetHost, int targetPort) {
        if (muxPort < 1 || muxPort > 65535 || targetHost == null || targetHost.trim().isEmpty()
                || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        String host = targetHost.trim();
        try {
            if (NativeBridgeLoader.isLoaded()) {
                String passTok = (socksPass != null && !socksPass.trim().isEmpty()) ? socksPass.trim() : "-";
                String goAddr = Wgbridge.requestRemoteVoipRelayAddr(muxPort, passTok, host, targetPort);
                if (goAddr != null && !goAddr.trim().isEmpty()) {
                    return goAddr.trim();
                }
            }
        } catch (Throwable ignored) {
        }
        String resp = sendWgp1ControlCommand(muxPort, socksPass, "VOIP_RELAY_ADDR " + host + " " + targetPort);
        if (resp.startsWith("OK ")) {
            String addr = resp.substring(3).trim();
            if (parsePortFromHostPort(addr) > 0 && !parseIpFromHostPort(addr).isEmpty()) {
                return addr;
            }
        }
        String respLegacy = sendWgp1ControlCommand(muxPort, socksPass, "VOIP_RELAY " + host + " " + targetPort);
        if (respLegacy.startsWith("OK ")) {
            try {
                int port = Integer.parseInt(respLegacy.substring(3).trim());
                if (port > 0 && port <= 65535) {
                    return "127.0.0.1:" + port;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return "";
    }

    static String startRemoteVoipRelayOverWgp1Addr(Context ctx, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, null);
        } catch (Throwable ignored) {
        }
        int regPort = -1;
        String regPass = "";
        if (ctx != null && "org.telegram.wgplus.module".equals(ctx.getPackageName())) {
            try {
                SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                regPort = sp.getInt("port", -1);
                regPass = sp.getString("socksPass", "");
            } catch (Throwable ignored) {
            }
        }
        String activePass = ctx != null ? getActiveSocksPass(ctx) : sSocksPass;
        int[] ports = new int[]{regPort, 48729, 48730, 48731, 48732};
        for (int p : ports) {
            if (p <= 0) {
                continue;
            }
            if (regPass != null && !regPass.isEmpty()) {
                String a = requestVoipRelayOverWgp1Addr(p, regPass, host, targetPort);
                if (!a.isEmpty()) {
                    return a;
                }
            }
            if (activePass != null && !activePass.isEmpty() && !activePass.equals(regPass)) {
                String a = requestVoipRelayOverWgp1Addr(p, activePass, host, targetPort);
                if (!a.isEmpty()) {
                    return a;
                }
            }
        }
        return "";
    }

    static final class Wgp1StatusResult {
        final boolean running;
        final boolean hsHealthy;
        final long hsSec;
        final String profileSig;

        Wgp1StatusResult(boolean running, boolean hsHealthy, long hsSec, String profileSig) {
            this.running = running;
            this.hsHealthy = hsHealthy;
            this.hsSec = hsSec;
            this.profileSig = profileSig != null ? profileSig : "";
        }
    }

    /** Queries full status including optional 5th profileSig field from whichever process owns {@code muxPort}. */
    static Wgp1StatusResult queryLiveStatusFullOverWgp1(int muxPort, String socksPass) {
        return parseWgp1StatusLine(sendWgp1ControlCommand(muxPort, socksPass, "STATUS"), false);
    }

    static Wgp1StatusResult queryPublicStatusOverWgp1(int muxPort) {
        return parseWgp1StatusLine(sendWgp1ControlCommand(muxPort, "-", "PUBLIC_STATUS"), true);
    }

    private static Wgp1StatusResult parseWgp1StatusLine(String resp, boolean isPublicHash) {
        if (resp == null || !resp.startsWith("OK ")) {
            return null;
        }
        String[] parts = resp.substring(3).trim().split("\\s+", 4);
        if (parts.length < 3) {
            return null;
        }
        try {
            boolean up = "true".equals(parts[0]);
            boolean hs = "true".equals(parts[1]);
            long hsSec = Long.parseLong(parts[2]);
            String rawSig = parts.length >= 4 ? parts[3].trim() : "";
            String sig = isPublicHash
                    ? ((!rawSig.isEmpty() && !"-".equals(rawSig)) ? ("HASH:" + rawSig) : "")
                    : rawSig;
            return new Wgp1StatusResult(up, hs, hsSec, sig);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    static Wgp1StatusResult queryLiveStatusWithFallback(
            Context ctx,
            String moduleApkPath,
            int muxPort,
            String socksPass,
            String requiredSig
    ) {
        if (muxPort < 1 || muxPort > 65535) {
            return null;
        }
        if (ctx != null && !NativeBridgeLoader.isLoaded()) {
            try {
                NativeBridgeLoader.ensureLoaded(ctx, moduleApkPath);
            } catch (Throwable ignored) {
            }
        }
        if (socksPass != null && !socksPass.isEmpty()) {
            Wgp1StatusResult full = queryLiveStatusFullOverWgp1(muxPort, socksPass);
            if (full != null) {
                return full;
            }
        }
        Wgp1StatusResult pub = queryPublicStatusOverWgp1(muxPort);
        if (pub != null && wgp1ProfileSigMatches(ctx, requiredSig, pub.profileSig)) {
            return pub;
        }
        return null;
    }

    /** Queries live {running(0|1), handshakeHealthy(0|1), lastHandshakeSec} from whichever process owns {@code muxPort}. */
    static long[] queryLiveStatusOverWgp1(int muxPort, String socksPass) {
        Wgp1StatusResult res = queryLiveStatusFullOverWgp1(muxPort, socksPass);
        if (res == null) {
            return null;
        }
        return new long[]{res.running ? 1L : 0L, res.hsHealthy ? 1L : 0L, res.hsSec};
    }

    static boolean wgp1ProfileSigMatches(Context context, String requiredSig, String peerSig) {
        if (requiredSig == null || requiredSig.isEmpty()) {
            return true;
        }
        if (peerSig == null || peerSig.isEmpty()) {
            return false;
        }
        if (peerSig.startsWith("HASH:")) {
            String peerHash = peerSig.substring(5).trim();
            if (peerHash.isEmpty()) {
                return false;
            }
            if (peerHash.equalsIgnoreCase(computeProfileSigHash(requiredSig))) {
                return true;
            }
            if (context != null && !isDohEnabled(context)) {
                int reqBar = requiredSig.lastIndexOf('|');
                if (reqBar > 0) {
                    try {
                        String pre = preResolveEndpoint(requiredSig.substring(0, reqBar).trim());
                        if (pre != null && !pre.isEmpty()) {
                            String altSig = pre + "|" + requiredSig.substring(reqBar + 1).trim();
                            if (peerHash.equalsIgnoreCase(computeProfileSigHash(altSig))) {
                                return true;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
            return false;
        }
        if (requiredSig.equals(peerSig)) {
            return true;
        }
        // When DoH is disabled, StartTunnelAdvanced receives preResolved IP instead of hostname;
        // also accept an exact peer public key match when endpoints resolve identically.
        int reqBar = requiredSig.lastIndexOf('|');
        int peerBar = peerSig.lastIndexOf('|');
        if (reqBar > 0 && peerBar > 0) {
            String reqEp = requiredSig.substring(0, reqBar).trim();
            String reqPub = requiredSig.substring(reqBar + 1).trim();
            String peerEp = peerSig.substring(0, peerBar).trim();
            String peerPub = peerSig.substring(peerBar + 1).trim();
            if (!reqPub.isEmpty() && reqPub.equals(peerPub)) {
                if (reqEp.equalsIgnoreCase(peerEp)) {
                    return true;
                }
                if (context != null && !isDohEnabled(context)) {
                    try {
                        String pre = preResolveEndpoint(reqEp);
                        if (pre != null && pre.equalsIgnoreCase(peerEp)) {
                            return true;
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return false;
    }

    /**
     * Loopback WGP1 shared-hub discovery fallback for hosts without QUERY_ALL_PACKAGES
     * (e.g. official Telegram 13.3.1 on targetSdk 34+), preventing duplicate concurrent tunnels.
     */
    private static int probeSharedTunnelOverWgp1(Context context, String requiredProfileSig) {
        if (context == null) {
            return -1;
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, null);
        } catch (Throwable ignored) {
        }
        if (Looper.myLooper() == Looper.getMainLooper() && !NativeBridgeLoader.isLoaded()) {
            return -1;
        }
        ensureSessionSocksCredentials(context);
        String user = sSocksUser;
        String pass = sSocksPass;
        if (pass == null || pass.isEmpty()) {
            try {
                SharedPreferences sp = getPrefs(context);
                user = sp.getString(KEY_PERSISTED_SOCKS_USER, user);
                pass = sp.getString(KEY_PERSISTED_SOCKS_PASS, "");
            } catch (Throwable ignored) {
            }
        }

        int myPort = -1;
        try {
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                myPort = (int) Wgbridge.getActivePort();
            }
        } catch (Throwable ignored) {
        }

        int[] candidatePorts = new int[]{48729, 48730, 48731, 48732};
        for (int p : candidatePorts) {
            if (p == myPort) {
                continue;
            }
            Wgp1StatusResult res = queryLiveStatusWithFallback(context, null, p, pass, requiredProfileSig);
            if (res != null && res.running && wgp1ProfileSigMatches(context, requiredProfileSig, res.profileSig)) {
                if (user != null && !user.isEmpty() && pass != null && !pass.isEmpty()) {
                    sSharedSocksUser = user;
                    sSharedSocksPass = pass;
                }
                sSharedLastHsSec = res.hsSec;
                sSharedHsHealthy = res.hsHealthy;
                sSharedHubPort = p;
                sCachedExternalSharedPort = p;
                sLastSharedHubCheckMs = SystemClock.elapsedRealtime();
                return p;
            }
        }
        return -1;
    }

    /**
     * Binds or reuses a local loopback UDP/TCP relay for a Telegram VoIP relay server,
     * preserving {@code targetPort} on {@code 127.0.0.x} when {@code targetPort >= 1024} so WebRTC
     * {@code ReflectorPort} and {@code TurnPort} accept remote candidates seamlessly, and executing
     * all WGP1 RPCs via Go JNI so Android's Main UI Thread never throws NetworkOnMainThreadException.
     */
    public static int startVoipEndpointRelay(Context ctx, String moduleApkPath, String targetHost, int targetPort) {
        return parsePortFromHostPort(startVoipEndpointRelayAddr(ctx, moduleApkPath, targetHost, targetPort));
    }

    public static String startVoipEndpointRelayAddr(Context ctx, String moduleApkPath, String targetHost, int targetPort) {
        String host = targetHost != null ? targetHost.trim() : "";
        if (host.isEmpty() || targetPort < 1 || targetPort > 65535) {
            return "";
        }
        try {
            NativeBridgeLoader.ensureLoaded(ctx, moduleApkPath);
            if (Wgbridge.isRunning()) {
                String localAddr = Wgbridge.startVoipEndpointRelayAddr(host, targetPort);
                if (localAddr != null && !localAddr.trim().isEmpty()) {
                    return localAddr.trim();
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            int activeMuxPort = getActivePort(ctx, moduleApkPath);
            String pass = getActiveSocksPass(ctx);
            String sharedPass = sSharedSocksPass;
            String detPass = "";
            if (ctx != null) {
                try {
                    TunnelConfig cfg = loadConfig(ctx);
                    if (cfg != null && !safeTrim(cfg.privateKey).isEmpty()) {
                        detPass = deriveProfileSocksPass(cfg.privateKey);
                    }
                } catch (Throwable ignored) {
                }
            }
            int[] candidatePorts = new int[]{activeMuxPort, 48729, 48730, 48731, 48732};
            for (int p : candidatePorts) {
                if (p <= 0) {
                    continue;
                }
                if (pass != null && !pass.isEmpty()) {
                    String addr = requestVoipRelayOverWgp1Addr(p, pass, host, targetPort);
                    if (!addr.isEmpty()) {
                        return addr;
                    }
                }
                if (sharedPass != null && !sharedPass.isEmpty() && !sharedPass.equals(pass)) {
                    String addr = requestVoipRelayOverWgp1Addr(p, sharedPass, host, targetPort);
                    if (!addr.isEmpty()) {
                        return addr;
                    }
                }
                if (!detPass.isEmpty() && !detPass.equals(pass) && !detPass.equals(sharedPass)) {
                    String addr = requestVoipRelayOverWgp1Addr(p, detPass, host, targetPort);
                    if (!addr.isEmpty()) {
                        return addr;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        if (ctx != null && !"org.telegram.wgplus.module".equals(ctx.getPackageName())) {
            try {
                Bundle req = new Bundle();
                req.putString(KeepaliveStatusProvider.EXTRA_HOST, host);
                req.putInt(KeepaliveStatusProvider.EXTRA_PORT, targetPort);
                Bundle out = ctx.getContentResolver().call(
                        STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_START_VOIP_RELAY,
                        null,
                        req
                );
                if (out != null) {
                    String addr = out.getString(KeepaliveStatusProvider.RESULT_LOCAL_ADDR, "");
                    if (addr != null && !addr.trim().isEmpty()) {
                        return addr.trim();
                    }
                    int lp = out.getInt(KeepaliveStatusProvider.RESULT_LOCAL_PORT, 0);
                    if (lp > 0) {
                        return "127.0.0.1:" + lp;
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "startVoipEndpointRelayAddr IPC warning: " + t.getMessage());
            }
        }
        return "";
    }

    private static int queryLiveSharedTunnelPort(Context context, String profileSig) {
        if (context == null || profileSig == null || profileSig.isEmpty()) return -1;
        try {
            NativeBridgeLoader.ensureLoaded(context, null);
        } catch (Throwable ignored) {
        }
        try {
            Bundle out = context.getContentResolver().call(
                    Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                    KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                    null,
                    null
            );
            if (out != null) {
                int port = out.getInt("port", -1);
                String sig = out.getString("sig", "");
                String owner = out.getString("owner", "");
                String sharedUser = out.getString("socksUser", "");
                String sharedPass = out.getString("socksPass", "");
                String myPkg = context.getPackageName();
                if (port > 0 && wgp1ProfileSigMatches(context, profileSig, sig) && myPkg != null && !myPkg.equals(owner)) {
                    Wgp1StatusResult live = queryLiveStatusWithFallback(context, null, port, sharedPass, profileSig);
                    if ((live != null && live.running) || (!NativeBridgeLoader.isLoaded() && isLocalLoopbackPortOpen(port, 250))) {
                        sSharedSocksUser = sharedUser != null ? sharedUser : "";
                        sSharedSocksPass = sharedPass != null ? sharedPass : "";
                        sSharedLastHsSec = live != null && live.hsSec > 0L ? live.hsSec : out.getLong("lastHsSec", 0L);
                        sSharedHsHealthy = (live != null && live.hsHealthy) || out.getBoolean("hsHealthy", false);
                        return port;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return probeSharedTunnelOverWgp1(context, profileSig);
    }

    private static boolean isWarpOrAwgConfig(TunnelConfig cfg, String awgParams) {
        if (cfg == null) {
            return false;
        }
        if (cfg.isWarp || !safeTrim(cfg.reserved).isEmpty()) {
            return true;
        }
        String epLower = safeTrim(cfg.endpoint).toLowerCase(java.util.Locale.US);
        if (epLower.contains("cloudflareclient") || epLower.startsWith("162.159.")) {
            return true;
        }
        return awgParams != null && !awgParams.trim().isEmpty();
    }

    public static boolean isHandshakeHealthyNow(Context context, String moduleApkPath) {
        try {
            if (moduleApkPath != null) {
                NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            }
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                return Wgbridge.isHandshakeHealthy();
            }
        } catch (Throwable ignored) {
        }
        if (!sIsSharedHubOwner && context != null && queryAnyLiveSharedTunnelPort(context) > 0) {
            return sSharedHsHealthy && sSharedLastHsSec > 0L;
        }
        return false;
    }

    static Bundle queryLocalRunningTunnelBundleForProvider(Context ctx, boolean nudgeIfAging) {
        if (ctx == null) {
            return null;
        }
        try {
            String apkPath = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
            NativeBridgeLoader.ensureLoaded(ctx, apkPath);
            if (!NativeBridgeLoader.isLoaded() || !Wgbridge.isRunning()) {
                return null;
            }
            int port = (int) Wgbridge.getActivePort();
            if (port <= 0) {
                return null;
            }
            TunnelStats st = getLiveStats(ctx, apkPath);
            boolean hsHealthy = Wgbridge.isHandshakeHealthy();
            long nowSec = System.currentTimeMillis() / 1000L;
            if (nudgeIfAging && (st.lastHandshakeSec <= 0L || Math.max(0L, nowSec - st.lastHandshakeSec) >= PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC)) {
                nudgeTunnelHandshakeAsync(ctx, apkPath, null);
            }
            SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
            TunnelConfig cfg = getConnectedProfile(ctx, apkPath);
            String sig = sp.getString("sig", "");
            if (sig.isEmpty() && cfg != null && cfg.hasPeerConfigured()) {
                sig = safeTrim(cfg.endpoint) + "|" + safeTrim(cfg.publicKey);
            }
            String profileId = sp.getString("profileId", "");
            if (profileId.isEmpty() && cfg != null && cfg.id != null) {
                profileId = cfg.id;
            }
            String profileName = sp.getString("profileName", "");
            if (profileName.isEmpty() && cfg != null && cfg.name != null) {
                profileName = cfg.name;
            }
            String socksUser = sSocksUser != null && !sSocksUser.isEmpty() ? sSocksUser : sp.getString("socksUser", "");
            String socksPass = sSocksPass != null && !sSocksPass.isEmpty() ? sSocksPass : sp.getString("socksPass", "");

            Bundle out = new Bundle();
            out.putInt("port", port);
            out.putString("sig", sig);
            out.putString("owner", ctx.getPackageName());
            out.putString("profileId", profileId);
            out.putString("profileName", profileName);
            out.putString("socksUser", socksUser);
            out.putString("socksPass", socksPass);
            out.putLong("lastHsSec", st.lastHandshakeSec);
            out.putBoolean("hsHealthy", hsHealthy);
            out.putLong("updatedAt", System.currentTimeMillis());
            return out;
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static void nudgeTunnelHandshakeAsync(final Context context, final String moduleApkPath, final Runnable onUpdatedMain) {
        if (context == null) {
            return;
        }
        long nowElapsed = SystemClock.elapsedRealtime();
        if ((nowElapsed - sLastHandshakeNudgeMs) < 2500L || !sHandshakeNudgeInFlight.compareAndSet(false, true)) {
            return;
        }
        sLastHandshakeNudgeMs = nowElapsed;
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        SYNC_EXEC.execute(() -> {
            try {
                try {
                    NativeBridgeLoader.ensureLoaded(appCtx, moduleApkPath);
                } catch (Throwable ignored) {
                }
                if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                    Wgbridge.ensureTunnelAlive(1800L);
                    int p = (int) Wgbridge.getActivePort();
                    TunnelConfig cfg = getConnectedProfile(appCtx, moduleApkPath);
                    if (p > 0) {
                        String sig = (cfg != null && cfg.hasPeerConfigured())
                                ? (safeTrim(cfg.endpoint) + "|" + safeTrim(cfg.publicKey))
                                : "";
                        registerSharedTunnel(
                                appCtx,
                                p,
                                sig,
                                cfg != null ? cfg.id : sConnectedProfileId,
                                cfg != null ? cfg.name : "",
                                sSocksUser,
                                sSocksPass
                        );
                    }
                } else {
                    try {
                        appCtx.getContentResolver().call(
                                Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                                KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                                "nudge",
                                null
                        );
                    } catch (Throwable ignored) {
                    }
                    sLastSharedHubCheckMs = 0L;
                    int p = queryAnyLiveSharedTunnelPort(appCtx);
                    long nowSec = System.currentTimeMillis() / 1000L;
                    if (p > 0 && (sSharedLastHsSec <= 0L || Math.max(0L, nowSec - sSharedLastHsSec) >= 135L)) {
                        try (Socket ignoredSock = openSocks5Ipv4Socket(
                                p,
                                getActiveSocksUser(),
                                getActiveSocksPass(appCtx),
                                new byte[]{1, 1, 1, 1},
                                443,
                                1800
                        )) {
                            // Deliberately trigger Go awaitHandshakeReadyOrFail on owning mux process.
                        } catch (Throwable ignored) {
                        }
                        try {
                            Thread.sleep(350L);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                        sLastSharedHubCheckMs = 0L;
                        queryAnyLiveSharedTunnelPort(appCtx);
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                sHandshakeNudgeInFlight.set(false);
                if (onUpdatedMain != null) {
                    new Handler(Looper.getMainLooper()).post(onUpdatedMain);
                }
            }
        });
    }

    public static long getSharedTunnelLastHandshakeSec(Context context) {
        try {
            if (context != null) {
                NativeBridgeLoader.ensureLoaded(context, null);
            }
            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                TunnelStats st = getLiveStats(context, null);
                long nowSec = System.currentTimeMillis() / 1000L;
                if (st.lastHandshakeSec > 0L && Math.max(0L, nowSec - st.lastHandshakeSec) < HANDSHAKE_HEALTHY_WINDOW_SEC) {
                    return st.lastHandshakeSec;
                }
            }
        } catch (Throwable ignored) {
        }
        if (context == null) {
            return 0L;
        }
        long nowSec = System.currentTimeMillis() / 1000L;
        if (sSharedLastHsSec <= 0L
                || Math.max(0L, nowSec - sSharedLastHsSec) >= PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC
                || (SystemClock.elapsedRealtime() - sLastSharedHubCheckMs) >= 2000L) {
            sLastSharedHubCheckMs = 0L;
        }
        int livePort = queryAnyLiveSharedTunnelPort(context);
        if (livePort > 0) {
            if (sSharedLastHsSec > 0L) {
                return sSharedLastHsSec;
            }
            if (sSharedHsHealthy) {
                return nowSec;
            }
        }
        try {
            int port = -1;
            long updatedAt = 0L;
            long lastHsSec = 0L;
            boolean hsHealthy = false;
            String myPkg = context.getPackageName();
            if ("org.telegram.wgplus.module".equals(myPkg)) {
                SharedPreferences sp = context.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                port = sp.getInt("port", -1);
                updatedAt = sp.getLong("updatedAt", 0L);
                lastHsSec = sp.getLong("lastHsSec", 0L);
                hsHealthy = sp.getBoolean("hsHealthy", false);
            } else {
                Bundle out = context.getContentResolver().call(
                        Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                        KeepaliveStatusProvider.METHOD_QUERY_SHARED_TUNNEL,
                        null,
                        null
                );
                if (out != null) {
                    port = out.getInt("port", -1);
                    updatedAt = out.getLong("updatedAt", 0L);
                    lastHsSec = out.getLong("lastHsSec", 0L);
                    hsHealthy = out.getBoolean("hsHealthy", false);
                }
            }
            if (port > 0 && (updatedAt <= 0L || Math.abs(System.currentTimeMillis() - updatedAt) < 300_000L)) {
                sSharedLastHsSec = lastHsSec;
                sSharedHsHealthy = hsHealthy;
                return (hsHealthy && lastHsSec > 0L) ? lastHsSec : 0L;
            }
        } catch (Throwable ignored) {
        }
        return 0L;
    }

    public static void onModuleVersionUpgraded(Context ctx, ClassLoader telegramClassLoader) {
        sLastBoundEnabled = null;
        sLastBoundPort = -1;
        sLastBoundUser = "";
        sLastBoundPass = "";
        sLastBoundHsHealthy = null;
        sLastHardRestartMs = 0L;
        sAutoMtuDowngraded = false;
        sLastReportedHsHealthy = false;
        sRoamRetryCount = 0;

        sSharedHubPort = -1;
        sIsSharedHubOwner = false;
        sSharedSocksUser = "";
        sSharedSocksPass = "";
        sSharedLastHsSec = 0L;
        sSharedHsHealthy = false;
        sCachedExternalSharedPort = -1;
        sLastSharedHubCheckMs = 0L;

        if (ctx == null) {
            return;
        }
        ensureSessionSocksCredentials(ctx);
        try {
            if (NativeBridgeLoader.isLoaded()) {
                Wgbridge.setSocksAuth(sSocksUser, sSocksPass);
                Wgbridge.resetSocksAuthRejectCount();
                if (Wgbridge.isRunning()) {
                    int activePort = (int) Wgbridge.getActivePort();
                    if (activePort > 0 && telegramClassLoader != null) {
                        postBindTelegramProxy(ctx, telegramClassLoader, true, activePort, isRouteCallsEnabled(ctx), true);
                    }
                    return;
                }
            }
        } catch (Throwable ignored) {
        }

        int sharedPort = queryAnyLiveSharedTunnelPort(ctx);
        if (sharedPort > 0) {
            if (telegramClassLoader != null) {
                postBindTelegramProxy(ctx, telegramClassLoader, true, sharedPort, isRouteCallsEnabled(ctx), true);
            }
            return;
        }
        if (isKillSwitchEnabled(ctx)) {
            int ksPort = enforceKillSwitchIfDisconnected(ctx, null, telegramClassLoader);
            if (ksPort <= 0) {
                preArmKillSwitchSync(ctx, telegramClassLoader);
            }
            return;
        }
        syncTelegramMainConfigForCalls(ctx, false, 1080, false);
        if (telegramClassLoader != null) {
            postBindTelegramProxy(ctx, telegramClassLoader, false, 1080, false, true);
        }
    }

    public static Object buildTelegramProxySettingsObject(ClassLoader cl, int port, String user, String pass) {
        return buildTelegramProxySettingsObjectInternal(cl, "127.0.0.1", port, user, pass);
    }

    private static Object buildTelegramProxySettingsObjectInternal(
            ClassLoader cl,
            String address,
            int port,
            String user,
            String pass
    ) {
        if (cl == null) {
            return null;
        }
        try {
            Class<?> proxySettingsCls = XposedHelpers.findClassIfExists("org.telegram.utils.proxy.ProxySettings", cl);
            if (proxySettingsCls == null) {
                return null;
            }
            String safeAddr = address != null ? address : "";
            String safeUser = user != null ? user : "";
            String safePass = pass != null ? pass : "";
            Class<?> typeCls = XposedHelpers.findClassIfExists("org.telegram.utils.proxy.ProxySettings$Type", cl);
            Object socks5Type = null;
            if (typeCls != null) {
                try {
                    socks5Type = XposedHelpers.getStaticObjectField(typeCls, "SOCKS5");
                } catch (Throwable ignored) {
                }
                if (socks5Type == null && typeCls.isEnum()) {
                    try {
                        @SuppressWarnings({"unchecked", "rawtypes"})
                        Object val = Enum.valueOf((Class) typeCls, "SOCKS5");
                        socks5Type = val;
                    } catch (Throwable ignored) {
                    }
                }
            }
            try {
                Object builder = XposedHelpers.callStaticMethod(proxySettingsCls, "builder");
                if (builder != null) {
                    if (socks5Type != null) {
                        try {
                            XposedHelpers.callMethod(builder, "setType", socks5Type);
                        } catch (Throwable ignored) {
                        }
                    }
                    XposedHelpers.callMethod(builder, "setAddress", safeAddr);
                    XposedHelpers.callMethod(builder, "setPort", port);
                    XposedHelpers.callMethod(builder, "setUser", safeUser);
                    XposedHelpers.callMethod(builder, "setPassword", safePass);
                    XposedHelpers.callMethod(builder, "setSecret", "");
                    Object built = XposedHelpers.callMethod(builder, "build");
                    if (built != null) {
                        return built;
                    }
                }
            } catch (Throwable ignored) {
            }
            if (typeCls != null && socks5Type != null) {
                try {
                    Constructor<?> ctor = proxySettingsCls.getDeclaredConstructor(
                            typeCls, String.class, int.class, String.class, String.class, String.class
                    );
                    ctor.setAccessible(true);
                    return ctor.newInstance(socks5Type, safeAddr, port, safeUser, safePass, "");
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        // R8-obfuscated ProxySettings fallback (e.g., Telegram 13.3.1 where ProxySettings is renamed):
        // discover the exact 2nd parameter type of ConnectionsManager.setProxySettings(boolean, <T>)
        // and invoke its static SharedPreferences factory after mainconfig has been updated.
        try {
            Class<?> cmCls = XposedHelpers.findClassIfExists("org.telegram.tgnet.ConnectionsManager", cl);
            Context appCtx = sSocksPrefsCtx;
            if (cmCls != null && appCtx != null) {
                Class<?> paramProxyCls = null;
                for (java.lang.reflect.Method m : cmCls.getDeclaredMethods()) {
                    if (!"setProxySettings".equals(m.getName())) {
                        continue;
                    }
                    Class<?>[] pts = m.getParameterTypes();
                    if (pts.length == 2 && pts[0] == boolean.class && !pts[1].isPrimitive()) {
                        paramProxyCls = pts[1];
                        break;
                    }
                }
                if (paramProxyCls != null) {
                    SharedPreferences mc = appCtx.getSharedPreferences(TG_MAINCONFIG, Context.MODE_PRIVATE);
                    for (java.lang.reflect.Method m : paramProxyCls.getDeclaredMethods()) {
                        Class<?>[] pts = m.getParameterTypes();
                        if (java.lang.reflect.Modifier.isStatic(m.getModifiers())
                                && pts.length == 1
                                && SharedPreferences.class.isAssignableFrom(pts[0])
                                && paramProxyCls.isAssignableFrom(m.getReturnType())) {
                            m.setAccessible(true);
                            Object obj = m.invoke(null, mc);
                            if (obj != null) {
                                return obj;
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void registerSharedTunnel(
            Context context,
            int port,
            String profileSig,
            String profileId,
            String profileName,
            String socksUser,
            String socksPass
    ) {
        if (context == null || port <= 0) return;
        try {
            long lastHsSec = 0L;
            boolean hsHealthy = false;
            try {
                if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                    hsHealthy = Wgbridge.isHandshakeHealthy();
                    TunnelStats st = getLiveStats(context, null);
                    lastHsSec = st.lastHandshakeSec;
                    if (!hsHealthy) {
                        lastHsSec = 0L;
                    }
                }
            } catch (Throwable ignored) {
            }
            Bundle b = new Bundle();
            b.putInt("port", port);
            b.putString("sig", profileSig != null ? profileSig : "");
            b.putString("owner", context.getPackageName());
            b.putString("profileId", profileId != null ? profileId : "");
            b.putString("profileName", profileName != null ? profileName : "");
            b.putString("socksUser", socksUser != null ? socksUser : "");
            b.putString("socksPass", socksPass != null ? socksPass : "");
            b.putLong("lastHsSec", lastHsSec);
            b.putBoolean("hsHealthy", hsHealthy);
            context.getContentResolver().call(
                    Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                    KeepaliveStatusProvider.METHOD_REGISTER_SHARED_TUNNEL,
                    null,
                    b
            );
            sLastSharedTunnelHeartbeatMs = System.currentTimeMillis();
        } catch (Throwable ignored) {
        }
    }

    private static void clearSharedTunnel(Context context) {
        clearSharedTunnelForPort(context, -1);
    }

    private static void clearSharedTunnelForPort(Context context, int onlyPort) {
        if (context == null) return;
        try {
            Bundle b = new Bundle();
            b.putString("owner", context.getPackageName());
            if (onlyPort > 0) {
                b.putInt("port", onlyPort);
            }
            context.getContentResolver().call(
                    Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY),
                    KeepaliveStatusProvider.METHOD_CLEAR_SHARED_TUNNEL,
                    null,
                    b
            );
        } catch (Throwable ignored) {
        }
    }

    public static void stopAndUnbind(Context context, String moduleApkPath, ClassLoader telegramClassLoader) {
        sUserManuallyStopped = true;
        stopFailoverMonitor();
        unregisterNetworkWatchdog(context);
        releaseForcedContinuityLocks();
        boolean wasOwner = sIsSharedHubOwner;
        sSharedHubPort = -1;
        sIsSharedHubOwner = false;
        if (wasOwner && context != null) {
            clearSharedTunnel(context);
        }
        sConnectedProfileId = "";
        sTunnelStartedAtMs = 0L;
        sKeepalivePausedForIdle = false;
        sLastActiveNetworkSignature = "";
        sActiveTunnelMtu = 1280;
        sLastBoundEnabled = null;
        sLastBoundPort = -1;
        sLastBoundUser = "";
        sLastBoundPass = "";
        sLastBoundHsHealthy = null;
        sLastReportedHsHealthy = false;
        sAutoMtuDowngraded = false;
        sRoamRetryCount = 0;
        if (context != null) {
            getPrefs(context).edit().remove(KEY_CONNECTED_PROFILE_ID).commit();
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            Wgbridge.stopTunnel();
        } catch (Throwable t) {
            Log.w(TAG, "StopTunnel warning: " + t.getMessage());
        }

        if (isKillSwitchEnabled(context)) {
            enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
        } else {
            syncForegroundKeepaliveService(context, false);
            if (telegramClassLoader != null) {
                postBindTelegramProxy(context, telegramClassLoader, false, 1080, false, true);
            }
        }
    }

    public static int getCachedSharedOrFallbackPort(Context context) {
        if (sSharedHubPort > 0) {
            return sSharedHubPort;
        }
        if (context != null) {
            try {
                int p = queryAnyLiveSharedTunnelPort(context);
                if (p > 0) {
                    return p;
                }
            } catch (Throwable ignored) {
            }
        }
        return 9; // RFC discard port: fail-closed placeholder until mux binds
    }

    /**
     * Synchronously pre-arms Kill Switch credentials & mainconfig during ApplicationLoader.onCreate()
     * before native ConnectionsManager reads config — never touches Wgbridge before libgojni loads
     * and never instantiates ConnectionsManager.getInstance() out-of-order on the main thread.
     */
    public static void preArmKillSwitchSync(Context context, ClassLoader telegramClassLoader) {
        if (context == null || !isKillSwitchEnabled(context)) {
            return;
        }
        try {
            ensureSessionSocksCredentials(context);
            int port = 9;
            if (NativeBridgeLoader.isLoaded()) {
                try {
                    if (Wgbridge.isRunning()) {
                        int ap = (int) Wgbridge.getActivePort();
                        if (ap > 0) port = ap;
                    } else {
                        int kp = (int) Wgbridge.getKillSwitchPort();
                        if (kp > 0) port = kp;
                    }
                } catch (Throwable ignored) {
                }
            } else if (sSharedHubPort > 0) {
                port = sSharedHubPort;
            }
            syncTelegramMainConfigForCalls(context, true, port, true);
        } catch (Throwable ignored) {
        }
    }

    public static void reapplyProxyToAccountIfActive(
            Context context,
            ClassLoader telegramClassLoader,
            int accountIdx
    ) {
        reapplyProxyToAccountIfActive(context, telegramClassLoader, accountIdx, false);
    }

    public static void reapplyProxyToAccountIfActive(
            Context context,
            ClassLoader telegramClassLoader,
            int accountIdx,
            boolean force
    ) {
        if (context == null || telegramClassLoader == null) {
            return;
        }
        if (!NativeBridgeLoader.isLoaded()) {
            if (isKillSwitchEnabled(context)) {
                preArmKillSwitchSync(context, telegramClassLoader);
            }
            return;
        }
        int port = getEffectiveProxyPort(context, null);
        if (port > 0) {
            postBindTelegramProxy(context, telegramClassLoader, true, port, isRouteCallsEnabled(context) || isKillSwitchEnabled(context), force);
        } else if (isKillSwitchEnabled(context)) {
            preArmKillSwitchSync(context, telegramClassLoader);
        }
    }

    /**
     * Engages the loopback SOCKS5 fail-closed Kill Switch guard so Telegram tgnet and VoIP calls
     * cannot fall back to direct ISP sockets while the WireGuard tunnel is disconnected.
     */
    public static int enforceKillSwitchIfDisconnected(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) {
        if (context == null || !isKillSwitchEnabled(context)) {
            return 0;
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (isTunnelRunning(context, moduleApkPath)) {
                return getActivePort(context, moduleApkPath);
            }
            if (sIsSharedHubOwner) {
                sIsSharedHubOwner = false;
                sSharedHubPort = -1;
                clearSharedTunnel(context);
            }
            ensureSessionSocksCredentials(context);
            Wgbridge.setSocksAuth(sSocksUser, sSocksPass);
            Wgbridge.resetSocksAuthRejectCount();
            int guardPort = (int) Wgbridge.startKillSwitchGuard();
            if (guardPort > 0 && telegramClassLoader != null) {
                postBindTelegramProxy(context, telegramClassLoader, true, guardPort, true, true);
            }
            return guardPort;
        } catch (Throwable t) {
            Log.w(TAG, "KillSwitch guard warning: " + t.getMessage());
            return 0;
        }
    }

    private static void releaseKillSwitchGuard(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            Wgbridge.stopKillSwitchGuard();
        } catch (Throwable ignored) {
        }
        if (!isTunnelRunning(context, moduleApkPath) && telegramClassLoader != null) {
            postBindTelegramProxy(context, telegramClassLoader, false, 1080, false);
        }
    }

    public static boolean isKillSwitchGuardActiveNow(Context context, String moduleApkPath) {
        if (context == null || !isKillSwitchEnabled(context)) {
            return false;
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            return !Wgbridge.isRunning() && Wgbridge.getKillSwitchPort() > 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean shouldRouteCallsNow(Context context, String moduleApkPath) {
        if (context == null) {
            return false;
        }
        // When Kill Switch is engaged and tunnel is down, force VoIP calls into the fail-closed guard port too!
        if (isKillSwitchGuardActiveNow(context, moduleApkPath)) {
            return true;
        }
        if (!isRouteCallsEnabled(context)) {
            return false;
        }
        return isTunnelRunning(context, moduleApkPath) && getActivePort(context, moduleApkPath) > 0;
    }

    public static int getEffectiveProxyPort(Context context, String moduleApkPath) {
        int tunnelPort = getActivePort(context, moduleApkPath);
        if (tunnelPort > 0) {
            return tunnelPort;
        }
        if (isKillSwitchEnabled(context)) {
            try {
                NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
                return (int) Wgbridge.getKillSwitchPort();
            } catch (Throwable ignored) {
            }
        }
        return 0;
    }

    /**
     * Concurrently probes all configured profiles via isolated cryptographic WireGuard / AmneziaWG handshakes,
     * selects the fastest responder, and live-switches if currently connected to a slower server.
     */
    public static PingWinnerResult pingAllProfilesAndSelectFastest(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) throws Exception {
        NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
        final List<TunnelConfig> profiles = loadProfiles(context);
        final List<TunnelConfig> configured = new ArrayList<>();
        for (TunnelConfig p : profiles) {
            if (p.hasPeerConfigured()) {
                configured.add(p);
            }
        }
        if (configured.isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ENDPOINT);
        }

        final boolean useDoH = isDohEnabled(context);
        int poolSize = Math.min(4, configured.size());
        ExecutorService pool = Executors.newFixedThreadPool(poolSize);
        List<Future<Integer>> futures = new ArrayList<>();

        for (final TunnelConfig item : configured) {
            futures.add(pool.submit(() -> {
                try {
                    String privHex = normalizeKeyToHex(item.privateKey);
                    String pubHex = normalizeKeyToHex(item.publicKey);
                    String pskHex = safeTrim(item.presharedKey).isEmpty() ? "" : normalizeKeyToHex(item.presharedKey);
                    String ep = useDoH ? safeTrim(item.endpoint) : preResolveEndpoint(item.endpoint);
                    syncEndpointDnsHintsToNative(context, item.endpoint);
                    long rtt = Wgbridge.probeEndpointHandshakeMs(
                            privHex,
                            pskHex,
                            pubHex,
                            ep,
                            item.toEffectiveAwgParamsString(),
                            useDoH,
                            3800L
                    );
                    int ms = Math.max(1, (int) rtt);
                    sPingCacheMs.put(item.id, ms);
                    return ms;
                } catch (Throwable err) {
                    sPingCacheMs.put(item.id, -1);
                    return -1;
                }
            }));
        }

        pool.shutdown();
        pool.awaitTermination(12, TimeUnit.SECONDS);

        TunnelConfig bestCfg = null;
        int bestMs = Integer.MAX_VALUE;
        for (int i = 0; i < configured.size(); i++) {
            int ms = -1;
            try {
                ms = futures.get(i).get(100, TimeUnit.MILLISECONDS);
            } catch (Throwable ignored) {
            }
            if (ms > 0 && ms < bestMs) {
                bestMs = ms;
                bestCfg = configured.get(i);
            }
        }

        if (bestCfg == null) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.PING_ALL_FAILED);
        }

        TunnelConfig selected = selectProfile(context, bestCfg.id);
        PingWinnerResult res = new PingWinnerResult();
        res.winner = selected;
        res.bestMs = bestMs;

        boolean runningNow = isTunnelRunning(context, moduleApkPath);
        String connectedId = getConnectedProfileId(context, moduleApkPath);
        if (runningNow && !selected.id.equals(connectedId)) {
            res.livePort = startAndBindProfile(context, selected, moduleApkPath, telegramClassLoader);
            res.switchedLive = true;
        }
        return res;
    }

    /**
     * Discovers the highest unfragmented inner tunnel MTU (1420 -> 1392 -> 1360 -> 1320 -> 1280)
     * across the mobile/ISP path, saves it to the profile, and reconnects if the tunnel was active.
     */
    public static int discoverAndApplyOptimalMtu(
            Context context,
            TunnelConfig draft,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) throws Exception {
        NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
        if (!draft.hasPeerConfigured()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.MISSING_ENDPOINT);
        }

        String privHex = normalizeKeyToHex(draft.privateKey);
        String pubHex = normalizeKeyToHex(draft.publicKey);
        String pskHex = safeTrim(draft.presharedKey).isEmpty() ? "" : normalizeKeyToHex(draft.presharedKey);
        String dns = safeTrim(draft.dns).isEmpty() ? "1.1.1.1" : safeTrim(draft.dns);
        boolean useDoH = isDohEnabled(context);
        String ep = useDoH ? safeTrim(draft.endpoint) : preResolveEndpoint(draft.endpoint);

        boolean wasRunning = isTunnelRunning(context, moduleApkPath);
        if (wasRunning) {
            // Pause active peer during MTU sweep so single-peer servers do not contend on source UDP port
            if (isKillSwitchEnabled(context)) {
                try {
                    int guardPort = (int) Wgbridge.startKillSwitchGuard();
                    if (guardPort > 0 && telegramClassLoader != null) {
                        postBindTelegramProxy(context, telegramClassLoader, true, guardPort, true);
                    }
                } catch (Throwable ignored) {
                }
            }
            try {
                Wgbridge.stopTunnel();
            } catch (Throwable ignored) {
            }
        }

        try {
            syncEndpointDnsHintsToNative(context, draft.endpoint);
            long optimal = Wgbridge.discoverOptimalMTU(
                    privHex,
                    pskHex,
                    safeTrim(draft.address).isEmpty() ? "10.0.0.2/32" : safeTrim(draft.address),
                    dns,
                    pubHex,
                    ep,
                    draft.toEffectiveAwgParamsString(),
                    useDoH,
                    "",
                    2800L
            );
            int bestMtu = clampMtu((int) optimal);
            draft.mtu = bestMtu;
            saveConfig(context, draft);
            if (wasRunning) {
                startAndBindProfile(context, draft, moduleApkPath, telegramClassLoader);
            }
            return bestMtu;
        } catch (Throwable err) {
            if (wasRunning) {
                try {
                    startAndBindProfile(context, draft, moduleApkPath, telegramClassLoader);
                } catch (Throwable ignored) {
                }
            }
            throw new WgStrings.WgException(WgStrings.ErrorCode.MTU_DISCOVERY_FAILED, err.getMessage(), err);
        }
    }

    /**
     * Driven by Application.ActivityLifecycleCallbacks to ensure immediate zero-delay tunnel
     * verification and Telegram tgnet socket wake-up on foreground resume, while maintaining
     * 24/7 CGNAT NAT persistence in the background.
     */
    public static void onAppForegroundStateChanged(
            final Context context,
            final String moduleApkPath,
            final boolean inForeground
    ) {
        onAppForegroundStateChanged(context, moduleApkPath, null, inForeground);
    }

    private static volatile long sLastBackgroundedAtMs;

    public static void onAppForegroundStateChanged(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader,
            final boolean inForeground
    ) {
        sAppInForeground = inForeground;
        Handler h = getMainHandler();
        if (sPendingIdleSaverTask != null) {
            if (h != null) {
                h.removeCallbacks(sPendingIdleSaverTask);
            }
            sPendingIdleSaverTask = null;
        }

        if (inForeground) {
            long bgElapsedMs = sLastBackgroundedAtMs > 0 ? (SystemClock.elapsedRealtime() - sLastBackgroundedAtMs) : 0L;
            final boolean longBg = bgElapsedMs >= 30_000L;
            getGuardianExecutor().execute(() -> {
                try {
                    if (sKeepalivePausedForIdle) {
                        restoreActiveKeepaliveNow(context, moduleApkPath);
                    }
                    if (!sUserManuallyStopped && !isTunnelRunning(context, moduleApkPath)) {
                        sSharedHubPort = -1;
                        sIsSharedHubOwner = false;
                        if (isAutoConnectEnabled(context) || !sConnectedProfileId.isEmpty()) {
                            TunnelConfig cfg = loadConfig(context);
                            if (cfg.hasPeerConfigured()) {
                                startAndBindProfile(context, cfg, moduleApkPath, telegramClassLoader);
                                return;
                            }
                        }
                        if (isKillSwitchEnabled(context)) {
                            enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
                        }
                    }
                    if (Wgbridge.isRunning()) {
                        acquireForcedContinuityLocks(context);
                        syncForegroundKeepaliveService(context, true);
                        long epochBefore = Wgbridge.getRecoveryEpoch();
                        boolean alive = Wgbridge.ensureTunnelAlive(1500L);
                        boolean rebound = (Wgbridge.getRecoveryEpoch() != epochBefore) || !alive;
                        if (!alive) {
                            rebound = Wgbridge.forceRebindAndHandshake() || rebound;
                        }
                        int activePort = (int) Wgbridge.getActivePort();
                        if (activePort > 0 && telegramClassLoader != null) {
                            postBindTelegramProxy(
                                    context,
                                    telegramClassLoader,
                                    true,
                                    activePort,
                                    isRouteCallsEnabled(context),
                                    rebound
                            );
                            XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, rebound || longBg);
                        }
                    } else if (isUsingSharedHub()) {
                        acquireForcedContinuityLocks(context);
                        int hubPort = sSharedHubPort;
                        if (hubPort > 0 && telegramClassLoader != null) {
                            postBindTelegramProxy(
                                    context,
                                    telegramClassLoader,
                                    true,
                                    hubPort,
                                    isRouteCallsEnabled(context),
                                    longBg
                            );
                            XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, longBg);
                        }
                    }
                } catch (Throwable ignored) {
                }
            });
        } else {
            sLastBackgroundedAtMs = SystemClock.elapsedRealtime();
            // In background: keep WakeLock/WifiLock/FG service held and keep CGNAT pinhole alive (<=18s cellular)
            getGuardianExecutor().execute(() -> {
                try {
                    if (isTunnelRunning(context, moduleApkPath)) {
                        acquireForcedContinuityLocks(context);
                        syncForegroundKeepaliveService(context, true);
                        if (isSmartKeepaliveEnabled(context)) {
                            Wgbridge.setPeerKeepalive(25L);
                            sKeepalivePausedForIdle = true;
                        } else {
                            TunnelConfig activeCfg = getConnectedProfile(context, moduleApkPath);
                            int ka = effectiveKeepAlive(context, activeCfg != null ? activeCfg.keepAlive : 20);
                            Wgbridge.setPeerKeepalive(ka);
                        }
                        if (telegramClassLoader != null) {
                            XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                        }
                    }
                } catch (Throwable ignored) {
                }
            });
        }
    }

    private static void restoreActiveKeepaliveNow(final Context context, final String moduleApkPath) {
        getGuardianExecutor().execute(() -> {
            try {
                if (!isTunnelRunning(context, moduleApkPath)) {
                    sKeepalivePausedForIdle = false;
                    return;
                }
                TunnelConfig activeCfg = getConnectedProfile(context, moduleApkPath);
                int ka = effectiveKeepAlive(context, activeCfg != null ? activeCfg.keepAlive : 20);
                Wgbridge.setPeerKeepalive(ka);
                sKeepalivePausedForIdle = false;
            } catch (Throwable ignored) {
            }
        });
    }

    private static void startFailoverMonitor(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        stopFailoverMonitor();
        if (context == null) {
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        ScheduledExecutorService exec = getGuardianExecutor();
        sGuardianFuture = exec.scheduleWithFixedDelay(() -> {
            if (sUserManuallyStopped || sFailoverCheckRunning) {
                return;
            }
            sFailoverCheckRunning = true;
            try {
                evaluateTunnelHealthAndFailover(appCtx, moduleApkPath, telegramClassLoader);
            } catch (Throwable ignored) {
            } finally {
                sFailoverCheckRunning = false;
            }
        }, 2L, 10L, TimeUnit.SECONDS);
    }

    private static void stopFailoverMonitor() {
        if (sGuardianFuture != null) {
            try {
                sGuardianFuture.cancel(false);
            } catch (Throwable ignored) {
            }
            sGuardianFuture = null;
        }
        sConsecutiveHealthFailures = 0;
    }

    private static void evaluateTunnelHealthAndFailover(
            final Context appCtx,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        if (sUserManuallyStopped) {
            return;
        }
        try {
            NativeBridgeLoader.ensureLoaded(appCtx, moduleApkPath);
        } catch (Throwable ignored) {
            return;
        }

        if (syncPullSharedStateFromProvider(appCtx, false) && Wgbridge.isRunning()) {
            String syncedActiveId = getPrefs(appCtx).getString(KEY_ACTIVE_PROFILE_ID, "");
            if (!syncedActiveId.isEmpty() && !syncedActiveId.equals(sConnectedProfileId)) {
                TunnelConfig nextCfg = loadConfig(appCtx);
                if (nextCfg != null && nextCfg.hasPeerConfigured()) {
                    try {
                        startAndBindProfile(appCtx, nextCfg, moduleApkPath, telegramClassLoader);
                        return;
                    } catch (Throwable ignored) {
                    }
                }
            }
        }

        // 1. Self-heal if tunnel unexpectedly stopped while supposed to be active 24/7
        if (!Wgbridge.isRunning()) {
            if (isUsingSharedHub()) {
                sConsecutiveHealthFailures = 0;
                if (telegramClassLoader != null) {
                    postBindTelegramProxy(appCtx, telegramClassLoader, true, sSharedHubPort, isRouteCallsEnabled(appCtx), false);
                    XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                }
                return;
            }
            sSharedHubPort = -1;
            sIsSharedHubOwner = false;
            if (isAutoConnectEnabled(appCtx) || !sConnectedProfileId.isEmpty()) {
                TunnelConfig target = getConnectedProfile(appCtx, moduleApkPath);
                if (target == null || !target.hasPeerConfigured()) {
                    target = loadConfig(appCtx);
                }
                if (target != null && target.hasPeerConfigured()) {
                    try {
                        startAndBindProfile(appCtx, target, moduleApkPath, telegramClassLoader);
                        return;
                    } catch (Throwable ignored) {
                    }
                }
            } else {
                return;
            }
        }

        acquireForcedContinuityLocks(appCtx);

        // 1a. Multi-app single-tunnel convergence: if a cold-start race bound port > 48729 while
        // canonical port 48729 already runs the same profile, yield immediately onto 48729 so
        // only ONE WireGuard session owns the device PrivateKey.
        try {
            int myPort = (int) Wgbridge.getActivePort();
            if (myPort > 48729) {
                TunnelConfig activeCfg = getConnectedProfile(appCtx, moduleApkPath);
                String requiredSig = (activeCfg != null && activeCfg.hasPeerConfigured())
                        ? (safeTrim(activeCfg.endpoint) + "|" + safeTrim(activeCfg.publicKey))
                        : "";
                Wgp1StatusResult canon = queryLiveStatusWithFallback(appCtx, moduleApkPath, 48729, sSocksPass, requiredSig);
                if (canon != null && canon.running && wgp1ProfileSigMatches(appCtx, requiredSig, canon.profileSig)) {
                    Wgbridge.setKillSwitchArmed(false);
                    Wgbridge.stopKillSwitchGuard();
                    Wgbridge.stopTunnel();
                    sIsSharedHubOwner = false;
                    sSharedHubPort = 48729;
                    sCachedExternalSharedPort = 48729;
                    sLastSharedHubCheckMs = SystemClock.elapsedRealtime();
                    sSharedLastHsSec = canon.hsSec;
                    sSharedHsHealthy = canon.hsHealthy;
                    clearSharedTunnelForPort(appCtx, myPort);
                    if (telegramClassLoader != null) {
                        postBindTelegramProxy(appCtx, telegramClassLoader, true, 48729, isRouteCallsEnabled(appCtx), true);
                        XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, true);
                    }
                    WgDiagnosticsLog.record("TUNNEL", "CONVERGE_SHARED", "yielded port=" + myPort + " -> 48729");
                    return;
                }
            }
        } catch (Throwable ignored) {
        }

        // 1b. Self-heal if SOCKS5 auth rejections spiked (stale Telegram mainconfig / SharedConfig creds)
        try {
            if (Wgbridge.getSocksAuthRejectCount() >= 3L) {
                Wgbridge.resetSocksAuthRejectCount();
                ensureSessionSocksCredentials(appCtx);
                Wgbridge.setSocksAuth(sSocksUser, sSocksPass);
                ModuleHygieneManager.triggerDesyncRecoveryHygiene(appCtx, telegramClassLoader, "socks_auth_reject_3x");
                if (telegramClassLoader != null) {
                    int p = (int) Wgbridge.getActivePort();
                    if (p > 0) {
                        postBindTelegramProxy(appCtx, telegramClassLoader, true, p, isRouteCallsEnabled(appCtx), true);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 2. Ensure active tunnel is responsive; EnsureTunnelAlive triggers soft probe then single hop if stalled
        boolean alive = false;
        try {
            alive = Wgbridge.ensureTunnelAlive(2200L);
        } catch (Throwable ignored) {
        }
        if (alive) {
            sConsecutiveHealthFailures = 0;
            TunnelConfig activeCfg = getConnectedProfile(appCtx, moduleApkPath);
            boolean hsNow = isHandshakeHealthyNow(appCtx, moduleApkPath);
            if (hsNow && (!sLastReportedHsHealthy || Math.abs(System.currentTimeMillis() - sLastSharedTunnelHeartbeatMs) >= 60_000L)) {
                boolean wasReportedHealthy = sLastReportedHsHealthy;
                sLastReportedHsHealthy = true;
                int activePort = 0;
                try {
                    activePort = (int) Wgbridge.getActivePort();
                } catch (Throwable ignored) {
                }
                if (activePort > 0) {
                    String sig = activeCfg != null
                            ? (safeTrim(activeCfg.endpoint) + "|" + safeTrim(activeCfg.publicKey))
                            : "";
                    registerSharedTunnel(
                            appCtx,
                            activePort,
                            sig,
                            activeCfg != null ? activeCfg.id : sConnectedProfileId,
                            activeCfg != null ? activeCfg.name : "",
                            sSocksUser,
                            sSocksPass
                    );
                    if (!wasReportedHealthy && telegramClassLoader != null) {
                        postBindTelegramProxy(appCtx, telegramClassLoader, true, activePort, isRouteCallsEnabled(appCtx), true);
                    }
                }
            } else if (telegramClassLoader != null) {
                // Only nudge Telegram accounts whose ConnectionState != Connected (3)
                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
            }
            return;
        }

        if (sLastReportedHsHealthy) {
            sLastReportedHsHealthy = false;
            int activePort = 0;
            try {
                activePort = (int) Wgbridge.getActivePort();
            } catch (Throwable ignored) {
            }
            if (activePort > 0) {
                TunnelConfig activeCfg = getConnectedProfile(appCtx, moduleApkPath);
                String sig = activeCfg != null
                        ? (safeTrim(activeCfg.endpoint) + "|" + safeTrim(activeCfg.publicKey))
                        : "";
                registerSharedTunnel(
                        appCtx,
                        activePort,
                        sig,
                        activeCfg != null ? activeCfg.id : sConnectedProfileId,
                        activeCfg != null ? activeCfg.name : "",
                        sSocksUser,
                        sSocksPass
                );
                if (telegramClassLoader != null) {
                    postBindTelegramProxy(appCtx, telegramClassLoader, true, activePort, isRouteCallsEnabled(appCtx), true);
                }
            }
        }

        List<TunnelConfig> profiles = loadProfiles(appCtx);
        List<TunnelConfig> backups = new ArrayList<>();
        String currentId = getConnectedProfileId(appCtx, moduleApkPath);
        TunnelConfig currentCfg = null;
        for (TunnelConfig p : profiles) {
            if (!p.hasPeerConfigured()) {
                continue;
            }
            if (p.id.equals(currentId)) {
                currentCfg = p;
            } else {
                backups.add(p);
            }
        }
        if (currentCfg == null && !profiles.isEmpty()) {
            currentCfg = profiles.get(0);
        }
        if (currentCfg == null || !currentCfg.hasPeerConfigured()) {
            return;
        }

        boolean useDoH = isDohEnabled(appCtx);
        sConsecutiveHealthFailures++;
        if (isKillSwitchEnabled(appCtx) && !Wgbridge.isRunning()) {
            enforceKillSwitchIfDisconnected(appCtx, moduleApkPath, telegramClassLoader);
        }

        // 3. Auto-downgrade oversized MTU (>1280) after 2 stalled ticks (60s restart cooldown protected)
        long nowElapsed = SystemClock.elapsedRealtime();
        if (sConsecutiveHealthFailures >= 2 && sActiveTunnelMtu > 1280 && !sAutoMtuDowngraded
                && (nowElapsed - sLastHardRestartMs >= 60_000L)) {
            sAutoMtuDowngraded = true;
            sLastHardRestartMs = nowElapsed;
            sConsecutiveHealthFailures = 0;
            WgDiagnosticsLog.record("HEALTH", "MTU_DROP", "Auto-downgrading MTU from " + sActiveTunnelMtu + " to 1280");
            try {
                startAndBindProfile(appCtx, currentCfg, moduleApkPath, telegramClassLoader);
            } catch (Throwable ignored) {
            }
            return;
        }
        if (sConsecutiveHealthFailures < 3) {
            return;
        }

        // 4. If Auto-Failover is enabled and backup profiles exist, switch to first healthy backup
        if (isAutoFailoverEnabled(appCtx) && !backups.isEmpty()) {
            for (final TunnelConfig candidate : backups) {
                try {
                    syncEndpointDnsHintsToNative(appCtx, candidate.endpoint);
                    long candRtt = Wgbridge.probeEndpointHandshakeMs(
                            normalizeKeyToHex(candidate.privateKey),
                            safeTrim(candidate.presharedKey).isEmpty() ? "" : normalizeKeyToHex(candidate.presharedKey),
                            normalizeKeyToHex(candidate.publicKey),
                            useDoH ? safeTrim(candidate.endpoint) : preResolveEndpoint(candidate.endpoint),
                            candidate.toEffectiveAwgParamsString(),
                            useDoH,
                            3000L
                    );
                    if (candRtt > 0) {
                        sPingCacheMs.put(candidate.id, (int) candRtt);
                        sLastHardRestartMs = nowElapsed;
                        startAndBindProfile(appCtx, candidate, moduleApkPath, telegramClassLoader);
                        final boolean isAr = isArabic(appCtx);
                        Handler h = getMainHandler();
                        if (h != null && sAppInForeground) {
                            h.post(() -> Toast.makeText(
                                    appCtx,
                                    WgStrings.toastFailoverSwitched(isAr, candidate.name),
                                    Toast.LENGTH_LONG
                            ).show());
                        }
                        return;
                    }
                } catch (Throwable ignored) {
                }
            }
        }

        // 5. Otherwise, hard-restart the current tunnel profile with a strict 60s anti-storm cooldown
        if (sConsecutiveHealthFailures >= 3 && (nowElapsed - sLastHardRestartMs >= 60_000L)) {
            sConsecutiveHealthFailures = 0;
            sLastHardRestartMs = nowElapsed;
            if (sActiveTunnelMtu > 1280) {
                sAutoMtuDowngraded = true;
            }
            try {
                startAndBindProfile(appCtx, currentCfg, moduleApkPath, telegramClassLoader);
            } catch (Throwable ignored) {
            }
        }
    }

    public static TunnelStats getLiveStats(Context context, String moduleApkPath) {
        TunnelStats out = new TunnelStats();
        try {
            if (!isTunnelRunning(context, moduleApkPath)) {
                return out;
            }
            String raw = Wgbridge.getTunnelStats();
            if (raw == null || raw.isEmpty()) {
                return out;
            }
            String[] lines = raw.split("\\r?\\n");
            for (String line : lines) {
                if (line.startsWith("rx_bytes=")) {
                    out.rxBytes = Long.parseLong(line.substring("rx_bytes=".length()).trim());
                } else if (line.startsWith("tx_bytes=")) {
                    out.txBytes = Long.parseLong(line.substring("tx_bytes=".length()).trim());
                } else if (line.startsWith("last_handshake_time_sec=")) {
                    out.lastHandshakeSec = Long.parseLong(line.substring("last_handshake_time_sec=".length()).trim());
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    public static TunnelVerifyResult verifyTunnel(Context context, String moduleApkPath) throws Exception {
        if (!isTunnelRunning(context, moduleApkPath)) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.TUNNEL_STOPPED);
        }
        boolean localRunning = false;
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            localRunning = Wgbridge.isRunning();
        } catch (Throwable ignored) {
        }
        int socksPort = getActivePort(context, moduleApkPath);
        if (socksPort <= 0) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.NO_ACTIVE_PORT);
        }
        if (!localRunning && context != null) {
            sLastSharedHubCheckMs = 0L;
            queryAnyLiveSharedTunnelPort(context);
        }
        final String socksUser = getActiveSocksUser();
        final String socksPass = getActiveSocksPass();

        TunnelVerifyResult res = new TunnelVerifyResult();

        Exception lastErr = null;
        byte[][] cfTargets = new byte[][]{
                new byte[]{1, 1, 1, 1},
                new byte[]{1, 0, 0, 1}
        };
        for (byte[] targetIp : cfTargets) {
            try {
                long tStart = System.nanoTime();
                try (Socket rawSocks = openSocks5Ipv4Socket(socksPort, socksUser, socksPass, targetIp, 443, 12000)) {
                    long connectDone = System.nanoTime();
                    res.tunnelPingMs = Math.max(1L, (connectDone - tStart) / 1_000_000L);

                    SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    try (SSLSocket ssl = (SSLSocket) sslFactory.createSocket(rawSocks, "one.one.one.one", 443, true)) {
                        ssl.setSoTimeout(12000);
                        ssl.startHandshake();
                        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify("one.one.one.one", ssl.getSession())) {
                            throw new SSLHandshakeException("TLS hostname mismatch");
                        }

                        OutputStream out = ssl.getOutputStream();
                        String req = "GET /cdn-cgi/trace HTTP/1.1\r\n"
                                + "Host: one.one.one.one\r\n"
                                + "User-Agent: WGPlus/1.4.0\r\n"
                                + "Connection: close\r\n\r\n";
                        out.write(req.getBytes(StandardCharsets.US_ASCII));
                        out.flush();

                        BufferedReader reader = new BufferedReader(
                                new InputStreamReader(ssl.getInputStream(), StandardCharsets.UTF_8)
                        );
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("ip=")) {
                                res.exitIp = line.substring(3).trim();
                            } else if (line.startsWith("loc=")) {
                                res.countryCode = line.substring(4).trim().toUpperCase(Locale.ROOT);
                            } else if (line.startsWith("colo=")) {
                                res.colo = line.substring(5).trim();
                            }
                        }
                    }
                }
                if (!res.exitIp.isEmpty()) {
                    lastErr = null;
                    break;
                }
            } catch (Exception e) {
                lastErr = e;
            }
        }

        if (res.exitIp.isEmpty()) {
            throw new WgStrings.WgException(
                    WgStrings.ErrorCode.VERIFY_ROUTE_FAILED,
                    lastErr != null ? lastErr.getMessage() : "",
                    lastErr
            );
        }

        try {
            long dcStart = System.nanoTime();
            try (Socket tgSock = openSocks5Ipv4Socket(
                    socksPort,
                    socksUser,
                    socksPass,
                    new byte[]{(byte) 149, (byte) 154, (byte) 167, 50},
                    443,
                    8000
            )) {
                res.telegramDcPingMs = Math.max(1L, (System.nanoTime() - dcStart) / 1_000_000L);
                res.telegramDcReachable = tgSock.isConnected();
            }
        } catch (Throwable ignored) {
            res.telegramDcReachable = false;
        }

        long udpLatency = probeUdpAssociateDns(socksPort, socksUser, socksPass, new byte[]{1, 1, 1, 1}, 53, 5500);
        if (udpLatency <= 0L) {
            udpLatency = probeUdpAssociateDns(socksPort, socksUser, socksPass, new byte[]{8, 8, 8, 8}, 53, 5500);
        }
        if (udpLatency > 0L) {
            res.udpCallsReady = true;
            res.udpPingMs = udpLatency;
        } else {
            res.udpCallsReady = false;
        }

        return res;
    }

    static void performSocks5ClientAuth(OutputStream out, DataInputStream in, String user, String pass) throws Exception {
        String u = user != null ? user : "";
        String p = pass != null ? pass : "";
        if (u.isEmpty() && p.isEmpty()) {
            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] greet = new byte[2];
            in.readFully(greet);
            if (greet[0] != 0x05 || greet[1] != 0x00) {
                throw new IllegalStateException("SOCKS5 auth mismatch: 0x" + Integer.toHexString(greet[1] & 0xFF));
            }
            return;
        }
        out.write(new byte[]{0x05, 0x02, 0x00, 0x02});
        out.flush();
        byte[] greet = new byte[2];
        in.readFully(greet);
        if (greet[0] != 0x05) {
            throw new IllegalStateException("SOCKS5 auth mismatch: 0x" + Integer.toHexString(greet[1] & 0xFF));
        }
        if (greet[1] == 0x00) {
            return;
        }
        if (greet[1] != 0x02) {
            throw new IllegalStateException("SOCKS5 auth mismatch: 0x" + Integer.toHexString(greet[1] & 0xFF));
        }
        byte[] uBytes = u.getBytes(StandardCharsets.UTF_8);
        byte[] pBytes = p.getBytes(StandardCharsets.UTF_8);
        if (uBytes.length > 255 || pBytes.length > 255) {
            throw new IllegalStateException("SOCKS5 credentials exceed 255 bytes");
        }
        ByteArrayOutputStream authReq = new ByteArrayOutputStream(3 + uBytes.length + pBytes.length);
        authReq.write(0x01);
        authReq.write(uBytes.length);
        authReq.write(uBytes);
        authReq.write(pBytes.length);
        authReq.write(pBytes);
        out.write(authReq.toByteArray());
        out.flush();
        byte[] authResp = new byte[2];
        in.readFully(authResp);
        if (authResp[1] != 0x00) {
            throw new IllegalStateException("SOCKS5 auth failed");
        }
    }

    private static long probeUdpAssociateDns(int localSocksPort, String user, String pass, byte[] dnsIpv4, int dnsPort, int timeoutMs) {
        try (Socket ctrlSock = new Socket()) {
            ctrlSock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 4000);
            ctrlSock.setSoTimeout(timeoutMs);

            OutputStream out = ctrlSock.getOutputStream();
            DataInputStream in = new DataInputStream(ctrlSock.getInputStream());

            performSocks5ClientAuth(out, in, user, pass);

            out.write(new byte[]{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
            out.flush();

            byte[] resp = new byte[10];
            in.readFully(resp);
            if (resp[0] != 0x05 || resp[1] != 0x00) {
                return -1L;
            }
            int relayPort = ((resp[8] & 0xFF) << 8) | (resp[9] & 0xFF);
            if (relayPort <= 0) {
                return -1L;
            }

            try (DatagramSocket udpSock = new DatagramSocket()) {
                udpSock.setSoTimeout(timeoutMs);

                ByteArrayOutputStream pkt = new ByteArrayOutputStream(48);
                pkt.write(new byte[]{0x00, 0x00, 0x00, 0x01});
                pkt.write(dnsIpv4);
                pkt.write((dnsPort >> 8) & 0xFF);
                pkt.write(dnsPort & 0xFF);

                pkt.write(new byte[]{
                        0x57, 0x47, 0x01, 0x00,
                        0x00, 0x01, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00
                });
                pkt.write(8);
                pkt.write("telegram".getBytes(StandardCharsets.US_ASCII));
                pkt.write(3);
                pkt.write("org".getBytes(StandardCharsets.US_ASCII));
                pkt.write(0);
                pkt.write(new byte[]{0x00, 0x01, 0x00, 0x01});

                byte[] sendBytes = pkt.toByteArray();
                DatagramPacket sendPkt = new DatagramPacket(
                        sendBytes,
                        sendBytes.length,
                        InetAddress.getByName("127.0.0.1"),
                        relayPort
                );

                long startNs = System.nanoTime();
                udpSock.send(sendPkt);

                byte[] recvBuf = new byte[512];
                DatagramPacket recvPkt = new DatagramPacket(recvBuf, recvBuf.length);
                udpSock.receive(recvPkt);
                long elapsedMs = Math.max(1L, (System.nanoTime() - startNs) / 1_000_000L);

                if (recvPkt.getLength() >= 22 && recvBuf[10] == 0x57 && recvBuf[11] == 0x47) {
                    return elapsedMs;
                }
            }
        } catch (Throwable ignored) {
        }
        return -1L;
    }

    private static Socket openSocks5Ipv4Socket(int localSocksPort, String user, String pass, byte[] ipv4, int targetPort, int timeoutMs) throws Exception {
        Socket sock = new Socket();
        try {
            sock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 5000);
            sock.setSoTimeout(timeoutMs);

            OutputStream out = sock.getOutputStream();
            DataInputStream in = new DataInputStream(sock.getInputStream());

            performSocks5ClientAuth(out, in, user, pass);

            byte[] req = new byte[]{
                    0x05, 0x01, 0x00, 0x01,
                    ipv4[0], ipv4[1], ipv4[2], ipv4[3],
                    (byte) ((targetPort >> 8) & 0xFF),
                    (byte) (targetPort & 0xFF)
            };
            out.write(req);
            out.flush();

            byte[] connResp = new byte[10];
            in.readFully(connResp);
            if (connResp[1] != 0x00) {
                throw new IllegalStateException("SOCKS5 connect code " + connResp[1]);
            }
            return sock;
        } catch (Exception e) {
            try {
                sock.close();
            } catch (Throwable ignored) {
            }
            throw e;
        }
    }

    public static boolean isTunnelRunning(Context context, String moduleApkPath) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (Wgbridge.isRunning()) {
                return true;
            }
            return isUsingSharedHub() || queryAnyLiveSharedTunnelPort(context) > 0;
        } catch (Throwable t) {
            return isUsingSharedHub() || queryAnyLiveSharedTunnelPort(context) > 0;
        }
    }

    public static int getActivePort(Context context, String moduleApkPath) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (Wgbridge.isRunning()) {
                return (int) Wgbridge.getActivePort();
            }
            if (isUsingSharedHub()) {
                return sSharedHubPort;
            }
            int extPort = queryAnyLiveSharedTunnelPort(context);
            return extPort > 0 ? extPort : 0;
        } catch (Throwable t) {
            if (isUsingSharedHub()) {
                return sSharedHubPort;
            }
            int extPort = queryAnyLiveSharedTunnelPort(context);
            return extPort > 0 ? extPort : 0;
        }
    }

    public static void postBindTelegramProxy(
            final Context context,
            final ClassLoader classLoader,
            final boolean enabled,
            final int localPort,
            final boolean routeCalls
    ) {
        postBindTelegramProxy(context, classLoader, enabled, localPort, routeCalls, false);
    }

    public static void postBindTelegramProxy(
            final Context context,
            final ClassLoader classLoader,
            final boolean enabled,
            final int localPort,
            final boolean routeCalls,
            final boolean force
    ) {
        if (classLoader == null) {
            return;
        }
        Runnable task = () -> bindTelegramProxyInternal(context, classLoader, enabled, localPort, routeCalls, force);
        if (Looper.myLooper() == Looper.getMainLooper()) {
            task.run();
        } else {
            Handler h = getMainHandler();
            if (h != null) {
                h.post(task);
            }
        }
    }

    private static void bindTelegramProxyInternal(
            Context context,
            ClassLoader classLoader,
            boolean enabled,
            int localPort,
            boolean routeCalls,
            boolean force
    ) {
        try {
            String socksUser = enabled ? getActiveSocksUser(context) : "";
            String socksPass = enabled ? getActiveSocksPass(context) : "";
            boolean hsHealthy = enabled && isHandshakeHealthyNow(context, null);

            Boolean prevEnabled = sLastBoundEnabled;
            int prevPort = sLastBoundPort;
            boolean prevRoute = sLastBoundRouteCalls;
            boolean changed = prevEnabled == null
                    || prevEnabled != enabled
                    || prevPort != localPort
                    || prevRoute != routeCalls
                    || !socksUser.equals(sLastBoundUser)
                    || !socksPass.equals(sLastBoundPass)
                    || !Boolean.valueOf(hsHealthy).equals(sLastBoundHsHealthy);

            syncTelegramMainConfigForCalls(context, enabled, localPort, routeCalls);
            if (!changed && !force) {
                return;
            }
            sApplyingProxyBindings = true;
            try {
                XposedProxyReflector.apply(classLoader, enabled, localPort, socksUser, socksPass, hsHealthy, true);
            } finally {
                sApplyingProxyBindings = false;
            }
            sLastBoundEnabled = enabled;
            sLastBoundPort = localPort;
            sLastBoundRouteCalls = routeCalls;
            sLastBoundUser = socksUser;
            sLastBoundPass = socksPass;
            sLastBoundHsHealthy = hsHealthy;
            Log.i(TAG, "Applied Telegram proxy & call settings (enabled=" + enabled
                    + ", port=" + localPort + ", routeCalls=" + routeCalls + ", hsHealthy=" + hsHealthy + ")");
        } catch (Throwable t) {
            Log.e(TAG, "Failed applying Telegram proxy settings", t);
        }
    }

    private static void syncTelegramMainConfigForCalls(
            Context context,
            boolean enabled,
            int localPort,
            boolean routeCalls
    ) {
        if (context == null) {
            return;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            SharedPreferences mc = appCtx.getSharedPreferences(TG_MAINCONFIG, Context.MODE_PRIVATE);
            SharedPreferences wgPrefs = getPrefs(appCtx);

            if (enabled) {
                if (!wgPrefs.getBoolean(KEY_MC_SNAPSHOT_TAKEN, false)) {
                    String curIp = mc.getString("proxy_ip", "");
                    if (!"127.0.0.1".equals(curIp)) {
                        wgPrefs.edit()
                                .putBoolean(KEY_MC_SNAPSHOT_TAKEN, true)
                                .putBoolean(KEY_MC_PREV_ENABLED, mc.getBoolean("proxy_enabled", false))
                                .putBoolean(KEY_MC_PREV_CALLS, mc.getBoolean("proxy_enabled_calls", false))
                                .putString(KEY_MC_PREV_IP, curIp != null ? curIp : "")
                                .putInt(KEY_MC_PREV_PORT, mc.getInt("proxy_port", 1080))
                                .putString(KEY_MC_PREV_USER, mc.getString("proxy_user", ""))
                                .putString(KEY_MC_PREV_PASS, mc.getString("proxy_pass", ""))
                                .putString(KEY_MC_PREV_SECRET, mc.getString("proxy_secret", ""))
                                .apply();
                    }
                }
                String activeU = getActiveSocksUser(appCtx);
                String activeP = getActiveSocksPass(appCtx);
                mc.edit()
                        .putBoolean("proxy_enabled", true)
                        .putBoolean("proxy_enabled_calls", routeCalls)
                        .putString("proxy_ip", "127.0.0.1")
                        .putInt("proxy_port", localPort)
                        .putString("proxy_user", activeU)
                        .putString("proxy_pass", activeP)
                        .putString("proxy_secret", "")
                        .apply();
                for (int acc = 1; acc <= 3; acc++) {
                    String mcName = TG_MAINCONFIG + acc;
                    java.io.File mcFile = new java.io.File(new java.io.File(appCtx.getApplicationInfo().dataDir, "shared_prefs"), mcName + ".xml");
                    if (mcFile.exists()) {
                        appCtx.getSharedPreferences(mcName, Context.MODE_PRIVATE).edit()
                                .putBoolean("proxy_enabled", true)
                                .putBoolean("proxy_enabled_calls", routeCalls)
                                .putString("proxy_ip", "127.0.0.1")
                                .putInt("proxy_port", localPort)
                                .putString("proxy_user", activeU)
                                .putString("proxy_pass", activeP)
                                .putString("proxy_secret", "")
                                .apply();
                    }
                }
            } else {
                if (wgPrefs.getBoolean(KEY_MC_SNAPSHOT_TAKEN, false)) {
                    mc.edit()
                            .putBoolean("proxy_enabled", wgPrefs.getBoolean(KEY_MC_PREV_ENABLED, false))
                            .putBoolean("proxy_enabled_calls", wgPrefs.getBoolean(KEY_MC_PREV_CALLS, false))
                            .putString("proxy_ip", wgPrefs.getString(KEY_MC_PREV_IP, ""))
                            .putInt("proxy_port", wgPrefs.getInt(KEY_MC_PREV_PORT, 1080))
                            .putString("proxy_user", wgPrefs.getString(KEY_MC_PREV_USER, ""))
                            .putString("proxy_pass", wgPrefs.getString(KEY_MC_PREV_PASS, ""))
                            .putString("proxy_secret", wgPrefs.getString(KEY_MC_PREV_SECRET, ""))
                            .apply();
                    wgPrefs.edit().putBoolean(KEY_MC_SNAPSHOT_TAKEN, false).apply();
                } else if ("127.0.0.1".equals(mc.getString("proxy_ip", ""))) {
                    mc.edit()
                            .putBoolean("proxy_enabled", false)
                            .putBoolean("proxy_enabled_calls", false)
                            .apply();
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "syncTelegramMainConfigForCalls warning: " + t.getMessage());
        }
    }

    private static void registerNetworkWatchdog(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        synchronized (WATCHDOG_LOCK) {
            if (sNetworkCallback != null) {
                return;
            }
            try {
                final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
                ConnectivityManager cm = (ConnectivityManager) appCtx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm == null) {
                    return;
                }
                ConnectivityManager.NetworkCallback cb = new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 160L, true);
                    }

                    @Override
                    public void onLost(Network network) {
                        sLastActiveNetworkSignature = "";
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 400L, true);
                    }

                    @Override
                    public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
                        String sig = computeActiveNetworkSignature(appCtx);
                        if (!sig.isEmpty() && sig.equals(sLastActiveNetworkSignature)) {
                            return;
                        }
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 300L, false);
                    }

                    @Override
                    public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                        String sig = computeActiveNetworkSignature(appCtx);
                        if (!sig.isEmpty() && sig.equals(sLastActiveNetworkSignature)) {
                            return;
                        }
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 260L, false);
                    }
                };
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    // Track ONLY the OS default active network instead of every background IMS/carrier net
                    cm.registerDefaultNetworkCallback(cb);
                } else {
                    NetworkRequest req = new NetworkRequest.Builder()
                            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                            .build();
                    cm.registerNetworkCallback(req, cb);
                }
                sNetworkCallback = cb;
            } catch (Throwable t) {
                Log.w(TAG, "Could not register network watchdog: " + t.getMessage());
            }
        }
    }

    private static void unregisterNetworkWatchdog(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        synchronized (WATCHDOG_LOCK) {
            if (sRoamingDebounceFuture != null) {
                try {
                    sRoamingDebounceFuture.cancel(false);
                } catch (Throwable ignored) {
                }
                sRoamingDebounceFuture = null;
            }
            if (sNetworkCallback == null) {
                return;
            }
            try {
                Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
                ConnectivityManager cm = (ConnectivityManager) appCtx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(sNetworkCallback);
                }
            } catch (Throwable ignored) {
            }
            sNetworkCallback = null;
        }
    }

    private static void scheduleDebouncedRoamingEvent(
            final Context appCtx,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader,
            final long delayMs,
            final boolean forceRecovery
    ) {
        synchronized (WATCHDOG_LOCK) {
            if (sRoamingDebounceFuture != null) {
                try {
                    sRoamingDebounceFuture.cancel(false);
                } catch (Throwable ignored) {
                }
            }
            sRoamingDebounceFuture = getGuardianExecutor().schedule(
                    () -> handleRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, forceRecovery),
                    delayMs,
                    TimeUnit.MILLISECONDS
            );
        }
    }

    private static void handleRoamingEvent(
            final Context appCtx,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader,
            final boolean forceRecovery
    ) {
        String currentSig = computeActiveNetworkSignature(appCtx);
        if (currentSig.isEmpty()) {
            return;
        }

        long now = System.currentTimeMillis();
        boolean sigChanged = !currentSig.equals(sLastActiveNetworkSignature);
        if (sigChanged) {
            sRoamRetryCount = 0;
        }
        if (!sigChanged && (!forceRecovery || sRoamRetryCount >= MAX_ROAM_RETRIES || (now - sLastRoamingUpdateMs < 10_000L))) {
            return;
        }
        sLastRoamingUpdateMs = now;

        try {
            if (!isTunnelRunning(appCtx, moduleApkPath)) {
                if (!sUserManuallyStopped && (isAutoConnectEnabled(appCtx) || !sConnectedProfileId.isEmpty())) {
                    TunnelConfig cfg = loadConfig(appCtx);
                    if (cfg.hasPeerConfigured()) {
                        startAndBindProfile(appCtx, cfg, moduleApkPath, telegramClassLoader);
                        return;
                    }
                }
                if (isKillSwitchEnabled(appCtx)) {
                    enforceKillSwitchIfDisconnected(appCtx, moduleApkPath, telegramClassLoader);
                }
                return;
            }

            boolean onCellular = isCellularNetworkActive(appCtx);
            TunnelConfig activeCfg = getConnectedProfile(appCtx, moduleApkPath);
            // Moving from high-MTU Wi-Fi (>1280) onto cellular CGNAT drops inner MTU to 1280;
            // never restart an already-healthy 1280 tunnel when moving back onto Wi-Fi.
            if (activeCfg != null && activeCfg.hasPeerConfigured() && onCellular && sActiveTunnelMtu > 1280) {
                startAndBindProfile(appCtx, activeCfg, moduleApkPath, telegramClassLoader);
                return;
            }

            if (!Wgbridge.isRunning()) {
                if (isUsingSharedHub()) {
                    try { Thread.sleep(350L); } catch (InterruptedException ignored) {}
                    if (isLocalLoopbackPortOpen(sSharedHubPort, 200)) {
                        sLastActiveNetworkSignature = currentSig;
                        sRoamRetryCount = 0;
                        postBindTelegramProxy(appCtx, telegramClassLoader, true, sSharedHubPort, isRouteCallsEnabled(appCtx), true);
                        XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, true);
                        return;
                    }
                    sSharedHubPort = -1;
                    sIsSharedHubOwner = false;
                }
                if (activeCfg != null && activeCfg.hasPeerConfigured()) {
                    startAndBindProfile(appCtx, activeCfg, moduleApkPath, telegramClassLoader);
                } else if (isKillSwitchEnabled(appCtx)) {
                    enforceKillSwitchIfDisconnected(appCtx, moduleApkPath, telegramClassLoader);
                }
                return;
            }

            int activePort = (int) Wgbridge.getActivePort();
            if (activePort <= 0) {
                return;
            }
            acquireForcedContinuityLocks(appCtx);
            syncForegroundKeepaliveService(appCtx, true);

            boolean hsOk = false;
            String rawEp = sWatchdogRawEndpoint;
            if (rawEp != null && !rawEp.isEmpty()) {
                syncEndpointDnsHintsToNative(appCtx, rawEp);
                boolean useDoH = isDohEnabled(appCtx);
                String ep = useDoH ? rawEp : preResolveEndpoint(rawEp);
                try {
                    Wgbridge.updatePeerEndpoint(ep);
                    hsOk = Wgbridge.isHandshakeHealthy();
                    if (!hsOk) {
                        hsOk = Wgbridge.ensureTunnelAlive(1500L);
                    }
                } catch (Throwable ignored) {
                    try {
                        hsOk = Wgbridge.forceRebindAndHandshake();
                    } catch (Throwable ignored2) {
                    }
                }
            } else {
                try {
                    hsOk = Wgbridge.ensureTunnelAlive(1500L);
                } catch (Throwable ignored) {
                }
            }

            if (hsOk) {
                sLastActiveNetworkSignature = currentSig;
                sRoamRetryCount = 0;
                sLastReportedHsHealthy = true;
                WgDiagnosticsLog.record("ROAM", "REBOUND", "sig=" + currentSig);
            } else if (sRoamRetryCount < MAX_ROAM_RETRIES) {
                // Routes may still be settling in netd; bound retries to MAX_ROAM_RETRIES (1.5s, 3.0s, 4.5s)
                sRoamRetryCount++;
                sLastReportedHsHealthy = false;
                scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 1500L * sRoamRetryCount, true);
                WgDiagnosticsLog.record("ROAM", "RETRY", "attempt=" + sRoamRetryCount + " sig=" + currentSig);
            } else {
                sLastActiveNetworkSignature = currentSig;
                sLastReportedHsHealthy = false;
                WgDiagnosticsLog.record("ROAM", "RETRY_CAP", "exhausted retries sig=" + currentSig);
            }

            int desiredKa = effectiveKeepAlive(appCtx, activeCfg != null ? activeCfg.keepAlive : 20);
            try {
                Wgbridge.setPeerKeepalive(desiredKa);
            } catch (Throwable ignored) {
            }

            postBindTelegramProxy(
                    appCtx,
                    telegramClassLoader,
                    true,
                    activePort,
                    isRouteCallsEnabled(appCtx),
                    true
            );
            XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, true);
        } catch (Throwable ignored) {
        }
    }

    private static final class XposedProxyReflector {
        private static int resolveMaxAccountCount(ClassLoader classLoader) {
            int maxAcc = 4;
            try {
                Class<?> uc = XposedHelpers.findClassIfExists("org.telegram.messenger.UserConfig", classLoader);
                if (uc != null) {
                    int val = XposedHelpers.getStaticIntField(uc, "MAX_ACCOUNT_COUNT");
                    if (val > maxAcc) {
                        maxAcc = Math.min(16, val);
                    }
                    try {
                        int sel = XposedHelpers.getStaticIntField(uc, "selectedAccount");
                        if (sel >= maxAcc && sel < 16) {
                            maxAcc = sel + 1;
                        }
                    } catch (Throwable ignored) {
                    }
                }
            } catch (Throwable ignored) {
            }
            return maxAcc;
        }

        private static boolean isAccountActivated(Class<?> userConfigCls, int acc) {
            if (acc <= 0) {
                return true;
            }
            if (userConfigCls == null) {
                // In R8-shrunk builds (e.g. Telegram 13.3.1), UserConfig is obfuscated;
                // include slots 1..3 cleanly since ConnectionsManager.native_setProxySettings ignores unused slots.
                return acc < 4;
            }
            try {
                Object ucInst = XposedHelpers.callStaticMethod(userConfigCls, "getInstance", acc);
                if (ucInst != null) {
                    Boolean activated = (Boolean) XposedHelpers.callMethod(ucInst, "isClientActivated");
                    if (activated != null && activated) {
                        return true;
                    }
                }
            } catch (Throwable ignored) {
            }
            try {
                return XposedHelpers.getStaticIntField(userConfigCls, "selectedAccount") == acc;
            } catch (Throwable ignored) {
            }
            return false;
        }

        private static String extractProxyInfoAddress(Object item) {
            if (item == null) {
                return "";
            }
            try {
                Object settings = XposedHelpers.getObjectField(item, "settings");
                if (settings != null) {
                    Object addr = XposedHelpers.callMethod(settings, "getAddress");
                    if (addr != null) {
                        return safeTrim(String.valueOf(addr));
                    }
                }
            } catch (Throwable ignored) {
            }
            try {
                return safeTrim((String) XposedHelpers.getObjectField(item, "address"));
            } catch (Throwable ignored) {
                return "";
            }
        }

        private static int extractProxyInfoPort(Object item) {
            if (item == null) {
                return -1;
            }
            try {
                Object settings = XposedHelpers.getObjectField(item, "settings");
                if (settings != null) {
                    Object p = XposedHelpers.callMethod(settings, "getPort");
                    if (p instanceof Number) {
                        return ((Number) p).intValue();
                    }
                }
            } catch (Throwable ignored) {
            }
            try {
                return XposedHelpers.getIntField(item, "port");
            } catch (Throwable ignored) {
                return -1;
            }
        }

        static void apply(ClassLoader classLoader, boolean enabled, int localPort, boolean forceNudge) {
            String socksUser = enabled ? WireGuardManager.getActiveSocksUser() : "";
            String socksPass = enabled ? WireGuardManager.getActiveSocksPass() : "";
            boolean hsHealthy = enabled && WireGuardManager.isHandshakeHealthyNow(sSocksPrefsCtx, null);
            apply(classLoader, enabled, localPort, socksUser, socksPass, hsHealthy, forceNudge);
        }

        static void apply(
                ClassLoader classLoader,
                boolean enabled,
                int localPort,
                String socksUser,
                String socksPass,
                boolean hsHealthy,
                boolean forceNudge
        ) {
            Class<?> connectionsManagerClass = XposedHelpers.findClassIfExists(
                    "org.telegram.tgnet.ConnectionsManager",
                    classLoader
            );
            if (connectionsManagerClass == null) {
                return;
            }
            String safeUser = enabled && socksUser != null ? socksUser : "";
            String safePass = enabled && socksPass != null ? socksPass : "";
            Object proxySettingsObj = WireGuardManager.buildTelegramProxySettingsObjectInternal(
                    classLoader,
                    enabled ? "127.0.0.1" : "",
                    enabled ? localPort : 0,
                    safeUser,
                    safePass
            );
            if (proxySettingsObj != null) {
                try {
                    Class<?> proxySettingsCls = proxySettingsObj.getClass();
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "setProxySettings",
                            new Class<?>[]{boolean.class, proxySettingsCls},
                            enabled,
                            proxySettingsObj
                    );
                } catch (Throwable ignored) {
                }
            }
            try {
                XposedHelpers.callStaticMethod(
                        connectionsManagerClass,
                        "setProxySettings",
                        new Class<?>[]{boolean.class, String.class, int.class, String.class, String.class, String.class},
                        enabled,
                        "127.0.0.1",
                        localPort,
                        safeUser,
                        safePass,
                        ""
                );
            } catch (Throwable ignored) {
                // Newer Telegram builds (12.10.4+) use 2-arg setProxySettings(boolean, ProxySettings) handled above.
            }

            syncSharedConfigProxyList(classLoader, enabled, localPort, safeUser, safePass, hsHealthy);

            Class<?> userConfigClass = XposedHelpers.findClassIfExists("org.telegram.messenger.UserConfig", classLoader);
            int maxAcc = resolveMaxAccountCount(classLoader);
            for (int acc = 0; acc < maxAcc; acc++) {
                if (acc > 0 && !isAccountActivated(userConfigClass, acc)) {
                    continue;
                }
                try {
                    // Ensure native ConnectionsManager slot is initialized (critical on Login / Add Account screens!)
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "getInstance",
                            new Class<?>[]{int.class},
                            acc
                    );
                } catch (Throwable ignored) {
                }
                try {
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "native_setProxySettings",
                            new Class<?>[]{int.class, String.class, int.class, String.class, String.class, String.class},
                            acc,
                            enabled ? "127.0.0.1" : "",
                            localPort,
                            safeUser,
                            safePass,
                            ""
                    );
                } catch (Throwable ignored) {
                }
            }

            // Wake Telegram's ProxyListActivity and Login screen observers immediately
            try {
                Class<?> ncCls = XposedHelpers.findClassIfExists("org.telegram.messenger.NotificationCenter", classLoader);
                if (ncCls != null) {
                    Object globalNc = XposedHelpers.callStaticMethod(ncCls, "getGlobalInstance");
                    int eventId = XposedHelpers.getStaticIntField(ncCls, "proxySettingsChanged");
                    if (globalNc != null) {
                        XposedHelpers.callMethod(globalNc, "postNotificationName", eventId, new Object[0]);
                    }
                }
            } catch (Throwable ignored) {
            }

            if (enabled) {
                nudgeTelegramConnections(classLoader, forceNudge);
            }
        }

        private static void syncSharedConfigProxyList(
                ClassLoader classLoader,
                boolean enabled,
                int localPort,
                String socksUser,
                String socksPass,
                boolean hsHealthy
        ) {
            try {
                Class<?> sharedConfigClass = XposedHelpers.findClass(
                        "org.telegram.messenger.SharedConfig",
                        classLoader
                );
                try {
                    XposedHelpers.callStaticMethod(sharedConfigClass, "loadProxyList");
                } catch (Throwable ignored) {
                }

                @SuppressWarnings("unchecked")
                List<Object> proxyList = (List<Object>) XposedHelpers.getStaticObjectField(sharedConfigClass, "proxyList");
                Object keptLoopback = null;
                if (proxyList != null) {
                    for (int i = proxyList.size() - 1; i >= 0; i--) {
                        Object item = proxyList.get(i);
                        if (item == null) {
                            proxyList.remove(i);
                            continue;
                        }
                        String addr = extractProxyInfoAddress(item);
                        int port = extractProxyInfoPort(item);
                        if ("127.0.0.1".equals(addr)) {
                            if (enabled && port == localPort && keptLoopback == null) {
                                keptLoopback = item;
                            } else {
                                proxyList.remove(i);
                            }
                        }
                    }
                }

                if (enabled) {
                    Object ps = WireGuardManager.buildTelegramProxySettingsObject(classLoader, localPort, socksUser, socksPass);
                    if (keptLoopback == null) {
                        Class<?> proxyInfoClass = XposedHelpers.findClass(
                                "org.telegram.messenger.SharedConfig$ProxyInfo",
                                classLoader
                        );
                        if (ps != null) {
                            try {
                                Constructor<?> ctorNew = proxyInfoClass.getDeclaredConstructor(ps.getClass());
                                ctorNew.setAccessible(true);
                                keptLoopback = ctorNew.newInstance(ps);
                            } catch (Throwable ignored) {
                            }
                        }
                        if (keptLoopback == null) {
                            Constructor<?> ctor = proxyInfoClass.getDeclaredConstructor(
                                    String.class, int.class, String.class, String.class, String.class
                            );
                            ctor.setAccessible(true);
                            keptLoopback = ctor.newInstance("127.0.0.1", localPort, socksUser, socksPass, "");
                        }
                        try {
                            XposedHelpers.callStaticMethod(sharedConfigClass, "addProxy", keptLoopback);
                        } catch (Throwable ignored) {
                            if (proxyList != null) {
                                proxyList.add(keptLoopback);
                            }
                        }
                    }
                    if (ps != null) {
                        try {
                            XposedHelpers.setObjectField(keptLoopback, "settings", ps);
                        } catch (Throwable ignored) {
                        }
                    }
                    try {
                        XposedHelpers.setObjectField(keptLoopback, "username", socksUser);
                        XposedHelpers.setObjectField(keptLoopback, "password", socksPass);
                        XposedHelpers.setObjectField(keptLoopback, "secret", "");
                    } catch (Throwable ignored) {
                    }
                    try {
                        XposedHelpers.setBooleanField(keptLoopback, "available", hsHealthy);
                        XposedHelpers.setBooleanField(keptLoopback, "checking", !hsHealthy);
                        XposedHelpers.setLongField(keptLoopback, "availableCheckTime", SystemClock.elapsedRealtime());
                    } catch (Throwable ignored) {
                    }
                    XposedHelpers.setStaticObjectField(sharedConfigClass, "currentProxy", keptLoopback);
                } else {
                    try {
                        Object cur = XposedHelpers.getStaticObjectField(sharedConfigClass, "currentProxy");
                        if (cur != null && "127.0.0.1".equals(extractProxyInfoAddress(cur))) {
                            XposedHelpers.setStaticObjectField(sharedConfigClass, "currentProxy", null);
                        }
                    } catch (Throwable ignored) {
                    }
                }

                try {
                    XposedHelpers.setStaticBooleanField(sharedConfigClass, "proxyEnabled", enabled);
                } catch (Throwable ignored) {
                }
                try {
                    XposedHelpers.callStaticMethod(sharedConfigClass, "saveProxyList");
                } catch (Throwable ignored) {
                }
            } catch (Throwable ignored) {
            }
        }

        static void nudgeTelegramConnections(ClassLoader classLoader) {
            nudgeTelegramConnections(classLoader, false);
        }

        static void nudgeTelegramConnections(ClassLoader classLoader, boolean force) {
            if (classLoader == null) {
                return;
            }
            try {
                Class<?> connectionsManagerClass = XposedHelpers.findClass(
                        "org.telegram.tgnet.ConnectionsManager",
                        classLoader
                );
                Class<?> userConfigClass = XposedHelpers.findClassIfExists(
                        "org.telegram.messenger.UserConfig",
                        classLoader
                );
                int maxAcc = resolveMaxAccountCount(classLoader);
                for (int acc = 0; acc < maxAcc; acc++) {
                    if (!isAccountActivated(userConfigClass, acc)) {
                        continue;
                    }
                    Object inst = null;
                    try {
                        inst = XposedHelpers.callStaticMethod(
                                connectionsManagerClass,
                                "getInstance",
                                new Class<?>[]{int.class},
                                acc
                        );
                    } catch (Throwable ignored) {
                    }

                    boolean needsWake = force;
                    if (!needsWake && inst != null) {
                        try {
                            int state = (Integer) XposedHelpers.callMethod(inst, "getConnectionState");
                            // ConnectionStateConnected == 3; only wake accounts not already connected
                            needsWake = (state != 3);
                        } catch (Throwable ignored) {
                            needsWake = true;
                        }
                    }
                    if (!needsWake) {
                        continue;
                    }

                    try {
                        XposedHelpers.callStaticMethod(
                                connectionsManagerClass,
                                "native_resumeNetwork",
                                new Class<?>[]{int.class, boolean.class},
                                acc,
                                false
                        );
                    } catch (Throwable ignored) {
                    }
                    if (inst != null) {
                        try {
                            XposedHelpers.callMethod(
                                    inst,
                                    "setAppPaused",
                                    new Class<?>[]{boolean.class, boolean.class},
                                    false,
                                    false
                            );
                        } catch (Throwable ignored) {
                        }
                        try {
                            XposedHelpers.callMethod(inst, "checkConnection");
                        } catch (Throwable ignored) {
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static int parseIntSafe(String s, int fallback) {
        try {
            return Integer.parseInt(safeTrim(s));
        } catch (Throwable ignored) {
            return fallback;
        }
    }

    private static int clampKeepAlive(int val) {
        if (val <= 0) {
            return 25;
        }
        return Math.min(val, 600);
    }

    private static int clampMtu(int val) {
        if (val <= 0) {
            return 1280;
        }
        return Math.max(1280, Math.min(1420, val));
    }

    private static String safeTrim(String s) {
        return s == null ? "" : s.trim();
    }
}
