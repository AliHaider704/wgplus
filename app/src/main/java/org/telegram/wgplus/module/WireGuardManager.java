package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
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
import java.util.ArrayList;
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

    // Legacy v1.1.0 single-profile keys (transparently migrated once)
    public static final String KEY_PRIVATE_KEY = "wg_private_key";
    public static final String KEY_ADDRESS = "wg_address";
    public static final String KEY_DNS = "wg_dns";
    public static final String KEY_PUBLIC_KEY = "wg_public_key";
    public static final String KEY_ENDPOINT = "wg_endpoint";
    public static final String KEY_KEEPALIVE = "wg_keepalive";

    public static final String KEY_UI_LANG = "wg_ui_lang";
    public static final String KEY_UI_DARK = "wg_ui_dark";

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
                    || !safeTrim(h4).isEmpty();
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
            return "Jc=3\nJmin=48\nJmax=108\n";
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

    public static SharedPreferences getPrefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static Integer getCachedPingMs(String profileId) {
        if (profileId == null || profileId.isEmpty()) {
            return null;
        }
        return sPingCacheMs.get(profileId);
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
    }

    public static boolean isAutoConnectEnabled(Context context) {
        return getPrefs(context).getBoolean(KEY_ENABLED, false);
    }

    public static void setEnabled(Context context, boolean enabled) {
        getPrefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply();
    }

    public static boolean isRouteCallsEnabled(Context context) {
        return getPrefs(context).getBoolean(KEY_ROUTE_CALLS, true);
    }

    public static void setRouteCallsEnabled(Context context, boolean routeCalls) {
        getPrefs(context).edit().putBoolean(KEY_ROUTE_CALLS, routeCalls).apply();
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
        }
    }

    public static boolean isSmartKeepaliveEnabled(Context context) {
        return context != null && getPrefs(context).getBoolean(KEY_SMART_KEEPALIVE, false);
    }

    public static void setSmartKeepaliveEnabled(Context context, String moduleApkPath, boolean enabled) {
        if (context == null) {
            return;
        }
        getPrefs(context).edit().putBoolean(KEY_SMART_KEEPALIVE, enabled).apply();
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

    private static void syncEndpointDnsHintsToNative(Context context, String rawEndpoint) {
        if (context == null) {
            return;
        }
        try {
            SharedPreferences prefs = getPrefs(context);
            String rawCache = prefs.getString(KEY_DNS_LKG_CACHE_JSON, "");
            if (rawCache != null && !rawCache.isEmpty()) {
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
                    Wgbridge.registerEndpointIpHint(host, ip);
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
    }

    public static synchronized TunnelConfig selectProfile(Context context, String profileId) {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        for (TunnelConfig p : profiles) {
            if (p.id.equals(profileId)) {
                prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, p.id).commit();
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
            if (currentName.isEmpty() || currentName.startsWith("خادم ") || currentName.startsWith("Server ")) {
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
        syncEndpointDnsHintsToNative(context, cfg.endpoint);

        String privHex = normalizeKeyToHex(cfg.privateKey);
        String pubHex = normalizeKeyToHex(cfg.publicKey);
        String pskHex = safeTrim(cfg.presharedKey).isEmpty() ? "" : normalizeKeyToHex(cfg.presharedKey);
        String dns = safeTrim(cfg.dns).isEmpty() ? "1.1.1.1" : safeTrim(cfg.dns);
        boolean onCellular = isCellularNetworkActive(context);
        int keepAlive = onCellular ? Math.min(20, clampKeepAlive(cfg.keepAlive)) : clampKeepAlive(cfg.keepAlive);
        int mtu = onCellular ? 1280 : clampMtu(cfg.mtu);
        boolean useDoH = isDohEnabled(context);
        // When DoH is enabled, pass raw hostname straight to Go so zero plaintext port-53 DNS leaks occur!
        String endpointForGo = useDoH ? safeTrim(cfg.endpoint) : preResolveEndpoint(cfg.endpoint);
        String awgParams = cfg.toEffectiveAwgParamsString();

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
            } else {
                if (isKillSwitchEnabled(context)) {
                    enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
                }
                throw firstErr;
            }
        }
        int localPort = (int) portLong;

        sConnectedProfileId = cfg.id;
        sKeepalivePausedForIdle = false;
        sConsecutiveHealthFailures = 0;
        getPrefs(context).edit()
                .putString(KEY_CONNECTED_PROFILE_ID, cfg.id)
                .putString(KEY_ACTIVE_PROFILE_ID, cfg.id)
                .commit();
        sWatchdogRawEndpoint = cfg.endpoint;

        if (telegramClassLoader != null) {
            postBindTelegramProxy(context, telegramClassLoader, true, localPort, isRouteCallsEnabled(context));
            registerNetworkWatchdog(context, moduleApkPath, telegramClassLoader);
        }
        // Release local kill-switch listener AFTER Telegram has rebound to the live tunnel port
        try {
            Wgbridge.stopKillSwitchGuard();
        } catch (Throwable ignored) {
        }
        // Always start the 24/7 Forced Continuity & Auto-Failover Guardian while connected
        startFailoverMonitor(context, moduleApkPath, telegramClassLoader);
        return localPort;
    }

    public static void stopAndUnbind(Context context, String moduleApkPath, ClassLoader telegramClassLoader) {
        sUserManuallyStopped = true;
        stopFailoverMonitor();
        unregisterNetworkWatchdog(context);
        releaseForcedContinuityLocks();
        sConnectedProfileId = "";
        sKeepalivePausedForIdle = false;
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
        } else if (telegramClassLoader != null) {
            postBindTelegramProxy(context, telegramClassLoader, false, 1080, false);
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
            if (Wgbridge.isRunning()) {
                return (int) Wgbridge.getActivePort();
            }
            int guardPort = (int) Wgbridge.startKillSwitchGuard();
            if (guardPort > 0 && telegramClassLoader != null) {
                postBindTelegramProxy(context, telegramClassLoader, true, guardPort, true);
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
            getGuardianExecutor().execute(() -> {
                try {
                    if (sKeepalivePausedForIdle) {
                        restoreActiveKeepaliveNow(context, moduleApkPath);
                    }
                    if (!sUserManuallyStopped && !isTunnelRunning(context, moduleApkPath)) {
                        if (isAutoConnectEnabled(context) || !sConnectedProfileId.isEmpty()) {
                            TunnelConfig cfg = loadConfig(context);
                            if (cfg.hasPeerConfigured()) {
                                startAndBindProfile(context, cfg, moduleApkPath, telegramClassLoader);
                                return;
                            }
                        }
                    }
                    if (isTunnelRunning(context, moduleApkPath)) {
                        acquireForcedContinuityLocks(context);
                        Wgbridge.ensureTunnelAlive(1400L);
                        int activePort = getActivePort(context, moduleApkPath);
                        if (activePort > 0 && telegramClassLoader != null) {
                            postBindTelegramProxy(
                                    context,
                                    telegramClassLoader,
                                    true,
                                    activePort,
                                    isRouteCallsEnabled(context)
                            );
                        }
                    }
                } catch (Throwable ignored) {
                }
            });
        } else {
            // In background: keep WakeLock/WifiLock held and keep CGNAT pinhole alive (25s max interval, never 0)
            getGuardianExecutor().execute(() -> {
                try {
                    if (isTunnelRunning(context, moduleApkPath)) {
                        acquireForcedContinuityLocks(context);
                        if (isSmartKeepaliveEnabled(context)) {
                            Wgbridge.setPeerKeepalive(25L);
                            sKeepalivePausedForIdle = true;
                        } else {
                            TunnelConfig activeCfg = getConnectedProfile(context, moduleApkPath);
                            int ka = activeCfg != null ? clampKeepAlive(activeCfg.keepAlive) : 20;
                            if (isCellularNetworkActive(context)) {
                                ka = Math.min(20, ka);
                            }
                            Wgbridge.setPeerKeepalive(ka);
                        }
                        if (telegramClassLoader != null) {
                            XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader);
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
                int ka = activeCfg != null ? clampKeepAlive(activeCfg.keepAlive) : 20;
                if (isCellularNetworkActive(context)) {
                    ka = Math.min(20, ka);
                }
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
        }, 10L, 10L, TimeUnit.SECONDS);
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

        // 1. Self-heal if tunnel unexpectedly stopped while supposed to be active 24/7
        if (!Wgbridge.isRunning()) {
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

        // 2. Ensure active tunnel is responsive; if stale or stalled, EnsureTunnelAlive triggers immediate rebind + handshake
        boolean alive = false;
        try {
            alive = Wgbridge.ensureTunnelAlive(2200L);
        } catch (Throwable ignored) {
        }
        if (alive) {
            sConsecutiveHealthFailures = 0;
            if (telegramClassLoader != null) {
                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader);
            }
            return;
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

        // 3. Probe current server directly
        boolean useDoH = isDohEnabled(appCtx);
        try {
            syncEndpointDnsHintsToNative(appCtx, currentCfg.endpoint);
            long rtt = Wgbridge.probeEndpointHandshakeMs(
                    normalizeKeyToHex(currentCfg.privateKey),
                    safeTrim(currentCfg.presharedKey).isEmpty() ? "" : normalizeKeyToHex(currentCfg.presharedKey),
                    normalizeKeyToHex(currentCfg.publicKey),
                    useDoH ? safeTrim(currentCfg.endpoint) : preResolveEndpoint(currentCfg.endpoint),
                    currentCfg.toEffectiveAwgParamsString(),
                    useDoH,
                    2800L
            );
            if (rtt > 0) {
                sConsecutiveHealthFailures = 0;
                Wgbridge.forceRebindAndHandshake();
                if (telegramClassLoader != null) {
                    XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader);
                }
                return;
            }
        } catch (Throwable ignored) {
        }

        sConsecutiveHealthFailures++;
        if (sConsecutiveHealthFailures < 2) {
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

        // 5. Otherwise, hard-restart the current tunnel profile to recover from deep carrier/socket state drop
        if (sConsecutiveHealthFailures >= 3) {
            sConsecutiveHealthFailures = 0;
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
        int socksPort = getActivePort(context, moduleApkPath);
        if (socksPort <= 0) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.NO_ACTIVE_PORT);
        }

        TunnelVerifyResult res = new TunnelVerifyResult();

        Exception lastErr = null;
        byte[][] cfTargets = new byte[][]{
                new byte[]{1, 1, 1, 1},
                new byte[]{1, 0, 0, 1}
        };
        for (byte[] targetIp : cfTargets) {
            try {
                long tStart = System.nanoTime();
                try (Socket rawSocks = openSocks5Ipv4Socket(socksPort, targetIp, 443, 12000)) {
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
                                + "User-Agent: WGPlus/1.3.0\r\n"
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

        long udpLatency = probeUdpAssociateDns(socksPort, new byte[]{1, 1, 1, 1}, 53, 5500);
        if (udpLatency <= 0L) {
            udpLatency = probeUdpAssociateDns(socksPort, new byte[]{8, 8, 8, 8}, 53, 5500);
        }
        if (udpLatency > 0L) {
            res.udpCallsReady = true;
            res.udpPingMs = udpLatency;
        } else {
            res.udpCallsReady = false;
        }

        return res;
    }

    private static long probeUdpAssociateDns(int localSocksPort, byte[] dnsIpv4, int dnsPort, int timeoutMs) {
        try (Socket ctrlSock = new Socket()) {
            ctrlSock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 4000);
            ctrlSock.setSoTimeout(timeoutMs);

            OutputStream out = ctrlSock.getOutputStream();
            DataInputStream in = new DataInputStream(ctrlSock.getInputStream());

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] greet = new byte[2];
            in.readFully(greet);
            if (greet[0] != 0x05 || greet[1] != 0x00) {
                return -1L;
            }

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

    private static Socket openSocks5Ipv4Socket(int localSocksPort, byte[] ipv4, int targetPort, int timeoutMs) throws Exception {
        Socket sock = new Socket();
        try {
            sock.connect(new InetSocketAddress("127.0.0.1", localSocksPort), 5000);
            sock.setSoTimeout(timeoutMs);

            OutputStream out = sock.getOutputStream();
            DataInputStream in = new DataInputStream(sock.getInputStream());

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();

            byte[] greetResp = new byte[2];
            in.readFully(greetResp);
            if (greetResp[0] != 0x05 || greetResp[1] != 0x00) {
                throw new IllegalStateException("SOCKS5 auth mismatch");
            }

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
            return Wgbridge.isRunning();
        } catch (Throwable t) {
            return false;
        }
    }

    public static int getActivePort(Context context, String moduleApkPath) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            return (int) Wgbridge.getActivePort();
        } catch (Throwable t) {
            return 0;
        }
    }

    public static void postBindTelegramProxy(
            final Context context,
            final ClassLoader classLoader,
            final boolean enabled,
            final int localPort,
            final boolean routeCalls
    ) {
        if (classLoader == null) {
            return;
        }
        Runnable task = () -> bindTelegramProxyInternal(context, classLoader, enabled, localPort, routeCalls);
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
            boolean routeCalls
    ) {
        try {
            syncTelegramMainConfigForCalls(context, enabled, localPort, routeCalls);
            XposedProxyReflector.apply(classLoader, enabled, localPort);
            Log.i(TAG, "Applied Telegram proxy & call settings (enabled=" + enabled
                    + ", port=" + localPort + ", routeCalls=" + routeCalls + ")");
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
                mc.edit()
                        .putBoolean("proxy_enabled", true)
                        .putBoolean("proxy_enabled_calls", routeCalls)
                        .putString("proxy_ip", "127.0.0.1")
                        .putInt("proxy_port", localPort)
                        .putString("proxy_user", "")
                        .putString("proxy_pass", "")
                        .putString("proxy_secret", "")
                        .apply();
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
                NetworkRequest req = new NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build();
                ConnectivityManager.NetworkCallback cb = new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 150L);
                    }

                    @Override
                    public void onLost(Network network) {
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 350L);
                    }

                    @Override
                    public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 450L);
                    }

                    @Override
                    public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 350L);
                    }
                };
                cm.registerNetworkCallback(req, cb);
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
            final long delayMs
    ) {
        synchronized (WATCHDOG_LOCK) {
            if (sRoamingDebounceFuture != null) {
                try {
                    sRoamingDebounceFuture.cancel(false);
                } catch (Throwable ignored) {
                }
            }
            sRoamingDebounceFuture = getGuardianExecutor().schedule(
                    () -> handleRoamingEvent(appCtx, moduleApkPath, telegramClassLoader),
                    delayMs,
                    TimeUnit.MILLISECONDS
            );
        }
    }

    private static void handleRoamingEvent(
            final Context appCtx,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        long now = System.currentTimeMillis();
        if (now - sLastRoamingUpdateMs < 900L) {
            return;
        }
        sLastRoamingUpdateMs = now;

        try {
            if (!isTunnelRunning(appCtx, moduleApkPath)) {
                if (!sUserManuallyStopped && (isAutoConnectEnabled(appCtx) || !sConnectedProfileId.isEmpty())) {
                    TunnelConfig cfg = loadConfig(appCtx);
                    if (cfg.hasPeerConfigured()) {
                        startAndBindProfile(appCtx, cfg, moduleApkPath, telegramClassLoader);
                    }
                }
                return;
            }
            int activePort = getActivePort(appCtx, moduleApkPath);
            if (activePort <= 0) {
                return;
            }
            acquireForcedContinuityLocks(appCtx);
            String rawEp = sWatchdogRawEndpoint;
            if (rawEp != null && !rawEp.isEmpty()) {
                syncEndpointDnsHintsToNative(appCtx, rawEp);
                boolean useDoH = isDohEnabled(appCtx);
                String ep = useDoH ? rawEp : preResolveEndpoint(rawEp);
                Wgbridge.updatePeerEndpoint(ep);
            } else {
                Wgbridge.forceRebindAndHandshake();
            }
            if (isCellularNetworkActive(appCtx)) {
                Wgbridge.setPeerKeepalive(20L);
            }
            postBindTelegramProxy(
                    appCtx,
                    telegramClassLoader,
                    true,
                    activePort,
                    isRouteCallsEnabled(appCtx)
            );
        } catch (Throwable ignored) {
        }
    }

    private static final class XposedProxyReflector {
        static void apply(ClassLoader classLoader, boolean enabled, int localPort) {
            Class<?> connectionsManagerClass = XposedHelpers.findClass(
                    "org.telegram.tgnet.ConnectionsManager",
                    classLoader
            );
            XposedHelpers.callStaticMethod(
                    connectionsManagerClass,
                    "setProxySettings",
                    new Class<?>[]{boolean.class, String.class, int.class, String.class, String.class, String.class},
                    enabled,
                    "127.0.0.1",
                    localPort,
                    "",
                    "",
                    ""
            );

            try {
                Class<?> sharedConfigClass = XposedHelpers.findClass(
                        "org.telegram.messenger.SharedConfig",
                        classLoader
                );
                if (enabled) {
                    Class<?> proxyInfoClass = XposedHelpers.findClass(
                            "org.telegram.messenger.SharedConfig$ProxyInfo",
                            classLoader
                    );
                    Constructor<?> ctor = proxyInfoClass.getDeclaredConstructor(
                            String.class, int.class, String.class, String.class, String.class
                    );
                    ctor.setAccessible(true);
                    Object proxyInfo = ctor.newInstance("127.0.0.1", localPort, "", "", "");
                    XposedHelpers.setStaticObjectField(sharedConfigClass, "currentProxy", proxyInfo);
                }
                try {
                    XposedHelpers.setStaticBooleanField(sharedConfigClass, "proxyEnabled", enabled);
                } catch (Throwable ignored) {
                }
            } catch (Throwable ignored) {
            }

            for (int acc = 0; acc < 4; acc++) {
                try {
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "native_setProxySettings",
                            new Class<?>[]{int.class, String.class, int.class, String.class, String.class, String.class},
                            acc,
                            enabled ? "127.0.0.1" : "",
                            localPort,
                            "",
                            "",
                            ""
                    );
                } catch (Throwable ignored) {
                }
            }

            if (enabled) {
                nudgeTelegramConnections(classLoader);
            }
        }

        static void nudgeTelegramConnections(ClassLoader classLoader) {
            if (classLoader == null) {
                return;
            }
            try {
                Class<?> connectionsManagerClass = XposedHelpers.findClass(
                        "org.telegram.tgnet.ConnectionsManager",
                        classLoader
                );
                for (int acc = 0; acc < 4; acc++) {
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
                    try {
                        Object inst = XposedHelpers.callStaticMethod(
                                connectionsManagerClass,
                                "getInstance",
                                new Class<?>[]{int.class},
                                acc
                        );
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
                    } catch (Throwable ignored) {
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
