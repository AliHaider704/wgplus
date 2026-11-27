package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import wgbridge.Wgbridge;

public final class WireGuardManager {
    static final String TAG = "WGPlusManager";
    public static final String PREFS_NAME = "wg_plus_isolated_prefs";
    public static final String BACKUP_SCHEMA = "wgplus-backup-v1";
    static final String TG_MAINCONFIG = "mainconfig";

    public static final String KEY_ENABLED = "wg_enabled";
    public static final String KEY_ROUTE_CALLS = "wg_route_calls";
    public static final String KEY_KILL_SWITCH = "wg_strict_kill_switch";
    public static final String KEY_AUTO_FAILOVER = "wg_auto_failover";
    public static final String KEY_DOH_ENABLED = "wg_doh_enabled";
    public static final String KEY_SMART_KEEPALIVE = "wg_smart_keepalive";
    public static final String KEY_PROFILES_JSON = "wg_profiles_v2_json";
    public static final String KEY_ACTIVE_PROFILE_ID = "wg_active_profile_id";
    public static final String KEY_CONNECTED_PROFILE_ID = "wg_connected_profile_id";
    static final String KEY_DNS_LKG_CACHE_JSON = "wg_dns_lkg_cache_json";
    static final String KEY_MIGRATED_FORCED_CONTINUITY_V1 = "wg_migrated_forced_continuity_v1";

    public static final String EXTRA_STOP_FOREGROUND_KEEPALIVE = "wgplus_stop_fg_keepalive";
    public static final String EXTRA_EXPECT_FOREGROUND_PROMOTE = "wgplus_expect_fg_promote";
    public static final String ACTION_KEEPALIVE_BRIDGE = "org.telegram.wgplus.ACTION_KEEPALIVE_BRIDGE";
    public static final String ACTION_SYNC_CONTINUITY = "org.telegram.wgplus.ACTION_SYNC_CONTINUITY";
    static final Uri STATUS_PROVIDER_URI = Uri.parse("content://" + KeepaliveStatusProvider.AUTHORITY);
    public static final String FG_NOTIFICATION_CHANNEL_ID = "wgplus_keepalive_silent_channel";
    public static final int FG_NOTIFICATION_ID = 49107;
    static final String FG_SERVICE_CLASS = "org.telegram.messenger.NotificationsService";

    static volatile long sLastStealthQueryMs;
    static volatile boolean sLastStealthProtected;
    static volatile boolean sLastStealthWantsAwake;
    static volatile long sTunnelStartedAtMs;
    public static final long HANDSHAKE_HEALTHY_WINDOW_SEC = 210L;
    public static final long PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC = 120L;
    static final AtomicBoolean sHandshakeNudgeInFlight = new AtomicBoolean(false);
    static volatile long sLastHandshakeNudgeMs = 0L;
    static volatile long sLastSharedTunnelHeartbeatMs = 0L;
    static volatile long sLastRemoteHygieneCheckMs;
    static volatile long sLastHandledHygieneReqMs;
    static final String KEY_SHARED_STATE_REV = "wg_shared_state_rev";
    static final ExecutorService SYNC_EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "wgplus-shared-sync");
        t.setDaemon(true);
        return t;
    });
    static volatile Context sSyncContext;
    static volatile boolean sSuppressSyncPush;
    static volatile long sLastSyncPullMs;
    static volatile long sLastHookHeartbeatMs = 0L;

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
    static final String KEY_CHANNEL_INVITED_V2 = "wg_channel_invited_v2";

    interface EndpointRelayStarter {
        int startRelay(String host, int port);
    }

    interface EndpointAddrRelayStarter {
        String startRelayAddr(String host, int port);
    }

    static final class SocksCredsSnapshot {
        static final SocksCredsSnapshot EMPTY = new SocksCredsSnapshot("", "");
        final String user;
        final String pass;

        SocksCredsSnapshot(String user, String pass) {
            this.user = user != null ? user : "";
            this.pass = pass != null ? pass : "";
        }
    }

    static final class SharedHubSnapshot {
        static final SharedHubSnapshot NONE = new SharedHubSnapshot(false, -1, "", "", 0L, false);
        final boolean isOwner;
        final int port;
        final String user;
        final String pass;
        final long lastHsSec;
        final boolean hsHealthy;

        SharedHubSnapshot(boolean isOwner, int port, String user, String pass, long lastHsSec, boolean hsHealthy) {
            this.isOwner = isOwner;
            this.port = port;
            this.user = user != null ? user : "";
            this.pass = pass != null ? pass : "";
            this.lastHsSec = lastHsSec;
            this.hsHealthy = hsHealthy;
        }
    }

    static final String KEY_PERSISTED_SOCKS_USER = "wg_socks_user_v2";
    static final String KEY_PERSISTED_SOCKS_PASS = "wg_socks_pass_v2";
    static final String KEY_RECENT_SOCKS_PASSES_CSV = "wg_recent_socks_passes_csv";
    static volatile Context sSocksPrefsCtx = null;
    static volatile SocksCredsSnapshot sSocksCreds = SocksCredsSnapshot.EMPTY;
    static volatile SharedHubSnapshot sSharedHub = SharedHubSnapshot.NONE;
    static volatile String sSocksUser = "";
    static volatile String sSocksPass = "";
    static volatile String sSharedSocksUser = "";
    static volatile String sSharedSocksPass = "";
    static volatile long sSharedLastHsSec = 0L;
    static volatile boolean sSharedHsHealthy = false;

    // Snapshot keys to cleanly restore any pre-existing user proxy in Telegram's mainconfig
    static final String KEY_MC_SNAPSHOT_TAKEN = "wg_mc_snapshot_taken";
    static final String KEY_MC_PREV_ENABLED = "wg_mc_prev_enabled";
    static final String KEY_MC_PREV_CALLS = "wg_mc_prev_calls";
    static final String KEY_MC_PREV_IP = "wg_mc_prev_ip";
    static final String KEY_MC_PREV_PORT = "wg_mc_prev_port";
    static final String KEY_MC_PREV_USER = "wg_mc_prev_user";
    static final String KEY_MC_PREV_PASS = "wg_mc_prev_pass";
    static final String KEY_MC_PREV_SECRET = "wg_mc_prev_secret";

    static final Object WATCHDOG_LOCK = new Object();
    static ConnectivityManager.NetworkCallback sNetworkCallback = null;
    static volatile String sWatchdogRawEndpoint = "";
    static volatile String sConnectedProfileId = "";
    static volatile long sLastRoamingUpdateMs = 0L;
    static volatile boolean sUserManuallyStopped = false;
    static volatile String sLastActiveNetworkSignature = "";
    static volatile int sActiveTunnelMtu = 1280;
    static volatile int sSharedHubPort = -1;
    static volatile boolean sIsSharedHubOwner = false;
    static volatile Boolean sLastBoundEnabled = null;
    static volatile int sLastBoundPort = -1;
    static volatile boolean sLastBoundRouteCalls = false;
    static volatile String sLastBoundUser = "";
    static volatile String sLastBoundPass = "";
    static volatile Boolean sLastBoundHsHealthy = null;
    static volatile long sLastHardRestartMs = 0L;
    static volatile boolean sAutoMtuDowngraded = false;
    static volatile boolean sLastReportedHsHealthy = false;
    static volatile int sRoamRetryCount = 0;
    static final int MAX_ROAM_RETRIES = 3;
    static volatile boolean sApplyingProxyBindings = false;
    static volatile long sNetworkLostAtElapsedMs = 0L;
    static volatile long sLastAutoTakeoverAttemptMs = 0L;

    public static boolean isApplyingProxyBindings() {
        return sApplyingProxyBindings;
    }

    static synchronized void updateLocalSocksCreds(String user, String pass) {
        SocksCredsSnapshot next = new SocksCredsSnapshot(user, pass);
        sSocksCreds = next;
        sSocksUser = next.user;
        sSocksPass = next.pass;
    }

    static synchronized void updateSharedHubClient(int port, String user, String pass, long lastHsSec, boolean hsHealthy) {
        SharedHubSnapshot next = new SharedHubSnapshot(false, port, user, pass, lastHsSec, hsHealthy);
        sSharedHub = next;
        sIsSharedHubOwner = false;
        sSharedHubPort = next.port;
        sSharedSocksUser = next.user;
        sSharedSocksPass = next.pass;
        sSharedLastHsSec = next.lastHsSec;
        sSharedHsHealthy = next.hsHealthy;
    }

    static synchronized void updateSharedHubOwner(int port, String user, String pass) {
        SharedHubSnapshot next = new SharedHubSnapshot(true, port, user, pass, 0L, false);
        sSharedHub = next;
        sIsSharedHubOwner = true;
        sSharedHubPort = next.port;
        sSharedSocksUser = "";
        sSharedSocksPass = "";
        sSharedLastHsSec = 0L;
        sSharedHsHealthy = false;
    }

    static synchronized void clearSharedHubState() {
        sSharedHub = SharedHubSnapshot.NONE;
        sSharedHubPort = -1;
        sIsSharedHubOwner = false;
        sSharedSocksUser = "";
        sSharedSocksPass = "";
        sSharedLastHsSec = 0L;
        sSharedHsHealthy = false;
    }

    // Live Ping RTT cache (profileId -> ms, or -1 on timeout)
    static final Map<String, Integer> sPingCacheMs = new ConcurrentHashMap<>();

    // 24/7 Forced Continuity Locks, Guardian Executor & Smart Keepalive background state
    static final Object LOCK_SYNC = new Object();
    static PowerManager.WakeLock sForcedWakeLock = null;
    static WifiManager.WifiLock sForcedWifiLock = null;
    static ScheduledExecutorService sGuardianExecutor = null;
    static ScheduledFuture<?> sGuardianFuture = null;
    static ScheduledFuture<?> sRoamingDebounceFuture = null;
    static Handler sMainHandler = null;
    static volatile boolean sAppInForeground = true;
    static volatile boolean sKeepalivePausedForIdle = false;
    static Runnable sPendingIdleSaverTask = null;
    static volatile int sConsecutiveHealthFailures = 0;
    static volatile boolean sFailoverCheckRunning = false;
    static volatile ClassLoader sDiagnosticHostClassLoader = null;
    static volatile long sLastSharedHubCheckMs = 0L;
    static volatile int sCachedExternalSharedPort = -1;
    static volatile boolean sSharedHubProbeInFlight = false;
    static volatile long sLastBackgroundedAtMs;

    static void setDiagnosticHostClassLoader(ClassLoader cl) {
        if (cl != null) {
            sDiagnosticHostClassLoader = cl;
        }
    }

    static synchronized ScheduledExecutorService getGuardianExecutor() {
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

    static synchronized Handler getMainHandler() {
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
            WgProxyBinder.enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
        } else {
            WgProxyBinder.releaseKillSwitchGuard(context, moduleApkPath, telegramClassLoader);
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
            WgHealthAndContinuity.startFailoverMonitor(context, moduleApkPath, telegramClassLoader);
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
            WgHealthAndContinuity.restoreActiveKeepaliveNow(context, moduleApkPath);
        }
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
                    TunnelConfig cfg = WgConfigCodec.configFromJsonObject(obj, true);
                    cfg.enabled = globalEnabled;
                    cfg.routeCalls = globalCalls;
                    if (cfg.name.isEmpty()) {
                        cfg.name = WgConfigCodec.deriveProfileName(cfg.endpoint, isAr, i + 1);
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
            migrated.name = WgConfigCodec.deriveProfileName(migrated.endpoint, isAr, 1);
            list.add(migrated);

            persistProfilesLocked(prefs, list, migrated.id, globalEnabled, globalCalls);
            if (prefs.contains(KEY_PRIVATE_KEY)) {
                prefs.edit().remove(KEY_PRIVATE_KEY).apply();
            }
        }

        return list;
    }

    /** Pure-Java multi-profile backup serializer (portable JSON bundle including AmneziaWG fields). */
    public static String serializeProfilesBackupJson(List<TunnelConfig> profiles) throws WgStrings.WgException {
        return WgConfigCodec.serializeProfilesBackupJson(profiles);
    }

    /** Pure-Java multi-profile backup deserializer. */
    public static List<TunnelConfig> deserializeProfilesBackupJson(String rawJson) throws WgStrings.WgException {
        return WgConfigCodec.deserializeProfilesBackupJson(rawJson);
    }

    public static synchronized String exportAllProfilesBackupJson(Context context) throws WgStrings.WgException {
        List<TunnelConfig> profiles = loadProfiles(context);
        return serializeProfilesBackupJson(profiles);
    }

    public static boolean isEncryptedBackupEnvelope(String raw) {
        return WgConfigCodec.isEncryptedBackupEnvelope(raw);
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
                baseName = WgConfigCodec.deriveProfileName(item.endpoint, isAr, existing.size() + 1);
            }
            item.name = WgConfigCodec.uniqueProfileName(baseName, existing, item.id);
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
            updated.name = WgConfigCodec.deriveProfileName(updated.endpoint, isAr, profiles.size() + 1);
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
        WgSyncAndCreds.syncDeterministicSocksCredentialsForProfile(context, updated);
    }

    public static synchronized TunnelConfig selectProfile(Context context, String profileId) {
        SharedPreferences prefs = getPrefs(context);
        List<TunnelConfig> profiles = loadProfiles(context);
        for (TunnelConfig p : profiles) {
            if (p.id.equals(profileId)) {
                prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, p.id).commit();
                WgSyncAndCreds.syncDeterministicSocksCredentialsForProfile(context, p);
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
        fresh.name = WgConfigCodec.uniqueProfileName(baseName, profiles, fresh.id);
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

        String candidateName = WgConfigCodec.sanitizeSuggestedName(suggestedName);
        if (candidateName.isEmpty()) {
            candidateName = WgConfigCodec.deriveProfileName(parsed.endpoint, isAr, reuseSingleEmptySlot ? 1 : (profiles.size() + 1));
        }
        parsed.name = WgConfigCodec.uniqueProfileName(candidateName, profiles, parsed.id);

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

    static void persistProfilesLocked(
            SharedPreferences prefs,
            List<TunnelConfig> profiles,
            String activeId,
            boolean enabled,
            boolean routeCalls
    ) {
        JSONArray arr = new JSONArray();
        for (TunnelConfig cfg : profiles) {
            try {
                arr.put(WgConfigCodec.configToJsonObject(cfg, true));
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

    public static String normalizeKeyToHex(String inputKey) throws WgStrings.WgException {
        return WgConfigCodec.normalizeKeyToHex(inputKey);
    }

    public static TunnelConfig parseConfText(String confText, TunnelConfig base) throws WgStrings.WgException {
        return WgConfigCodec.parseConfText(confText, base);
    }

    public static String exportConfText(TunnelConfig cfg) {
        return WgConfigCodec.exportConfText(cfg);
    }

    public static TunnelConfig parseWarpGeneratedJson(String rawJson, String[] outEndpointV4) throws Exception {
        return WgConfigCodec.parseWarpGeneratedJson(rawJson, outEndpointV4);
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
                target.name = WgConfigCodec.uniqueProfileName(
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
                    WgHealthAndContinuity.persistEndpointDnsHint(context, "engage.cloudflareclient.com", epV4[0]);
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
        final SharedHubSnapshot hubBefore = sSharedHub;
        final boolean hadExistingSession = hubBefore.isOwner
                || hubBefore.port > 0
                || Wgbridge.isRunning();
        ModuleHygieneManager.trimInMemoryCaches();
        WgHealthAndContinuity.acquireForcedContinuityLocks(context);
        WgHealthAndContinuity.registerScreenPreWarmReceiverIfNeeded(context, moduleApkPath, telegramClassLoader);
        WgHealthAndContinuity.syncHostLinkMtuSensor(context);
        WgSyncAndCreds.syncDeterministicSocksCredentialsForProfile(context, cfg);

        // Reuse an already-running WireGuard tunnel hosted by another local Telegram client or module app
        // so multiple open Telegram clients share ONE WireGuard session with zero PrivateKey collisions.
        String profileSig = safeTrim(cfg.endpoint) + "|" + safeTrim(cfg.publicKey);
        int sharedPort = WgSharedHubAndVoip.queryLiveSharedTunnelPort(context, profileSig);
        if (sharedPort > 0) {
            try {
                Wgbridge.setKillSwitchArmed(false);
                Wgbridge.stopKillSwitchGuard();
                if (Wgbridge.isRunning()) {
                    Wgbridge.stopTunnel();
                }
            } catch (Throwable ignored) {
            }
            SharedHubSnapshot clientSnap = sSharedHub;
            updateSharedHubClient(sharedPort, clientSnap.user, clientSnap.pass, clientSnap.lastHsSec, clientSnap.hsHealthy);
            sConnectedProfileId = cfg.id;
            sTunnelStartedAtMs = SystemClock.elapsedRealtime();
            sActiveTunnelMtu = clampMtu(cfg.mtu);
            sLastActiveNetworkSignature = WgHealthAndContinuity.computeActiveNetworkSignature(context);
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
                WgHealthAndContinuity.registerNetworkWatchdog(context, moduleApkPath, telegramClassLoader);
                WgHealthAndContinuity.startFailoverMonitor(context, moduleApkPath, telegramClassLoader);
                maybeForceReconnectTelegramOnRebind(telegramClassLoader, hadExistingSession || sNetworkLostAtElapsedMs > 0L);
            }
            return sharedPort;
        }

        WgHealthAndContinuity.syncEndpointDnsHintsToNative(context, cfg.endpoint);

        WgSyncAndCreds.ensureSessionSocksCredentials(context);
        SocksCredsSnapshot creds = sSocksCreds;
        try {
            Wgbridge.setSocksAuth(creds.user, creds.pass);
            Wgbridge.resetSocksAuthRejectCount();
            WgSyncAndCreds.syncAllowedProfilePasswordsToNative(context);
        } catch (Throwable ignored) {
        }

        String privHex = normalizeKeyToHex(cfg.privateKey);
        String pubHex = normalizeKeyToHex(cfg.publicKey);
        String pskHex = safeTrim(cfg.presharedKey).isEmpty() ? "" : normalizeKeyToHex(cfg.presharedKey);
        String dns = safeTrim(cfg.dns).isEmpty() ? "1.1.1.1" : safeTrim(cfg.dns);
        boolean onCellular = WgHealthAndContinuity.isCellularNetworkActive(context);
        int keepAlive = WgHealthAndContinuity.effectiveKeepAlive(context, cfg.keepAlive);
        String awgParams = cfg.toEffectiveAwgParamsString();
        int mtu = sAutoMtuDowngraded ? 1280 : clampMtu(cfg.mtu);
        boolean useDoH = isDohEnabled(context);
        // When DoH is enabled, pass raw hostname straight to Go so zero plaintext port-53 DNS leaks occur!
        String endpointForGo = useDoH ? safeTrim(cfg.endpoint) : WgTunnelProber.preResolveEndpoint(cfg.endpoint);

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
            String sysResolved = WgTunnelProber.preResolveEndpoint(cfg.endpoint);
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
        SocksCredsSnapshot activeCreds = sSocksCreds;
        updateSharedHubOwner(localPort, activeCreds.user, activeCreds.pass);
        WgSharedHubAndVoip.registerSharedTunnel(context, localPort, profileSig, cfg.id, cfg.name, activeCreds.user, activeCreds.pass);

        sConnectedProfileId = cfg.id;
        sTunnelStartedAtMs = SystemClock.elapsedRealtime();
        int liveMtu = 1280;
        try {
            int polled = (int) Wgbridge.getActiveMTU();
            if (polled >= 1200) {
                liveMtu = polled;
            }
        } catch (Throwable ignored) {
        }
        sActiveTunnelMtu = liveMtu;
        sLastActiveNetworkSignature = WgHealthAndContinuity.computeActiveNetworkSignature(context);
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
            WgHealthAndContinuity.registerNetworkWatchdog(context, moduleApkPath, telegramClassLoader);
            maybeForceReconnectTelegramOnRebind(telegramClassLoader, hadExistingSession || sNetworkLostAtElapsedMs > 0L);
        }
        syncForegroundKeepaliveService(context, true);
        // Keep muxKillSwitch armed if Kill Switch is enabled so unexpected tunnel death fails closed immediately.
        try {
            Wgbridge.setKillSwitchArmed(isKillSwitchEnabled(context));
        } catch (Throwable ignored) {
        }
        // Always start the 24/7 Forced Continuity & Auto-Failover Guardian while connected
        WgHealthAndContinuity.startFailoverMonitor(context, moduleApkPath, telegramClassLoader);
        return localPort;
    }

    private static void maybeForceReconnectTelegramOnRebind(final ClassLoader telegramClassLoader, boolean forceOutageReset) {
        sNetworkLostAtElapsedMs = 0L;
        if (telegramClassLoader == null) {
            return;
        }
        Handler mainH = getMainHandler();
        if (mainH != null) {
            mainH.postDelayed(() -> XposedProxyReflector.smartRecoverTelegramConnections(telegramClassLoader, forceOutageReset), 120L);
        }
    }

    static int getLiveOrCachedTunnelMtu() {
        if (sSharedHub.isOwner) {
            try {
                int polled = (int) Wgbridge.getActiveMTU();
                if (polled >= 1200) {
                    sActiveTunnelMtu = polled;
                    return polled;
                }
            } catch (Throwable ignored) {
            }
        }
        return sActiveTunnelMtu;
    }

    public static void stopAndUnbind(Context context, String moduleApkPath, ClassLoader telegramClassLoader) {
        sUserManuallyStopped = true;
        WgHealthAndContinuity.stopFailoverMonitor();
        WgHealthAndContinuity.unregisterNetworkWatchdog(context);
        WgHealthAndContinuity.releaseForcedContinuityLocks();
        boolean wasOwner = sSharedHub.isOwner;
        clearSharedHubState();
        if (wasOwner && context != null) {
            WgSharedHubAndVoip.clearSharedTunnel(context);
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
                return sSharedHub.port;
            }
            int extPort = queryAnyLiveSharedTunnelPort(context);
            return extPort > 0 ? extPort : 0;
        } catch (Throwable t) {
            if (isUsingSharedHub()) {
                return sSharedHub.port;
            }
            int extPort = queryAnyLiveSharedTunnelPort(context);
            return extPort > 0 ? extPort : 0;
        }
    }

    static int parseIntSafe(String s, int fallback) {
        try {
            return Integer.parseInt(safeTrim(s));
        } catch (Throwable ignored) {
            return fallback;
        }
    }

    static int clampKeepAlive(int val) {
        if (val <= 0) {
            return 25;
        }
        return Math.min(val, 600);
    }

    static int clampMtu(int val) {
        if (val <= 0) {
            return 1280;
        }
        return Math.max(1280, Math.min(1420, val));
    }

    static String safeTrim(String s) {
        return s == null ? "" : s.trim();
    }

    // Delegators to WgSyncAndCreds
    static Context getSocksPrefsContext() { return WgSyncAndCreds.getSocksPrefsContext(); }
    static String deriveProfileSocksPass(String privateKey) { return WgSyncAndCreds.deriveProfileSocksPass(privateKey); }
    static String computeProfileSigHash(String profileSig) { return WgSyncAndCreds.computeProfileSigHash(profileSig); }
    public static String getActiveSocksUser() { return WgSyncAndCreds.getActiveSocksUser(); }
    public static String getActiveSocksUser(Context context) { return WgSyncAndCreds.getActiveSocksUser(context); }
    public static String getClientSocksUser(Context context) { return WgSyncAndCreds.getClientSocksUser(context); }
    public static String getActiveSocksPass() { return WgSyncAndCreds.getActiveSocksPass(); }
    public static String getActiveSocksPass(Context context) { return WgSyncAndCreds.getActiveSocksPass(context); }
    public static boolean openOfficialChannel(final Context ctx, final Runnable onBeforeRedirect) { return WgSyncAndCreds.openOfficialChannel(ctx, onBeforeRedirect); }
    public static void maybeInviteToOfficialChannel(final Context ctx, final boolean isAr) { WgSyncAndCreds.maybeInviteToOfficialChannel(ctx, isAr, null); }
    public static void maybeInviteToOfficialChannel(final Context ctx, final boolean isAr, final Runnable onBeforeRedirect) { WgSyncAndCreds.maybeInviteToOfficialChannel(ctx, isAr, onBeforeRedirect); }
    public static String exportSharedSyncBundleJson(Context context) { return WgSyncAndCreds.exportSharedSyncBundleJson(context); }
    public static long importSharedSyncBundleJson(Context context, String rawJson, boolean keepIncomingRev) { return WgSyncAndCreds.importSharedSyncBundleJson(context, rawJson, keepIncomingRev); }
    public static boolean syncPullSharedStateFromProvider(Context context, boolean force) { return WgSyncAndCreds.syncPullSharedStateFromProvider(context, force); }
    public static void scheduleSyncPushToProvider(Context context) { WgSyncAndCreds.scheduleSyncPushToProvider(context); }
    public static void publishWorldReadableSyncBundle(Context appCtx) { WgSyncAndCreds.publishWorldReadableSyncBundle(appCtx); }
    public static void reportHookActiveToProvider(Context context, String hostPkg) { WgSyncAndCreds.reportHookActiveToProvider(context, hostPkg); }
    public static Bundle queryHookStatusFromProvider(Context context) { return WgSyncAndCreds.queryHookStatusFromProvider(context); }
    public static void pollAndRunRemoteHygieneIfRequested(Context context) { WgSyncAndCreds.pollAndRunRemoteHygieneIfRequested(context); }

    // Delegators to WgSharedHubAndVoip
    static String patchVoipConfigJsonForProxy(String rawJson) { return WgSharedHubAndVoip.patchVoipConfigJsonForProxy(rawJson); }
    static String rewriteGroupCallJoinPayload(String payloadJson, EndpointRelayStarter relayStarter, boolean killSwitchBlackhole) { return WgSharedHubAndVoip.rewriteGroupCallJoinPayload(payloadJson, relayStarter, killSwitchBlackhole); }
    static String rewriteGroupCallJoinPayloadAddr(String payloadJson, EndpointAddrRelayStarter relayStarter, boolean killSwitchBlackhole) { return WgSharedHubAndVoip.rewriteGroupCallJoinPayloadAddr(payloadJson, relayStarter, killSwitchBlackhole); }
    static boolean isUsingSharedHub() { return WgSharedHubAndVoip.isUsingSharedHub(); }
    public static int queryAnyLiveSharedTunnelPort(Context context) { return WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(context); }
    public static boolean isSharedTunnelObserved(Context context, String moduleApkPath) { return WgSharedHubAndVoip.isSharedTunnelObserved(context, moduleApkPath); }
    static String parseIpFromHostPort(String hostPort) { return WgSharedHubAndVoip.parseIpFromHostPort(hostPort); }
    static int parsePortFromHostPort(String hostPort) { return WgSharedHubAndVoip.parsePortFromHostPort(hostPort); }
    public static int startLocalVoipEndpointRelay(Context ctx, String targetHost, int targetPort) { return WgSharedHubAndVoip.startLocalVoipEndpointRelay(ctx, targetHost, targetPort); }
    public static String startLocalVoipEndpointRelayAddr(Context ctx, String targetHost, int targetPort) { return WgSharedHubAndVoip.startLocalVoipEndpointRelayAddr(ctx, targetHost, targetPort); }
    static int requestVoipRelayOverWgp1(int muxPort, String socksPass, String targetHost, int targetPort) { return WgSharedHubAndVoip.requestVoipRelayOverWgp1(muxPort, socksPass, targetHost, targetPort); }
    static String requestVoipRelayOverWgp1Addr(int muxPort, String socksPass, String targetHost, int targetPort) { return WgSharedHubAndVoip.requestVoipRelayOverWgp1Addr(muxPort, socksPass, targetHost, targetPort); }
    static String startRemoteVoipRelayOverWgp1Addr(Context ctx, String targetHost, int targetPort) { return WgSharedHubAndVoip.startRemoteVoipRelayOverWgp1Addr(ctx, targetHost, targetPort); }
    static long[] queryLiveStatusOverWgp1(int muxPort, String socksPass) { return WgSharedHubAndVoip.queryLiveStatusOverWgp1(muxPort, socksPass); }
    static boolean wgp1ProfileSigMatches(Context context, String requiredSig, String peerSig) { return WgSharedHubAndVoip.wgp1ProfileSigMatches(context, requiredSig, peerSig); }
    public static int startVoipEndpointRelay(Context ctx, String moduleApkPath, String targetHost, int targetPort) { return WgSharedHubAndVoip.startVoipEndpointRelay(ctx, moduleApkPath, targetHost, targetPort); }
    public static String startVoipEndpointRelayAddr(Context ctx, String moduleApkPath, String targetHost, int targetPort) { return WgSharedHubAndVoip.startVoipEndpointRelayAddr(ctx, moduleApkPath, targetHost, targetPort); }
    static boolean shouldTakeOverSharedTunnelFromUnprotectedOwner(String myPkg, String ownerPkg, boolean daemonOrRootActive) { return WgSharedHubAndVoip.shouldTakeOverSharedTunnelFromUnprotectedOwner(myPkg, ownerPkg, daemonOrRootActive); }
    public static boolean yieldLocalTunnelForForegroundClient(Context context) { return WgSharedHubAndVoip.yieldLocalTunnelForForegroundClient(context); }
    public static boolean isHandshakeHealthyNow(Context context, String moduleApkPath) { return WgSharedHubAndVoip.isHandshakeHealthyNow(context, moduleApkPath); }
    static Bundle queryLocalRunningTunnelBundleForProvider(Context ctx, boolean nudgeIfAging) { return WgSharedHubAndVoip.queryLocalRunningTunnelBundleForProvider(ctx, nudgeIfAging); }
    public static void nudgeTunnelHandshakeAsync(final Context context, final String moduleApkPath, final Runnable onUpdatedMain) { WgSharedHubAndVoip.nudgeTunnelHandshakeAsync(context, moduleApkPath, onUpdatedMain); }
    public static long getSharedTunnelLastHandshakeSec(Context context) { return WgSharedHubAndVoip.getSharedTunnelLastHandshakeSec(context); }
    static Bundle fetchSharedHubInfoBundle(Context context) { return WgSharedHubAndVoip.fetchSharedHubInfoBundle(context); }
    static String fetchRemoteEngineDiagnosticsBundle(Context context, String moduleApkPath, int port) { return WgSharedHubAndVoip.fetchRemoteEngineDiagnosticsBundle(context, moduleApkPath, port); }

    // Delegators to WgHealthAndContinuity & WgTunnelProber
    public static boolean shouldForceTelegramAlwaysAwake(Context context, String moduleApkPath) { return WgHealthAndContinuity.shouldForceTelegramAlwaysAwake(context, moduleApkPath); }
    public static boolean queryAndSyncStealthContinuity(Context context, boolean wantsAwake, boolean forceFresh) { return WgHealthAndContinuity.queryAndSyncStealthContinuity(context, wantsAwake, forceFresh); }
    public static void syncForegroundKeepaliveService(Context context, boolean active) { WgHealthAndContinuity.syncForegroundKeepaliveService(context, active); }
    public static PingWinnerResult pingAllProfilesAndSelectFastest(final Context context, final String moduleApkPath, final ClassLoader telegramClassLoader) throws Exception { return WgTunnelProber.pingAllProfilesAndSelectFastest(context, moduleApkPath, telegramClassLoader); }
    public static int discoverAndApplyOptimalMtu(Context context, TunnelConfig draft, String moduleApkPath, ClassLoader telegramClassLoader) throws Exception { return WgTunnelProber.discoverAndApplyOptimalMtu(context, draft, moduleApkPath, telegramClassLoader); }
    public static void onAppForegroundStateChanged(final Context context, final String moduleApkPath, final boolean inForeground) { WgHealthAndContinuity.onAppForegroundStateChanged(context, moduleApkPath, null, inForeground); }
    public static void onAppForegroundStateChanged(final Context context, final String moduleApkPath, final ClassLoader telegramClassLoader, final boolean inForeground) { WgHealthAndContinuity.onAppForegroundStateChanged(context, moduleApkPath, telegramClassLoader, inForeground); }
    public static TunnelVerifyResult verifyTunnel(Context context, String moduleApkPath) throws Exception { return WgTunnelProber.verifyTunnel(context, moduleApkPath); }
    static void performSocks5ClientAuth(OutputStream out, DataInputStream in, String user, String pass) throws Exception { WgTunnelProber.performSocks5ClientAuth(out, in, user, pass); }
    static Socket openSocks5HostSocket(int localSocksPort, String user, String pass, String targetHost, int targetPort, int timeoutMs) throws Exception { return WgTunnelProber.openSocks5HostSocket(localSocksPort, user, pass, targetHost, targetPort, timeoutMs); }

    // Delegators to WgProxyBinder
    public static void onModuleVersionUpgraded(Context ctx, ClassLoader telegramClassLoader) { WgProxyBinder.onModuleVersionUpgraded(ctx, telegramClassLoader); }
    public static Object buildTelegramProxySettingsObject(ClassLoader cl, int port, String user, String pass) { return WgProxyBinder.buildTelegramProxySettingsObject(cl, port, user, pass); }
    static Object buildTelegramProxySettingsObjectInternal(ClassLoader cl, String address, int port, String user, String pass) { return WgProxyBinder.buildTelegramProxySettingsObjectInternal(cl, address, port, user, pass); }
    public static int getCachedSharedOrFallbackPort(Context context) { return WgProxyBinder.getCachedSharedOrFallbackPort(context); }
    public static void preArmKillSwitchSync(Context context, ClassLoader telegramClassLoader) { WgProxyBinder.preArmKillSwitchSync(context, telegramClassLoader); }
    public static void reapplyProxyToAccountIfActive(Context context, ClassLoader telegramClassLoader, int accountIdx) { WgProxyBinder.reapplyProxyToAccountIfActive(context, telegramClassLoader, accountIdx, false); }
    public static void reapplyProxyToAccountIfActive(Context context, ClassLoader telegramClassLoader, int accountIdx, boolean force) { WgProxyBinder.reapplyProxyToAccountIfActive(context, telegramClassLoader, accountIdx, force); }
    public static int enforceKillSwitchIfDisconnected(Context context, String moduleApkPath, ClassLoader telegramClassLoader) { return WgProxyBinder.enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader); }
    public static boolean isKillSwitchGuardActiveNow(Context context, String moduleApkPath) { return WgProxyBinder.isKillSwitchGuardActiveNow(context, moduleApkPath); }
    public static boolean shouldRouteCallsNow(Context context, String moduleApkPath) { return WgProxyBinder.shouldRouteCallsNow(context, moduleApkPath); }
    public static int getEffectiveProxyPort(Context context, String moduleApkPath) { return WgProxyBinder.getEffectiveProxyPort(context, moduleApkPath); }
    public static void postBindTelegramProxy(final Context context, final ClassLoader classLoader, final boolean enabled, final int localPort, final boolean routeCalls) { WgProxyBinder.postBindTelegramProxy(context, classLoader, enabled, localPort, routeCalls, false); }
    public static void postBindTelegramProxy(final Context context, final ClassLoader classLoader, final boolean enabled, final int localPort, final boolean routeCalls, final boolean force) { WgProxyBinder.postBindTelegramProxy(context, classLoader, enabled, localPort, routeCalls, force); }
    static String getDiagnosticsInternalStateSummary(Context context) { return WgProxyBinder.getDiagnosticsInternalStateSummary(context); }
    static String detectInjectionMode(Context context) { return WgProxyBinder.detectInjectionMode(context); }
    static String inspectTelegramProxyHealthSummary(Context context) { return WgProxyBinder.inspectTelegramProxyHealthSummary(context); }
}
