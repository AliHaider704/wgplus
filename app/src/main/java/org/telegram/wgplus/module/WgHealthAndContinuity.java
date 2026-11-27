package org.telegram.wgplus.module;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
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

import org.json.JSONObject;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import wgbridge.Wgbridge;

/**
 * 24/7 Forced Continuity locks, stealth keepalive service, DNS hints, multi-server ping,
 * optimal MTU path discovery, failover guardian, roaming watchdog, and route verification
 * extracted from {@link WireGuardManager}.
 */
final class WgHealthAndContinuity {

    private WgHealthAndContinuity() {
    }

    private static final AtomicBoolean sScreenPreWarmRegistered = new AtomicBoolean(false);
    private static volatile long sLastScreenPreWarmMs = 0L;

    /**
     * Returns true when Telegram's native tgnet sockets should be forced awake 24/7
     * (blocking setAppPaused(true) and native_pauseNetwork) so background delivery,
     * messages, and incoming calls stay live across cellular and Wi-Fi.
     */
    static boolean shouldForceTelegramAlwaysAwake(Context context, String moduleApkPath) {
        if (context == null || !hasActiveOsNetwork(context)) {
            return false;
        }
        if (WireGuardManager.sUserManuallyStopped && !WireGuardManager.isKillSwitchEnabled(context)) {
            return false;
        }
        if (!WireGuardManager.sConnectedProfileId.isEmpty()) {
            return true;
        }
        try {
            if (WireGuardManager.isAutoConnectEnabled(context) || WireGuardManager.isKillSwitchEnabled(context)) {
                return true;
            }
            String savedConn = WireGuardManager.getPrefs(context).getString(WireGuardManager.KEY_CONNECTED_PROFILE_ID, "");
            if (savedConn != null && !savedConn.isEmpty()) {
                return true;
            }
        } catch (Throwable ignored) {
        }
        return WireGuardManager.isTunnelRunning(context, moduleApkPath);
    }

    static boolean isOuterVpnActive(Context context) {
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
            NetworkCapabilities nc = cm.getNetworkCapabilities(active);
            return nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } catch (Throwable ignored) {
            return false;
        }
    }

    static boolean isOsNetworkValidated(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return true;
            }
            Network active = cm.getActiveNetwork();
            if (active == null) {
                return false;
            }
            NetworkCapabilities nc = cm.getNetworkCapabilities(active);
            if (nc == null) {
                return false;
            }
            return nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
        } catch (Throwable ignored) {
            return true;
        }
    }

    static void syncHostLinkMtuSensor(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return;
        }
        try {
            if (!NativeBridgeLoader.isLoaded()) {
                return;
            }
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return;
            }
            Network active = cm.getActiveNetwork();
            if (active == null) {
                return;
            }
            NetworkCapabilities nc = cm.getNetworkCapabilities(active);
            boolean outerVpn = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            int linkMtu = 0;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                LinkProperties lp = cm.getLinkProperties(active);
                if (lp != null) {
                    linkMtu = lp.getMtu();
                }
            }
            Wgbridge.setHostLinkMTU(linkMtu, outerVpn);
        } catch (Throwable ignored) {
        }
    }

    static void registerScreenPreWarmReceiverIfNeeded(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        if (context == null || !sScreenPreWarmRegistered.compareAndSet(false, true)) {
            return;
        }
        try {
            final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            IntentFilter filter = new IntentFilter();
            filter.addAction(Intent.ACTION_SCREEN_ON);
            filter.addAction(Intent.ACTION_USER_PRESENT);
            BroadcastReceiver rx = new BroadcastReceiver() {
                @Override
                public void onReceive(Context ctx, Intent intent) {
                    if (WireGuardManager.sUserManuallyStopped) {
                        return;
                    }
                    long now = SystemClock.elapsedRealtime();
                    if (now - sLastScreenPreWarmMs < 4000L) {
                        return;
                    }
                    sLastScreenPreWarmMs = now;
                    WireGuardManager.getGuardianExecutor().execute(() -> {
                        try {
                            if (!hasActiveOsNetwork(appCtx)) {
                                return;
                            }
                            syncHostLinkMtuSensor(appCtx);
                            if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                                if (!Wgbridge.isTunnelHotVerified()) {
                                    Wgbridge.ensureTunnelAlive(1200L);
                                }
                                if (telegramClassLoader != null) {
                                    XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                                }
                            } else if (WgSharedHubAndVoip.isUsingSharedHub() && telegramClassLoader != null) {
                                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                            }
                        } catch (Throwable ignored) {
                        }
                    });
                }
            };
            if (Build.VERSION.SDK_INT >= 33) {
                appCtx.registerReceiver(rx, filter, Context.RECEIVER_EXPORTED);
            } else {
                appCtx.registerReceiver(rx, filter);
            }
        } catch (Throwable ignored) {
            sScreenPreWarmRegistered.set(false);
        }
    }

    static void acquireForcedContinuityLocks(Context context) {
        if (context == null) {
            return;
        }
        synchronized (WireGuardManager.LOCK_SYNC) {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            try {
                if (WireGuardManager.sForcedWakeLock == null) {
                    PowerManager pm = (PowerManager) appCtx.getSystemService(Context.POWER_SERVICE);
                    if (pm != null) {
                        WireGuardManager.sForcedWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "WireGuardPlus::ForcedContinuityWakeLock");
                        WireGuardManager.sForcedWakeLock.setReferenceCounted(false);
                    }
                }
                if (WireGuardManager.sForcedWakeLock != null && !WireGuardManager.sForcedWakeLock.isHeld()) {
                    WireGuardManager.sForcedWakeLock.acquire();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (WireGuardManager.sForcedWifiLock == null) {
                    WifiManager wm = (WifiManager) appCtx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                    if (wm != null) {
                        int lockMode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                                ? WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                                : WifiManager.WIFI_MODE_FULL_HIGH_PERF;
                        WireGuardManager.sForcedWifiLock = wm.createWifiLock(lockMode, "WireGuardPlus::ForcedContinuityWifiLock");
                        WireGuardManager.sForcedWifiLock.setReferenceCounted(false);
                    }
                }
                if (WireGuardManager.sForcedWifiLock != null && !WireGuardManager.sForcedWifiLock.isHeld()) {
                    WireGuardManager.sForcedWifiLock.acquire();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    static void releaseForcedContinuityLocks() {
        synchronized (WireGuardManager.LOCK_SYNC) {
            try {
                if (WireGuardManager.sForcedWakeLock != null && WireGuardManager.sForcedWakeLock.isHeld()) {
                    WireGuardManager.sForcedWakeLock.release();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (WireGuardManager.sForcedWifiLock != null && WireGuardManager.sForcedWifiLock.isHeld()) {
                    WireGuardManager.sForcedWifiLock.release();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    static boolean isCellularNetworkActive(Context context) {
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

    static int effectiveKeepAlive(Context context, int configuredKeepAlive) {
        int clamped = WireGuardManager.clampKeepAlive(configuredKeepAlive);
        return isCellularNetworkActive(context) ? Math.min(18, clamped) : clamped;
    }

    /**
     * Queries the companion module's {@link KeepaliveStatusProvider} to apply elevated
     * {@code setProcessImportant} + silent {@link KeepaliveBridgeListenerService} protection
     * for this host process before falling back to a standard foreground service notification.
     */
    static boolean queryAndSyncStealthContinuity(Context context, boolean wantsAwake, boolean forceFresh) {
        if (context == null) {
            return false;
        }
        long now = SystemClock.elapsedRealtime();
        if (!forceFresh && wantsAwake == WireGuardManager.sLastStealthWantsAwake
                && (now - WireGuardManager.sLastStealthQueryMs) < 60_000L) {
            return WireGuardManager.sLastStealthProtected;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        // Never block the host app UI thread on synchronous ContentProvider Binder IPC
        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (now - WireGuardManager.sLastStealthQueryMs >= 10_000L) {
                WireGuardManager.sLastStealthQueryMs = now;
                WireGuardManager.getGuardianExecutor().execute(() -> queryAndSyncStealthContinuity(appCtx, wantsAwake, true));
            }
            return WireGuardManager.sLastStealthProtected;
        }
        try {
            Bundle extras = new Bundle();
            extras.putInt(KeepaliveStatusProvider.EXTRA_PID, Process.myPid());
            extras.putBoolean(KeepaliveStatusProvider.EXTRA_WANTS_ALWAYS_AWAKE, wantsAwake);
            Bundle res = appCtx.getContentResolver().call(
                    WireGuardManager.STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_ENSURE_STEALTH,
                    appCtx.getPackageName(),
                    extras
            );
            boolean stealth = res != null && res.getBoolean(KeepaliveStatusProvider.RESULT_STEALTH_PROTECTED, false);
            WireGuardManager.sLastStealthWantsAwake = wantsAwake;
            WireGuardManager.sLastStealthProtected = stealth;
            WireGuardManager.sLastStealthQueryMs = now;
            return stealth;
        } catch (Throwable ignored) {
            WireGuardManager.sLastStealthWantsAwake = wantsAwake;
            WireGuardManager.sLastStealthProtected = false;
            WireGuardManager.sLastStealthQueryMs = now;
            return false;
        }
    }

    static void syncForegroundKeepaliveService(Context context, boolean active) {
        if (context == null) {
            return;
        }
        if (TelegramXBridge.PACKAGE_NAME.equals(context.getPackageName())) {
            return;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            Intent intent = new Intent();
            intent.setClassName(appCtx.getPackageName(), WireGuardManager.FG_SERVICE_CLASS);
            if (!active) {
                queryAndSyncStealthContinuity(appCtx, false, true);
                intent.putExtra(WireGuardManager.EXTRA_STOP_FOREGROUND_KEEPALIVE, true);
                try {
                    appCtx.startService(intent);
                } catch (Throwable ignored) {
                }
                return;
            }
            if (queryAndSyncStealthContinuity(appCtx, true, true)) {
                // Stealth protection active (elevated force-imp and/or silent NotificationListener bind):
                // Do NOT call startForegroundService (avoids 5s timer crash and removes any old FG notification).
                intent.setAction(WireGuardManager.ACTION_SYNC_CONTINUITY);
                try {
                    appCtx.startService(intent);
                } catch (Throwable ignored) {
                }
                return;
            }
            intent.putExtra(WireGuardManager.EXTRA_EXPECT_FOREGROUND_PROMOTE, true);
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
            ServiceInfo si = pm.getServiceInfo(new ComponentName(context.getPackageName(), WireGuardManager.FG_SERVICE_CLASS), 0);
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

    static String computeActiveNetworkSignature(Context context) {
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
                ifName = WireGuardManager.safeTrim(lp.getInterfaceName());
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

    static void syncEndpointDnsHintsToNative(Context context, String rawEndpoint) {
        if (context == null) {
            return;
        }
        try {
            SharedPreferences prefs = WireGuardManager.getPrefs(context);
            String rawCache = prefs.getString(WireGuardManager.KEY_DNS_LKG_CACHE_JSON, "");
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

    static void persistEndpointDnsHint(Context context, String host, String ip) {
        if (context == null || host == null || host.isEmpty() || ip == null || ip.isEmpty()) {
            return;
        }
        try {
            SharedPreferences prefs = WireGuardManager.getPrefs(context);
            String rawCache = prefs.getString(WireGuardManager.KEY_DNS_LKG_CACHE_JSON, "");
            JSONObject obj = (rawCache != null && !rawCache.isEmpty()) ? new JSONObject(rawCache) : new JSONObject();
            obj.put(host.toLowerCase(Locale.ROOT), ip);
            prefs.edit().putString(WireGuardManager.KEY_DNS_LKG_CACHE_JSON, obj.toString()).apply();
        } catch (Throwable ignored) {
        }
    }

    private static String extractEndpointHost(String rawEndpoint) {
        String ep = WireGuardManager.safeTrim(rawEndpoint);
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

    /**
     * Driven by Application.ActivityLifecycleCallbacks to ensure immediate zero-delay tunnel
     * verification and Telegram tgnet socket wake-up on foreground resume, while maintaining
     * 24/7 CGNAT NAT persistence in the background.
     */
    static void onAppForegroundStateChanged(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader,
            final boolean inForeground
    ) {
        WireGuardManager.sAppInForeground = inForeground;
        Handler h = WireGuardManager.getMainHandler();
        if (WireGuardManager.sPendingIdleSaverTask != null) {
            if (h != null) {
                h.removeCallbacks(WireGuardManager.sPendingIdleSaverTask);
            }
            WireGuardManager.sPendingIdleSaverTask = null;
        }

        if (inForeground) {
            long bgElapsedMs = WireGuardManager.sLastBackgroundedAtMs > 0 ? (SystemClock.elapsedRealtime() - WireGuardManager.sLastBackgroundedAtMs) : 0L;
            final boolean longBg = bgElapsedMs >= 30_000L;
            WireGuardManager.getGuardianExecutor().execute(() -> {
                try {
                    ModuleHygieneManager.trimInMemoryCaches();
                    if (WireGuardManager.sKeepalivePausedForIdle) {
                        restoreActiveKeepaliveNow(context, moduleApkPath);
                    }
                    if (!WireGuardManager.sUserManuallyStopped && !WireGuardManager.isTunnelRunning(context, moduleApkPath)) {
                        WireGuardManager.clearSharedHubState();
                        if (WireGuardManager.isAutoConnectEnabled(context) || !WireGuardManager.sConnectedProfileId.isEmpty()) {
                            WireGuardManager.TunnelConfig cfg = WireGuardManager.loadConfig(context);
                            if (cfg.hasPeerConfigured()) {
                                WireGuardManager.startAndBindProfile(context, cfg, moduleApkPath, telegramClassLoader);
                                return;
                            }
                        }
                        if (WireGuardManager.isKillSwitchEnabled(context)) {
                            WgProxyBinder.enforceKillSwitchIfDisconnected(context, moduleApkPath, telegramClassLoader);
                        }
                    }
                    if (Wgbridge.isRunning()) {
                        boolean osOnline = hasActiveOsNetwork(context);
                        if (osOnline) {
                            acquireForcedContinuityLocks(context);
                            syncHostLinkMtuSensor(context);
                        } else {
                            releaseForcedContinuityLocks();
                        }
                        syncForegroundKeepaliveService(context, true);
                        boolean wasOffline = WireGuardManager.sNetworkLostAtElapsedMs > 0L;
                        boolean tunnelHot = !wasOffline && osOnline && Wgbridge.isTunnelHotVerified();
                        boolean rebound = false;
                        if (!tunnelHot && osOnline) {
                            long epochBefore = Wgbridge.getRecoveryEpoch();
                            boolean alive = Wgbridge.ensureTunnelAlive(1500L);
                            rebound = (Wgbridge.getRecoveryEpoch() != epochBefore) || !alive;
                            if (!alive) {
                                rebound = Wgbridge.forceRebindAndHandshake() || rebound;
                            }
                        }
                        if (wasOffline || rebound) {
                            Wgbridge.resetActiveProxyConnections("foreground_wake_rebound");
                            WireGuardManager.sNetworkLostAtElapsedMs = 0L;
                            if (telegramClassLoader != null) {
                                XposedProxyReflector.smartRecoverTelegramConnections(telegramClassLoader, true);
                            }
                        } else if (wasOffline) {
                            WireGuardManager.sNetworkLostAtElapsedMs = 0L;
                        }
                        int activePort = (int) Wgbridge.getActivePort();
                        if (activePort > 0 && telegramClassLoader != null) {
                            WgProxyBinder.postBindTelegramProxy(
                                    context,
                                    telegramClassLoader,
                                    true,
                                    activePort,
                                    WireGuardManager.isRouteCallsEnabled(context),
                                    rebound
                            );
                            if (!wasOffline && !rebound) {
                                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                            }
                        }
                    } else if (WgSharedHubAndVoip.isUsingSharedHub()) {
                        if (hasActiveOsNetwork(context)) {
                            acquireForcedContinuityLocks(context);
                        } else {
                            releaseForcedContinuityLocks();
                        }
                        if (WgSharedHubAndVoip.ensureSharedHubResponsiveOrTakeOver(context, moduleApkPath, telegramClassLoader, "foreground_resume")) {
                            return;
                        }
                        boolean wasOffline = WireGuardManager.sNetworkLostAtElapsedMs > 0L;
                        int hubPort = WireGuardManager.sSharedHub.port;
                        if (hubPort > 0 && telegramClassLoader != null) {
                            WgProxyBinder.postBindTelegramProxy(
                                    context,
                                    telegramClassLoader,
                                    true,
                                    hubPort,
                                    WireGuardManager.isRouteCallsEnabled(context),
                                    false
                            );
                            if (wasOffline) {
                                WireGuardManager.sNetworkLostAtElapsedMs = 0L;
                                XposedProxyReflector.smartRecoverTelegramConnections(telegramClassLoader, true);
                            } else {
                                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                            }
                        }
                    }
                } catch (Throwable ignored) {
                }
            });
        } else {
            WireGuardManager.sLastBackgroundedAtMs = SystemClock.elapsedRealtime();
            // In background: keep WakeLock/WifiLock only while OS internet is active; sleep at 0% CPU when offline.
            WireGuardManager.getGuardianExecutor().execute(() -> {
                try {
                    if (!hasActiveOsNetwork(context)) {
                        releaseForcedContinuityLocks();
                        if (telegramClassLoader != null) {
                            XposedProxyReflector.pauseTelegramForOffline(telegramClassLoader);
                        }
                        return;
                    }
                    if (WireGuardManager.isTunnelRunning(context, moduleApkPath)) {
                        acquireForcedContinuityLocks(context);
                        syncForegroundKeepaliveService(context, true);
                        if (WireGuardManager.isSmartKeepaliveEnabled(context)) {
                            Wgbridge.setPeerKeepalive(25L);
                            WireGuardManager.sKeepalivePausedForIdle = true;
                        } else {
                            WireGuardManager.TunnelConfig activeCfg = WireGuardManager.getConnectedProfile(context, moduleApkPath);
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

    static void restoreActiveKeepaliveNow(final Context context, final String moduleApkPath) {
        WireGuardManager.getGuardianExecutor().execute(() -> {
            try {
                if (!WireGuardManager.isTunnelRunning(context, moduleApkPath)) {
                    WireGuardManager.sKeepalivePausedForIdle = false;
                    return;
                }
                WireGuardManager.TunnelConfig activeCfg = WireGuardManager.getConnectedProfile(context, moduleApkPath);
                int ka = effectiveKeepAlive(context, activeCfg != null ? activeCfg.keepAlive : 20);
                Wgbridge.setPeerKeepalive(ka);
                WireGuardManager.sKeepalivePausedForIdle = false;
            } catch (Throwable ignored) {
            }
        });
    }

    static boolean hasActiveOsNetwork(Context context) {
        if (context == null) {
            return true;
        }
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return true;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = cm.getActiveNetwork();
                if (active == null) {
                    return false;
                }
                NetworkCapabilities nc = cm.getNetworkCapabilities(active);
                return nc == null || nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
            }
            NetworkInfo ni = cm.getActiveNetworkInfo();
            return ni != null && ni.isConnected();
        } catch (Throwable ignored) {
            return true;
        }
    }

    static void startFailoverMonitor(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        stopFailoverMonitor();
        if (context == null) {
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        ScheduledExecutorService exec = WireGuardManager.getGuardianExecutor();
        WireGuardManager.sGuardianFuture = exec.scheduleWithFixedDelay(() -> {
            if (WireGuardManager.sUserManuallyStopped || WireGuardManager.sFailoverCheckRunning) {
                return;
            }
            WireGuardManager.sFailoverCheckRunning = true;
            try {
                evaluateTunnelHealthAndFailover(appCtx, moduleApkPath, telegramClassLoader);
            } catch (Throwable ignored) {
            } finally {
                WireGuardManager.sFailoverCheckRunning = false;
            }
        }, 2L, 10L, TimeUnit.SECONDS);
    }

    static void stopFailoverMonitor() {
        if (WireGuardManager.sGuardianFuture != null) {
            try {
                WireGuardManager.sGuardianFuture.cancel(false);
            } catch (Throwable ignored) {
            }
            WireGuardManager.sGuardianFuture = null;
        }
        WireGuardManager.sConsecutiveHealthFailures = 0;
    }

    private static void evaluateTunnelHealthAndFailover(
            final Context appCtx,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        if (WireGuardManager.sUserManuallyStopped) {
            return;
        }
        try {
            NativeBridgeLoader.ensureLoaded(appCtx, moduleApkPath);
        } catch (Throwable ignored) {
            return;
        }

        if (WgSyncAndCreds.syncPullSharedStateFromProvider(appCtx, false) && Wgbridge.isRunning()) {
            WgSyncAndCreds.syncAllowedProfilePasswordsToNative(appCtx);
            String syncedActiveId = WireGuardManager.getPrefs(appCtx).getString(WireGuardManager.KEY_ACTIVE_PROFILE_ID, "");
            if (!syncedActiveId.isEmpty() && !syncedActiveId.equals(WireGuardManager.sConnectedProfileId)) {
                WireGuardManager.TunnelConfig nextCfg = WireGuardManager.loadConfig(appCtx);
                if (nextCfg != null && nextCfg.hasPeerConfigured()) {
                    try {
                        WireGuardManager.startAndBindProfile(appCtx, nextCfg, moduleApkPath, telegramClassLoader);
                        return;
                    } catch (Throwable ignored) {
                    }
                }
            }
        }

        // 1. Self-heal if tunnel unexpectedly stopped while supposed to be active 24/7
        if (!Wgbridge.isRunning()) {
            if (WgSharedHubAndVoip.isUsingSharedHub()) {
                if (WireGuardManager.sAppInForeground && WgSharedHubAndVoip.ensureSharedHubResponsiveOrTakeOver(appCtx, moduleApkPath, telegramClassLoader, "health_monitor_foreground")) {
                    return;
                }
                WireGuardManager.sConsecutiveHealthFailures = 0;
                WireGuardManager.sLastSharedHubCheckMs = 0L;
                int freshPort = WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(appCtx);
                int bindPort = freshPort > 0 ? freshPort : WireGuardManager.sSharedHub.port;
                if (telegramClassLoader != null && bindPort > 0) {
                    WgProxyBinder.postBindTelegramProxy(appCtx, telegramClassLoader, true, bindPort, WireGuardManager.isRouteCallsEnabled(appCtx), false);
                    XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
                }
                return;
            }
            WireGuardManager.clearSharedHubState();
            if (!hasActiveOsNetwork(appCtx)) {
                WireGuardManager.sConsecutiveHealthFailures = 0;
                return;
            }
            if (WireGuardManager.isAutoConnectEnabled(appCtx) || !WireGuardManager.sConnectedProfileId.isEmpty()) {
                WireGuardManager.TunnelConfig target = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
                if (target == null || !target.hasPeerConfigured()) {
                    target = WireGuardManager.loadConfig(appCtx);
                }
                if (target != null && target.hasPeerConfigured()) {
                    try {
                        WireGuardManager.startAndBindProfile(appCtx, target, moduleApkPath, telegramClassLoader);
                        return;
                    } catch (Throwable ignored) {
                    }
                }
            } else {
                return;
            }
        }

        // Quiesce locks & tgnet reconnect spins immediately while OS has zero active internet route;
        // ConnectivityManager callbacks resume recovery as soon as connectivity returns.
        if (!hasActiveOsNetwork(appCtx)) {
            releaseForcedContinuityLocks();
            WireGuardManager.sConsecutiveHealthFailures = 0;
            if (WireGuardManager.sNetworkLostAtElapsedMs <= 0L) {
                WireGuardManager.sNetworkLostAtElapsedMs = SystemClock.elapsedRealtime();
            }
            if (telegramClassLoader != null) {
                XposedProxyReflector.pauseTelegramForOffline(telegramClassLoader);
            }
            return;
        }

        acquireForcedContinuityLocks(appCtx);
        syncHostLinkMtuSensor(appCtx);

        // 1a. Multi-app single-tunnel convergence: if a cold-start race bound port > 48729 while
        // canonical port 48729 already runs the same profile, yield immediately onto 48729 so
        // only ONE WireGuard session owns the device PrivateKey.
        try {
            int myPort = (int) Wgbridge.getActivePort();
            if (myPort > 48729) {
                WireGuardManager.TunnelConfig activeCfg = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
                String requiredSig = (activeCfg != null && activeCfg.hasPeerConfigured())
                        ? (WireGuardManager.safeTrim(activeCfg.endpoint) + "|" + WireGuardManager.safeTrim(activeCfg.publicKey))
                        : "";
                WgSharedHubAndVoip.Wgp1StatusResult canon = WgSharedHubAndVoip.queryLiveStatusWithFallback(appCtx, moduleApkPath, 48729, WireGuardManager.sSocksCreds.pass, requiredSig);
                if (canon != null && canon.running && WgSharedHubAndVoip.wgp1ProfileSigMatches(appCtx, requiredSig, canon.profileSig)) {
                    Wgbridge.setKillSwitchArmed(false);
                    Wgbridge.stopKillSwitchGuard();
                    Wgbridge.stopTunnel();
                    WireGuardManager.SharedHubSnapshot prevHub = WireGuardManager.sSharedHub;
                    WireGuardManager.updateSharedHubClient(48729, prevHub.user, prevHub.pass, canon.hsSec, canon.hsHealthy);
                    WireGuardManager.sCachedExternalSharedPort = 48729;
                    WireGuardManager.sLastSharedHubCheckMs = SystemClock.elapsedRealtime();
                    WgSharedHubAndVoip.clearSharedTunnelForPort(appCtx, myPort);
                    if (telegramClassLoader != null) {
                        WgProxyBinder.postBindTelegramProxy(appCtx, telegramClassLoader, true, 48729, WireGuardManager.isRouteCallsEnabled(appCtx), true);
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
                WgSyncAndCreds.ensureSessionSocksCredentials(appCtx);
                WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
                Wgbridge.setSocksAuth(creds.user, creds.pass);
                WgSyncAndCreds.syncAllowedProfilePasswordsToNative(appCtx);
                ModuleHygieneManager.triggerDesyncRecoveryHygiene(appCtx, telegramClassLoader, "socks_auth_reject_3x");
                WgTelemetryReporter.reportAnomalyAsync(appCtx, moduleApkPath, "SOCKS_AUTH_DESYNC", "rejects>=3");
                if (telegramClassLoader != null) {
                    int p = (int) Wgbridge.getActivePort();
                    if (p > 0) {
                        WgProxyBinder.postBindTelegramProxy(appCtx, telegramClassLoader, true, p, WireGuardManager.isRouteCallsEnabled(appCtx), true);
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
            WireGuardManager.sConsecutiveHealthFailures = 0;
            WgSyncAndCreds.scheduleHookHeartbeatThrottled(appCtx);
            WireGuardManager.TunnelConfig activeCfg = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
            boolean hsNow = WgSharedHubAndVoip.isHandshakeHealthyNow(appCtx, moduleApkPath);
            if (hsNow && (!WireGuardManager.sLastReportedHsHealthy || Math.abs(System.currentTimeMillis() - WireGuardManager.sLastSharedTunnelHeartbeatMs) >= 60_000L)) {
                boolean wasReportedHealthy = WireGuardManager.sLastReportedHsHealthy;
                WireGuardManager.sLastReportedHsHealthy = true;
                int activePort = 0;
                try {
                    activePort = (int) Wgbridge.getActivePort();
                } catch (Throwable ignored) {
                }
                if (activePort > 0) {
                    String sig = activeCfg != null
                            ? (WireGuardManager.safeTrim(activeCfg.endpoint) + "|" + WireGuardManager.safeTrim(activeCfg.publicKey))
                            : "";
                    WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
                    WgSharedHubAndVoip.registerSharedTunnel(
                            appCtx,
                            activePort,
                            sig,
                            activeCfg != null ? activeCfg.id : WireGuardManager.sConnectedProfileId,
                            activeCfg != null ? activeCfg.name : "",
                            creds.user,
                            creds.pass
                    );
                    if (!wasReportedHealthy && telegramClassLoader != null) {
                        WgProxyBinder.postBindTelegramProxy(appCtx, telegramClassLoader, true, activePort, WireGuardManager.isRouteCallsEnabled(appCtx), true);
                    }
                }
            } else if (telegramClassLoader != null) {
                // Only nudge Telegram accounts whose ConnectionState != Connected (3)
                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, false);
            }
            return;
        }

        if (WireGuardManager.sLastReportedHsHealthy) {
            WireGuardManager.sLastReportedHsHealthy = false;
            int activePort = 0;
            try {
                activePort = (int) Wgbridge.getActivePort();
            } catch (Throwable ignored) {
            }
            if (activePort > 0) {
                WireGuardManager.TunnelConfig activeCfg = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
                String sig = activeCfg != null
                        ? (WireGuardManager.safeTrim(activeCfg.endpoint) + "|" + WireGuardManager.safeTrim(activeCfg.publicKey))
                        : "";
                WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
                WgSharedHubAndVoip.registerSharedTunnel(
                        appCtx,
                        activePort,
                        sig,
                        activeCfg != null ? activeCfg.id : WireGuardManager.sConnectedProfileId,
                        activeCfg != null ? activeCfg.name : "",
                        creds.user,
                        creds.pass
                );
                if (telegramClassLoader != null) {
                    WgProxyBinder.postBindTelegramProxy(appCtx, telegramClassLoader, true, activePort, WireGuardManager.isRouteCallsEnabled(appCtx), true);
                }
            }
        }

        List<WireGuardManager.TunnelConfig> profiles = WireGuardManager.loadProfiles(appCtx);
        List<WireGuardManager.TunnelConfig> backups = new ArrayList<>();
        String currentId = WireGuardManager.getConnectedProfileId(appCtx, moduleApkPath);
        WireGuardManager.TunnelConfig currentCfg = null;
        for (WireGuardManager.TunnelConfig p : profiles) {
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

        boolean useDoH = WireGuardManager.isDohEnabled(appCtx);
        WireGuardManager.sConsecutiveHealthFailures++;
        if (WireGuardManager.isKillSwitchEnabled(appCtx) && !Wgbridge.isRunning()) {
            WgProxyBinder.enforceKillSwitchIfDisconnected(appCtx, moduleApkPath, telegramClassLoader);
        }

        // 3. Auto-downgrade oversized MTU (>1280) in-place on first stall tick without dropping sockets
        long nowElapsed = SystemClock.elapsedRealtime();
        int liveMtu = WireGuardManager.getLiveOrCachedTunnelMtu();
        if (WireGuardManager.sConsecutiveHealthFailures >= 1 && liveMtu > 1280) {
            WireGuardManager.sAutoMtuDowngraded = true;
            WgDiagnosticsLog.record("HEALTH", "MTU_DROP", "In-place step-down MTU from " + liveMtu + " to 1280");
            try {
                Wgbridge.stepDownActiveTunnelMTU(1280L, "health_stall");
            } catch (Throwable ignored) {
            }
            WireGuardManager.sActiveTunnelMtu = 1280;
            return;
        }
        if (WireGuardManager.sConsecutiveHealthFailures < 3) {
            return;
        }

        // 4. If Auto-Failover is enabled and backup profiles exist, switch to first healthy backup
        if (WireGuardManager.isAutoFailoverEnabled(appCtx) && !backups.isEmpty()) {
            for (final WireGuardManager.TunnelConfig candidate : backups) {
                try {
                    syncEndpointDnsHintsToNative(appCtx, candidate.endpoint);
                    long candRtt = Wgbridge.probeEndpointHandshakeMs(
                            WireGuardManager.normalizeKeyToHex(candidate.privateKey),
                            WireGuardManager.safeTrim(candidate.presharedKey).isEmpty() ? "" : WireGuardManager.normalizeKeyToHex(candidate.presharedKey),
                            WireGuardManager.normalizeKeyToHex(candidate.publicKey),
                            useDoH ? WireGuardManager.safeTrim(candidate.endpoint) : WgTunnelProber.preResolveEndpoint(candidate.endpoint),
                            candidate.toEffectiveAwgParamsString(),
                            useDoH,
                            3000L
                    );
                    if (candRtt > 0) {
                        WireGuardManager.sPingCacheMs.put(candidate.id, (int) candRtt);
                        WireGuardManager.sLastHardRestartMs = nowElapsed;
                        WireGuardManager.startAndBindProfile(appCtx, candidate, moduleApkPath, telegramClassLoader);
                        final boolean isAr = WireGuardManager.isArabic(appCtx);
                        Handler h = WireGuardManager.getMainHandler();
                        if (h != null && WireGuardManager.sAppInForeground) {
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
        if (WireGuardManager.sConsecutiveHealthFailures >= 3 && (nowElapsed - WireGuardManager.sLastHardRestartMs >= 60_000L)) {
            WireGuardManager.sConsecutiveHealthFailures = 0;
            WireGuardManager.sLastHardRestartMs = nowElapsed;
            if (WireGuardManager.sActiveTunnelMtu > 1280) {
                WireGuardManager.sAutoMtuDowngraded = true;
            }
            WgTelemetryReporter.reportAnomalyAsync(appCtx, moduleApkPath, "HEALTH_FAILOVER_3X", currentCfg != null ? currentCfg.name : "");
            try {
                WireGuardManager.startAndBindProfile(appCtx, currentCfg, moduleApkPath, telegramClassLoader);
            } catch (Throwable ignored) {
            }
        }
    }

    static void registerNetworkWatchdog(
            final Context context,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader
    ) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        synchronized (WireGuardManager.WATCHDOG_LOCK) {
            if (WireGuardManager.sNetworkCallback != null) {
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
                        WireGuardManager.sNetworkLostAtElapsedMs = SystemClock.elapsedRealtime();
                        WireGuardManager.sLastActiveNetworkSignature = "";
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 400L, true);
                    }

                    @Override
                    public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
                        String sig = computeActiveNetworkSignature(appCtx);
                        if (!sig.isEmpty() && sig.equals(WireGuardManager.sLastActiveNetworkSignature)) {
                            return;
                        }
                        scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 300L, false);
                    }

                    @Override
                    public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                        String sig = computeActiveNetworkSignature(appCtx);
                        if (!sig.isEmpty() && sig.equals(WireGuardManager.sLastActiveNetworkSignature)) {
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
                WireGuardManager.sNetworkCallback = cb;
            } catch (Throwable t) {
                Log.w(WireGuardManager.TAG, "Could not register network watchdog: " + t.getMessage());
            }
        }
    }

    static void unregisterNetworkWatchdog(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        synchronized (WireGuardManager.WATCHDOG_LOCK) {
            if (WireGuardManager.sRoamingDebounceFuture != null) {
                try {
                    WireGuardManager.sRoamingDebounceFuture.cancel(false);
                } catch (Throwable ignored) {
                }
                WireGuardManager.sRoamingDebounceFuture = null;
            }
            if (WireGuardManager.sNetworkCallback == null) {
                return;
            }
            try {
                Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
                ConnectivityManager cm = (ConnectivityManager) appCtx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(WireGuardManager.sNetworkCallback);
                }
            } catch (Throwable ignored) {
            }
            WireGuardManager.sNetworkCallback = null;
        }
    }

    private static void scheduleDebouncedRoamingEvent(
            final Context appCtx,
            final String moduleApkPath,
            final ClassLoader telegramClassLoader,
            final long delayMs,
            final boolean forceRecovery
    ) {
        synchronized (WireGuardManager.WATCHDOG_LOCK) {
            if (WireGuardManager.sRoamingDebounceFuture != null) {
                try {
                    WireGuardManager.sRoamingDebounceFuture.cancel(false);
                } catch (Throwable ignored) {
                }
            }
            WireGuardManager.sRoamingDebounceFuture = WireGuardManager.getGuardianExecutor().schedule(
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
        if (currentSig.isEmpty() || !hasActiveOsNetwork(appCtx)) {
            if (WireGuardManager.sNetworkLostAtElapsedMs <= 0L) {
                WireGuardManager.sNetworkLostAtElapsedMs = SystemClock.elapsedRealtime();
            }
            releaseForcedContinuityLocks();
            if (telegramClassLoader != null) {
                XposedProxyReflector.pauseTelegramForOffline(telegramClassLoader);
            }
            WgDiagnosticsLog.record("ROAM", "OFFLINE_SLEEP", "released wakelocks & paused tgnet");
            return;
        }

        long now = System.currentTimeMillis();
        boolean sigChanged = !currentSig.equals(WireGuardManager.sLastActiveNetworkSignature);
        if (sigChanged) {
            WireGuardManager.sRoamRetryCount = 0;
        }
        if (!sigChanged && (!forceRecovery || WireGuardManager.sRoamRetryCount >= WireGuardManager.MAX_ROAM_RETRIES || (now - WireGuardManager.sLastRoamingUpdateMs < 10_000L))) {
            return;
        }
        WireGuardManager.sLastRoamingUpdateMs = now;

        try {
            if (!WireGuardManager.isTunnelRunning(appCtx, moduleApkPath)) {
                if (!WireGuardManager.sUserManuallyStopped && (WireGuardManager.isAutoConnectEnabled(appCtx) || !WireGuardManager.sConnectedProfileId.isEmpty())) {
                    WireGuardManager.TunnelConfig cfg = WireGuardManager.loadConfig(appCtx);
                    if (cfg.hasPeerConfigured()) {
                        WireGuardManager.startAndBindProfile(appCtx, cfg, moduleApkPath, telegramClassLoader);
                        return;
                    }
                }
                if (WireGuardManager.isKillSwitchEnabled(appCtx)) {
                    WgProxyBinder.enforceKillSwitchIfDisconnected(appCtx, moduleApkPath, telegramClassLoader);
                }
                return;
            }

            boolean onCellular = isCellularNetworkActive(appCtx);
            WireGuardManager.TunnelConfig activeCfg = WireGuardManager.getConnectedProfile(appCtx, moduleApkPath);
            // Moving onto cellular CGNAT drops inner MTU to 1280 in-place without tearing down sockets.
            if (onCellular && WireGuardManager.getLiveOrCachedTunnelMtu() > 1280) {
                try {
                    Wgbridge.stepDownActiveTunnelMTU(1280L, "cellular_roam");
                    WireGuardManager.sActiveTunnelMtu = 1280;
                } catch (Throwable ignored) {
                }
            }

            if (!Wgbridge.isRunning()) {
                boolean wasOffline = WireGuardManager.sNetworkLostAtElapsedMs > 0L;
                if (WgSharedHubAndVoip.isUsingSharedHub()) {
                    if (WgSharedHubAndVoip.ensureSharedHubResponsiveOrTakeOver(appCtx, moduleApkPath, telegramClassLoader, "roaming_shared_check")) {
                        return;
                    }
                    WireGuardManager.SharedHubSnapshot hubSnap = WireGuardManager.sSharedHub;
                    WgSharedHubAndVoip.Wgp1StatusResult live = WgSharedHubAndVoip.queryLiveStatusWithFallback(appCtx, moduleApkPath, hubSnap.port, hubSnap.pass, null);
                    if (live != null && live.running) {
                        WireGuardManager.sLastActiveNetworkSignature = currentSig;
                        WireGuardManager.sRoamRetryCount = 0;
                        WgProxyBinder.postBindTelegramProxy(appCtx, telegramClassLoader, true, hubSnap.port, WireGuardManager.isRouteCallsEnabled(appCtx), false);
                        if (wasOffline) {
                            WireGuardManager.sNetworkLostAtElapsedMs = 0L;
                            XposedProxyReflector.forceReconnectTelegramAfterOutage(telegramClassLoader);
                            WgTelemetryReporter.flushPendingIfOnlineAsync(appCtx, moduleApkPath);
                        } else {
                            XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, true);
                        }
                        return;
                    }
                    WireGuardManager.clearSharedHubState();
                }
                if (activeCfg != null && activeCfg.hasPeerConfigured()) {
                    WireGuardManager.startAndBindProfile(appCtx, activeCfg, moduleApkPath, telegramClassLoader);
                    if (wasOffline) {
                        WireGuardManager.sNetworkLostAtElapsedMs = 0L;
                        WgTelemetryReporter.flushPendingIfOnlineAsync(appCtx, moduleApkPath);
                    }
                } else if (WireGuardManager.isKillSwitchEnabled(appCtx)) {
                    WgProxyBinder.enforceKillSwitchIfDisconnected(appCtx, moduleApkPath, telegramClassLoader);
                }
                return;
            }

            boolean wasOffline = WireGuardManager.sNetworkLostAtElapsedMs > 0L;
            int activePort = (int) Wgbridge.getActivePort();
            if (activePort <= 0) {
                return;
            }
            // Quiesce locks & tgnet reconnect spins immediately while OS has zero active internet route;
        // ConnectivityManager callbacks resume recovery as soon as connectivity returns.
        if (!hasActiveOsNetwork(appCtx)) {
            releaseForcedContinuityLocks();
            WireGuardManager.sConsecutiveHealthFailures = 0;
            if (WireGuardManager.sNetworkLostAtElapsedMs <= 0L) {
                WireGuardManager.sNetworkLostAtElapsedMs = SystemClock.elapsedRealtime();
            }
            if (telegramClassLoader != null) {
                XposedProxyReflector.pauseTelegramForOffline(telegramClassLoader);
            }
            return;
        }

        acquireForcedContinuityLocks(appCtx);
        syncHostLinkMtuSensor(appCtx);
            syncForegroundKeepaliveService(appCtx, true);

            if (wasOffline) {
                Wgbridge.resetActiveProxyConnections("network_restored");
            }

            boolean hsOk = false;
            String rawEp = WireGuardManager.sWatchdogRawEndpoint;
            if (rawEp != null && !rawEp.isEmpty()) {
                syncEndpointDnsHintsToNative(appCtx, rawEp);
                boolean useDoH = WireGuardManager.isDohEnabled(appCtx);
                String ep = useDoH ? rawEp : WgTunnelProber.preResolveEndpoint(rawEp);
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
                WireGuardManager.sLastActiveNetworkSignature = currentSig;
                WireGuardManager.sRoamRetryCount = 0;
                WireGuardManager.sLastReportedHsHealthy = true;
                try {
                    Wgbridge.calibrateActiveTunnelMTUAsync();
                } catch (Throwable ignored) {
                }
                if (wasOffline) {
                    WireGuardManager.sNetworkLostAtElapsedMs = 0L;
                    WgTelemetryReporter.flushPendingIfOnlineAsync(appCtx, moduleApkPath);
                }
                WgDiagnosticsLog.record("ROAM", "REBOUND", "sig=" + currentSig);
            } else if (WireGuardManager.sRoamRetryCount < WireGuardManager.MAX_ROAM_RETRIES) {
                // Routes may still be settling in netd; bound retries to MAX_ROAM_RETRIES (1.5s, 3.0s, 4.5s)
                WireGuardManager.sRoamRetryCount++;
                WireGuardManager.sLastReportedHsHealthy = false;
                scheduleDebouncedRoamingEvent(appCtx, moduleApkPath, telegramClassLoader, 1500L * WireGuardManager.sRoamRetryCount, true);
                WgDiagnosticsLog.record("ROAM", "RETRY", "attempt=" + WireGuardManager.sRoamRetryCount + " sig=" + currentSig);
            } else {
                WireGuardManager.sLastActiveNetworkSignature = currentSig;
                WireGuardManager.sLastReportedHsHealthy = false;
                WgDiagnosticsLog.record("ROAM", "RETRY_CAP", "exhausted retries sig=" + currentSig);
            }

            int desiredKa = effectiveKeepAlive(appCtx, activeCfg != null ? activeCfg.keepAlive : 20);
            try {
                Wgbridge.setPeerKeepalive(desiredKa);
            } catch (Throwable ignored) {
            }

            WgProxyBinder.postBindTelegramProxy(
                    appCtx,
                    telegramClassLoader,
                    true,
                    activePort,
                    WireGuardManager.isRouteCallsEnabled(appCtx),
                    false
            );
            if (wasOffline && hsOk) {
                XposedProxyReflector.smartRecoverTelegramConnections(telegramClassLoader, true);
            } else {
                XposedProxyReflector.nudgeTelegramConnections(telegramClassLoader, true);
            }
        } catch (Throwable ignored) {
        }
    }
}
