package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import de.robv.android.xposed.XposedHelpers;
import wgbridge.Wgbridge;

/**
 * Telegram ProxySettings reflection builder, mainconfig snapshot/restore, Kill Switch guard,
 * version-upgrade rebind, and host proxy health diagnostics extracted from {@link WireGuardManager}.
 */
final class WgProxyBinder {

    private WgProxyBinder() {
    }

    static void onModuleVersionUpgraded(Context ctx, ClassLoader telegramClassLoader) {
        WireGuardManager.sLastBoundEnabled = null;
        WireGuardManager.sLastBoundPort = -1;
        WireGuardManager.sLastBoundUser = "";
        WireGuardManager.sLastBoundPass = "";
        WireGuardManager.sLastBoundHsHealthy = null;
        WireGuardManager.sLastHardRestartMs = 0L;
        WireGuardManager.sAutoMtuDowngraded = false;
        WireGuardManager.sLastReportedHsHealthy = false;
        WireGuardManager.sRoamRetryCount = 0;

        WireGuardManager.clearSharedHubState();
        WireGuardManager.sCachedExternalSharedPort = -1;
        WireGuardManager.sLastSharedHubCheckMs = 0L;

        if (ctx == null) {
            return;
        }
        WgSyncAndCreds.ensureSessionSocksCredentials(ctx);
        try {
            if (NativeBridgeLoader.isLoaded()) {
                WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
                Wgbridge.setSocksAuth(creds.user, creds.pass);
                Wgbridge.resetSocksAuthRejectCount();
                if (Wgbridge.isRunning()) {
                    int activePort = (int) Wgbridge.getActivePort();
                    if (activePort > 0 && telegramClassLoader != null) {
                        postBindTelegramProxy(ctx, telegramClassLoader, true, activePort, WireGuardManager.isRouteCallsEnabled(ctx), true);
                    }
                    return;
                }
            }
        } catch (Throwable ignored) {
        }

        int sharedPort = WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(ctx);
        if (sharedPort > 0) {
            if (telegramClassLoader != null) {
                postBindTelegramProxy(ctx, telegramClassLoader, true, sharedPort, WireGuardManager.isRouteCallsEnabled(ctx), true);
            }
            return;
        }
        if (WireGuardManager.isKillSwitchEnabled(ctx)) {
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

    static Object buildTelegramProxySettingsObject(ClassLoader cl, int port, String user, String pass) {
        return buildTelegramProxySettingsObjectInternal(cl, "127.0.0.1", port, user, pass);
    }

    static Object buildTelegramProxySettingsObjectInternal(
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
            Context appCtx = WireGuardManager.sSocksPrefsCtx;
            if (cmCls != null && appCtx != null) {
                Class<?> paramProxyCls = null;
                for (Method m : cmCls.getDeclaredMethods()) {
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
                    SharedPreferences mc = appCtx.getSharedPreferences(WireGuardManager.TG_MAINCONFIG, Context.MODE_PRIVATE);
                    for (Method m : paramProxyCls.getDeclaredMethods()) {
                        Class<?>[] pts = m.getParameterTypes();
                        if (Modifier.isStatic(m.getModifiers())
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

    static int getCachedSharedOrFallbackPort(Context context) {
        int hubPort = WireGuardManager.sSharedHub.port;
        if (hubPort > 0) {
            return hubPort;
        }
        if (context != null) {
            try {
                int p = WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(context);
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
     * before native ConnectionsManager reads config - never touches Wgbridge before libgojni loads
     * and never instantiates ConnectionsManager.getInstance() out-of-order on the main thread.
     */
    static void preArmKillSwitchSync(Context context, ClassLoader telegramClassLoader) {
        if (context == null || !WireGuardManager.isKillSwitchEnabled(context)) {
            return;
        }
        try {
            WgSyncAndCreds.ensureSessionSocksCredentials(context);
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
            } else if (WireGuardManager.sSharedHub.port > 0) {
                port = WireGuardManager.sSharedHub.port;
            }
            syncTelegramMainConfigForCalls(context, true, port, true);
        } catch (Throwable ignored) {
        }
    }

    static void reapplyProxyToAccountIfActive(
            Context context,
            ClassLoader telegramClassLoader,
            int accountIdx
    ) {
        reapplyProxyToAccountIfActive(context, telegramClassLoader, accountIdx, false);
    }

    static void reapplyProxyToAccountIfActive(
            Context context,
            ClassLoader telegramClassLoader,
            int accountIdx,
            boolean force
    ) {
        if (context == null || telegramClassLoader == null) {
            return;
        }
        if (!NativeBridgeLoader.isLoaded()) {
            if (WireGuardManager.isKillSwitchEnabled(context)) {
                preArmKillSwitchSync(context, telegramClassLoader);
            }
            return;
        }
        int port = getEffectiveProxyPort(context, null);
        if (port > 0) {
            postBindTelegramProxy(context, telegramClassLoader, true, port, WireGuardManager.isRouteCallsEnabled(context) || WireGuardManager.isKillSwitchEnabled(context), force);
        } else if (WireGuardManager.isKillSwitchEnabled(context)) {
            preArmKillSwitchSync(context, telegramClassLoader);
        }
    }

    /**
     * Engages the loopback SOCKS5 fail-closed Kill Switch guard so Telegram tgnet and VoIP calls
     * cannot fall back to direct ISP sockets while the WireGuard tunnel is disconnected.
     */
    static int enforceKillSwitchIfDisconnected(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) {
        if (context == null || !WireGuardManager.isKillSwitchEnabled(context)) {
            return 0;
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            if (WireGuardManager.isTunnelRunning(context, moduleApkPath)) {
                return WireGuardManager.getActivePort(context, moduleApkPath);
            }
            if (WireGuardManager.sSharedHub.isOwner) {
                WireGuardManager.clearSharedHubState();
                WgSharedHubAndVoip.clearSharedTunnel(context);
            }
            WgSyncAndCreds.ensureSessionSocksCredentials(context);
            WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
            Wgbridge.setSocksAuth(creds.user, creds.pass);
            Wgbridge.resetSocksAuthRejectCount();
            int guardPort = (int) Wgbridge.startKillSwitchGuard();
            if (guardPort > 0 && telegramClassLoader != null) {
                postBindTelegramProxy(context, telegramClassLoader, true, guardPort, true, true);
            }
            return guardPort;
        } catch (Throwable t) {
            Log.w(WireGuardManager.TAG, "KillSwitch guard warning: " + t.getMessage());
            return 0;
        }
    }

    static void releaseKillSwitchGuard(
            Context context,
            String moduleApkPath,
            ClassLoader telegramClassLoader
    ) {
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            Wgbridge.stopKillSwitchGuard();
        } catch (Throwable ignored) {
        }
        if (!WireGuardManager.isTunnelRunning(context, moduleApkPath) && telegramClassLoader != null) {
            postBindTelegramProxy(context, telegramClassLoader, false, 1080, false);
        }
    }

    static boolean isKillSwitchGuardActiveNow(Context context, String moduleApkPath) {
        if (context == null || !WireGuardManager.isKillSwitchEnabled(context)) {
            return false;
        }
        try {
            NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
            return !Wgbridge.isRunning() && Wgbridge.getKillSwitchPort() > 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    static boolean shouldRouteCallsNow(Context context, String moduleApkPath) {
        if (context == null) {
            return false;
        }
        // When Kill Switch is engaged and tunnel is down, force VoIP calls into the fail-closed guard port too!
        if (isKillSwitchGuardActiveNow(context, moduleApkPath)) {
            return true;
        }
        if (!WireGuardManager.isRouteCallsEnabled(context)) {
            return false;
        }
        return WireGuardManager.isTunnelRunning(context, moduleApkPath) && WireGuardManager.getActivePort(context, moduleApkPath) > 0;
    }

    static int getEffectiveProxyPort(Context context, String moduleApkPath) {
        int tunnelPort = WireGuardManager.getActivePort(context, moduleApkPath);
        if (tunnelPort > 0) {
            return tunnelPort;
        }
        if (WireGuardManager.isKillSwitchEnabled(context)) {
            try {
                NativeBridgeLoader.ensureLoaded(context, moduleApkPath);
                return (int) Wgbridge.getKillSwitchPort();
            } catch (Throwable ignored) {
            }
        }
        return 0;
    }

    static void postBindTelegramProxy(
            final Context context,
            final ClassLoader classLoader,
            final boolean enabled,
            final int localPort,
            final boolean routeCalls
    ) {
        postBindTelegramProxy(context, classLoader, enabled, localPort, routeCalls, false);
    }

    static void postBindTelegramProxy(
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
            Handler h = WireGuardManager.getMainHandler();
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
            String socksUser = enabled ? WgSyncAndCreds.getClientSocksUser(context) : "";
            String socksPass = enabled ? WgSyncAndCreds.getActiveSocksPass(context) : "";
            boolean hsHealthy = enabled && WgSharedHubAndVoip.isHandshakeHealthyNow(context, null);

            Boolean prevEnabled = WireGuardManager.sLastBoundEnabled;
            int prevPort = WireGuardManager.sLastBoundPort;
            boolean prevRoute = WireGuardManager.sLastBoundRouteCalls;
            boolean endpointOrAuthChanged = prevEnabled == null
                    || prevEnabled != enabled
                    || prevPort != localPort
                    || prevRoute != routeCalls
                    || !socksUser.equals(WireGuardManager.sLastBoundUser)
                    || !socksPass.equals(WireGuardManager.sLastBoundPass);
            boolean badgeOnlyChanged = !endpointOrAuthChanged
                    && !Boolean.valueOf(hsHealthy).equals(WireGuardManager.sLastBoundHsHealthy);

            syncTelegramMainConfigForCalls(context, enabled, localPort, routeCalls);
            if (!endpointOrAuthChanged && !badgeOnlyChanged && !force) {
                return;
            }
            if (!endpointOrAuthChanged && !force) {
                WireGuardManager.sApplyingProxyBindings = true;
                try {
                    XposedProxyReflector.syncBadgeOnly(classLoader, enabled, localPort, socksUser, socksPass, hsHealthy);
                } finally {
                    WireGuardManager.sApplyingProxyBindings = false;
                }
                WireGuardManager.sLastBoundHsHealthy = hsHealthy;
                return;
            }
            WireGuardManager.sApplyingProxyBindings = true;
            try {
                XposedProxyReflector.apply(classLoader, enabled, localPort, socksUser, socksPass, hsHealthy, true);
            } finally {
                WireGuardManager.sApplyingProxyBindings = false;
            }
            WireGuardManager.sLastBoundEnabled = enabled;
            WireGuardManager.sLastBoundPort = localPort;
            WireGuardManager.sLastBoundRouteCalls = routeCalls;
            WireGuardManager.sLastBoundUser = socksUser;
            WireGuardManager.sLastBoundPass = socksPass;
            WireGuardManager.sLastBoundHsHealthy = hsHealthy;
            WgSyncAndCreds.scheduleHookHeartbeatThrottled(context);
            Log.i(WireGuardManager.TAG, "Applied Telegram proxy & call settings (enabled=" + enabled
                    + ", port=" + localPort + ", routeCalls=" + routeCalls + ", hsHealthy=" + hsHealthy + ")");
        } catch (Throwable t) {
            Log.e(WireGuardManager.TAG, "Failed applying Telegram proxy settings", t);
        }
    }

    static void syncTelegramMainConfigForCalls(
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
            SharedPreferences mc = appCtx.getSharedPreferences(WireGuardManager.TG_MAINCONFIG, Context.MODE_PRIVATE);
            SharedPreferences wgPrefs = WireGuardManager.getPrefs(appCtx);

            if (enabled) {
                if (!wgPrefs.getBoolean(WireGuardManager.KEY_MC_SNAPSHOT_TAKEN, false)) {
                    String curIp = mc.getString("proxy_ip", "");
                    if (!"127.0.0.1".equals(curIp)) {
                        wgPrefs.edit()
                                .putBoolean(WireGuardManager.KEY_MC_SNAPSHOT_TAKEN, true)
                                .putBoolean(WireGuardManager.KEY_MC_PREV_ENABLED, mc.getBoolean("proxy_enabled", false))
                                .putBoolean(WireGuardManager.KEY_MC_PREV_CALLS, mc.getBoolean("proxy_enabled_calls", false))
                                .putString(WireGuardManager.KEY_MC_PREV_IP, curIp != null ? curIp : "")
                                .putInt(WireGuardManager.KEY_MC_PREV_PORT, mc.getInt("proxy_port", 1080))
                                .putString(WireGuardManager.KEY_MC_PREV_USER, mc.getString("proxy_user", ""))
                                .putString(WireGuardManager.KEY_MC_PREV_PASS, mc.getString("proxy_pass", ""))
                                .putString(WireGuardManager.KEY_MC_PREV_SECRET, mc.getString("proxy_secret", ""))
                                .apply();
                    }
                }
                String activeU = WgSyncAndCreds.getClientSocksUser(appCtx);
                String activeP = WgSyncAndCreds.getActiveSocksPass(appCtx);
                mc.edit()
                        .putBoolean("proxy_enabled", true)
                        .putBoolean("proxy_enabled_calls", routeCalls)
                        .putString("proxy_ip", "127.0.0.1")
                        .putInt("proxy_port", localPort)
                        .putString("proxy_user", activeU)
                        .putString("proxy_pass", activeP)
                        .putString("proxy_secret", "")
                        .apply();
                for (int acc = 1; acc < 16; acc++) {
                    String mcName = WireGuardManager.TG_MAINCONFIG + acc;
                    File mcFile = new File(new File(appCtx.getApplicationInfo().dataDir, "shared_prefs"), mcName + ".xml");
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
                if (wgPrefs.getBoolean(WireGuardManager.KEY_MC_SNAPSHOT_TAKEN, false)) {
                    mc.edit()
                            .putBoolean("proxy_enabled", wgPrefs.getBoolean(WireGuardManager.KEY_MC_PREV_ENABLED, false))
                            .putBoolean("proxy_enabled_calls", wgPrefs.getBoolean(WireGuardManager.KEY_MC_PREV_CALLS, false))
                            .putString("proxy_ip", wgPrefs.getString(WireGuardManager.KEY_MC_PREV_IP, ""))
                            .putInt("proxy_port", wgPrefs.getInt(WireGuardManager.KEY_MC_PREV_PORT, 1080))
                            .putString("proxy_user", wgPrefs.getString(WireGuardManager.KEY_MC_PREV_USER, ""))
                            .putString("proxy_pass", wgPrefs.getString(WireGuardManager.KEY_MC_PREV_PASS, ""))
                            .putString("proxy_secret", wgPrefs.getString(WireGuardManager.KEY_MC_PREV_SECRET, ""))
                            .apply();
                    wgPrefs.edit().putBoolean(WireGuardManager.KEY_MC_SNAPSHOT_TAKEN, false).apply();
                } else if ("127.0.0.1".equals(mc.getString("proxy_ip", ""))) {
                    mc.edit()
                            .putBoolean("proxy_enabled", false)
                            .putBoolean("proxy_enabled_calls", false)
                            .apply();
                }
            }
        } catch (Throwable t) {
            Log.w(WireGuardManager.TAG, "syncTelegramMainConfigForCalls warning: " + t.getMessage());
        }
    }

    static String getDiagnosticsInternalStateSummary(Context context) {
        WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
        StringBuilder sb = new StringBuilder();
        sb.append("inFg=").append(WireGuardManager.sAppInForeground)
                .append(", sharedOwner=").append(hub.isOwner)
                .append(", sharedPort=").append(hub.port)
                .append(", activeMtu=").append(WireGuardManager.getLiveOrCachedTunnelMtu())
                .append(", mtuDowngraded=").append(WireGuardManager.sAutoMtuDowngraded)
                .append(", healthFailures=").append(WireGuardManager.sConsecutiveHealthFailures)
                .append(", roamRetries=").append(WireGuardManager.sRoamRetryCount)
                .append(", lastBoundPort=").append(WireGuardManager.sLastBoundPort)
                .append(", lastBoundHsHealthy=").append(WireGuardManager.sLastBoundHsHealthy)
                .append(", lastBoundCalls=").append(WireGuardManager.sLastBoundRouteCalls);
        if (context != null) {
            try {
                sb.append(", failOver=").append(WireGuardManager.isAutoFailoverEnabled(context))
                        .append(", smartKA=").append(WireGuardManager.isSmartKeepaliveEnabled(context))
                        .append(", profiles=").append(WireGuardManager.loadProfiles(context).size());
            } catch (Throwable ignored) {
            }
        }
        return sb.toString();
    }

    static String detectInjectionMode(Context context) {
        if (context == null) {
            return "Unknown";
        }
        String pkg = context.getPackageName();
        if ("org.telegram.wgplus.module".equals(pkg)) {
            return "Standalone_Companion";
        }
        boolean hasLspatchAsset = false;
        try {
            String[] list = context.getAssets().list("lspatch");
            hasLspatchAsset = list != null && list.length > 0;
        } catch (Throwable ignored) {
        }
        if (hasLspatchAsset) {
            try (InputStream is = context.getAssets().open("lspatch/origin.apk")) {
                if (is != null) {
                    return "LSPatch_Portable";
                }
            } catch (Throwable ignored) {
            }
            return "LSPatch_Local";
        }
        try {
            Class.forName("de.robv.android.xposed.XposedBridge", false, WireGuardManager.class.getClassLoader());
            return "LSPosed";
        } catch (Throwable ignored) {
        }
        return "Hooked_Other";
    }

    static String inspectTelegramProxyHealthSummary(Context context) {
        ClassLoader cl = WireGuardManager.sDiagnosticHostClassLoader != null
                ? WireGuardManager.sDiagnosticHostClassLoader
                : (context != null ? context.getClassLoader() : null);
        if (cl == null) {
            return "n/a";
        }
        Class<?> connectionsManagerClass = XposedHelpers.findClassIfExists("org.telegram.tgnet.ConnectionsManager", cl);
        if (connectionsManagerClass == null) {
            return "n/a (standalone)";
        }
        StringBuilder sb = new StringBuilder();
        try {
            Class<?> userConfigClass = XposedHelpers.findClassIfExists("org.telegram.messenger.UserConfig", cl);
            int maxAcc = XposedProxyReflector.resolveMaxAccountCount(cl);
            int activeCount = 0;
            for (int acc = 0; acc < maxAcc; acc++) {
                if (!XposedProxyReflector.isAccountActivated(userConfigClass, acc)) {
                    continue;
                }
                activeCount++;
                String stLabel = "?";
                try {
                    Object inst = XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "getInstance",
                            new Class<?>[]{int.class},
                            acc
                    );
                    if (inst != null) {
                        int st = (Integer) XposedHelpers.callMethod(inst, "getConnectionState");
                        if (st == 1) {
                            stLabel = "Connecting(1)";
                        } else if (st == 2) {
                            stLabel = "Updating(2)";
                        } else if (st == 3) {
                            stLabel = "Connected(3)";
                        } else if (st == 4) {
                            stLabel = "WaitNet(4)";
                        } else if (st == 5) {
                            stLabel = "ConnProxy(5)";
                        } else {
                            stLabel = String.valueOf(st);
                        }
                    }
                } catch (Throwable ignored) {
                }
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append("acc").append(acc).append("=").append(stLabel);
            }
            if (activeCount == 0) {
                sb.append("no_activated_slots");
            }
        } catch (Throwable t) {
            sb.append("slots_err");
        }
        try {
            Class<?> sharedConfigClass = XposedHelpers.findClassIfExists("org.telegram.messenger.SharedConfig", cl);
            if (sharedConfigClass != null) {
                boolean pEnabled = XposedHelpers.getStaticBooleanField(sharedConfigClass, "proxyEnabled");
                boolean pCalls = XposedHelpers.getStaticBooleanField(sharedConfigClass, "proxyEnabledCalls");
                Object curProxy = XposedHelpers.getStaticObjectField(sharedConfigClass, "currentProxy");
                String addr = curProxy != null ? XposedProxyReflector.extractProxyInfoAddress(curProxy) : "none";
                int port = curProxy != null ? XposedProxyReflector.extractProxyInfoPort(curProxy) : 0;
                boolean avail = false;
                boolean checking = false;
                if (curProxy != null) {
                    try {
                        avail = XposedHelpers.getBooleanField(curProxy, "available");
                        checking = XposedHelpers.getBooleanField(curProxy, "checking");
                    } catch (Throwable ignored) {
                    }
                }
                String safeAddr = "127.0.0.1".equals(addr) || "none".equals(addr) ? addr : "[NON_LOOPBACK]";
                sb.append(" | SharedConfig(enabled=").append(pEnabled)
                        .append(", calls=").append(pCalls)
                        .append(", addr=").append(safeAddr)
                        .append(":").append(port)
                        .append(", avail=").append(avail)
                        .append(", chk=").append(checking)
                        .append(")");
            }
        } catch (Throwable ignored) {
        }
        return sb.toString();
    }
}
