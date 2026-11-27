package org.telegram.wgplus.module;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Process;
import android.provider.Settings;
import android.util.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Coordinates the Sovereign Continuity stack across built-in Wireless ADB, self-privileged
 * Binder elevation, detached {@code wgplus_daemon}, silent {@link KeepaliveBridgeListenerService}
 * capability binding, and OS Doze/MARs/Data-Saver exemptions so Telegram stays continuously
 * responsive with zero persistent notifications and zero "1 active app" banners.
 */
public final class ContinuityBridgeManager {

    private static final String TAG = "WGPlusContinuity";
    private static final String PREFS_NAME = "wg_plus_module_continuity_prefs";
    private static final String KEY_STEALTH_HYBRID_ENABLED = "stealth_hybrid_enabled";
    private static final String KEY_WANTED_PACKAGES = "wanted_telegram_packages";

    public static final String TELEGRAM_KEEPALIVE_SERVICE = "org.telegram.messenger.NotificationsService";
    private static final String PKG_PLUS = "org.telegram.plus";
    private static final String PKG_OFFICIAL = "org.telegram.messenger";
    private static final String PKG_GOLD = "org.telegram.gold";
    static final List<String> DEFAULT_TARGET_PACKAGES = Arrays.asList(
            PKG_PLUS,
            PKG_OFFICIAL,
            PKG_GOLD,
            "org.telegram.messenger.beta",
            "org.telegram.messenger.web",
            "ir.ilmili.telegraph",
            "ir.p2021.telegraph",
            "com.radolyn.ayugram",
            "org.thunderdog.challegram",
            "xyz.nextalone.nagram",
            "uz.unnarsx.cherrygram",
            "tw.nekomimi.nekogram",
            "nekox.messenger",
            "org.forkgram.messenger",
            "org.forkclient.messenger",
            "com.exteragram.messenger",
            "it.octogram.android",
            "com.iMe.android",
            "app.nicegram"
    );

    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor();
    private static final ConcurrentHashMap<Integer, Long> sElevatedPids = new ConcurrentHashMap<>();
    private static volatile boolean sExemptionsAppliedOnce;
    private static final AtomicBoolean sWifiCallbackRegistered = new AtomicBoolean(false);

    public enum ContinuityTier {
        HYBRID_FULL,
        PRIVILEGED_ONLY,
        LISTENER_BOOT_GUARD,
        STANDARD_FGS
    }

    public static final class StealthSnapshot {
        public final boolean stealthHybridEnabled;
        public final boolean forcedImportant;
        public final boolean listenerEnabled;
        public final boolean listenerConnected;
        public final boolean stealthProtected;
        public final ContinuityTier tier;
        public final boolean rootActive;
        public final boolean selfPrivileged;
        public final boolean daemonActive;
        public final boolean builtinAdbPaired;

        public StealthSnapshot(
                boolean stealthHybridEnabled,
                boolean forcedImportant,
                boolean listenerEnabled,
                boolean listenerConnected,
                boolean stealthProtected,
                ContinuityTier tier,
                boolean rootActive,
                boolean selfPrivileged,
                boolean daemonActive,
                boolean builtinAdbPaired
        ) {
            this.stealthHybridEnabled = stealthHybridEnabled;
            this.forcedImportant = forcedImportant;
            this.listenerEnabled = listenerEnabled;
            this.listenerConnected = listenerConnected;
            this.stealthProtected = stealthProtected;
            this.tier = tier;
            this.rootActive = rootActive;
            this.selfPrivileged = selfPrivileged;
            this.daemonActive = daemonActive;
            this.builtinAdbPaired = builtinAdbPaired;
        }
    }

    private ContinuityBridgeManager() {
    }

    private static SharedPreferences prefs(Context context) {
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        return appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static boolean isStealthHybridEnabled(Context context) {
        if (context == null) {
            return true;
        }
        return prefs(context).getBoolean(KEY_STEALTH_HYBRID_ENABLED, true);
    }

    public static void setStealthHybridEnabled(Context context, boolean enabled) {
        if (context == null) {
            return;
        }
        prefs(context).edit().putBoolean(KEY_STEALTH_HYBRID_ENABLED, enabled).apply();
        KeepaliveBridgeListenerService.syncBindings();
        if (!enabled) {
            releaseElevatedPids(context);
        } else {
            activateHybridAsync(context, null);
        }
        notifyInstalledTelegramServices(context);
    }

    public static List<String> getInstalledTargetPackages(Context context) {
        if (context == null) {
            return Collections.emptyList();
        }
        ArrayList<String> installed = new ArrayList<>();
        for (String pkg : DEFAULT_TARGET_PACKAGES) {
            if (isPackageInstalled(context, pkg) && !installed.contains(pkg)) {
                installed.add(pkg);
            }
        }
        return installed;
    }

    public static Set<String> getWantedPackages(Context context) {
        if (context == null) {
            return Collections.emptySet();
        }
        Set<String> stored = prefs(context).getStringSet(KEY_WANTED_PACKAGES, null);
        HashSet<String> result = new HashSet<>();
        if (stored != null && !stored.isEmpty()) {
            result.addAll(stored);
        }
        for (String pkg : DEFAULT_TARGET_PACKAGES) {
            if (isPackageInstalled(context, pkg)) {
                result.add(pkg);
            }
        }
        return result;
    }

    public static void markPackageAwakeWanted(Context context, String pkg, boolean wanted) {
        if (context == null || pkg == null || pkg.isEmpty()) {
            return;
        }
        HashSet<String> set = new HashSet<>(prefs(context).getStringSet(KEY_WANTED_PACKAGES, new HashSet<>()));
        boolean changed;
        if (wanted) {
            changed = set.add(pkg);
        } else {
            changed = set.remove(pkg);
        }
        if (changed) {
            prefs(context).edit().putStringSet(KEY_WANTED_PACKAGES, set).apply();
        }
    }

    public static boolean isPackageInstalled(Context context, String pkg) {
        if (context == null || pkg == null || pkg.isEmpty()) {
            return false;
        }
        try {
            PackageManager pm = context.getPackageManager();
            if (pm == null) {
                return false;
            }
            pm.getPackageInfo(pkg, 0);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static ContinuityTier computeContinuityTier(
            boolean stealthEnabled,
            boolean privilegedElevated,
            boolean listenerActive
    ) {
        if (!stealthEnabled) {
            return ContinuityTier.STANDARD_FGS;
        }
        if (privilegedElevated && listenerActive) {
            return ContinuityTier.HYBRID_FULL;
        }
        if (privilegedElevated) {
            return ContinuityTier.PRIVILEGED_ONLY;
        }
        if (listenerActive) {
            return ContinuityTier.LISTENER_BOOT_GUARD;
        }
        return ContinuityTier.STANDARD_FGS;
    }

    public static boolean isWirelessAdbUsable(Context context) {
        if (context == null || !BuiltinAdbKeyManager.isPaired(context)) {
            return false;
        }
        try {
            boolean devEnabled = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                    0
            ) == 1;
            if (!devEnabled) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                boolean wifiAdb = Settings.Global.getInt(
                        context.getContentResolver(),
                        "adb_wifi_enabled",
                        0
                ) == 1;
                return wifiAdb
                        || PrivilegeBridge.hasSelfWriteSecureSettingsPermission(context)
                        || BuiltinAdbKeyManager.getDynamicTcpPort(context) == 5555;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static String getActivePrivilegeMode(Context context) {
        if (context != null && PrivilegeBridge.isStandaloneDaemonAlive(context)) {
            return PrivilegeBridge.getLastDaemonUid() == 0 ? "ROOT_DAEMON" : "WGPLUS_DAEMON";
        }
        if (PrivilegeBridge.isRootAvailablePassive(context)) {
            return "ROOT";
        }
        boolean usableAdb = isWirelessAdbUsable(context);
        if (context != null && PrivilegeBridge.hasSelfProcessLimitPermission(context)) {
            return usableAdb ? "BUILTIN_ADB_SELF" : "SELF_PRIVILEGED";
        }
        if (usableAdb) {
            return "BUILTIN_ADB";
        }
        if (KeepaliveBridgeListenerService.isConnected()
                || (context != null && KeepaliveBridgeListenerService.isNotificationListenerEnabled(context))) {
            return "BOOT_GUARD";
        }
        return "STANDARD";
    }

    public static boolean hasAnyPrivilegeBackend(Context context) {
        if (PrivilegeBridge.isRootAvailablePassive(context)) {
            return true;
        }
        if (context == null) {
            return false;
        }
        return PrivilegeBridge.hasSelfProcessLimitPermission(context)
                || PrivilegeBridge.isStandaloneDaemonAlive(context)
                || isWirelessAdbUsable(context)
                || PrivilegeBridge.hasRootBinaryOnDisk();
    }

    public static void registerPassiveWifiRecovery(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return;
        }
        if (!sWifiCallbackRegistered.compareAndSet(false, true)) {
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        try {
            ConnectivityManager cm = (ConnectivityManager) appCtx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                sWifiCallbackRegistered.set(false);
                return;
            }
            NetworkRequest req = new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .build();
            cm.registerNetworkCallback(req, new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    if (!isStealthHybridEnabled(appCtx)) {
                        return;
                    }
                    if (!isWirelessAdbUsable(appCtx) && !PrivilegeBridge.isRootAvailablePassive(appCtx)) {
                        return;
                    }
                    WORKER.execute(() -> {
                        try {
                            PrivilegeBridge.resetDaemonBootstrapBackoff();
                            if (!PrivilegeBridge.isStandaloneDaemonAlive(appCtx)) {
                                if (PrivilegeBridge.isRootAvailablePassive(appCtx)) {
                                    List<String> pkgs = collectInstalledTargetsAndModule(appCtx);
                                    String listenerComp = appCtx.getPackageName() + "/" + KeepaliveBridgeListenerService.class.getName();
                                    PrivilegeBridge.bootstrapRootOncePerBoot(appCtx, pkgs, listenerComp, true);
                                } else {
                                    WgAdbConnectionManager.getInstance(appCtx).bootstrapSovereignShell(true);
                                }
                            }
                        } catch (Throwable ignored) {
                        }
                    });
                }
            });
        } catch (Throwable t) {
            sWifiCallbackRegistered.set(false);
            Log.w(TAG, "registerPassiveWifiRecovery warning: " + t.getMessage());
        }
    }

    public static void onDeviceBootOrPackageUpdated(Context context) {
        if (context == null) {
            return;
        }
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        registerPassiveWifiRecovery(appCtx);
        if (!isStealthHybridEnabled(appCtx)) {
            return;
        }
        activateHybridOneTap(appCtx);
    }

    public static StealthSnapshot ensureStealthProtection(
            Context context,
            String targetPkg,
            int targetPid,
            boolean wantsAlwaysAwake
    ) {
        if (context == null) {
            return new StealthSnapshot(true, false, false, false, false, ContinuityTier.STANDARD_FGS, false, false, false, false);
        }
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        boolean stealthEnabled = isStealthHybridEnabled(appCtx);

        if (targetPkg != null && !targetPkg.isEmpty()) {
            markPackageAwakeWanted(appCtx, targetPkg, wantsAlwaysAwake);
        }

        boolean listenerEnabled = KeepaliveBridgeListenerService.isNotificationListenerEnabled(appCtx);
        if (!listenerEnabled && stealthEnabled && wantsAlwaysAwake) {
            PrivilegeBridge.selfHealNotificationListener(appCtx);
            listenerEnabled = KeepaliveBridgeListenerService.isNotificationListenerEnabled(appCtx);
        }
        boolean listenerConnected = KeepaliveBridgeListenerService.isConnected();

        boolean daemonAlive = PrivilegeBridge.isStandaloneDaemonAlive(appCtx);
        boolean rootReady = PrivilegeBridge.isRootAvailablePassive(appCtx);
        boolean selfPrivileged = PrivilegeBridge.hasSelfProcessLimitPermission(appCtx);
        boolean builtinAdbPaired = isWirelessAdbUsable(appCtx);
        boolean privilegeReady = daemonAlive || rootReady || selfPrivileged || builtinAdbPaired;

        if (!stealthEnabled || !wantsAlwaysAwake) {
            if (targetPid > 0 && privilegeReady && sElevatedPids.containsKey(targetPid)) {
                PrivilegeBridge.applyProcessImportant(appCtx, targetPid, false);
                sElevatedPids.remove(targetPid);
            }
            KeepaliveBridgeListenerService.syncBindings();
            return new StealthSnapshot(
                    stealthEnabled,
                    false,
                    listenerEnabled,
                    listenerConnected,
                    false,
                    ContinuityTier.STANDARD_FGS,
                    rootReady,
                    selfPrivileged,
                    daemonAlive,
                    builtinAdbPaired
            );
        }

        boolean forcedImportant = false;
        if (privilegeReady) {
            ensureOsExemptionsAsync(appCtx, true);
            if ((rootReady || builtinAdbPaired) && !daemonAlive) {
                PrivilegeBridge.bootstrapStandaloneDaemonAsync(appCtx, new ArrayList<>(getWantedPackages(appCtx)));
            }
            if (targetPid > 0) {
                forcedImportant = PrivilegeBridge.applyProcessImportant(appCtx, targetPid, true);
                if (forcedImportant) {
                    sElevatedPids.put(targetPid, System.currentTimeMillis());
                }
            }
            if (!listenerConnected) {
                PrivilegeBridge.applyProcessImportant(appCtx, Process.myPid(), true);
            }
        }

        boolean listenerBound = KeepaliveBridgeListenerService.syncBindings()
                && (targetPkg == null || targetPkg.isEmpty() || KeepaliveBridgeListenerService.isBoundForPackage(targetPkg));

        ContinuityTier tier = computeContinuityTier(true, forcedImportant, listenerBound || listenerConnected);
        boolean stealthProtected = tier != ContinuityTier.STANDARD_FGS;
        return new StealthSnapshot(
                true,
                forcedImportant,
                listenerEnabled,
                listenerConnected,
                stealthProtected,
                tier,
                rootReady,
                selfPrivileged,
                daemonAlive,
                builtinAdbPaired
        );
    }

    public static StealthSnapshot captureStatusSnapshot(Context context) {
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        boolean stealthEnabled = isStealthHybridEnabled(appCtx);
        boolean listenerEnabled = KeepaliveBridgeListenerService.isNotificationListenerEnabled(appCtx);
        boolean listenerConnected = KeepaliveBridgeListenerService.isConnected();

        boolean daemonAlive = PrivilegeBridge.isStandaloneDaemonAlive(appCtx);
        boolean rootReady = PrivilegeBridge.isRootAvailablePassive(appCtx);
        boolean selfPrivileged = PrivilegeBridge.hasSelfProcessLimitPermission(appCtx);
        boolean builtinAdbPaired = isWirelessAdbUsable(appCtx);
        boolean sovereignReady = daemonAlive || rootReady || selfPrivileged;
        boolean forcedImportant = sovereignReady && (!sElevatedPids.isEmpty() || daemonAlive || selfPrivileged);
        ContinuityTier tier = computeContinuityTier(stealthEnabled, sovereignReady, listenerConnected || listenerEnabled);
        boolean stealthProtected = tier != ContinuityTier.STANDARD_FGS;
        return new StealthSnapshot(
                stealthEnabled,
                forcedImportant,
                listenerEnabled,
                listenerConnected,
                stealthProtected,
                tier,
                rootReady,
                selfPrivileged,
                daemonAlive,
                builtinAdbPaired
        );
    }

    public static StealthSnapshot activateHybridOneTap(Context context) {
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        prefs(appCtx).edit().putBoolean(KEY_STEALTH_HYBRID_ENABLED, true).apply();
        registerPassiveWifiRecovery(appCtx);

        boolean daemonAlive = PrivilegeBridge.isStandaloneDaemonAlive(appCtx);
        boolean selfPrivileged = PrivilegeBridge.hasSelfProcessLimitPermission(appCtx);
        boolean builtinAdbPaired = isWirelessAdbUsable(appCtx);
        List<String> pkgs = collectInstalledTargetsAndModule(appCtx);
        String listenerComp = appCtx.getPackageName() + "/" + KeepaliveBridgeListenerService.class.getName();

        boolean rootBootstrapped = false;
        if (!daemonAlive && !builtinAdbPaired && PrivilegeBridge.hasRootBinaryOnDisk()) {
            // Single consolidated su invocation once per boot (starts root daemon + exemptions)
            rootBootstrapped = PrivilegeBridge.bootstrapRootOncePerBoot(appCtx, pkgs, listenerComp, true);
            daemonAlive = PrivilegeBridge.isStandaloneDaemonAlive(appCtx);
        }

        boolean rootReady = rootBootstrapped || PrivilegeBridge.isRootAvailablePassive(appCtx);
        if (daemonAlive || selfPrivileged || builtinAdbPaired || rootReady) {
            PrivilegeBridge.selfHealNotificationListener(appCtx);
            if (!PrivilegeBridge.hasExemptionsAppliedThisBoot(appCtx)) {
                sExemptionsAppliedOnce = PrivilegeBridge.applyOsContinuityExemptions(appCtx, pkgs, listenerComp, true);
            } else {
                sExemptionsAppliedOnce = true;
            }

            // Boost processes ONLY via daemon/self Binder - never spawn per-package su calls!
            if (daemonAlive || selfPrivileged) {
                for (String pkg : getWantedPackages(appCtx)) {
                    List<Integer> pids = resolveRunningPidsViaDaemon(appCtx, pkg);
                    for (int pid : pids) {
                        if (PrivilegeBridge.applyProcessImportant(appCtx, pid, true)) {
                            sElevatedPids.put(pid, System.currentTimeMillis());
                        }
                    }
                }
            }
            if (!KeepaliveBridgeListenerService.isConnected()) {
                PrivilegeBridge.applyProcessImportant(appCtx, Process.myPid(), true);
            }
        }

        KeepaliveBridgeListenerService.syncBindings();
        notifyInstalledTelegramServices(appCtx);
        return captureStatusSnapshot(appCtx);
    }

    public static void activateHybridAsync(Context context, Runnable onDone) {
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        WORKER.execute(() -> {
            try {
                activateHybridOneTap(appCtx);
            } catch (Throwable t) {
                Log.w(TAG, "activateHybridAsync warning: " + t.getMessage());
            } finally {
                if (onDone != null) {
                    onDone.run();
                }
            }
        });
    }

    public static void onListenerConnectedAsync(Context context) {
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        WORKER.execute(() -> {
            try {
                if (isStealthHybridEnabled(appCtx)) {
                    if (hasAnyPrivilegeBackend(appCtx)) {
                        activateHybridOneTap(appCtx);
                    } else {
                        notifyInstalledTelegramServices(appCtx);
                    }
                }
            } catch (Throwable ignored) {
            }
        });
    }

    private static void ensureOsExemptionsAsync(Context appCtx, boolean grantListener) {
        if (sExemptionsAppliedOnce) {
            return;
        }
        sExemptionsAppliedOnce = true;
        WORKER.execute(() -> {
            try {
                List<String> pkgs = collectInstalledTargetsAndModule(appCtx);
                String listenerComp = appCtx.getPackageName() + "/" + KeepaliveBridgeListenerService.class.getName();
                PrivilegeBridge.applyOsContinuityExemptions(appCtx, pkgs, listenerComp, grantListener);
            } catch (Throwable ignored) {
            }
        });
    }

    private static void releaseElevatedPids(Context appCtx) {
        WORKER.execute(() -> {
            for (Integer pid : new ArrayList<>(sElevatedPids.keySet())) {
                if (pid != null && pid > 0) {
                    PrivilegeBridge.applyProcessImportant(appCtx, pid, false);
                }
                sElevatedPids.remove(pid);
            }
        });
    }

    private static List<String> collectInstalledTargetsAndModule(Context context) {
        ArrayList<String> pkgs = new ArrayList<>();
        pkgs.add(context.getPackageName());
        for (String p : DEFAULT_TARGET_PACKAGES) {
            if (isPackageInstalled(context, p) && !pkgs.contains(p)) {
                pkgs.add(p);
            }
        }
        return pkgs;
    }

    private static List<Integer> resolveRunningPidsViaDaemon(Context context, String pkg) {
        ArrayList<Integer> pids = new ArrayList<>();
        if (context == null || !DaemonProcessHelper.isSafeToken(pkg) || !PrivilegeBridge.isStandaloneDaemonAlive(context)) {
            return pids;
        }
        PrivilegeBridge.ShellResult res = PrivilegeBridge.runShellCommand(context, "pidof " + pkg, 3000);
        if (!res.output.isEmpty()) {
            String[] parts = res.output.trim().split("\\s+");
            for (String p : parts) {
                try {
                    int val = Integer.parseInt(p.trim());
                    if (val > 0) {
                        pids.add(val);
                    }
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return pids;
    }

    private static void notifyInstalledTelegramServices(Context context) {
        for (String pkg : getWantedPackages(context)) {
            if (!isPackageInstalled(context, pkg)) {
                continue;
            }
            try {
                Intent sync = new Intent(WireGuardManager.ACTION_SYNC_CONTINUITY);
                sync.setClassName(pkg, TELEGRAM_KEEPALIVE_SERVICE);
                context.startService(sync);
            } catch (Throwable ignored) {
                // Target may currently be stopped or restricted from background startService; harmless.
            }
        }
    }
}
