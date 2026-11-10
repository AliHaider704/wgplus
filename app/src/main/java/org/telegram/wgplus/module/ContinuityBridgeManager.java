package org.telegram.wgplus.module;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Process;
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

/**
 * Coordinates the non-root Hybrid Continuity stack across Shizuku (uid=2000), silent
 * {@link KeepaliveBridgeListenerService} capability binding, and OS Doze/MARs/Data-Saver
 * exemptions so Telegram stays continuously responsive with zero persistent notifications
 * and zero "1 active app" Samsung Quick Panel banners.
 */
public final class ContinuityBridgeManager {

    private static final String TAG = "WGPlusContinuity";
    private static final String PREFS_NAME = "wg_plus_module_continuity_prefs";
    private static final String KEY_STEALTH_HYBRID_ENABLED = "stealth_hybrid_enabled";
    private static final String KEY_WANTED_PACKAGES = "wanted_telegram_packages";

    public static final String TELEGRAM_KEEPALIVE_SERVICE = "org.telegram.messenger.NotificationsService";
    private static final String PKG_PLUS = "org.telegram.plus";
    private static final String PKG_OFFICIAL = "org.telegram.messenger";
    private static final List<String> DEFAULT_TARGET_PACKAGES = Arrays.asList(
            PKG_PLUS,
            PKG_OFFICIAL,
            "org.telegram.messenger.beta",
            "org.telegram.messenger.web"
    );

    private static final ExecutorService WORKER = Executors.newSingleThreadExecutor();
    private static final ConcurrentHashMap<Integer, Long> sElevatedPids = new ConcurrentHashMap<>();
    private static volatile boolean sExemptionsAppliedOnce;

    public enum ContinuityTier {
        HYBRID_FULL,
        SHIZUKU_ONLY,
        LISTENER_BOOT_GUARD,
        STANDARD_FGS
    }

    public static final class StealthSnapshot {
        public final boolean stealthHybridEnabled;
        public final boolean shizukuInstalled;
        public final boolean shizukuRunning;
        public final boolean shizukuGranted;
        public final boolean forcedImportant;
        public final boolean listenerEnabled;
        public final boolean listenerConnected;
        public final boolean stealthProtected;
        public final ContinuityTier tier;

        public StealthSnapshot(
                boolean stealthHybridEnabled,
                boolean shizukuInstalled,
                boolean shizukuRunning,
                boolean shizukuGranted,
                boolean forcedImportant,
                boolean listenerEnabled,
                boolean listenerConnected,
                boolean stealthProtected,
                ContinuityTier tier
        ) {
            this.stealthHybridEnabled = stealthHybridEnabled;
            this.shizukuInstalled = shizukuInstalled;
            this.shizukuRunning = shizukuRunning;
            this.shizukuGranted = shizukuGranted;
            this.forcedImportant = forcedImportant;
            this.listenerEnabled = listenerEnabled;
            this.listenerConnected = listenerConnected;
            this.stealthProtected = stealthProtected;
            this.tier = tier;
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

    public static Set<String> getWantedPackages(Context context) {
        if (context == null) {
            return Collections.emptySet();
        }
        Set<String> stored = prefs(context).getStringSet(KEY_WANTED_PACKAGES, null);
        HashSet<String> result = new HashSet<>();
        if (stored != null && !stored.isEmpty()) {
            result.addAll(stored);
        } else {
            if (isPackageInstalled(context, PKG_PLUS)) {
                result.add(PKG_PLUS);
            }
            if (isPackageInstalled(context, PKG_OFFICIAL)) {
                result.add(PKG_OFFICIAL);
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
            boolean shizukuElevated,
            boolean listenerActive
    ) {
        if (!stealthEnabled) {
            return ContinuityTier.STANDARD_FGS;
        }
        if (shizukuElevated && listenerActive) {
            return ContinuityTier.HYBRID_FULL;
        }
        if (shizukuElevated) {
            return ContinuityTier.SHIZUKU_ONLY;
        }
        if (listenerActive) {
            return ContinuityTier.LISTENER_BOOT_GUARD;
        }
        return ContinuityTier.STANDARD_FGS;
    }

    public static StealthSnapshot ensureStealthProtection(
            Context context,
            String targetPkg,
            int targetPid,
            boolean wantsAlwaysAwake
    ) {
        if (context == null) {
            return new StealthSnapshot(true, false, false, false, false, false, false, false, ContinuityTier.STANDARD_FGS);
        }
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        boolean stealthEnabled = isStealthHybridEnabled(appCtx);

        if (targetPkg != null && !targetPkg.isEmpty()) {
            markPackageAwakeWanted(appCtx, targetPkg, wantsAlwaysAwake);
        }

        boolean shizukuInstalled = ShizukuBridge.isShizukuInstalled(appCtx);
        boolean shizukuRunning = shizukuInstalled && ShizukuBridge.isRunning(appCtx);
        boolean shizukuGranted = shizukuRunning && ShizukuBridge.hasPermission(appCtx);
        boolean listenerEnabled = KeepaliveBridgeListenerService.isNotificationListenerEnabled(appCtx);
        boolean listenerConnected = KeepaliveBridgeListenerService.isConnected();

        if (!stealthEnabled || !wantsAlwaysAwake) {
            if (targetPid > 0 && shizukuGranted && sElevatedPids.containsKey(targetPid)) {
                ShizukuBridge.applyProcessImportant(appCtx, targetPid, false);
                sElevatedPids.remove(targetPid);
            }
            KeepaliveBridgeListenerService.syncBindings();
            return new StealthSnapshot(
                    stealthEnabled,
                    shizukuInstalled,
                    shizukuRunning,
                    shizukuGranted,
                    false,
                    listenerEnabled,
                    listenerConnected,
                    false,
                    ContinuityTier.STANDARD_FGS
            );
        }

        boolean forcedImportant = false;
        if (shizukuGranted) {
            ensureOsExemptionsAsync(appCtx, true);
            if (targetPid > 0) {
                forcedImportant = ShizukuBridge.applyProcessImportant(appCtx, targetPid, true);
                if (forcedImportant) {
                    sElevatedPids.put(targetPid, System.currentTimeMillis());
                }
            }
            // Keep our own companion process elevated while holding the death-linked binder token
            if (!listenerConnected) {
                ShizukuBridge.applyProcessImportant(appCtx, Process.myPid(), true);
            }
        }

        boolean listenerBound = KeepaliveBridgeListenerService.syncBindings()
                && (targetPkg == null || targetPkg.isEmpty() || KeepaliveBridgeListenerService.isBoundForPackage(targetPkg));

        ContinuityTier tier = computeContinuityTier(true, forcedImportant, listenerBound || listenerConnected);
        boolean stealthProtected = tier != ContinuityTier.STANDARD_FGS;
        return new StealthSnapshot(
                true,
                shizukuInstalled,
                shizukuRunning,
                shizukuGranted,
                forcedImportant,
                listenerEnabled,
                listenerConnected,
                stealthProtected,
                tier
        );
    }

    public static StealthSnapshot captureStatusSnapshot(Context context) {
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        boolean stealthEnabled = isStealthHybridEnabled(appCtx);
        boolean shizukuInstalled = ShizukuBridge.isShizukuInstalled(appCtx);
        boolean shizukuRunning = shizukuInstalled && ShizukuBridge.isRunning(appCtx);
        boolean shizukuGranted = shizukuRunning && ShizukuBridge.hasPermission(appCtx);
        boolean listenerEnabled = KeepaliveBridgeListenerService.isNotificationListenerEnabled(appCtx);
        boolean listenerConnected = KeepaliveBridgeListenerService.isConnected();

        boolean forcedImportant = shizukuGranted && !sElevatedPids.isEmpty();
        ContinuityTier tier = computeContinuityTier(stealthEnabled, forcedImportant || shizukuGranted, listenerConnected || listenerEnabled);
        boolean stealthProtected = tier != ContinuityTier.STANDARD_FGS;
        return new StealthSnapshot(
                stealthEnabled,
                shizukuInstalled,
                shizukuRunning,
                shizukuGranted,
                forcedImportant,
                listenerEnabled,
                listenerConnected,
                stealthProtected,
                tier
        );
    }

    public static StealthSnapshot activateHybridOneTap(Context context) {
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        prefs(appCtx).edit().putBoolean(KEY_STEALTH_HYBRID_ENABLED, true).apply();

        boolean shizukuInstalled = ShizukuBridge.isShizukuInstalled(appCtx);
        boolean shizukuRunning = shizukuInstalled && ShizukuBridge.isRunning(appCtx);
        boolean shizukuGranted = shizukuRunning && ShizukuBridge.hasPermission(appCtx);

        if (shizukuGranted) {
            List<String> pkgs = collectInstalledTargetsAndModule(appCtx);
            String listenerComp = appCtx.getPackageName() + "/" + KeepaliveBridgeListenerService.class.getName();
            sExemptionsAppliedOnce = ShizukuBridge.applyOsContinuityExemptions(appCtx, pkgs, listenerComp, true);

            for (String pkg : getWantedPackages(appCtx)) {
                List<Integer> pids = resolveRunningPids(appCtx, pkg);
                for (int pid : pids) {
                    if (ShizukuBridge.applyProcessImportant(appCtx, pid, true)) {
                        sElevatedPids.put(pid, System.currentTimeMillis());
                    }
                }
            }
            if (!KeepaliveBridgeListenerService.isConnected()) {
                ShizukuBridge.applyProcessImportant(appCtx, Process.myPid(), true);
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
                    if (ShizukuBridge.hasPermission(appCtx)) {
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
                ShizukuBridge.applyOsContinuityExemptions(appCtx, pkgs, listenerComp, grantListener);
            } catch (Throwable ignored) {
            }
        });
    }

    private static void releaseElevatedPids(Context appCtx) {
        WORKER.execute(() -> {
            for (Integer pid : new ArrayList<>(sElevatedPids.keySet())) {
                if (pid != null && pid > 0) {
                    ShizukuBridge.applyProcessImportant(appCtx, pid, false);
                }
                sElevatedPids.remove(pid);
            }
        });
    }

    private static List<String> collectInstalledTargetsAndModule(Context context) {
        ArrayList<String> pkgs = new ArrayList<>();
        pkgs.add(context.getPackageName());
        if (isPackageInstalled(context, ShizukuBridge.SHIZUKU_PACKAGE)) {
            pkgs.add(ShizukuBridge.SHIZUKU_PACKAGE);
        }
        for (String p : DEFAULT_TARGET_PACKAGES) {
            if (isPackageInstalled(context, p) && !pkgs.contains(p)) {
                pkgs.add(p);
            }
        }
        return pkgs;
    }

    private static List<Integer> resolveRunningPids(Context context, String pkg) {
        ArrayList<Integer> pids = new ArrayList<>();
        ShizukuBridge.ShellResult res = ShizukuBridge.runShellCommand(context, "pidof " + pkg, 3000);
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
