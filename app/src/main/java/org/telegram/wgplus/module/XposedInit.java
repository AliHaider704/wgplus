package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Application;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ComponentCallbacks2;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.res.Configuration;
import android.graphics.Typeface;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XCallback;

public class XposedInit implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    private static final Set<String> SUPPORTED_TGNET_PACKAGES = new HashSet<>(Arrays.asList(
            "org.telegram.plus",
            "org.telegram.messenger",
            "org.telegram.messenger.web",
            "org.telegram.messenger.beta",
            "org.telegram.gold",
            "ir.ilmili.telegraph",
            "ir.p2021.telegraph",
            "com.radolyn.ayugram",
            "xyz.nextalone.nagram"
    ));
    private static final String FAB_TAG = "wg_plus_floating_trigger";
    // ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING (API 34+); kept as literal for compileSdk compatibility.
    private static final int FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING = 0x00000200;

    private static final ExecutorService STARTUP_EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(() -> {
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
            } catch (Throwable ignored) {
            }
            r.run();
        }, "wgplus-host-startup");
        t.setDaemon(true);
        return t;
    });

    private static volatile String MODULE_PATH = null;
    private static volatile Context sHostAppContext = null;
    private static volatile boolean sLifecycleRegistered = false;
    private static final AtomicBoolean sMemoryCallbacksRegistered = new AtomicBoolean(false);

    public static String getModulePath() {
        return MODULE_PATH;
    }

    public static void registerHostMemoryCallbacks(Context ctx) {
        if (ctx == null || !sMemoryCallbacksRegistered.compareAndSet(false, true)) {
            return;
        }
        Context appCandidate = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        if (!(appCandidate instanceof Application)) {
            sMemoryCallbacksRegistered.set(false);
            return;
        }
        ((Application) appCandidate).registerComponentCallbacks(new ComponentCallbacks2() {
            @Override
            public void onTrimMemory(int level) {
                if (level >= TRIM_MEMORY_RUNNING_LOW || level >= TRIM_MEMORY_UI_HIDDEN) {
                    ModuleHygieneManager.trimInMemoryCaches();
                }
            }

            @Override
            public void onConfigurationChanged(Configuration newConfig) {
            }

            @Override
            public void onLowMemory() {
                ModuleHygieneManager.trimInMemoryCaches();
            }
        });
    }

    @Override
    public void initZygote(StartupParam startupParam) {
        if (startupParam != null) {
            MODULE_PATH = startupParam.modulePath;
        }
    }

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.packageName == null) {
            return;
        }
        if ("org.telegram.wgplus.module".equals(lpparam.packageName)) {
            return;
        }
        if (TelegramXBridge.PACKAGE_NAME.equals(lpparam.packageName)) {
            TelegramXBridge.installHooks(lpparam, MODULE_PATH);
            return;
        }
        boolean knownClient = SUPPORTED_TGNET_PACKAGES.contains(lpparam.packageName);
        boolean dynamicTgnetClient = !knownClient
                && XposedHelpers.findClassIfExists("org.telegram.messenger.ApplicationLoader", lpparam.classLoader) != null;
        if (!knownClient && !dynamicTgnetClient) {
            return;
        }

        hookApplicationLoader(lpparam);
        hookProxyListActivity(lpparam);
        hookVoipCalls(lpparam);
        hookConnectionsManagerKeepAlive(lpparam);
        hookNotificationsService(lpparam);
        hookActivityFilePickerResult(lpparam);
    }

    private void hookApplicationLoader(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    "org.telegram.messenger.ApplicationLoader",
                    lpparam.classLoader,
                    "onCreate",
                    new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Context appContext = resolveHostApplicationContext(param.thisObject, lpparam.classLoader);
                                if (appContext == null) {
                                    return;
                                }
                                sHostAppContext = appContext;
                                final Context hostAppCtx = appContext;

                                // Fast lifecycle registration on main thread; zero heavy I/O or ZIP scanning here
                                registerSmartKeepaliveLifecycle(hostAppCtx, lpparam.classLoader);
                                registerHostMemoryCallbacks(hostAppCtx);
                                // Fail-closed synchronous Kill Switch pre-arm before ConnectionsManager dials out
                                WireGuardManager.preArmKillSwitchSync(hostAppCtx, lpparam.classLoader);

                                STARTUP_EXEC.execute(() -> {
                                    try {
                                        WireGuardManager.reportHookActiveToProvider(hostAppCtx, lpparam.packageName);
                                        WireGuardManager.syncPullSharedStateFromProvider(hostAppCtx, true);
                                        NativeBridgeLoader.ensureLoaded(hostAppCtx, MODULE_PATH);

                                        final boolean autoConnect = WireGuardManager.isAutoConnectEnabled(hostAppCtx);
                                        if (autoConnect && NativeBridgeLoader.isLoaded()) {
                                            try {
                                                wgbridge.Wgbridge.setTunnelStartupPending(true);
                                            } catch (Throwable ignored) {
                                            }
                                        }

                                        if (WireGuardManager.isKillSwitchEnabled(hostAppCtx)) {
                                            int ksPort = WireGuardManager.enforceKillSwitchIfDisconnected(
                                                    hostAppCtx,
                                                    MODULE_PATH,
                                                    lpparam.classLoader
                                            );
                                            if (ksPort > 0) {
                                                XposedBridge.log("WGPlus: Engaged strict kill switch guard on 127.0.0.1:" + ksPort);
                                            }
                                        }

                                        if (WireGuardManager.shouldForceTelegramAlwaysAwake(hostAppCtx, MODULE_PATH)) {
                                            WireGuardManager.syncForegroundKeepaliveService(hostAppCtx, true);
                                        }

                                        if (autoConnect) {
                                            try {
                                                int port = WireGuardManager.startAndBind(
                                                        hostAppCtx,
                                                        MODULE_PATH,
                                                        lpparam.classLoader
                                                );
                                                XposedBridge.log("WGPlus: Auto-started WireGuard tunnel on 127.0.0.1:" + port);
                                            } catch (Throwable err) {
                                                XposedBridge.log("WGPlus: Auto-start failed: " + err.getMessage());
                                            } finally {
                                                if (NativeBridgeLoader.isLoaded()) {
                                                    try {
                                                        wgbridge.Wgbridge.setTunnelStartupPending(false);
                                                    } catch (Throwable ignored) {
                                                    }
                                                }
                                            }
                                        }

                                        ModuleHygieneManager.runAutoHygieneIfDueAsync(hostAppCtx);
                                    } catch (Throwable t) {
                                        XposedBridge.log("WGPlus startup worker warning: " + t.getMessage());
                                    }
                                });
                            } catch (Throwable t) {
                                XposedBridge.log(t);
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log("WGPlus: Failed hooking ApplicationLoader.onCreate: " + t.getMessage());
        }
    }

    private static void registerSmartKeepaliveLifecycle(final Context hostAppCtx, final ClassLoader telegramClassLoader) {
        if (sLifecycleRegistered || hostAppCtx == null) {
            return;
        }
        Context appCandidate = hostAppCtx.getApplicationContext() != null
                ? hostAppCtx.getApplicationContext()
                : hostAppCtx;
        if (!(appCandidate instanceof Application)) {
            return;
        }
        sLifecycleRegistered = true;
        final Application app = (Application) appCandidate;
        final AtomicInteger startedCount = new AtomicInteger(0);
        app.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            @Override
            public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            }

            @Override
            public void onActivityStarted(Activity activity) {
                if (startedCount.incrementAndGet() == 1) {
                    WireGuardManager.onAppForegroundStateChanged(hostAppCtx, MODULE_PATH, telegramClassLoader, true);
                }
            }

            @Override
            public void onActivityResumed(Activity activity) {
            }

            @Override
            public void onActivityPaused(Activity activity) {
            }

            @Override
            public void onActivityStopped(Activity activity) {
                int remaining = startedCount.decrementAndGet();
                if (remaining <= 0) {
                    startedCount.set(0);
                    WireGuardManager.onAppForegroundStateChanged(hostAppCtx, MODULE_PATH, telegramClassLoader, false);
                    STARTUP_EXEC.execute(() -> {
                        ModuleHygieneManager.trimInMemoryCaches();
                        WireGuardManager.pollAndRunRemoteHygieneIfRequested(hostAppCtx);
                    });
                }
            }

            @Override
            public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
            }

            @Override
            public void onActivityDestroyed(Activity activity) {
            }
        });
    }

    /**
     * Prevents Telegram's native MTProto engine (ConnectionsManager) from pausing or tearing down
     * background sockets when the screen turns off or the app goes to the background while the tunnel is active.
     */
    private void hookConnectionsManagerKeepAlive(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            final Class<?> cmClass = XposedHelpers.findClassIfExists(
                    "org.telegram.tgnet.ConnectionsManager",
                    lpparam.classLoader
            );
            if (cmClass == null) {
                return;
            }
            XposedHelpers.findAndHookMethod(
                    cmClass,
                    "setAppPaused",
                    boolean.class,
                    boolean.class,
                    new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args == null || param.args.length < 2) {
                                    return;
                                }
                                boolean pausing = Boolean.TRUE.equals(param.args[0]);
                                boolean byScreenState = Boolean.TRUE.equals(param.args[1]);
                                // Screen-state calls can also trigger native_pauseNetwork in Telegram when appResumeCount == 0
                                if (!pausing && !byScreenState) {
                                    return;
                                }
                                Context ctx = getOrResolveAppContext(lpparam.classLoader);
                                if (WireGuardManager.shouldForceTelegramAlwaysAwake(ctx, MODULE_PATH)) {
                                    param.args[0] = false;
                                    param.args[1] = false;
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    }
            );
            XposedHelpers.findAndHookMethod(
                    cmClass,
                    "native_pauseNetwork",
                    int.class,
                    new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                Context ctx = getOrResolveAppContext(lpparam.classLoader);
                                if (WireGuardManager.shouldForceTelegramAlwaysAwake(ctx, MODULE_PATH)) {
                                    param.setResult(null);
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    }
            );
            XposedHelpers.findAndHookMethod(
                    cmClass,
                    "native_setNetworkAvailable",
                    int.class,
                    boolean.class,
                    int.class,
                    boolean.class,
                    new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                if (param.args == null || param.args.length < 4) {
                                    return;
                                }
                                if (Boolean.TRUE.equals(param.args[3])) {
                                    Context ctx = getOrResolveAppContext(lpparam.classLoader);
                                    if (WireGuardManager.shouldForceTelegramAlwaysAwake(ctx, MODULE_PATH)) {
                                        param.args[3] = false;
                                    }
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    }
            );
            // Enforce Kill Switch against Telegram clearing/disabling proxy & re-bind immediately on Login/Add-Account init
            XposedBridge.hookAllMethods(cmClass, "setProxySettings", new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args == null || param.args.length < 6) {
                            return;
                        }
                        Context ctx = getOrResolveAppContext(lpparam.classLoader);
                        if (!WireGuardManager.isKillSwitchEnabled(ctx)) {
                            return;
                        }
                        boolean enabled = Boolean.TRUE.equals(param.args[0]);
                        String addr = param.args[1] instanceof String ? (String) param.args[1] : "";
                        if (!enabled || !"127.0.0.1".equals(addr)) {
                            int effPort = NativeBridgeLoader.isLoaded()
                                    ? WireGuardManager.getEffectiveProxyPort(ctx, MODULE_PATH)
                                    : WireGuardManager.getCachedSharedOrFallbackPort(ctx);
                            param.args[0] = true;
                            param.args[1] = "127.0.0.1";
                            param.args[2] = effPort > 0 ? effPort : 9;
                            param.args[3] = WireGuardManager.getActiveSocksUser();
                            param.args[4] = WireGuardManager.getActiveSocksPass();
                            param.args[5] = "";
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            XposedBridge.hookAllMethods(cmClass, "native_setProxySettings", new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.args == null || param.args.length < 6) {
                            return;
                        }
                        Context ctx = getOrResolveAppContext(lpparam.classLoader);
                        if (!WireGuardManager.isKillSwitchEnabled(ctx)) {
                            return;
                        }
                        String addr = param.args[1] instanceof String ? (String) param.args[1] : "";
                        if (!"127.0.0.1".equals(addr)) {
                            int effPort = NativeBridgeLoader.isLoaded()
                                    ? WireGuardManager.getEffectiveProxyPort(ctx, MODULE_PATH)
                                    : WireGuardManager.getCachedSharedOrFallbackPort(ctx);
                            param.args[1] = "127.0.0.1";
                            param.args[2] = effPort > 0 ? effPort : 9;
                            param.args[3] = WireGuardManager.getActiveSocksUser();
                            param.args[4] = WireGuardManager.getActiveSocksPass();
                            param.args[5] = "";
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            XC_MethodHook rebindOnAccountLifecycle = new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        final Context ctx = getOrResolveAppContext(lpparam.classLoader);
                        STARTUP_EXEC.execute(() -> {
                            try {
                                Thread.sleep(250L);
                                if (NativeBridgeLoader.isLoaded()) {
                                    WireGuardManager.reapplyProxyToAccountIfActive(ctx, lpparam.classLoader, 0);
                                }
                            } catch (Throwable ignored) {
                            }
                        });
                    } catch (Throwable ignored) {
                    }
                }
            };
            XposedBridge.hookAllMethods(cmClass, "init", rebindOnAccountLifecycle);
            XposedBridge.hookAllMethods(cmClass, "cleanup", rebindOnAccountLifecycle);
        } catch (Throwable t) {
            XposedBridge.log("WGPlus: ConnectionsManager keepalive hook warning: " + t.getMessage());
        }
    }

    /**
     * Promotes Telegram's declared NotificationsService (foregroundServiceType=dataSync) to an active
     * foreground service while 24/7 WireGuard continuity is enabled so Samsung Freecess and Doze do not
     * freeze or demote the process into background cgroups while the screen is off.
     */
    private void hookNotificationsService(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            final Class<?> nsClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.NotificationsService",
                    lpparam.classLoader
            );
            if (nsClass == null) {
                return;
            }
            final Binder keepaliveBridgeBinder = new Binder();
            XposedHelpers.findAndHookMethod(
                    nsClass,
                    "onBind",
                    Intent.class,
                    new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                Intent intent = param.args != null && param.args.length > 0 && param.args[0] instanceof Intent
                                        ? (Intent) param.args[0]
                                        : null;
                                if (intent != null && WireGuardManager.ACTION_KEEPALIVE_BRIDGE.equals(intent.getAction())) {
                                    param.setResult(keepaliveBridgeBinder);
                                    if (param.thisObject instanceof Service) {
                                        demoteNotificationsService((Service) param.thisObject, false);
                                    }
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    }
            );
            Method targetOnStart = null;
            for (Class<?> c = nsClass; c != null && Service.class.isAssignableFrom(c); c = c.getSuperclass()) {
                try {
                    targetOnStart = c.getDeclaredMethod("onStartCommand", Intent.class, int.class, int.class);
                    break;
                } catch (NoSuchMethodException ignored) {
                }
            }
            if (targetOnStart != null) {
                XposedBridge.hookMethod(
                        targetOnStart,
                        new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                try {
                                    if (!nsClass.isInstance(param.thisObject)
                                            || !(param.thisObject instanceof Service)) {
                                        return;
                                    }
                                Service service = (Service) param.thisObject;
                                Intent intent = param.args != null && param.args.length > 0 && param.args[0] instanceof Intent
                                        ? (Intent) param.args[0]
                                        : null;
                                boolean stopRequested = intent != null && intent.getBooleanExtra(
                                        WireGuardManager.EXTRA_STOP_FOREGROUND_KEEPALIVE,
                                        false
                                );
                                boolean expectFgPromote = intent != null && intent.getBooleanExtra(
                                        WireGuardManager.EXTRA_EXPECT_FOREGROUND_PROMOTE,
                                        false
                                );
                                boolean syncAction = intent != null && WireGuardManager.ACTION_SYNC_CONTINUITY.equals(
                                        intent.getAction()
                                );
                                boolean forceAwake = !stopRequested
                                        && WireGuardManager.shouldForceTelegramAlwaysAwake(service, MODULE_PATH);
                                if (!forceAwake) {
                                    WireGuardManager.queryAndSyncStealthContinuity(service, false, false);
                                    if (expectFgPromote) {
                                        promoteNotificationsServiceToForeground(service);
                                        new Handler(Looper.getMainLooper()).post(
                                                () -> demoteNotificationsService(service, stopRequested)
                                        );
                                    } else if (stopRequested) {
                                        new Handler(Looper.getMainLooper()).post(
                                                () -> demoteNotificationsService(service, true)
                                        );
                                    } else {
                                        cancelOwnForegroundNotification(service);
                                    }
                                    return;
                                }
                                boolean stealth = WireGuardManager.queryAndSyncStealthContinuity(
                                        service,
                                        true,
                                        syncAction
                                );
                                if (stealth) {
                                    if (expectFgPromote) {
                                        promoteNotificationsServiceToForeground(service);
                                        new Handler(Looper.getMainLooper()).post(
                                                () -> demoteNotificationsService(service, false)
                                        );
                                    } else if (syncAction) {
                                        new Handler(Looper.getMainLooper()).post(
                                                () -> demoteNotificationsService(service, false)
                                        );
                                    } else {
                                        cancelOwnForegroundNotification(service);
                                    }
                                    param.setResult(Service.START_NOT_STICKY);
                                } else {
                                    promoteNotificationsServiceToForeground(service);
                                    param.setResult(Service.START_STICKY);
                                }
                            } catch (Throwable t) {
                                XposedBridge.log("WGPlus: NotificationsService hook warning: " + t.getMessage());
                            }
                        }
                    }
                );
            } else {
                XposedBridge.log("WGPlus: NotificationsService onStartCommand method not found");
            }
            XposedBridge.hookAllMethods(nsClass, "onTimeout", new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        if (param.thisObject instanceof Service) {
                            demoteNotificationsService((Service) param.thisObject, true);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log("WGPlus: Failed hooking NotificationsService: " + t.getMessage());
        }
    }

    private static void promoteNotificationsServiceToForeground(Service service) {
        if (service == null) {
            return;
        }
        boolean isAr = WireGuardManager.isArabic(service);
        String title = isAr ? "حماية استمرارية الاتصال" : "Continuity Guard Active";
        String body = isAr
                ? "النفق المشفر يعمل باستمرار للحفاظ على الرسائل والمكالمات"
                : "Encrypted tunnel is active for continuous messages and calls";

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) service.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                NotificationChannel ch = new NotificationChannel(
                        WireGuardManager.FG_NOTIFICATION_CHANNEL_ID,
                        title,
                        NotificationManager.IMPORTANCE_MIN
                );
                ch.setShowBadge(false);
                ch.setSound(null, null);
                ch.enableVibration(false);
                ch.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
                nm.createNotificationChannel(ch);
            }
        }

        int smallIcon = android.R.drawable.stat_notify_sync;
        if (service.getApplicationInfo() != null && service.getApplicationInfo().icon != 0) {
            smallIcon = service.getApplicationInfo().icon;
        }

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(service, WireGuardManager.FG_NOTIFICATION_CHANNEL_ID)
                : new Notification.Builder(service);
        Notification notification = builder
                .setSmallIcon(smallIcon)
                .setContentTitle(title)
                .setContentText(body)
                .setOngoing(true)
                .setShowWhen(false)
                .build();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            int fgType = resolvePreferredForegroundServiceType(service);
            if (fgType != 0) {
                try {
                    service.startForeground(
                            WireGuardManager.FG_NOTIFICATION_ID,
                            notification,
                            fgType
                    );
                    return;
                } catch (Throwable t) {
                    XposedBridge.log("WGPlus: startForeground(type=" + fgType + ") fallback: " + t.getMessage());
                }
            }
        }
        service.startForeground(WireGuardManager.FG_NOTIFICATION_ID, notification);
    }

    private static int resolvePreferredForegroundServiceType(Service service) {
        if (service == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return 0;
        }
        try {
            PackageManager pm = service.getPackageManager();
            if (pm != null) {
                ServiceInfo si = pm.getServiceInfo(new ComponentName(service, service.getClass()), 0);
                if (si != null) {
                    int declaredType = si.getForegroundServiceType();
                    if ((declaredType & ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC) != 0) {
                        return ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC;
                    }
                    if ((declaredType & FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING) != 0) {
                        return FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING;
                    }
                    return declaredType;
                }
            }
        } catch (Throwable ignored) {
        }
        return 0;
    }

    private static void cancelOwnForegroundNotification(Service service) {
        if (service == null) {
            return;
        }
        try {
            NotificationManager nm = (NotificationManager) service.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.cancel(WireGuardManager.FG_NOTIFICATION_ID);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void demoteNotificationsService(Service service, boolean stopSelf) {
        if (service == null) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                service.stopForeground(Service.STOP_FOREGROUND_REMOVE);
            } else {
                service.stopForeground(true);
            }
        } catch (Throwable ignored) {
        }
        try {
            NotificationManager nm = (NotificationManager) service.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.cancel(WireGuardManager.FG_NOTIFICATION_ID);
            }
        } catch (Throwable ignored) {
        }
        if (stopSelf) {
            try {
                service.stopSelf();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * Non-destructively hooks Telegram's VoIP native instance creation (tgcalls Instance.makeNativeInstance
     * and legacy VoIPController.start) so voice and video call media always route through the local
     * WireGuard SOCKS5 proxy (or the fail-closed Kill Switch guard when disconnected).
     */
    private void hookVoipCalls(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            final Class<?> instanceClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.voip.Instance",
                    lpparam.classLoader
            );
            final Class<?> proxyClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.voip.Instance$Proxy",
                    lpparam.classLoader
            );
            final Class<?> configClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.voip.Instance$Config",
                    lpparam.classLoader
            );
            final Class<?> endpointClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.voip.Instance$Endpoint",
                    lpparam.classLoader
            );
            final XC_MethodHook voipProxyInjector = new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        Context ctx = getOrResolveAppContext(lpparam.classLoader);
                        boolean ks = WireGuardManager.isKillSwitchEnabled(ctx);
                        if (!ks && !WireGuardManager.shouldRouteCallsNow(ctx, MODULE_PATH)) {
                            return;
                        }
                        int effectivePort = WireGuardManager.getEffectiveProxyPort(ctx, MODULE_PATH);
                        if (effectivePort <= 0 && ks) {
                            effectivePort = WireGuardManager.enforceKillSwitchIfDisconnected(ctx, MODULE_PATH, lpparam.classLoader);
                            if (effectivePort <= 0) {
                                effectivePort = 9; // fail-closed blackhole when Kill Switch is armed
                            }
                        }
                        if (effectivePort <= 0 || param.args == null) {
                            return;
                        }
                        String socksUser = WireGuardManager.getActiveSocksUser();
                        String socksPass = WireGuardManager.getActiveSocksPass();
                        boolean hasAuth = socksUser != null && !socksUser.isEmpty();
                        Class<?>[] paramTypes = ((Method) param.method).getParameterTypes();
                        boolean injectedProxy = false;
                        for (int i = 0; i < paramTypes.length && i < param.args.length; i++) {
                            if (proxyClass.isAssignableFrom(paramTypes[i])) {
                                Constructor<?> ctor = proxyClass.getDeclaredConstructor(
                                        String.class, int.class, String.class, String.class
                                );
                                ctor.setAccessible(true);
                                param.args[i] = ctor.newInstance("127.0.0.1", effectivePort, socksUser, socksPass);
                                injectedProxy = true;
                                String msg = ((Method) param.method).getName()
                                        + " port=" + effectivePort + " auth=" + hasAuth;
                                XposedBridge.log("WGPlus: Routed tgcalls VoIP instance (" + msg + ")");
                                WgDiagnosticsLog.record("VOIP", "ROUTE", msg);
                                break;
                            }
                        }
                        if (injectedProxy) {
                            if (configClass != null) {
                                for (int i = 0; i < paramTypes.length && i < param.args.length; i++) {
                                    if (param.args[i] != null && configClass.isAssignableFrom(paramTypes[i])) {
                                        try {
                                            XposedHelpers.setBooleanField(param.args[i], "enableP2p", false);
                                        } catch (Throwable ignored) {
                                        }
                                        break;
                                    }
                                }
                            }
                            if (endpointClass != null) {
                                int relayedCount = 0;
                                boolean tunnelUp = WireGuardManager.isTunnelRunning(ctx, MODULE_PATH);
                                for (int i = 0; i < param.args.length; i++) {
                                    Object arg = param.args[i];
                                    if (arg != null && arg.getClass().isArray()
                                            && endpointClass.isAssignableFrom(arg.getClass().getComponentType())) {
                                        Object[] eps = (Object[]) arg;
                                        for (Object ep : eps) {
                                            if (ep == null) {
                                                continue;
                                            }
                                            try {
                                                Object ipv4Obj = XposedHelpers.getObjectField(ep, "ipv4");
                                                String rawIpv4 = ipv4Obj instanceof String ? ((String) ipv4Obj).trim() : "";
                                                int rawPort = XposedHelpers.getIntField(ep, "port");
                                                if (!rawIpv4.isEmpty() && !"127.0.0.1".equals(rawIpv4) && rawPort > 0) {
                                                    int localPort = WireGuardManager.startVoipEndpointRelay(
                                                            ctx,
                                                            MODULE_PATH,
                                                            rawIpv4,
                                                            rawPort
                                                    );
                                                    if (localPort > 0) {
                                                        XposedHelpers.setObjectField(ep, "ipv4", "127.0.0.1");
                                                        try {
                                                            XposedHelpers.setObjectField(ep, "ipv6", "");
                                                        } catch (Throwable ignored) {
                                                        }
                                                        XposedHelpers.setIntField(ep, "port", localPort);
                                                        XposedBridge.log("WGPlus: Relayed VoIP endpoint " + rawIpv4 + ":" + rawPort + " -> 127.0.0.1:" + localPort);
                                                        WgDiagnosticsLog.record("VOIP", "RELAY", rawPort + "->" + localPort);
                                                        relayedCount++;
                                                    } else if (ks && !tunnelUp) {
                                                        XposedHelpers.setObjectField(ep, "ipv4", "127.0.0.1");
                                                        try {
                                                            XposedHelpers.setObjectField(ep, "ipv6", "");
                                                        } catch (Throwable ignored) {
                                                        }
                                                        XposedHelpers.setIntField(ep, "port", 9);
                                                    }
                                                }
                                            } catch (Throwable ignored) {
                                            }
                                        }
                                    }
                                }
                                if (relayedCount > 0) {
                                    WgDiagnosticsLog.record("VOIP", "EP_RELAY", "count=" + relayedCount);
                                }
                            }
                        }
                    } catch (Throwable t) {
                        XposedBridge.log("WGPlus: VoIP Instance hook warning: " + t.getMessage());
                        WgDiagnosticsLog.record("VOIP", "HOOK_WARN", t.getMessage());
                    }
                }
            };
            if (instanceClass != null && proxyClass != null) {
                for (Method m : instanceClass.getDeclaredMethods()) {
                    if ("makeNativeInstance".equals(m.getName())) {
                        XposedBridge.hookMethod(m, voipProxyInjector);
                    }
                }
            }
            final Class<?> nativeInstanceClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.voip.NativeInstance",
                    lpparam.classLoader
            );
            if (nativeInstanceClass != null && proxyClass != null) {
                for (Method m : nativeInstanceClass.getDeclaredMethods()) {
                    if ("makeGroup".equals(m.getName()) || "make".equals(m.getName())) {
                        XposedBridge.hookMethod(m, voipProxyInjector);
                    }
                }
            }
        } catch (Throwable t) {
            XposedBridge.log("WGPlus: Failed hooking VoIP Instance: " + t.getMessage());
        }

        // Legacy libtgvoip fallback
        try {
            final Class<?> controllerClass = XposedHelpers.findClassIfExists(
                    "org.telegram.messenger.voip.VoIPController",
                    lpparam.classLoader
            );
            if (controllerClass != null) {
                XposedHelpers.findAndHookMethod(
                        controllerClass,
                        "start",
                        new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                try {
                                    Context ctx = getOrResolveAppContext(lpparam.classLoader);
                                    boolean ks = WireGuardManager.isKillSwitchEnabled(ctx);
                                    if (!ks && !WireGuardManager.shouldRouteCallsNow(ctx, MODULE_PATH)) {
                                        return;
                                    }
                                    int effectivePort = WireGuardManager.getEffectiveProxyPort(ctx, MODULE_PATH);
                                    if (effectivePort <= 0 && ks) {
                                        effectivePort = WireGuardManager.enforceKillSwitchIfDisconnected(ctx, MODULE_PATH, lpparam.classLoader);
                                        if (effectivePort <= 0) {
                                            effectivePort = 9;
                                        }
                                    }
                                    if (effectivePort > 0 && param.thisObject != null) {
                                        XposedHelpers.callMethod(
                                                param.thisObject,
                                                "setProxy",
                                                "127.0.0.1",
                                                effectivePort,
                                                WireGuardManager.getActiveSocksUser(),
                                                WireGuardManager.getActiveSocksPass()
                                        );
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        }
                );
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Captures ONLY our dedicated .conf (0x5747) and QR gallery image (0x5748) picker results on host Activities
     * (both Telegram's DEX LaunchActivity for non-root LSPatch and Activity.class fallback for LSPosed)
     * without interfering with any Telegram or TeleVip activity results.
     */
    private void hookActivityFilePickerResult(final XC_LoadPackage.LoadPackageParam lpparam) {
        final XC_MethodHook pickerResultHook = new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    if (param.args == null || param.args.length < 3 || !(param.args[0] instanceof Integer)) {
                        return;
                    }
                    int requestCode = (Integer) param.args[0];
                    if (requestCode != WireGuardDialog.REQ_IMPORT_CONF_FILE
                            && requestCode != WireGuardDialog.REQ_IMPORT_QR_IMAGE) {
                        return;
                    }
                    int resultCode = (Integer) param.args[1];
                    Intent data = (Intent) param.args[2];
                    Activity act = (Activity) param.thisObject;
                    WireGuardDialog.onPickerActivityResult(act, requestCode, resultCode, data);
                    param.setResult(null);
                } catch (Throwable t) {
                    XposedBridge.log(t);
                }
            }
        };

        String[] hostActivityClasses = new String[]{
                "org.telegram.ui.LaunchActivity",
                "org.telegram.ui.ExternalActionActivity"
        };
        for (String clsName : hostActivityClasses) {
            try {
                Class<?> actCls = XposedHelpers.findClassIfExists(clsName, lpparam.classLoader);
                while (actCls != null && actCls != Activity.class && actCls != Object.class) {
                    try {
                        Method m = actCls.getDeclaredMethod("onActivityResult", int.class, int.class, Intent.class);
                        XposedBridge.hookMethod(m, pickerResultHook);
                        break;
                    } catch (NoSuchMethodException ignored) {
                        actCls = actCls.getSuperclass();
                    }
                }
            } catch (Throwable t) {
                XposedBridge.log("WGPlus: Host activity hook warning for " + clsName + ": " + t.getMessage());
            }
        }

        try {
            XposedHelpers.findAndHookMethod(
                    Activity.class,
                    "onActivityResult",
                    int.class,
                    int.class,
                    Intent.class,
                    pickerResultHook
            );
        } catch (Throwable ignored) {
        }
    }

    private void hookProxyListActivity(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    "org.telegram.ui.ProxyListActivity",
                    lpparam.classLoader,
                    "createView",
                    Context.class,
                    new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object result = param.getResult();
                                if (!(result instanceof ViewGroup)) {
                                    return;
                                }
                                ViewGroup rootGroup = (ViewGroup) result;
                                if (rootGroup.findViewWithTag(FAB_TAG) != null) {
                                    return;
                                }

                                Context argCtx = (param.args != null && param.args.length > 0 && param.args[0] instanceof Context)
                                        ? (Context) param.args[0]
                                        : rootGroup.getContext();
                                Context resolvedCtx = resolveActivityContext(param.thisObject, argCtx);
                                if (resolvedCtx == null) {
                                    return;
                                }

                                final Context dialogCtx = resolvedCtx;

                                final LinearLayout triggerBtn = new LinearLayout(dialogCtx);
                                triggerBtn.setTag(FAB_TAG);
                                triggerBtn.setOrientation(LinearLayout.HORIZONTAL);
                                triggerBtn.setGravity(Gravity.CENTER_VERTICAL);
                                triggerBtn.setClickable(true);
                                triggerBtn.setFocusable(true);
                                triggerBtn.setMinimumHeight(WgTheme.dp(dialogCtx, 44));

                                final View stateDot = new View(dialogCtx);
                                final TextView triggerLabel = new TextView(dialogCtx);
                                triggerLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
                                triggerLabel.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);

                                final Runnable syncTriggerStyle = () -> {
                                    boolean isAr = WireGuardManager.isArabic(dialogCtx);
                                    WgTheme theme = WgTheme.of(WireGuardManager.isDarkTheme(dialogCtx));
                                    boolean active = WireGuardManager.isTunnelRunning(dialogCtx, MODULE_PATH);
                                    boolean guarded = !active && WireGuardManager.isKillSwitchGuardActiveNow(dialogCtx, MODULE_PATH);

                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                                        triggerBtn.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
                                    }
                                    triggerBtn.removeAllViews();

                                    int dotSize = WgTheme.dp(dialogCtx, 7);
                                    int dotColor = active ? theme.activeDot : (guarded ? theme.pendingDot : theme.textSecondary);
                                    stateDot.setBackground(WgTheme.statusDot(dialogCtx, dotColor, 7f));
                                    LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotSize, dotSize);
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                                        dotLp.setMarginEnd(WgTheme.dp(dialogCtx, 8));
                                    } else if (isAr) {
                                        dotLp.leftMargin = WgTheme.dp(dialogCtx, 8);
                                    } else {
                                        dotLp.rightMargin = WgTheme.dp(dialogCtx, 8);
                                    }
                                    triggerBtn.addView(stateDot, dotLp);

                                    triggerLabel.setText(WgStrings.floatingTriggerLabel(isAr));
                                    triggerLabel.setTextColor(active ? theme.activeText : (guarded ? theme.pendingText : theme.textPrimary));
                                    triggerBtn.addView(triggerLabel);

                                    int padH = WgTheme.dp(dialogCtx, 15);
                                    int padV = WgTheme.dp(dialogCtx, 10);
                                    triggerBtn.setPadding(padH, padV, padH, padV);
                                    // Elevated floating trigger above scrolling ProxyListActivity list (R-12 elevation reason)
                                    triggerBtn.setBackground(WgTheme.interactiveBackground(
                                            dialogCtx,
                                            active ? theme.activeBg : (guarded ? theme.pendingBg : theme.surfaceCard),
                                            theme.surfaceSecondaryBtnPressed,
                                            active ? theme.activeBorder : (guarded ? theme.pendingBorder : theme.accentPrimary),
                                            theme.accentPrimary,
                                            10f
                                    ));
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                                        triggerBtn.setElevation(WgTheme.dp(dialogCtx, 3));
                                    }
                                };

                                syncTriggerStyle.run();

                                FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                                        ViewGroup.LayoutParams.WRAP_CONTENT,
                                        ViewGroup.LayoutParams.WRAP_CONTENT,
                                        Gravity.BOTTOM | Gravity.END
                                );
                                int marginEnd = WgTheme.dp(dialogCtx, 18);
                                int marginBottom = WgTheme.dp(dialogCtx, 22);
                                lp.setMargins(marginEnd, marginBottom, marginEnd, marginBottom);
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                                    lp.setMarginEnd(marginEnd);
                                }

                                triggerBtn.setOnClickListener((View v) ->
                                        WireGuardDialog.show(dialogCtx, lpparam.classLoader, MODULE_PATH, syncTriggerStyle)
                                );

                                if (rootGroup instanceof FrameLayout) {
                                    rootGroup.addView(triggerBtn, lp);
                                } else {
                                    rootGroup.addView(triggerBtn, new ViewGroup.LayoutParams(
                                            ViewGroup.LayoutParams.WRAP_CONTENT,
                                            ViewGroup.LayoutParams.WRAP_CONTENT
                                    ));
                                }

                                try {
                                    Object actionBar = XposedHelpers.getObjectField(param.thisObject, "actionBar");
                                    if (actionBar instanceof View) {
                                        ((View) actionBar).setOnLongClickListener(v -> {
                                            WireGuardDialog.show(dialogCtx, lpparam.classLoader, MODULE_PATH, syncTriggerStyle);
                                            return true;
                                        });
                                    }
                                } catch (Throwable ignored) {
                                }
                            } catch (Throwable t) {
                                XposedBridge.log(t);
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log("WGPlus: Failed hooking ProxyListActivity.createView: " + t.getMessage());
        }
    }

    private static Context resolveHostApplicationContext(Object appLoaderInstance, ClassLoader cl) {
        Context appContext = null;
        try {
            Class<?> targetCls = appLoaderInstance != null
                    ? appLoaderInstance.getClass()
                    : XposedHelpers.findClass("org.telegram.messenger.ApplicationLoader", cl);
            appContext = (Context) XposedHelpers.getStaticObjectField(targetCls, "applicationContext");
        } catch (Throwable ignored) {
        }
        if (appContext == null && appLoaderInstance instanceof Application) {
            appContext = ((Application) appLoaderInstance).getApplicationContext();
            if (appContext == null) {
                appContext = (Application) appLoaderInstance;
            }
        }
        return appContext;
    }

    private static Context getOrResolveAppContext(ClassLoader cl) {
        if (sHostAppContext != null) {
            return sHostAppContext;
        }
        Context resolved = resolveHostApplicationContext(null, cl);
        if (resolved != null) {
            sHostAppContext = resolved;
        }
        return resolved;
    }

    private static Context resolveActivityContext(Object fragmentInstance, Context fallback) {
        if (fallback instanceof Activity) {
            return fallback;
        }
        try {
            Object parentActivity = XposedHelpers.callMethod(fragmentInstance, "getParentActivity");
            if (parentActivity instanceof Context) {
                return (Context) parentActivity;
            }
        } catch (Throwable ignored) {
        }
        return fallback;
    }
}
