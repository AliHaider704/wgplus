package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XCallback;

public class XposedInit implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    private static final String TARGET_PLUS = "org.telegram.plus";
    private static final String TARGET_OFFICIAL = "org.telegram.messenger";
    private static final String FAB_TAG = "wg_plus_floating_trigger";

    private static volatile String MODULE_PATH = null;
    private static volatile Context sHostAppContext = null;
    private static volatile boolean sLifecycleRegistered = false;

    public static String getModulePath() {
        return MODULE_PATH;
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
        if (!TARGET_PLUS.equals(lpparam.packageName) && !TARGET_OFFICIAL.equals(lpparam.packageName)) {
            return;
        }

        hookApplicationLoader(lpparam);
        hookProxyListActivity(lpparam);
        hookVoipCalls(lpparam);
        hookConnectionsManagerKeepAlive(lpparam);
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
                                NativeBridgeLoader.ensureLoaded(hostAppCtx, MODULE_PATH);

                                // 1. Engage strict fail-closed Kill Switch immediately before any network socket opens
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

                                // 2. Register ActivityLifecycleCallbacks for 24/7 Continuity & Foreground Fast-Resume
                                registerSmartKeepaliveLifecycle(hostAppCtx, lpparam.classLoader);

                                // 3. Auto-start configured WireGuard / AmneziaWG tunnel if enabled
                                if (WireGuardManager.isAutoConnectEnabled(hostAppCtx)) {
                                    new Thread(() -> {
                                        try {
                                            int port = WireGuardManager.startAndBind(
                                                    hostAppCtx,
                                                    MODULE_PATH,
                                                    lpparam.classLoader
                                            );
                                            XposedBridge.log("WGPlus: Auto-started WireGuard tunnel on 127.0.0.1:" + port);
                                        } catch (Throwable err) {
                                            XposedBridge.log("WGPlus: Auto-start failed: " + err.getMessage());
                                        }
                                    }, "wg-plus-autostart").start();
                                }
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
                                if (!pausing) {
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
        } catch (Throwable t) {
            XposedBridge.log("WGPlus: ConnectionsManager keepalive hook warning: " + t.getMessage());
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
            if (instanceClass != null && proxyClass != null) {
                Method[] methods = instanceClass.getDeclaredMethods();
                for (Method m : methods) {
                    if (!"makeNativeInstance".equals(m.getName())) {
                        continue;
                    }
                    XposedBridge.hookMethod(m, new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                Context ctx = getOrResolveAppContext(lpparam.classLoader);
                                if (!WireGuardManager.shouldRouteCallsNow(ctx, MODULE_PATH)) {
                                    return;
                                }
                                int effectivePort = WireGuardManager.getEffectiveProxyPort(ctx, MODULE_PATH);
                                if (effectivePort <= 0 || param.args == null) {
                                    return;
                                }
                                Class<?>[] paramTypes = ((Method) param.method).getParameterTypes();
                                for (int i = 0; i < paramTypes.length && i < param.args.length; i++) {
                                    if (proxyClass.isAssignableFrom(paramTypes[i])) {
                                        Constructor<?> ctor = proxyClass.getDeclaredConstructor(
                                                String.class, int.class, String.class, String.class
                                        );
                                        ctor.setAccessible(true);
                                        param.args[i] = ctor.newInstance("127.0.0.1", effectivePort, "", "");
                                        XposedBridge.log("WGPlus: Routed tgcalls VoIP instance through 127.0.0.1:" + effectivePort);
                                        break;
                                    }
                                }
                            } catch (Throwable t) {
                                XposedBridge.log("WGPlus: VoIP Instance hook warning: " + t.getMessage());
                            }
                        }
                    });
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
                                    if (!WireGuardManager.shouldRouteCallsNow(ctx, MODULE_PATH)) {
                                        return;
                                    }
                                    int effectivePort = WireGuardManager.getEffectiveProxyPort(ctx, MODULE_PATH);
                                    if (effectivePort > 0 && param.thisObject != null) {
                                        XposedHelpers.callMethod(
                                                param.thisObject,
                                                "setProxy",
                                                "127.0.0.1",
                                                effectivePort,
                                                "",
                                                ""
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
                                if (!(result instanceof FrameLayout)) {
                                    return;
                                }
                                FrameLayout rootFrame = (FrameLayout) result;
                                if (rootFrame.findViewWithTag(FAB_TAG) != null) {
                                    return;
                                }

                                Context argCtx = (param.args != null && param.args.length > 0 && param.args[0] instanceof Context)
                                        ? (Context) param.args[0]
                                        : rootFrame.getContext();
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

                                rootFrame.addView(triggerBtn, lp);

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
