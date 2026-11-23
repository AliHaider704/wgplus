package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Application;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Build;
import android.os.Process;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import de.robv.android.xposed.callbacks.XCallback;

/**
 * Non-destructive Xposed/LSPatch bridge for Telegram X ({@code org.thunderdog.challegram}).
 * Uses TDLib reflective proxy injection when un-obfuscated and a safe {@code tg://socks}
 * fallback, while keeping all heavy native startup off the main UI thread.
 */
public final class TelegramXBridge {

    public static final String PACKAGE_NAME = "org.thunderdog.challegram";
    private static final String TRIGGER_TAG = "wg_plus_tgx_trigger";
    private static final AtomicBoolean sBootstrapped = new AtomicBoolean(false);
    private static final ExecutorService BG_EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(() -> {
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
            } catch (Throwable ignored) {
            }
            r.run();
        }, "wgplus-tgx-init");
        t.setDaemon(true);
        return t;
    });

    private TelegramXBridge() {
    }

    public static void installHooks(final XC_LoadPackage.LoadPackageParam lpparam, final String modulePath) {
        if (lpparam == null || lpparam.classLoader == null) {
            return;
        }
        hookApplicationStartup(lpparam, modulePath);
        hookProxyControllerUi(lpparam, modulePath);
        hookActivityFilePicker(lpparam);
    }

    private static void hookApplicationStartup(final XC_LoadPackage.LoadPackageParam lpparam, final String modulePath) {
        Class<?> baseApp = XposedHelpers.findClassIfExists("org.thunderdog.challegram.BaseApplication", lpparam.classLoader);
        Class<?> targetApp = baseApp != null ? baseApp : Application.class;
        try {
            XposedHelpers.findAndHookMethod(targetApp, "onCreate", new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        if (!(param.thisObject instanceof Context)) {
                            return;
                        }
                        Context ctx = (Context) param.thisObject;
                        if (!PACKAGE_NAME.equals(ctx.getPackageName())) {
                            return;
                        }
                        if (!sBootstrapped.compareAndSet(false, true)) {
                            return;
                        }
                        final Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
                        XposedInit.registerHostMemoryCallbacks(appCtx);

                        BG_EXEC.execute(() -> {
                            try {
                                WireGuardManager.reportHookActiveToProvider(appCtx, PACKAGE_NAME);
                                WireGuardManager.syncPullSharedStateFromProvider(appCtx, true);
                                NativeBridgeLoader.ensureLoaded(appCtx, modulePath);
                                if (WireGuardManager.isKillSwitchEnabled(appCtx)) {
                                    int ksPort = WireGuardManager.enforceKillSwitchIfDisconnected(appCtx, modulePath, lpparam.classLoader);
                                    applyTdlibProxyReflective(lpparam.classLoader, ksPort > 0 ? ksPort : 9);
                                }
                                if (WireGuardManager.isAutoConnectEnabled(appCtx)) {
                                    int port = WireGuardManager.startAndBind(appCtx, modulePath, lpparam.classLoader);
                                    applyTdlibProxyReflective(lpparam.classLoader, port);
                                }
                                ModuleHygieneManager.runAutoHygieneIfDueAsync(appCtx);
                            } catch (Throwable t) {
                                XposedBridge.log("WGPlus TGX async init warning: " + t.getMessage());
                            }
                        });
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log("WGPlus TGX Application hook warning: " + t.getMessage());
        }
    }

    private static void hookProxyControllerUi(final XC_LoadPackage.LoadPackageParam lpparam, final String modulePath) {
        String[] candidates = new String[]{
                "org.thunderdog.challegram.ui.SettingsProxyController",
                "org.thunderdog.challegram.ui.SettingsNetworkController"
        };
        for (String clsName : candidates) {
            try {
                Class<?> cls = XposedHelpers.findClassIfExists(clsName, lpparam.classLoader);
                if (cls == null) {
                    continue;
                }
                for (Method m : cls.getDeclaredMethods()) {
                    if (!"onCreateView".equals(m.getName())) {
                        continue;
                    }
                    XposedBridge.hookMethod(m, new XC_MethodHook(XCallback.PRIORITY_DEFAULT) {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object res = param.getResult();
                                if (!(res instanceof ViewGroup)) {
                                    return;
                                }
                                attachFloatingTrigger((ViewGroup) res, lpparam.classLoader, modulePath);
                            } catch (Throwable ignored) {
                            }
                        }
                    });
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static void hookActivityFilePicker(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    Activity.class,
                    "onActivityResult",
                    int.class,
                    int.class,
                    Intent.class,
                    new XC_MethodHook(XCallback.PRIORITY_HIGHEST) {
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
                            } catch (Throwable ignored) {
                            }
                        }
                    }
            );
        } catch (Throwable ignored) {
        }
    }

    private static void attachFloatingTrigger(
            final ViewGroup root,
            final ClassLoader cl,
            final String modulePath
    ) {
        if (root == null || root.findViewWithTag(TRIGGER_TAG) != null) {
            return;
        }
        final Context ctx = root.getContext();
        if (ctx == null) {
            return;
        }
        boolean isAr = WireGuardManager.isArabic(ctx);
        WgTheme theme = WgTheme.of(WireGuardManager.isDarkTheme(ctx));
        boolean active = WireGuardManager.isTunnelRunning(ctx, modulePath);

        LinearLayout btn = new LinearLayout(ctx);
        btn.setTag(TRIGGER_TAG);
        btn.setOrientation(LinearLayout.HORIZONTAL);
        btn.setGravity(Gravity.CENTER_VERTICAL);
        btn.setClickable(true);
        btn.setFocusable(true);
        btn.setMinimumHeight(WgTheme.dp(ctx, 44));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            btn.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        }

        View dot = new View(ctx);
        int dotPx = WgTheme.dp(ctx, 7);
        dot.setBackground(WgTheme.statusDot(ctx, active ? theme.activeDot : theme.textSecondary, 7f));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotPx, dotPx);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            dotLp.setMarginEnd(WgTheme.dp(ctx, 8));
        } else {
            dotLp.rightMargin = WgTheme.dp(ctx, 8);
        }
        btn.addView(dot, dotLp);

        TextView label = new TextView(ctx);
        label.setText(WgStrings.floatingTriggerLabel(isAr));
        label.setTextColor(active ? theme.activeText : theme.textPrimary);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        btn.addView(label);

        btn.setPadding(WgTheme.dp(ctx, 14), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 14), WgTheme.dp(ctx, 10));
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                active ? theme.activeBg : theme.surfaceCard,
                theme.surfaceSecondaryBtnPressed,
                active ? theme.activeBorder : theme.accentPrimary,
                theme.accentPrimary,
                10f
        ));
        btn.setOnClickListener(v -> WireGuardDialog.show(ctx, cl, modulePath, null));

        if (root instanceof FrameLayout) {
            FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    Gravity.BOTTOM | Gravity.END
            );
            int m = WgTheme.dp(ctx, 18);
            lp.setMargins(m, m, m, m);
            root.addView(btn, lp);
        } else {
            root.addView(btn, new ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));
        }
    }

    /**
     * Attempts non-destructive TDLib proxy registration via {@code TdApi$AddProxy} when classes
     * are not ProGuard-obfuscated, falling back cleanly when unavailable.
     */
    public static boolean applyTdlibProxyReflective(ClassLoader cl, int localPort) {
        if (cl == null || localPort <= 0) {
            return false;
        }
        try {
            Class<?> addProxyCls = XposedHelpers.findClassIfExists("org.drinkless.tdlib.TdApi$AddProxy", cl);
            Class<?> socksCls = XposedHelpers.findClassIfExists("org.drinkless.tdlib.TdApi$ProxyTypeSocks5", cl);
            Class<?> tdlibManCls = XposedHelpers.findClassIfExists("org.thunderdog.challegram.telegram.TdlibManager", cl);
            if (addProxyCls == null || socksCls == null || tdlibManCls == null) {
                return false;
            }
            Constructor<?> socksCtor = socksCls.getDeclaredConstructor(String.class, String.class);
            socksCtor.setAccessible(true);
            Object proxyType = socksCtor.newInstance(
                    WireGuardManager.getActiveSocksUser(),
                    WireGuardManager.getActiveSocksPass()
            );

            Constructor<?> addCtor = addProxyCls.getDeclaredConstructor(String.class, int.class, boolean.class, XposedHelpers.findClass("org.drinkless.tdlib.TdApi$ProxyType", cl));
            addCtor.setAccessible(true);
            Object req = addCtor.newInstance("127.0.0.1", localPort, true, proxyType);

            Object manager = XposedHelpers.callStaticMethod(tdlibManCls, "instance");
            if (manager == null) {
                return false;
            }
            Object account = XposedHelpers.callMethod(manager, "currentNoWakeup");
            if (account == null) {
                return false;
            }
            Object client = XposedHelpers.callMethod(account, "client");
            if (client == null) {
                return false;
            }
            // Also enable use_proxy_for_calls in TDLib when available
            try {
                Class<?> setOptCls = XposedHelpers.findClassIfExists("org.drinkless.tdlib.TdApi$SetOption", cl);
                Class<?> optBoolCls = XposedHelpers.findClassIfExists("org.drinkless.tdlib.TdApi$OptionValueBoolean", cl);
                Class<?> optValCls = XposedHelpers.findClassIfExists("org.drinkless.tdlib.TdApi$OptionValue", cl);
                if (setOptCls != null && optBoolCls != null && optValCls != null) {
                    Object boolVal = optBoolCls.getDeclaredConstructor(boolean.class).newInstance(true);
                    Object setOpt = setOptCls.getDeclaredConstructor(String.class, optValCls).newInstance("use_proxy_for_calls", boolVal);
                    for (Method m : client.getClass().getMethods()) {
                        if ("send".equals(m.getName()) && m.getParameterTypes().length >= 2) {
                            m.invoke(client, setOpt, null);
                            break;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
            for (Method m : client.getClass().getMethods()) {
                if ("send".equals(m.getName()) && m.getParameterTypes().length >= 2) {
                    m.invoke(client, req, null);
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Builds a standard {@code tg://socks} Intent so the user can apply local SOCKS5 to Telegram X
     * even on builds with obfuscated internal TDLib wrappers.
     */
    public static Intent buildSocksDispatchIntent(int port) {
        StringBuilder uri = new StringBuilder("tg://socks?server=127.0.0.1&port=").append(port);
        String user = WireGuardManager.getActiveSocksUser();
        String pass = WireGuardManager.getActiveSocksPass();
        if (user != null && !user.isEmpty()) {
            uri.append("&user=").append(Uri.encode(user)).append("&pass=").append(Uri.encode(pass != null ? pass : ""));
        }
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(uri.toString()));
        i.setPackage(PACKAGE_NAME);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        return i;
    }
}
