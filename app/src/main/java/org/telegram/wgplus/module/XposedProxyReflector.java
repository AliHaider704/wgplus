package org.telegram.wgplus.module;

import android.content.Context;
import android.os.SystemClock;

import java.lang.reflect.Constructor;
import java.util.List;

import de.robv.android.xposed.XposedHelpers;

/**
 * Reflects proxy settings and connection nudges into hooked Telegram Java/native layers.
 */
final class XposedProxyReflector {

    private XposedProxyReflector() {
    }

    static int resolveMaxAccountCount(ClassLoader classLoader) {
        int maxAcc = 4;
        try {
            Class<?> uc = XposedHelpers.findClassIfExists("org.telegram.messenger.UserConfig", classLoader);
            if (uc != null) {
                // Forked clients (e.g. Plus Messenger) commonly run 10+ accounts (acc8, acc9).
                maxAcc = 16;
                try {
                    int val = XposedHelpers.getStaticIntField(uc, "MAX_ACCOUNT_COUNT");
                    if (val > maxAcc) {
                        maxAcc = Math.min(32, val);
                    }
                } catch (Throwable ignored) {
                }
                try {
                    int sel = XposedHelpers.getStaticIntField(uc, "selectedAccount");
                    if (sel >= maxAcc && sel < 32) {
                        maxAcc = sel + 1;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return maxAcc;
    }

    static boolean isAccountActivated(Class<?> userConfigCls, int acc) {
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

    static String extractProxyInfoAddress(Object item) {
        if (item == null) {
            return "";
        }
        try {
            Object settings = XposedHelpers.getObjectField(item, "settings");
            if (settings != null) {
                Object addr = XposedHelpers.callMethod(settings, "getAddress");
                if (addr != null) {
                    return WireGuardManager.safeTrim(String.valueOf(addr));
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            return WireGuardManager.safeTrim((String) XposedHelpers.getObjectField(item, "address"));
        } catch (Throwable ignored) {
            return "";
        }
    }

    static int extractProxyInfoPort(Object item) {
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
        Context ctx = WireGuardManager.getSocksPrefsContext();
        String socksUser = enabled ? WireGuardManager.getClientSocksUser(ctx) : "";
        String socksPass = enabled ? WireGuardManager.getActiveSocksPass() : "";
        boolean hsHealthy = enabled && WireGuardManager.isHandshakeHealthyNow(ctx, null);
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

    static void syncBadgeOnly(
            ClassLoader classLoader,
            boolean enabled,
            int localPort,
            String socksUser,
            String socksPass,
            boolean hsHealthy
    ) {
        if (classLoader == null) {
            return;
        }
        try {
            String safeUser = socksUser != null ? socksUser : "";
            String safePass = socksPass != null ? socksPass : "";
            syncSharedConfigProxyList(classLoader, enabled, localPort, safeUser, safePass, hsHealthy);
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

                wakeSingleAccountSilently(connectionsManagerClass, inst, acc);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void wakeSingleAccountSilently(Class<?> connectionsManagerClass, Object inst, int acc) {
        try {
            XposedHelpers.callStaticMethod(
                    connectionsManagerClass,
                    "native_setNetworkAvailable",
                    new Class<?>[]{int.class, boolean.class, int.class, boolean.class},
                    acc,
                    true,
                    1,
                    false
            );
        } catch (Throwable ignored) {
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

    /**
     * Two-stage recovery that wakes tgnet immediately without sending native_setNetworkAvailable(false)
     * (preventing any "Waiting for network" UI flash on healthy connections), and only cycles offline->online
     * after 2.8s if an outage left specific account slots stuck outside ConnectionStateConnected (3).
     */
    static void smartRecoverTelegramConnections(final ClassLoader classLoader, boolean scheduleFallbackCycleIfStuck) {
        if (classLoader == null) {
            return;
        }
        nudgeTelegramConnections(classLoader, false);
        if (!scheduleFallbackCycleIfStuck) {
            return;
        }
        try {
            WireGuardManager.getGuardianExecutor().schedule(() -> {
                try {
                    Context ctx = WireGuardManager.getSocksPrefsContext();
                    if (!WgHealthAndContinuity.hasActiveOsNetwork(ctx)) {
                        return;
                    }
                    Class<?> cmCls = XposedHelpers.findClassIfExists("org.telegram.tgnet.ConnectionsManager", classLoader);
                    if (cmCls == null) {
                        return;
                    }
                    Class<?> ucCls = XposedHelpers.findClassIfExists("org.telegram.messenger.UserConfig", classLoader);
                    int maxAcc = resolveMaxAccountCount(classLoader);
                    for (int acc = 0; acc < maxAcc; acc++) {
                        if (!isAccountActivated(ucCls, acc)) {
                            continue;
                        }
                        Object inst = null;
                        int state = -1;
                        try {
                            inst = XposedHelpers.callStaticMethod(cmCls, "getInstance", new Class<?>[]{int.class}, acc);
                            if (inst != null) {
                                state = (Integer) XposedHelpers.callMethod(inst, "getConnectionState");
                            }
                        } catch (Throwable ignored) {
                        }
                        if (state == 3) {
                            continue;
                        }
                        try {
                            XposedHelpers.callStaticMethod(
                                    cmCls,
                                    "native_setNetworkAvailable",
                                    new Class<?>[]{int.class, boolean.class, int.class, boolean.class},
                                    acc,
                                    false,
                                    0,
                                    false
                            );
                        } catch (Throwable ignored) {
                        }
                        wakeSingleAccountSilently(cmCls, inst, acc);
                    }
                } catch (Throwable ignored) {
                }
            }, 2800L, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (Throwable ignored) {
        }
    }

    static void forceReconnectTelegramAfterOutage(ClassLoader classLoader) {
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
                if (acc > 0 && !isAccountActivated(userConfigClass, acc)) {
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
                try {
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "native_setNetworkAvailable",
                            new Class<?>[]{int.class, boolean.class, int.class, boolean.class},
                            acc,
                            false,
                            0,
                            false
                    );
                } catch (Throwable ignored) {
                }
                try {
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "native_setNetworkAvailable",
                            new Class<?>[]{int.class, boolean.class, int.class, boolean.class},
                            acc,
                            true,
                            1,
                            false
                    );
                } catch (Throwable ignored) {
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
            try {
                if (XposedHelpers.findMethodExactIfExists(connectionsManagerClass, "onNetworkChanged") != null) {
                    XposedHelpers.callStaticMethod(connectionsManagerClass, "onNetworkChanged");
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {
        }
    }

    static void pauseTelegramForOffline(ClassLoader classLoader) {
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
                if (acc > 0 && !isAccountActivated(userConfigClass, acc)) {
                    continue;
                }
                try {
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "native_setNetworkAvailable",
                            new Class<?>[]{int.class, boolean.class, int.class, boolean.class},
                            acc,
                            false,
                            0,
                            false
                    );
                } catch (Throwable ignored) {
                }
                try {
                    XposedHelpers.callStaticMethod(
                            connectionsManagerClass,
                            "native_pauseNetwork",
                            new Class<?>[]{int.class},
                            acc
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
                        XposedHelpers.callMethod(
                                inst,
                                "setAppPaused",
                                new Class<?>[]{boolean.class, boolean.class},
                                true,
                                false
                        );
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
    }
}
