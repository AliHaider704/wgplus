package org.telegram.wgplus.module;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.BatteryManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.conscrypt.Conscrypt;

import io.github.muntashirakon.adb.AbsAdbConnectionManager;
import io.github.muntashirakon.adb.AdbPairingRequiredException;
import io.github.muntashirakon.adb.AdbStream;

/**
 * Self-contained Wireless ADB client backed by libadb-android + Conscrypt TLS 1.3 + SPAKE2.
 * Supports one-time 6-digit pairing, automatic silent TLS reconnection on Wi-Fi via
 * WRITE_SECURE_SETTINGS (keeping adb_wifi_enabled active without notifications), and dynamic
 * loopback TCP port reconnection (127.0.0.1:<dynamicPort>) when strictly on Mobile Data.
 */
public final class WgAdbConnectionManager extends AbsAdbConnectionManager {

    private static final String TAG = "WGPlusBuiltinAdb";
    private static final long CONNECT_TIMEOUT_MS = 7000L;

    private static volatile WgAdbConnectionManager sInstance;
    private static volatile boolean sConscryptInstalled;
    private static final Object IO_LOCK = new Object();

    private final Context mAppCtx;
    private final PrivateKey mPrivateKey;
    private final Certificate mCertificate;

    private WgAdbConnectionManager(Context appCtx, BuiltinAdbKeyManager.KeyIdentity identity) {
        this.mAppCtx = appCtx;
        this.mPrivateKey = identity.privateKey;
        this.mCertificate = identity.certificate;
        setApi(Build.VERSION.SDK_INT);
        setTimeout(15L, TimeUnit.SECONDS);
        setThrowOnUnauthorised(true);
    }

    private static void ensureConscrypt() {
        if (sConscryptInstalled) {
            return;
        }
        try {
            if (Security.getProvider("Conscrypt") == null) {
                Security.insertProviderAt(Conscrypt.newProvider(), 1);
            }
            sConscryptInstalled = true;
        } catch (Throwable t) {
            Log.w(TAG, "Conscrypt insert warning: " + t.getMessage());
        }
    }

    public static synchronized WgAdbConnectionManager getInstance(Context context) throws Exception {
        ensureConscrypt();
        if (sInstance != null) {
            return sInstance;
        }
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        BuiltinAdbKeyManager.KeyIdentity id = BuiltinAdbKeyManager.getOrCreateIdentity(appCtx);
        sInstance = new WgAdbConnectionManager(appCtx, id);
        return sInstance;
    }

    @Override
    protected PrivateKey getPrivateKey() {
        return mPrivateKey;
    }

    @Override
    protected Certificate getCertificate() {
        return mCertificate;
    }

    @Override
    protected String getDeviceName() {
        return "WireGuardPlus";
    }

    /**
     * Completes one-time SPAKE2 + TLS 1.3 Wireless Debugging pairing on Android 11+.
     */
    public boolean pairWithCode(Context context, String host, int port, String sixDigitCode) {
        if (!BuiltinAdbKeyManager.isValidPairingCode(sixDigitCode) || port <= 1024 || port > 65535) {
            return false;
        }
        String safeHost = (host == null || host.trim().isEmpty()) ? "127.0.0.1" : host.trim();
        synchronized (IO_LOCK) {
            try {
                boolean paired = pair(safeHost, port, sixDigitCode.trim());
                if (paired) {
                    BuiltinAdbKeyManager.markPaired(mAppCtx, true);
                    bootstrapSovereignShellLocked(true);
                }
                return paired;
            } catch (Throwable t) {
                Log.w(TAG, "pairWithCode failed: " + t.getMessage());
                return false;
            }
        }
    }

    /**
     * Connects silently using dynamic local TCP loopback first (works on Mobile Data without Wi-Fi),
     * then falls back to Wireless Debugging TLS (NsdManager _adb-tls-connect._tcp) on Wi-Fi.
     */
    public boolean connectSmart(boolean allowEnableWifiAdb) {
        synchronized (IO_LOCK) {
            return connectSmartLocked(allowEnableWifiAdb) != ConnectPath.NONE;
        }
    }

    public PrivilegeBridge.ShellResult runShellCommand(String command, int timeoutMs) {
        if (command == null || command.trim().isEmpty()) {
            return new PrivilegeBridge.ShellResult(-1, "empty", false);
        }
        synchronized (IO_LOCK) {
            ConnectPath path = connectSmartLocked(true);
            if (path == ConnectPath.NONE) {
                return new PrivilegeBridge.ShellResult(-1, "builtin adb unavailable", false);
            }
            try {
                return execOverConnectedAdbLocked(command, timeoutMs);
            } finally {
                try {
                    disconnect();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    public boolean bootstrapSovereignShell(boolean allowEnableWifiAdb) {
        synchronized (IO_LOCK) {
            return bootstrapSovereignShellLocked(allowEnableWifiAdb);
        }
    }

    private boolean bootstrapSovereignShellLocked(boolean allowEnableWifiAdb) {
        ConnectPath path = connectSmartLocked(allowEnableWifiAdb);
        if (path == ConnectPath.NONE) {
            return false;
        }
        try {
            List<String> targets = collectTargets();
            String modulePkg = mAppCtx.getPackageName();
            String listenerComp = modulePkg + "/" + KeepaliveBridgeListenerService.class.getName();
            boolean daemonAlreadyAlive = PrivilegeBridge.isStandaloneDaemonAlive(mAppCtx);
            StringBuilder quickCmd = new StringBuilder();
            if (!PrivilegeBridge.hasSelfProcessLimitPermission(mAppCtx)
                    || !PrivilegeBridge.hasSelfWriteSecureSettingsPermission(mAppCtx)) {
                quickCmd.append("pm grant ").append(modulePkg)
                        .append(" android.permission.SET_PROCESS_LIMIT 2>/dev/null || true; ");
                quickCmd.append("pm grant ").append(modulePkg)
                        .append(" android.permission.WRITE_SECURE_SETTINGS 2>/dev/null || true; ");
            }
            if (!KeepaliveBridgeListenerService.isNotificationListenerEnabled(mAppCtx)) {
                quickCmd.append("cmd notification allow_listener ").append(listenerComp)
                        .append(" 2>/dev/null || true; ");
            }
            if (!daemonAlreadyAlive) {
                String daemonCmd = PrivilegeBridge.buildDaemonLaunchCommand(mAppCtx, targets);
                if (!daemonCmd.isEmpty()) {
                    quickCmd.append(daemonCmd).append(" sleep 0.25;");
                }
            } else {
                quickCmd.append("cmd deviceidle whitelist +").append(modulePkg).append(" 2>/dev/null || true;");
            }
            PrivilegeBridge.ShellResult res = execOverConnectedAdbLocked(quickCmd.toString(), 6000);

            if (path == ConnectPath.WIFI_TLS
                    && BuiltinAdbKeyManager.isMobileTcpHealEnabled(mAppCtx)
                    && !isUsbConnected(mAppCtx)) {
                ensureDynamicTcpPortLocked();
            }
            return res.ok;
        } catch (Throwable t) {
            Log.w(TAG, "bootstrapSovereignShell warning: " + t.getMessage());
            return false;
        } finally {
            try {
                disconnect();
            } catch (Throwable ignored) {
            }
        }
    }

    private enum ConnectPath {
        NONE,
        LOCAL_TCP,
        WIFI_TLS
    }

    private ConnectPath connectSmartLocked(boolean allowEnableWifiAdb) {
        if (isConnected()) {
            return ConnectPath.WIFI_TLS;
        }

        // 1. Dynamic local TCP port probe (works even when Wi-Fi is OFF / Mobile Data ONLY)
        int dynPort = BuiltinAdbKeyManager.getDynamicTcpPort(mAppCtx);
        if (tryConnectTcpPortLocked(dynPort)) {
            return ConnectPath.LOCAL_TCP;
        }
        if (dynPort != 5555 && tryConnectTcpPortLocked(5555)) {
            BuiltinAdbKeyManager.setDynamicTcpPort(mAppCtx, 5555);
            return ConnectPath.LOCAL_TCP;
        }

        // 2. Wireless Debugging TLS over Wi-Fi (Android requires Wi-Fi for adb_wifi_enabled)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || !isWifiConnected(mAppCtx)) {
            return ConnectPath.NONE;
        }
        if (!BuiltinAdbKeyManager.isPaired(mAppCtx)) {
            return ConnectPath.NONE;
        }

        if (allowEnableWifiAdb && PrivilegeBridge.hasSelfWriteSecureSettingsPermission(mAppCtx)) {
            try {
                Settings.Global.putInt(mAppCtx.getContentResolver(), "adb_enabled", 1);
                if (Settings.Global.getInt(mAppCtx.getContentResolver(), "adb_wifi_enabled", 0) != 1) {
                    Settings.Global.putInt(mAppCtx.getContentResolver(), "adb_wifi_enabled", 1);
                    try {
                        Thread.sleep(600L);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "enable adb_wifi_enabled warning: " + t.getMessage());
            }
        }

        try {
            if (connectTls(mAppCtx, CONNECT_TIMEOUT_MS)) {
                BuiltinAdbKeyManager.markPaired(mAppCtx, true);
                return ConnectPath.WIFI_TLS;
            }
        } catch (AdbPairingRequiredException e) {
            Log.w(TAG, "Pairing key rejected by adbd; clearing paired flag");
            BuiltinAdbKeyManager.markPaired(mAppCtx, false);
        } catch (Throwable t) {
            Log.w(TAG, "connectTls warning: " + t.getMessage());
        }
        return ConnectPath.NONE;
    }

    private boolean tryConnectTcpPortLocked(int port) {
        if (!BuiltinAdbKeyManager.isLoopbackPortOpen(port)) {
            return false;
        }
        try {
            if (connect("127.0.0.1", port)) {
                return true;
            }
        } catch (Throwable t) {
            Log.d(TAG, "Local TCP port " + port + " connect skipped: " + t.getMessage());
        }
        return false;
    }

    private void ensureDynamicTcpPortLocked() {
        try {
            int candidate = BuiltinAdbKeyManager.pickCandidateDynamicPort(mAppCtx);
            try (AdbStream stream = openStream("tcpip:" + candidate)) {
                // Consume acknowledgment briefly
                byte[] buf = new byte[256];
                long deadline = System.currentTimeMillis() + 1200L;
                while (System.currentTimeMillis() < deadline && !stream.isClosed()) {
                    if (stream.available() > 0) {
                        stream.read(buf, 0, buf.length);
                        break;
                    }
                    Thread.sleep(60L);
                }
            }
            BuiltinAdbKeyManager.setDynamicTcpPort(mAppCtx, candidate);
        } catch (Throwable t) {
            Log.d(TAG, "ensureDynamicTcpPort skipped: " + t.getMessage());
        }
    }

    private PrivilegeBridge.ShellResult execOverConnectedAdbLocked(String cmd, int timeoutMs) {
        try (AdbStream stream = openStream("shell:" + cmd)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InputStream is = stream.openInputStream();
            byte[] buf = new byte[4096];
            long deadline = System.currentTimeMillis() + Math.max(1500L, timeoutMs);
            while (System.currentTimeMillis() < deadline) {
                int avail = stream.available();
                if (avail > 0) {
                    int n = is.read(buf, 0, Math.min(buf.length, avail));
                    if (n < 0) {
                        break;
                    }
                    if (n > 0) {
                        out.write(buf, 0, n);
                    }
                } else if (stream.isClosed()) {
                    break;
                } else {
                    Thread.sleep(25L);
                }
            }
            String text = new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
            return new PrivilegeBridge.ShellResult(0, text, true);
        } catch (Throwable t) {
            return new PrivilegeBridge.ShellResult(-1, t.getMessage(), false);
        }
    }

    private List<String> collectTargets() {
        ArrayList<String> out = new ArrayList<>();
        out.add(mAppCtx.getPackageName());
        for (String pkg : ContinuityBridgeManager.DEFAULT_TARGET_PACKAGES) {
            if (!out.contains(pkg)) {
                out.add(pkg);
            }
        }
        return out;
    }

    public static boolean isWifiConnected(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = cm.getActiveNetwork();
                if (active != null) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        return true;
                    }
                }
                for (Network net : cm.getAllNetworks()) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                        return true;
                    }
                }
                return false;
            }
            android.net.NetworkInfo info = cm.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
            return info != null && info.isConnected();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isUsbConnected(Context context) {
        try {
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.registerReceiver(null, ifilter);
            if (batteryStatus == null) {
                return false;
            }
            int plugged = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
            return (plugged & BatteryManager.BATTERY_PLUGGED_USB) != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }
}
