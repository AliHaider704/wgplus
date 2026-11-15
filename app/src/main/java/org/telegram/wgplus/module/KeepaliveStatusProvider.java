package org.telegram.wgplus.module;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

/**
 * Synchronous Binder IPC bridge queried by hooked Telegram processes ({@code WireGuardManager})
 * via {@code ContentResolver.call} to elevate PID importance via Sovereign Self-Privilege /
 * Root / Standalone Daemon and ensure silent {@link KeepaliveBridgeListenerService}
 * capability binding before deciding foreground service promotion.
 */
public class KeepaliveStatusProvider extends ContentProvider {

    public static final String AUTHORITY = "org.telegram.wgplus.module.status";
    public static final String METHOD_ENSURE_STEALTH = "ensure_stealth";
    public static final String METHOD_QUERY_STATUS = "query_status";
    public static final String METHOD_REGISTER_DAEMON = "register_daemon";
    public static final String METHOD_CACHE_TX_CODE = "cache_tx_code";

    public static final String EXTRA_PID = "pid";
    public static final String EXTRA_WANTS_ALWAYS_AWAKE = "wants_always_awake";

    public static final String RESULT_STEALTH_PROTECTED = "stealth_protected";
    public static final String RESULT_FORCED_IMPORTANT = "forced_important";
    public static final String RESULT_LISTENER_ACTIVE = "listener_active";
    public static final String RESULT_TIER = "tier";
    public static final String RESULT_PRIVILEGE_MODE = "privilege_mode";
    public static final String RESULT_SELF_PRIVILEGED = "self_privileged";
    public static final String RESULT_DAEMON_ACTIVE = "daemon_active";
    public static final String RESULT_ROOT_ACTIVE = "root_active";
    public static final String RESULT_SECURE_SETTINGS = "secure_settings_granted";
    public static final String RESULT_ADB_PAIRED = "adb_paired";
    public static final String RESULT_ADB_TCP_PORT = "adb_tcp_port";

    @Override
    public boolean onCreate() {
        Context ctx = getContext();
        if (ctx != null) {
            ContinuityBridgeManager.registerPassiveWifiRecovery(ctx);
        }
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        Context ctx = getContext();
        if (ctx == null) {
            return null;
        }
        if (METHOD_REGISTER_DAEMON.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            if (extras != null) {
                int port = extras.getInt("port", -1);
                int pid = extras.getInt("pid", -1);
                int uid = extras.getInt("uid", -1);
                int tx = extras.getInt("tx", -1);
                String token = extras.getString("token", "");
                PrivilegeBridge.registerDaemonEndpoint(ctx, port, pid, uid, tx, token);
                Bundle out = new Bundle();
                out.putBoolean("registered", port > 0 && !token.isEmpty());
                return out;
            }
            return null;
        }
        if (METHOD_CACHE_TX_CODE.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            int tx = extras != null ? extras.getInt("tx", -1) : -1;
            PrivilegeBridge.cacheResolvedTxCode(ctx, tx);
            Bundle out = new Bundle();
            out.putInt("tx", tx);
            return out;
        }
        String safePkg = sanitizePackageName(arg);
        if (METHOD_ENSURE_STEALTH.equals(method)) {
            int pid = extras != null ? extras.getInt(EXTRA_PID, -1) : -1;
            boolean wantsAwake = extras == null || extras.getBoolean(EXTRA_WANTS_ALWAYS_AWAKE, true);
            ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.ensureStealthProtection(
                    ctx,
                    safePkg,
                    pid,
                    wantsAwake
            );
            return toBundle(ctx, snap);
        }
        if (METHOD_QUERY_STATUS.equals(method)) {
            return toBundle(ctx, ContinuityBridgeManager.captureStatusSnapshot(ctx));
        }
        return null;
    }

    private static boolean isPrivilegedCaller() {
        int caller = Binder.getCallingUid();
        return caller == Process.myUid() || caller == 0 || caller == 2000;
    }

    private static Bundle toBundle(Context ctx, ContinuityBridgeManager.StealthSnapshot snap) {
        Bundle b = new Bundle();
        b.putBoolean(RESULT_STEALTH_PROTECTED, snap.stealthProtected);
        b.putBoolean(RESULT_FORCED_IMPORTANT, snap.forcedImportant);
        b.putBoolean(RESULT_LISTENER_ACTIVE, snap.listenerConnected || snap.listenerEnabled);
        b.putString(RESULT_TIER, snap.tier.name());
        b.putString(RESULT_PRIVILEGE_MODE, ContinuityBridgeManager.getActivePrivilegeMode(ctx));
        b.putBoolean(RESULT_SELF_PRIVILEGED, PrivilegeBridge.hasSelfProcessLimitPermission(ctx));
        b.putBoolean(RESULT_DAEMON_ACTIVE, PrivilegeBridge.isStandaloneDaemonAlive(ctx));
        b.putBoolean(RESULT_ROOT_ACTIVE, snap.rootActive);
        b.putBoolean(RESULT_SECURE_SETTINGS, PrivilegeBridge.hasSelfWriteSecureSettingsPermission(ctx));
        b.putBoolean(RESULT_ADB_PAIRED, snap.builtinAdbPaired);
        b.putInt(RESULT_ADB_TCP_PORT, BuiltinAdbKeyManager.getDynamicTcpPort(ctx));
        return b;
    }

    private static String sanitizePackageName(String pkg) {
        if (pkg == null) {
            return "";
        }
        String trimmed = pkg.trim();
        if (trimmed.length() > 128 || trimmed.isEmpty()) {
            return "";
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '_';
            if (!ok) {
                return "";
            }
        }
        return trimmed;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
