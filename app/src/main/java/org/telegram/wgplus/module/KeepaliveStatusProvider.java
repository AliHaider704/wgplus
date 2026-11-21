package org.telegram.wgplus.module;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Synchronous Binder IPC bridge queried by hooked Telegram processes ({@code WireGuardManager})
 * and privileged automation callers (shell uid=2000 / root uid=0) via {@code ContentResolver.call}.
 */
public class KeepaliveStatusProvider extends ContentProvider {

    public static final String AUTHORITY = "org.telegram.wgplus.module.status";
    public static final String METHOD_ENSURE_STEALTH = "ensure_stealth";
    public static final String METHOD_QUERY_STATUS = "query_status";
    public static final String METHOD_REGISTER_DAEMON = "register_daemon";
    public static final String METHOD_CACHE_TX_CODE = "cache_tx_code";
    public static final String METHOD_REPORT_HOOK_ACTIVE = "report_hook_active";
    public static final String METHOD_QUERY_HOOK_STATUS = "query_hook_status";
    public static final String METHOD_REQUEST_REMOTE_HYGIENE = "request_remote_hygiene";

    // Privileged headless automation APIs (shell/root callers only)
    public static final String METHOD_AUTOMATION_STATUS = "automation_status";
    public static final String METHOD_AUTOMATION_QUICK_WARP = "automation_quick_warp";
    public static final String METHOD_AUTOMATION_IMPORT_CONF = "automation_import_conf";
    public static final String METHOD_AUTOMATION_CLEAN_CACHE = "automation_clean_cache";

    // Cross-client shared config/state sync APIs (companion + hooked Telegram packages)
    public static final String METHOD_SYNC_PULL_STATE = "sync_pull_shared_state";
    public static final String METHOD_SYNC_PUSH_STATE = "sync_push_shared_state";
    public static final String EXTRA_JSON = "json";

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
    public static final String RESULT_HOOK_PKG = "hook_pkg";
    public static final String RESULT_HOOK_LAST_MS = "hook_last_ms";
    public static final String RESULT_HYGIENE_REQ_MS = "hygiene_req_ms";
    public static final String RESULT_JSON = "json";

    private static final String HOOK_PREFS = "wg_plus_hook_telemetry";
    private static final String KEY_HOOK_PKG = "hook_last_pkg";
    private static final String KEY_HOOK_LAST_MS = "hook_last_epoch_ms";
    private static final String KEY_HOOK_PACKAGES_JSON = "hook_packages_json";
    private static final String KEY_HYGIENE_REQ_MS = "hygiene_req_ms";

    private static SharedPreferences hookPrefs(Context ctx) {
        Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        return appCtx.getSharedPreferences(HOOK_PREFS, Context.MODE_PRIVATE);
    }

    public static void recordHookHeartbeatLocal(Context ctx, String pkg) {
        if (ctx == null || pkg == null || pkg.isEmpty()) {
            return;
        }
        String safe = sanitizePackageName(pkg);
        if (safe.isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        SharedPreferences prefs = hookPrefs(ctx);
        JSONObject map = new JSONObject();
        try {
            String raw = prefs.getString(KEY_HOOK_PACKAGES_JSON, "");
            if (!raw.isEmpty()) {
                map = new JSONObject(raw);
            }
            map.put(safe, now);
        } catch (Throwable ignored) {
        }
        prefs.edit()
                .putString(KEY_HOOK_PKG, safe)
                .putLong(KEY_HOOK_LAST_MS, now)
                .putString(KEY_HOOK_PACKAGES_JSON, map.toString())
                .apply();
    }

    public static void requestRemoteHygieneLocal(Context ctx) {
        if (ctx == null) {
            return;
        }
        hookPrefs(ctx).edit().putLong(KEY_HYGIENE_REQ_MS, System.currentTimeMillis()).apply();
    }

    public static Bundle readHookTelemetryBundle(Context ctx) {
        Bundle b = new Bundle();
        if (ctx == null) {
            return b;
        }
        SharedPreferences p = hookPrefs(ctx);
        b.putString(RESULT_HOOK_PKG, p.getString(KEY_HOOK_PKG, ""));
        b.putLong(RESULT_HOOK_LAST_MS, p.getLong(KEY_HOOK_LAST_MS, 0L));
        b.putLong(RESULT_HYGIENE_REQ_MS, p.getLong(KEY_HYGIENE_REQ_MS, 0L));
        return b;
    }

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
        if (METHOD_REPORT_HOOK_ACTIVE.equals(method)) {
            if (!safePkg.isEmpty()) {
                recordHookHeartbeatLocal(ctx, safePkg);
            }
            return readHookTelemetryBundle(ctx);
        }
        if (METHOD_QUERY_HOOK_STATUS.equals(method)) {
            return readHookTelemetryBundle(ctx);
        }
        if (METHOD_REQUEST_REMOTE_HYGIENE.equals(method)) {
            requestRemoteHygieneLocal(ctx);
            return readHookTelemetryBundle(ctx);
        }
        if (METHOD_SYNC_PULL_STATE.equals(method)) {
            if (!isTrustedSyncCaller(ctx)) {
                return null;
            }
            Bundle out = new Bundle();
            out.putString(RESULT_JSON, WireGuardManager.exportSharedSyncBundleJson(ctx));
            return out;
        }
        if (METHOD_SYNC_PUSH_STATE.equals(method)) {
            if (!isTrustedSyncCaller(ctx)) {
                return null;
            }
            String json = extras != null ? extras.getString(EXTRA_JSON, "") : "";
            long rev = WireGuardManager.importSharedSyncBundleJson(ctx, json, false);
            Bundle out = new Bundle();
            out.putBoolean("ok", rev >= 0);
            out.putLong("stateRev", rev);
            return out;
        }
        if (METHOD_AUTOMATION_STATUS.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            return handleAutomationStatus(ctx);
        }
        if (METHOD_AUTOMATION_QUICK_WARP.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            return handleAutomationQuickWarp(ctx, extras);
        }
        if (METHOD_AUTOMATION_IMPORT_CONF.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            return handleAutomationImportConf(ctx, extras);
        }
        if (METHOD_AUTOMATION_CLEAN_CACHE.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            return handleAutomationCleanCache(ctx);
        }
        return null;
    }

    private static Bundle handleAutomationStatus(Context ctx) {
        Bundle out = new Bundle();
        try {
            ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(ctx);
            Bundle hook = readHookTelemetryBundle(ctx);
            List<String> installed = ContinuityBridgeManager.getInstalledTargetPackages(ctx);
            String apkPath = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
            boolean running = false;
            int port = 0;
            WireGuardManager.TunnelStats stats = new WireGuardManager.TunnelStats();
            try {
                running = WireGuardManager.isTunnelRunning(ctx, apkPath);
                port = running ? WireGuardManager.getActivePort(ctx, apkPath) : 0;
                if (running) {
                    stats = WireGuardManager.getLiveStats(ctx, apkPath);
                }
            } catch (Throwable ignored) {
            }
            JSONObject obj = new JSONObject();
            obj.put("version", WgStrings.VERSION_LABEL);
            obj.put("installedClients", new JSONArray(installed));
            obj.put("hookPackage", hook.getString(RESULT_HOOK_PKG, ""));
            obj.put("hookLastSeenMs", hook.getLong(RESULT_HOOK_LAST_MS, 0L));
            JSONArray hookPackagesArr = new JSONArray();
            try {
                String rawMap = hookPrefs(ctx).getString(KEY_HOOK_PACKAGES_JSON, "");
                if (!rawMap.isEmpty()) {
                    JSONObject map = new JSONObject(rawMap);
                    java.util.Iterator<String> keys = map.keys();
                    while (keys.hasNext()) {
                        hookPackagesArr.put(keys.next());
                    }
                }
            } catch (Throwable ignored) {
            }
            obj.put("hookPackages", hookPackagesArr);
            obj.put("hasConfiguredProfile", WireGuardManager.hasAnyConfiguredProfile(ctx));
            obj.put("tunnelRunning", running);
            obj.put("activePort", port);
            obj.put("rxBytes", stats.rxBytes);
            obj.put("txBytes", stats.txBytes);
            obj.put("lastHandshakeSec", stats.lastHandshakeSec);
            obj.put("privilegeMode", ContinuityBridgeManager.getActivePrivilegeMode(ctx));
            obj.put("continuityTier", snap.tier.name());
            obj.put("stealthProtected", snap.stealthProtected);
            obj.put("daemonActive", snap.daemonActive);
            obj.put("rootActive", snap.rootActive);
            out.putString(RESULT_JSON, obj.toString());
        } catch (Throwable t) {
            out.putString(RESULT_JSON, "{\"error\":\"" + String.valueOf(t.getMessage()).replace("\"", "'") + "\"}");
        }
        return out;
    }

    private static Bundle handleAutomationQuickWarp(Context ctx, Bundle extras) {
        Bundle out = new Bundle();
        try {
            boolean forceNew = extras != null && extras.getBoolean("force_new", false);
            String apkPath = ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
            WireGuardManager.QuickWarpResult res = WireGuardManager.quickConnectFreeWarp(ctx, apkPath, null, forceNew);
            JSONObject obj = new JSONObject();
            obj.put("ok", true);
            obj.put("profileId", res.profile != null ? res.profile.id : "");
            obj.put("profileName", res.profile != null ? res.profile.name : "");
            obj.put("endpoint", res.profile != null ? res.profile.endpoint : "");
            obj.put("localPort", res.localPort);
            obj.put("createdNew", res.createdNew);
            out.putString(RESULT_JSON, obj.toString());
        } catch (Throwable t) {
            out.putString(RESULT_JSON, "{\"ok\":false,\"error\":\"" + String.valueOf(t.getMessage()).replace("\"", "'") + "\"}");
        }
        return out;
    }

    private static Bundle handleAutomationImportConf(Context ctx, Bundle extras) {
        Bundle out = new Bundle();
        try {
            String conf = extras != null ? extras.getString("conf", "") : "";
            String name = extras != null ? extras.getString("name", "") : "";
            WireGuardManager.TunnelConfig imported = WireGuardManager.importConfAsProfile(
                    ctx,
                    conf,
                    name,
                    WireGuardManager.isAutoConnectEnabled(ctx),
                    WireGuardManager.isRouteCallsEnabled(ctx)
            );
            JSONObject obj = new JSONObject();
            obj.put("ok", true);
            obj.put("profileId", imported.id);
            obj.put("profileName", imported.name);
            obj.put("endpoint", imported.endpoint);
            out.putString(RESULT_JSON, obj.toString());
        } catch (Throwable t) {
            out.putString(RESULT_JSON, "{\"ok\":false,\"error\":\"" + String.valueOf(t.getMessage()).replace("\"", "'") + "\"}");
        }
        return out;
    }

    private static Bundle handleAutomationCleanCache(Context ctx) {
        Bundle out = new Bundle();
        try {
            requestRemoteHygieneLocal(ctx);
            ModuleHygieneManager.HygieneReport report = ModuleHygieneManager.cleanCachesSafely(ctx, true);
            JSONObject obj = new JSONObject();
            obj.put("ok", true);
            obj.put("freedBytes", report.freedBytes);
            obj.put("filesDeleted", report.filesDeleted);
            obj.put("ramTrimmed", report.ramTrimmed);
            out.putString(RESULT_JSON, obj.toString());
        } catch (Throwable t) {
            out.putString(RESULT_JSON, "{\"ok\":false,\"error\":\"" + String.valueOf(t.getMessage()).replace("\"", "'") + "\"}");
        }
        return out;
    }

    private static boolean isPrivilegedCaller() {
        int caller = Binder.getCallingUid();
        return caller == Process.myUid() || caller == 0 || caller == 2000;
    }

    private static boolean isTrustedSyncCaller(Context ctx) {
        if (isPrivilegedCaller()) {
            return true;
        }
        if (ctx == null) {
            return false;
        }
        try {
            String[] pkgs = ctx.getPackageManager().getPackagesForUid(Binder.getCallingUid());
            if (pkgs == null) {
                return false;
            }
            for (String p : pkgs) {
                for (String target : ContinuityBridgeManager.DEFAULT_TARGET_PACKAGES) {
                    if (target.equals(p)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
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
