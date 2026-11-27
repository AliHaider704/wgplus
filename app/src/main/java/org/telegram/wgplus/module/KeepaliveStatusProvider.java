package org.telegram.wgplus.module;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

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
    public static final String METHOD_AUTOMATION_VERIFY = "automation_verify";
    public static final String METHOD_AUTOMATION_QUICK_WARP = "automation_quick_warp";
    public static final String METHOD_AUTOMATION_IMPORT_CONF = "automation_import_conf";
    public static final String METHOD_AUTOMATION_CLEAN_CACHE = "automation_clean_cache";

    // Cross-client shared config/state sync APIs (companion + hooked Telegram packages)
    public static final String METHOD_SYNC_PULL_STATE = "sync_pull_shared_state";
    public static final String METHOD_SYNC_PUSH_STATE = "sync_push_shared_state";
    public static final String METHOD_REGISTER_SHARED_TUNNEL = "register_shared_tunnel";
    public static final String METHOD_QUERY_SHARED_TUNNEL = "query_shared_tunnel";
    public static final String METHOD_CLEAR_SHARED_TUNNEL = "clear_shared_tunnel";
    public static final String METHOD_REQUEST_YIELD_TUNNEL = "request_yield_tunnel";
    public static final String METHOD_START_VOIP_RELAY = "start_voip_relay";
    public static final String EXTRA_JSON = "json";
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORT = "port";
    public static final String RESULT_LOCAL_PORT = "local_port";
    public static final String RESULT_LOCAL_ADDR = "local_addr";

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
    public static final String RESULT_INSTANCES_JSON = "instances_json";
    public static final String RESULT_JSON = "json";

    private static final String HOOK_PREFS = "wg_plus_hook_telemetry";
    private static final String KEY_HOOK_PKG = "hook_last_pkg";
    private static final String KEY_HOOK_LAST_MS = "hook_last_epoch_ms";
    private static final String KEY_HOOK_PACKAGES_JSON = "hook_packages_json";
    private static final String KEY_INSTANCE_PREFIX = "inst_";
    private static final String KEY_HYGIENE_REQ_MS = "hygiene_req_ms";
    private static final long VISIBILITY_GRANT_INTERVAL_MS = 15_000L;
    private static volatile long sLastVisibilityGrantMs = 0L;
    private static volatile String sLastGrantedPkgCsv = "";

    public static void grantVisibilityToInstalledTargets(Context ctx) {
        if (ctx == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - sLastVisibilityGrantMs < VISIBILITY_GRANT_INTERVAL_MS && !sLastGrantedPkgCsv.isEmpty()) {
            return;
        }
        sLastVisibilityGrantMs = now;
        try {
            List<String> targets = ContinuityBridgeManager.getInstalledTargetPackages(ctx);
            if (targets == null || targets.isEmpty()) {
                return;
            }
            Uri providerUri = Uri.parse("content://" + AUTHORITY);
            String myPkg = ctx.getPackageName();
            StringBuilder csv = new StringBuilder();
            for (String pkg : targets) {
                if (pkg == null || pkg.isEmpty() || pkg.equals(myPkg)) {
                    continue;
                }
                if (csv.length() > 0) {
                    csv.append(',');
                }
                csv.append(pkg);
                try {
                    ctx.grantUriPermission(
                            pkg,
                            providerUri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    );
                } catch (Throwable ignored) {
                }
            }
            String joined = csv.toString();
            if (!joined.equals(sLastGrantedPkgCsv)) {
                sLastGrantedPkgCsv = joined;
                WireGuardManager.publishWorldReadableSyncBundle(ctx);
            }
        } catch (Throwable ignored) {
        }
    }

    private static SharedPreferences hookPrefs(Context ctx) {
        Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        return appCtx.getSharedPreferences(HOOK_PREFS, Context.MODE_PRIVATE);
    }

    public static void recordHookHeartbeatLocal(Context ctx, String pkg) {
        recordHookHeartbeatLocal(ctx, pkg, null);
    }

    public static void recordHookHeartbeatLocal(Context ctx, String pkg, Bundle extras) {
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
        JSONObject inst = new JSONObject();
        try {
            String prevRaw = prefs.getString(KEY_INSTANCE_PREFIX + safe, "");
            if (!prevRaw.isEmpty()) {
                inst = new JSONObject(prevRaw);
            }
        } catch (Throwable ignored) {
        }
        try {
            inst.put("pkg", safe);
            inst.put("ts", now);
            if (extras != null) {
                String ver = extras.getString("host_ver", "");
                if (!ver.isEmpty()) inst.put("ver", ver);
                String mode = extras.getString("mode", "");
                if (!mode.isEmpty()) inst.put("mode", mode);
                String role = extras.getString("role", "");
                if (!role.isEmpty()) inst.put("role", role);
                if (extras.containsKey("port")) inst.put("port", extras.getInt("port", -1));
                if (extras.containsKey("running")) inst.put("running", extras.getBoolean("running", false));
                if (extras.containsKey("shared")) inst.put("shared", extras.getBoolean("shared", false));
                String tgState = extras.getString("tg_state", "");
                if (!tgState.isEmpty()) inst.put("tgState", tgState);
                String lastEv = extras.getString("last_event", "");
                if (!lastEv.isEmpty()) inst.put("lastEvent", lastEv);
            }
        } catch (Throwable ignored) {
        }
        prefs.edit()
                .putString(KEY_HOOK_PKG, safe)
                .putLong(KEY_HOOK_LAST_MS, now)
                .putString(KEY_HOOK_PACKAGES_JSON, map.toString())
                .putString(KEY_INSTANCE_PREFIX + safe, inst.toString())
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
        try {
            long now = System.currentTimeMillis();
            java.util.TreeMap<String, JSONObject> sorted = new java.util.TreeMap<>();
            java.util.Map<String, ?> all = p.getAll();
            if (all != null) {
                for (java.util.Map.Entry<String, ?> e : all.entrySet()) {
                    if (e.getKey() != null && e.getKey().startsWith(KEY_INSTANCE_PREFIX) && e.getValue() instanceof String) {
                        try {
                            JSONObject o = new JSONObject((String) e.getValue());
                            String pkg = o.optString("pkg", e.getKey().substring(KEY_INSTANCE_PREFIX.length()));
                            long ts = o.optLong("ts", 0L);
                            o.put("ageSec", ts > 0L ? Math.max(0L, (now - ts) / 1000L) : -1L);
                            sorted.put(pkg, o);
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }
            JSONArray arr = new JSONArray();
            for (JSONObject o : sorted.values()) {
                arr.put(o);
            }
            b.putString(RESULT_INSTANCES_JSON, arr.toString());
        } catch (Throwable ignored) {
            b.putString(RESULT_INSTANCES_JSON, "[]");
        }
        return b;
    }

    @Override
    public boolean onCreate() {
        Context ctx = getContext();
        if (ctx != null) {
            ContinuityBridgeManager.registerPassiveWifiRecovery(ctx);
            grantVisibilityToInstalledTargets(ctx);
            WireGuardManager.publishWorldReadableSyncBundle(ctx);
        }
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        Context ctx = getContext();
        if (ctx == null) {
            return null;
        }
        grantVisibilityToInstalledTargets(ctx);
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
                String resolvedToken = PrivilegeBridge.mintOrUpdateDaemonEndpoint(ctx, port, pid, uid, tx, token);
                Bundle out = new Bundle();
                out.putBoolean("registered", port > 0 && !resolvedToken.isEmpty());
                if (!resolvedToken.isEmpty()) {
                    out.putString("token", resolvedToken);
                }
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
        String callerPkg = resolveVerifiedCallerPackage(ctx, arg);
        if (callerPkg == null) {
            WgDiagnosticsLog.record("SEC", "PROVIDER_DENY", "rejected uid=" + Binder.getCallingUid() + " method=" + method);
            return null;
        }
        String safePkg = callerPkg;
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
                recordHookHeartbeatLocal(ctx, safePkg, extras);
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
            Bundle out = new Bundle();
            out.putString(RESULT_JSON, WireGuardManager.exportSharedSyncBundleJson(ctx));
            return out;
        }
        if (METHOD_SYNC_PUSH_STATE.equals(method)) {
            String json = extras != null ? extras.getString(EXTRA_JSON, "") : "";
            long rev = WireGuardManager.importSharedSyncBundleJson(ctx, json, false);
            if (rev >= 0L) {
                WireGuardManager.publishWorldReadableSyncBundle(ctx);
            }
            Bundle out = new Bundle();
            out.putBoolean("ok", rev >= 0);
            out.putLong("stateRev", rev);
            return out;
        }
        if (METHOD_REGISTER_SHARED_TUNNEL.equals(method)) {
            int port = extras != null ? extras.getInt("port", -1) : -1;
            String sig = extras != null ? extras.getString("sig", "") : "";
            String owner = !safePkg.isEmpty() ? safePkg : (extras != null ? sanitizePackageName(extras.getString("owner", "")) : "");
            String profileId = extras != null ? extras.getString("profileId", "") : "";
            String profileName = extras != null ? extras.getString("profileName", "") : "";
            String socksUser = extras != null ? extras.getString("socksUser", "") : "";
            String socksPass = extras != null ? extras.getString("socksPass", "") : "";
            long lastHsSec = extras != null ? extras.getLong("lastHsSec", 0L) : 0L;
            boolean hsHealthy = extras != null && extras.getBoolean("hsHealthy", false);
            ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE).edit()
                    .putInt("port", port)
                    .putString("sig", sig != null ? sig : "")
                    .putString("owner", owner != null ? owner : "")
                    .putString("profileId", profileId != null ? profileId : "")
                    .putString("profileName", profileName != null ? profileName : "")
                    .putString("socksUser", socksUser != null ? socksUser : "")
                    .putString("socksPass", socksPass != null ? socksPass : "")
                    .putLong("lastHsSec", lastHsSec)
                    .putBoolean("hsHealthy", hsHealthy)
                    .putLong("updatedAt", System.currentTimeMillis())
                    .commit();
            Bundle out = new Bundle();
            out.putBoolean("ok", true);
            return out;
        }
        if (METHOD_QUERY_SHARED_TUNNEL.equals(method)) {
            boolean daemonOrRootActive = PrivilegeBridge.isStandaloneDaemonAlive(ctx)
                    || PrivilegeBridge.isRootAvailablePassive(ctx);
            Bundle liveLocal = WireGuardManager.queryLocalRunningTunnelBundleForProvider(ctx, "nudge".equals(arg));
            if (liveLocal != null) {
                ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE).edit()
                        .putInt("port", liveLocal.getInt("port", -1))
                        .putLong("lastHsSec", liveLocal.getLong("lastHsSec", 0L))
                        .putBoolean("hsHealthy", liveLocal.getBoolean("hsHealthy", false))
                        .putLong("updatedAt", liveLocal.getLong("updatedAt", System.currentTimeMillis()))
                        .commit();
                liveLocal.putBoolean("daemonOrRootActive", daemonOrRootActive);
                return liveLocal;
            }
            android.content.SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
            Bundle out = new Bundle();
            out.putInt("port", sp.getInt("port", -1));
            out.putString("sig", sp.getString("sig", ""));
            out.putString("owner", sp.getString("owner", ""));
            out.putString("profileId", sp.getString("profileId", ""));
            out.putString("profileName", sp.getString("profileName", ""));
            out.putString("socksUser", sp.getString("socksUser", ""));
            out.putString("socksPass", sp.getString("socksPass", ""));
            out.putLong("lastHsSec", sp.getLong("lastHsSec", 0L));
            out.putBoolean("hsHealthy", sp.getBoolean("hsHealthy", false));
            out.putLong("updatedAt", sp.getLong("updatedAt", 0L));
            out.putBoolean("daemonOrRootActive", daemonOrRootActive);
            return out;
        }
        if (METHOD_REQUEST_YIELD_TUNNEL.equals(method)) {
            boolean yielded = WireGuardManager.yieldLocalTunnelForForegroundClient(ctx);
            android.content.SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
            String curOwner = sp.getString("owner", "");
            if ("org.telegram.wgplus.module".equals(curOwner)) {
                sp.edit().clear().commit();
            }
            Bundle out = new Bundle();
            out.putBoolean("yielded", yielded);
            return out;
        }
        if (METHOD_CLEAR_SHARED_TUNNEL.equals(method)) {
            String callerOwner = !safePkg.isEmpty() ? safePkg : (extras != null ? sanitizePackageName(extras.getString("owner", "")) : "");
            int clearPort = extras != null ? extras.getInt("port", -1) : -1;
            android.content.SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
            String curOwner = sp.getString("owner", "");
            int curPort = sp.getInt("port", -1);
            if ((curOwner.isEmpty() || curOwner.equals(callerOwner))
                    && (clearPort <= 0 || curPort <= 0 || clearPort == curPort)) {
                sp.edit().clear().commit();
            }
            Bundle out = new Bundle();
            out.putBoolean("ok", true);
            return out;
        }
        if (METHOD_START_VOIP_RELAY.equals(method)) {
            String host = extras != null ? extras.getString(EXTRA_HOST, "") : "";
            int port = extras != null ? extras.getInt(EXTRA_PORT, -1) : -1;
            String localAddr = WireGuardManager.startLocalVoipEndpointRelayAddr(ctx, host, port);
            if (localAddr.isEmpty()) {
                localAddr = WireGuardManager.startRemoteVoipRelayOverWgp1Addr(ctx, host, port);
            }
            int localPort = WireGuardManager.parsePortFromHostPort(localAddr);
            Bundle out = new Bundle();
            out.putString(RESULT_LOCAL_ADDR, localAddr);
            out.putInt(RESULT_LOCAL_PORT, localPort);
            return out;
        }
        if (METHOD_AUTOMATION_STATUS.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            return handleAutomationStatus(ctx);
        }
        if (METHOD_AUTOMATION_VERIFY.equals(method)) {
            if (!isPrivilegedCaller()) {
                return null;
            }
            return handleAutomationVerify(ctx);
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
            try {
                String instRaw = hook.getString(RESULT_INSTANCES_JSON, "[]");
                obj.put("hookInstances", new JSONArray(instRaw));
            } catch (Throwable ignored) {
            }
            obj.put("hasConfiguredProfile", WireGuardManager.hasAnyConfiguredProfile(ctx));
            obj.put("tunnelRunning", running);
            obj.put("activePort", port);
            long effectiveHsSec = stats.lastHandshakeSec;
            boolean effectiveHsHealthy = effectiveHsSec > 0L;
            if (!effectiveHsHealthy && running && port > 0) {
                android.content.SharedPreferences sp = ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE);
                effectiveHsSec = sp.getLong("lastHsSec", 0L);
                effectiveHsHealthy = effectiveHsSec > 0L && sp.getBoolean("hsHealthy", false);
                String spPass = sp.getString("socksPass", "");
                String probePass = !spPass.isEmpty() ? spPass : WireGuardManager.getActiveSocksPass(ctx);
                long[] live = WireGuardManager.queryLiveStatusOverWgp1(port, probePass);
                if (live != null && live.length >= 3) {
                    running = live[0] == 1L;
                    effectiveHsHealthy = live[1] == 1L;
                    if (live[2] > 0L) {
                        effectiveHsSec = live[2];
                    }
                }
            }
            obj.put("rxBytes", stats.rxBytes);
            obj.put("txBytes", stats.txBytes);
            obj.put("lastHandshakeSec", effectiveHsSec);
            obj.put("handshakeHealthy", effectiveHsHealthy);
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

    private static Bundle handleAutomationVerify(Context ctx) {
        Bundle out = new Bundle();
        try {
            String apkPath = ctx != null && ctx.getApplicationInfo() != null ? ctx.getApplicationInfo().sourceDir : null;
            try {
                NativeBridgeLoader.ensureLoaded(ctx, apkPath);
            } catch (Throwable ignored) {
            }
            int port = WireGuardManager.getActivePort(ctx, apkPath);
            android.content.SharedPreferences sp = ctx != null
                    ? ctx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE)
                    : null;
            if (port <= 0 && sp != null) {
                port = sp.getInt("port", 0);
            }
            String spPass = sp != null ? sp.getString("socksPass", "") : "";
            String probePass = !spPass.isEmpty() ? spPass : WireGuardManager.getActiveSocksPass(ctx);
            String probeUser = WireGuardManager.getActiveSocksUser(ctx);

            JSONObject obj = new JSONObject();
            obj.put("version", WgStrings.VERSION_LABEL);
            obj.put("port", port);
            if (port > 0) {
                String verifyRaw = "";
                try {
                    verifyRaw = wgbridge.Wgbridge.verifyRouteAndCallsJSON(port, probeUser, probePass);
                } catch (Throwable t) {
                    obj.put("verifyError", String.valueOf(t.getMessage()));
                }
                if (verifyRaw != null && !verifyRaw.trim().isEmpty()) {
                    try {
                        obj.put("verify", new JSONObject(verifyRaw));
                    } catch (Throwable ignored) {
                        obj.put("verifyRaw", verifyRaw);
                    }
                }
                String diagRaw = WgSharedHubAndVoip.fetchRemoteEngineDiagnosticsBundle(ctx, apkPath, port);
                if (diagRaw != null && !diagRaw.trim().isEmpty()) {
                    try {
                        obj.put("remoteDiag", new JSONObject(diagRaw));
                    } catch (Throwable ignored) {
                        obj.put("remoteDiagRaw", diagRaw);
                    }
                }
            }
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

    private static final String CERT_PINS_PREFS = "wg_plus_trusted_caller_certs";
    private static final String KEY_APPROVED_PREFIX = "approved_cert_";
    private static final String KEY_PENDING_PREFIX = "pending_cert_";
    private static final String KEY_PENDING_TS_PREFIX = "pending_ts_";
    private static final String KEY_REJECTED_PREFIX = "rejected_cert_";
    // Cryptographically verified via apksigner --print-certs on device/GitHub APKs or APKMirror records (sha256, lowercase hex).
    private static final Set<String> KNOWN_OFFICIAL_CERTS = new HashSet<>(Arrays.asList(
            // Official Telegram Google Play (org.telegram.messenger)
            "496b68c0f0e38839e141ef48b636260b8215c255a0e7aa80147f9bb2e149c173",
            // Official Telegram Direct / Web / Beta (org.telegram.messenger.web, .beta; CN=Nikolay Kudashov, O=VK; apksigner + APKMirror)
            "49c1522548ebacd46ce322b6fd47f6092bb745d0f88082145caf35e14dcc38e1",
            // Plus Messenger (org.telegram.plus; CN=rafalense; apksigner on device + APKMirror)
            "6ebb622268aad319dbe8a1f414837d2843a9b35856aefb7dee2971a3d493f276",
            // Telegram X (org.thunderdog.challegram; APKMirror)
            "b577c8d6f67d2eb1e837e89695993055fd9b9f5fc47f2a0fa5d9de2fb489a385",
            // Nicegram (app.nicegram; Play App Signing; APKMirror)
            "bce0abdcc35da8b05c8824dc602811717cf9e8facf470ad6b2e4c049a7f3a0ca",
            // Graph Messenger / Telegraph (ir.ilmili.telegraph; CN=Masoud BH, O=ilmili; APKMirror)
            "e7d5ad736aeecd2fe237679e4deaf2a40bb32fc07837fe48778a5b41c0418862",
            // Nekogram v13.2.2 (Nekogram-13.2.2-7303-armeabi-v7a.apk; apksigner)
            "5ce932b970199fbda2aae7bf21e1ad9e70b0809a7b1ac94c0699f5d5ada83313",
            // Nagram v13.1.1.1258 (Nagram-v13.1.1.1258-armeabi-v7a.apk; apksigner)
            "88a8afe3ccbee080c13b73832aab8c98a9f19d1c65f3bcfd50b8d01c0bc80e9e",
            // exteraGram v13.2.2 (exteraGram-lite-universal-20261124.apk; apksigner)
            "f1a56d605801a6a73d7270f7ce5a9b126e6669955d2536011dfb20f5f15bf754",
            // Cherrygram 11.6.0 (Cherrygram-11.6.0-TG-13.2.2-armeabi-v7a.apk; apksigner)
            "a9d5ba4a1aa06b969bfec97b557183160c856f1e1401d756a043af110dddc71f",
            // OctoGram v3.5.1_3801 (OctoGram_arm32.apk; apksigner)
            "9bd25f08e031a7c878f468336795191adb23ad8044c1ace4c7cf0f34cdf8d4cd",
            // Forkgram 13.2.3.0 (ForkClient.13.2.3.0.apk; apksigner)
            "0880f186d777f3cb6d82a66d02bd58850e3a270a26b678175459a95511235ae5"
    ));

    public static final class PendingClientApproval {
        public final String pkg;
        public final String certSha256;
        public final boolean certChanged;
        public final long requestedAtMs;

        PendingClientApproval(String pkg, String certSha256, boolean certChanged, long requestedAtMs) {
            this.pkg = pkg;
            this.certSha256 = certSha256;
            this.certChanged = certChanged;
            this.requestedAtMs = requestedAtMs;
        }
    }

    private static boolean isPrivilegedCaller() {
        int caller = Binder.getCallingUid();
        return caller == Process.myUid() || caller == 0 || caller == 2000;
    }

    private static String resolveVerifiedCallerPackage(Context ctx, String argHint) {
        if (isPrivilegedCaller()) {
            return sanitizePackageName(argHint);
        }
        if (ctx == null) {
            return null;
        }
        try {
            PackageManager pm = ctx.getPackageManager();
            if (pm == null) {
                return null;
            }
            String[] pkgs = pm.getPackagesForUid(Binder.getCallingUid());
            if (pkgs == null || pkgs.length == 0) {
                return null;
            }
            for (String p : pkgs) {
                if (!isSupportedTelegramPackage(p)) {
                    continue;
                }
                if (verifyPackageSigningTrust(ctx, pm, p)) {
                    return p;
                }
            }
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SEC", "PROVIDER_VERIFY_ERR", t);
        }
        return null;
    }

    static boolean isSupportedTelegramPackage(String pkg) {
        return pkg != null && ContinuityBridgeManager.DEFAULT_TARGET_PACKAGES.contains(pkg);
    }

    /**
     * Explicit trust evaluator (no silent TOFU and no auto-repin on package updates).
     * Returns 0 = deny (requires explicit user approval in module UI), 1 = allow.
     */
    static int evaluateCallerTrustDecision(
            String pkg,
            String certHash,
            String ownCertHash,
            String userApprovedCert
    ) {
        if (!isSupportedTelegramPackage(pkg) || certHash == null || certHash.isEmpty()) {
            return 0;
        }
        if (KNOWN_OFFICIAL_CERTS.contains(certHash)) {
            return 1;
        }
        if (ownCertHash != null && !ownCertHash.isEmpty() && ownCertHash.equals(certHash)) {
            return 1;
        }
        if (userApprovedCert != null && !userApprovedCert.isEmpty() && userApprovedCert.equals(certHash)) {
            return 1;
        }
        return 0;
    }

    static boolean verifyPackageSigningTrust(Context ctx, PackageManager pm, String pkg) {
        if (ctx == null || pm == null || !isSupportedTelegramPackage(pkg)) {
            return false;
        }
        String certHash = computePrimarySigningCertSha256(pm, pkg);
        String ownCert = computePrimarySigningCertSha256(pm, ctx.getPackageName());
        boolean hasLauncher = hasLauncherEntryActivity(pm, pkg);

        SharedPreferences pins = ctx.getSharedPreferences(CERT_PINS_PREFS, Context.MODE_PRIVATE);
        String approved = pins.getString(KEY_APPROVED_PREFIX + pkg, "");
        String rejected = pins.getString(KEY_REJECTED_PREFIX + pkg, "");

        int decision = evaluateCallerTrustDecision(pkg, certHash, ownCert, approved);
        if (decision > 0) {
            if (pins.contains(KEY_PENDING_PREFIX + pkg)) {
                pins.edit()
                        .remove(KEY_PENDING_PREFIX + pkg)
                        .remove(KEY_PENDING_TS_PREFIX + pkg)
                        .apply();
            }
            return true;
        }

        if (!certHash.isEmpty() && hasLauncher && !certHash.equals(rejected)) {
            String prevPending = pins.getString(KEY_PENDING_PREFIX + pkg, "");
            if (!certHash.equals(prevPending)) {
                pins.edit()
                        .putString(KEY_PENDING_PREFIX + pkg, certHash)
                        .putLong(KEY_PENDING_TS_PREFIX + pkg, System.currentTimeMillis())
                        .apply();
                String code = (!approved.isEmpty() && !approved.equals(certHash))
                        ? "CERT_PIN_MISMATCH"
                        : "CERT_APPROVAL_REQUIRED";
                WgDiagnosticsLog.record("SEC", code,
                        "pkg=" + pkg + " cert12=" + certHash.substring(0, Math.min(12, certHash.length())));
            }
        }
        return false;
    }

    public static List<PendingClientApproval> getPendingClientApprovals(Context ctx) {
        ArrayList<PendingClientApproval> list = new ArrayList<>();
        if (ctx == null) {
            return list;
        }
        try {
            PackageManager pm = ctx.getPackageManager();
            SharedPreferences pins = ctx.getSharedPreferences(CERT_PINS_PREFS, Context.MODE_PRIVATE);
            Map<String, ?> all = pins.getAll();
            if (all == null || all.isEmpty()) {
                return list;
            }
            for (Map.Entry<String, ?> e : all.entrySet()) {
                String k = e.getKey();
                if (k == null || !k.startsWith(KEY_PENDING_PREFIX) || !(e.getValue() instanceof String)) {
                    continue;
                }
                String pkg = k.substring(KEY_PENDING_PREFIX.length());
                String pendingCert = ((String) e.getValue()).trim().toLowerCase(Locale.US);
                if (!isSupportedTelegramPackage(pkg) || pendingCert.length() != 64) {
                    pins.edit().remove(k).remove(KEY_PENDING_TS_PREFIX + pkg).apply();
                    continue;
                }
                if (pm != null && !isPackageInstalled(pm, pkg)) {
                    pins.edit().remove(k).remove(KEY_PENDING_TS_PREFIX + pkg).apply();
                    continue;
                }
                String approved = pins.getString(KEY_APPROVED_PREFIX + pkg, "");
                if (approved.equals(pendingCert) || KNOWN_OFFICIAL_CERTS.contains(pendingCert)) {
                    pins.edit().remove(k).remove(KEY_PENDING_TS_PREFIX + pkg).apply();
                    continue;
                }
                long ts = pins.getLong(KEY_PENDING_TS_PREFIX + pkg, 0L);
                boolean certChanged = !approved.isEmpty() && !approved.equals(pendingCert);
                list.add(new PendingClientApproval(pkg, pendingCert, certChanged, ts));
            }
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SEC", "LIST_PENDING_CERTS_ERR", t);
        }
        return list;
    }

    public static void approveClientCertificate(Context ctx, String pkg, String certSha256) {
        if (ctx == null || !isSupportedTelegramPackage(pkg) || !isValidSha256Hex(certSha256)) {
            return;
        }
        String norm = certSha256.trim().toLowerCase(Locale.US);
        SharedPreferences pins = ctx.getSharedPreferences(CERT_PINS_PREFS, Context.MODE_PRIVATE);
        pins.edit()
                .putString(KEY_APPROVED_PREFIX + pkg, norm)
                .remove(KEY_PENDING_PREFIX + pkg)
                .remove(KEY_PENDING_TS_PREFIX + pkg)
                .remove(KEY_REJECTED_PREFIX + pkg)
                .apply();
        WgDiagnosticsLog.record("SEC", "CERT_USER_APPROVED",
                "pkg=" + pkg + " cert12=" + norm.substring(0, 12));
    }

    public static void rejectClientCertificate(Context ctx, String pkg, String certSha256) {
        if (ctx == null || !isSupportedTelegramPackage(pkg) || !isValidSha256Hex(certSha256)) {
            return;
        }
        String norm = certSha256.trim().toLowerCase(Locale.US);
        SharedPreferences pins = ctx.getSharedPreferences(CERT_PINS_PREFS, Context.MODE_PRIVATE);
        pins.edit()
                .putString(KEY_REJECTED_PREFIX + pkg, norm)
                .remove(KEY_PENDING_PREFIX + pkg)
                .remove(KEY_PENDING_TS_PREFIX + pkg)
                .apply();
        WgDiagnosticsLog.record("SEC", "CERT_USER_REJECTED",
                "pkg=" + pkg + " cert12=" + norm.substring(0, 12));
    }

    private static boolean isValidSha256Hex(String s) {
        if (s == null) {
            return false;
        }
        String trimmed = s.trim();
        if (trimmed.length() != 64) {
            return false;
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            boolean hex = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPackageInstalled(PackageManager pm, String pkg) {
        try {
            return pm.getPackageInfo(pkg, 0) != null;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean hasLauncherEntryActivity(PackageManager pm, String pkg) {
        try {
            Intent mainIntent = new Intent(Intent.ACTION_MAIN);
            mainIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            mainIntent.setPackage(pkg);
            List<ResolveInfo> resolved = pm.queryIntentActivities(mainIntent, 0);
            return resolved != null && !resolved.isEmpty();
        } catch (Throwable ignored) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private static String computePrimarySigningCertSha256(PackageManager pm, String pkg) {
        try {
            Signature activeSig = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi != null && pi.signingInfo != null) {
                    SigningInfo si = pi.signingInfo;
                    Signature[] signers = si.getApkContentsSigners();
                    if (signers != null && signers.length > 0 && signers[0] != null) {
                        activeSig = signers[0];
                    } else {
                        Signature[] history = si.getSigningCertificateHistory();
                        if (history != null && history.length > 0) {
                            activeSig = history[history.length - 1];
                        }
                    }
                }
            } else {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                if (pi != null && pi.signatures != null && pi.signatures.length > 0) {
                    activeSig = pi.signatures[0];
                }
            }
            if (activeSig == null) {
                return "";
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(activeSig.toByteArray());
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format(Locale.US, "%02x", b & 0xff));
            }
            return hex.toString();
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SEC", "CERT_HASH_ERR", t);
            return "";
        }
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

    static String sanitizePackageName(String pkg) {
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
