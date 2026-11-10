package org.telegram.wgplus.module;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

/**
 * Synchronous Binder IPC bridge queried by hooked Telegram processes ({@code WireGuardManager})
 * via {@code ContentResolver.call} to elevate PID importance via Shizuku and ensure silent
 * {@link KeepaliveBridgeListenerService} capability binding before deciding foreground service promotion.
 */
public class KeepaliveStatusProvider extends ContentProvider {

    public static final String AUTHORITY = "org.telegram.wgplus.module.status";
    public static final String METHOD_ENSURE_STEALTH = "ensure_stealth";
    public static final String METHOD_QUERY_STATUS = "query_status";

    public static final String EXTRA_PID = "pid";
    public static final String EXTRA_WANTS_ALWAYS_AWAKE = "wants_always_awake";

    public static final String RESULT_STEALTH_PROTECTED = "stealth_protected";
    public static final String RESULT_SHIZUKU_RUNNING = "shizuku_running";
    public static final String RESULT_SHIZUKU_GRANTED = "shizuku_granted";
    public static final String RESULT_FORCED_IMPORTANT = "forced_important";
    public static final String RESULT_LISTENER_ACTIVE = "listener_active";
    public static final String RESULT_TIER = "tier";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        Context ctx = getContext();
        if (ctx == null) {
            return null;
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
            return toBundle(snap);
        }
        if (METHOD_QUERY_STATUS.equals(method)) {
            return toBundle(ContinuityBridgeManager.captureStatusSnapshot(ctx));
        }
        return null;
    }

    private static Bundle toBundle(ContinuityBridgeManager.StealthSnapshot snap) {
        Bundle b = new Bundle();
        b.putBoolean(RESULT_STEALTH_PROTECTED, snap.stealthProtected);
        b.putBoolean(RESULT_SHIZUKU_RUNNING, snap.shizukuRunning);
        b.putBoolean(RESULT_SHIZUKU_GRANTED, snap.shizukuGranted);
        b.putBoolean(RESULT_FORCED_IMPORTANT, snap.forcedImportant);
        b.putBoolean(RESULT_LISTENER_ACTIVE, snap.listenerConnected || snap.listenerEnabled);
        b.putString(RESULT_TIER, snap.tier.name());
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
