package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Process;
import android.util.Log;

import java.io.File;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import wgbridge.Wgbridge;

/**
 * Lightweight, non-destructive cache hygiene and RAM trimmer for hooked Telegram clients and the
 * companion app. Cleans only safe module temp files and expired disposable cache entries while
 * strictly preserving LSPatch/Xposed artifacts, DEX/OAT caches, databases, prefs, and session data.
 */
public final class ModuleHygieneManager {

    private static final String TAG = "WGPlusHygiene";
    private static final String HYGIENE_PREFS = "wg_plus_hygiene_prefs";
    private static final String KEY_LAST_RUN_MS = "last_auto_hygiene_ms";
    private static final long AUTO_INTERVAL_MS = 24L * 60L * 60L * 1000L;
    private static final long AUTO_THRESHOLD_BYTES = 150L * 1024L * 1024L;
    private static final long AUTO_MIN_AGE_MS = 2L * 60L * 60L * 1000L;
    private static final long MANUAL_MIN_AGE_MS = 5L * 60L * 1000L;

    private static final ExecutorService HYGIENE_EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(() -> {
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
            } catch (Throwable ignored) {
            }
            r.run();
        }, "wgplus-hygiene");
        t.setDaemon(true);
        return t;
    });

    private static final AtomicBoolean sAutoQueued = new AtomicBoolean(false);
    private static volatile long sLastAutoMemMs = 0L;

    public static final class HygieneReport {
        public final long freedBytes;
        public final int filesDeleted;
        public final boolean ramTrimmed;

        public HygieneReport(long freedBytes, int filesDeleted, boolean ramTrimmed) {
            this.freedBytes = freedBytes;
            this.filesDeleted = filesDeleted;
            this.ramTrimmed = ramTrimmed;
        }
    }

    private ModuleHygieneManager() {
    }

    /**
     * Returns true ONLY if the path segment or relative path is safe temporary cache storage.
     * Protected LSPatch/Xposed, runtime bytecode, native bridge, WebView, and user storage paths
     * always return false.
     */
    static boolean isSafeCachePath(String pathOrName) {
        if (pathOrName == null) {
            return false;
        }
        String low = pathOrName.trim().toLowerCase(Locale.ROOT).replace('\\', '/');
        if (low.isEmpty()) {
            return false;
        }
        String[] blocked = new String[]{
                "lspatch",
                "lsposed",
                "xposed",
                "televip",
                "wg_native",
                "shared_prefs",
                "databases",
                "no_backup",
                "code_cache",
                "webview",
                "chromium",
                "/files",
                "/lib/",
                ".dex",
                ".oat",
                ".vdex",
                ".art",
                "tgnet",
                "cache4.db",
                "userconfing"
        };
        for (String token : blocked) {
            if (low.contains(token)) {
                return false;
            }
        }
        return !low.equals("files") && !low.equals("lib") && !low.endsWith(".apk") && !low.endsWith(".so");
    }

    public static boolean trimInMemoryCaches() {
        boolean trimmed = false;
        try {
            WireGuardManager.clearRuntimePingCache();
            trimmed = true;
        } catch (Throwable ignored) {
        }
        try {
            if (NativeBridgeLoader.isLoaded()) {
                Wgbridge.clearDnsCache();
                trimmed = true;
            }
        } catch (Throwable ignored) {
        }
        return trimmed;
    }

    public static void runAutoHygieneIfDueAsync(final Context hostCtx) {
        if (hostCtx == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - sLastAutoMemMs < AUTO_INTERVAL_MS) {
            return;
        }
        final Context appCtx = hostCtx.getApplicationContext() != null ? hostCtx.getApplicationContext() : hostCtx;
        if (!sAutoQueued.compareAndSet(false, true)) {
            return;
        }
        HYGIENE_EXEC.execute(() -> {
            try {
                SharedPreferences prefs = appCtx.getSharedPreferences(HYGIENE_PREFS, Context.MODE_PRIVATE);
                long prev = prefs.getLong(KEY_LAST_RUN_MS, 0L);
                long cur = System.currentTimeMillis();
                if (cur - prev < AUTO_INTERVAL_MS) {
                    sLastAutoMemMs = prev;
                    return;
                }
                cleanCachesSafely(appCtx, false);
                sLastAutoMemMs = cur;
            } catch (Throwable t) {
                Log.w(TAG, "Auto hygiene warning: " + t.getMessage());
            } finally {
                sAutoQueued.set(false);
            }
        });
    }

    public static HygieneReport cleanCachesSafely(Context ctx, boolean forceThresholdBypass) {
        boolean ramTrimmed = trimInMemoryCaches();
        if (ctx == null) {
            return new HygieneReport(0L, 0, ramTrimmed);
        }
        Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        long now = System.currentTimeMillis();
        long[] stats = new long[2]; // [0]=freedBytes, [1]=filesDeleted

        // 1. Clean orphaned module temp files inside wg_native (keep libgojni.so and libgojni.meta intact)
        try {
            File nativeDir = new File(appCtx.getFilesDir(), "wg_native");
            if (nativeDir.isDirectory()) {
                File[] nf = nativeDir.listFiles();
                if (nf != null) {
                    for (File f : nf) {
                        if (f.isFile() && f.getName().endsWith(".tmp") && (now - f.lastModified()) > 60_000L) {
                            long len = f.length();
                            if (f.delete()) {
                                stats[0] += len;
                                stats[1]++;
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 2. Measure cleanable cache inside cacheDir (strictly excluding protected paths)
        File cacheDir = appCtx.getCacheDir();
        if (cacheDir != null && cacheDir.isDirectory()) {
            long totalCleanable = measureCleanableBytes(cacheDir, cacheDir.getAbsolutePath(), 0);
            if (forceThresholdBypass || totalCleanable > AUTO_THRESHOLD_BYTES) {
                long minAge = forceThresholdBypass ? MANUAL_MIN_AGE_MS : AUTO_MIN_AGE_MS;
                purgeOldSafeFiles(cacheDir, cacheDir.getAbsolutePath(), now, minAge, 0, stats);
            }
        }

        // 3. In manual optimization inside companion/device with active daemon, trim stale external cache files
        if (forceThresholdBypass) {
            try {
                File extCache = appCtx.getExternalCacheDir();
                if (extCache != null && extCache.isDirectory()) {
                    purgeOldSafeFiles(extCache, extCache.getAbsolutePath(), now, MANUAL_MIN_AGE_MS, 0, stats);
                }
            } catch (Throwable ignored) {
            }
        }

        try {
            appCtx.getSharedPreferences(HYGIENE_PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putLong(KEY_LAST_RUN_MS, now)
                    .apply();
            sLastAutoMemMs = now;
        } catch (Throwable ignored) {
        }

        return new HygieneReport(stats[0], (int) stats[1], ramTrimmed);
    }

    private static long measureCleanableBytes(File dir, String rootPath, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 4) {
            return 0L;
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return 0L;
        }
        long total = 0L;
        for (File child : children) {
            String rel = relativePath(rootPath, child.getAbsolutePath());
            if (!isSafeCachePath(rel) || !isSafeCachePath(child.getName())) {
                continue;
            }
            if (child.isDirectory()) {
                total += measureCleanableBytes(child, rootPath, depth + 1);
            } else {
                total += Math.max(0L, child.length());
            }
        }
        return total;
    }

    private static void purgeOldSafeFiles(
            File dir,
            String rootPath,
            long nowMs,
            long minAgeMs,
            int depth,
            long[] stats
    ) {
        if (dir == null || !dir.isDirectory() || depth > 4) {
            return;
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            String rel = relativePath(rootPath, child.getAbsolutePath());
            if (!isSafeCachePath(rel) || !isSafeCachePath(child.getName())) {
                continue;
            }
            if (child.isDirectory()) {
                purgeOldSafeFiles(child, rootPath, nowMs, minAgeMs, depth + 1, stats);
                String[] remain = child.list();
                if (remain != null && remain.length == 0) {
                    child.delete();
                }
            } else if ((nowMs - child.lastModified()) >= minAgeMs) {
                long len = Math.max(0L, child.length());
                if (child.delete()) {
                    stats[0] += len;
                    stats[1]++;
                }
            }
        }
    }

    private static String relativePath(String root, String full) {
        if (full.startsWith(root) && full.length() > root.length()) {
            return full.substring(root.length());
        }
        return full;
    }
}
