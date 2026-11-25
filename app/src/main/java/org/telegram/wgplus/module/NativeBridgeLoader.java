package org.telegram.wgplus.module;

import android.content.Context;
import android.os.Build;
import android.system.Os;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import go.Seq;
import wgbridge.Wgbridge;

public final class NativeBridgeLoader {
    private static final String TAG = "WGPlusNativeLoader";
    private static final String LIB_NAME = "libgojni.so";
    private static final String META_NAME = "libgojni.meta";

    private static volatile boolean sLoaded = false;
    private static volatile Throwable sLoadFailure = null;

    private NativeBridgeLoader() {
    }

    public static boolean isLoaded() {
        return sLoaded;
    }

    public static synchronized void ensureLoaded(Context hostContext, String moduleApkPath) {
        if (sLoaded) {
            return;
        }
        if (sLoadFailure != null) {
            throw new IllegalStateException(
                    "Native bridge failed earlier (" + sLoadFailure.getClass().getSimpleName()
                            + ": " + sLoadFailure.getMessage() + ")",
                    sLoadFailure
            );
        }
        if (hostContext == null) {
            throw new IllegalArgumentException("hostContext cannot be null");
        }
        String effectiveModulePath = (moduleApkPath == null || moduleApkPath.trim().isEmpty())
                ? XposedInit.getModulePath()
                : moduleApkPath.trim();

        Context appCtx = hostContext.getApplicationContext() != null
                ? hostContext.getApplicationContext()
                : hostContext;

        File nativeDir = new File(appCtx.getFilesDir(), "wg_native");
        if (!nativeDir.exists() && !nativeDir.mkdirs()) {
            Log.w(TAG, "Could not create wg_native directory: " + nativeDir);
        }
        File targetSo = new File(nativeDir, LIB_NAME);
        File metaFile = new File(nativeDir, META_NAME);
        File staleTmp = new File(nativeDir, LIB_NAME + ".tmp");
        if (staleTmp.exists()) {
            makeWritableForDelete(staleTmp);
            staleTmp.delete();
        }

        try {
            boolean fastPathHit = isFastPathValid(appCtx, effectiveModulePath, targetSo, metaFile);
            boolean extracted = fastPathHit || tryExtractFromCandidates(appCtx, effectiveModulePath, targetSo);
            if (extracted && targetSo.exists()) {
                applyReadOnlyExecPermissions(targetSo);
                System.load(targetSo.getAbsolutePath());
                if (!fastPathHit) {
                    writeFastPathMeta(appCtx, effectiveModulePath, targetSo, metaFile);
                }
            } else {
                System.loadLibrary("gojni");
            }

            // Initialize gomobile JNI bindings immediately inside synchronized block
            Seq.touch();
            Seq.setContext(appCtx);
            Wgbridge.touch();

            sLoaded = true;
            Log.i(TAG, "Successfully initialized libgojni.so and wgbridge JNI (fastPath=" + fastPathHit + ")");
        } catch (Throwable t) {
            if (metaFile.exists()) {
                metaFile.delete();
            }
            sLoadFailure = t;
            Log.e(TAG, "Failed loading native WireGuard bridge", t);
            throw new IllegalStateException(
                    t.getClass().getSimpleName() + ": " + t.getMessage(),
                    t
            );
        }
    }

    private static String computeHostFingerprint(Context appCtx, String moduleApkPath) {
        String hostSourceDir = appCtx.getApplicationInfo() != null ? appCtx.getApplicationInfo().sourceDir : "";
        File hostApk = (hostSourceDir != null && !hostSourceDir.isEmpty()) ? new File(hostSourceDir) : null;
        long hostMod = hostApk != null && hostApk.exists() ? hostApk.lastModified() : 0L;
        long hostLen = hostApk != null && hostApk.exists() ? hostApk.length() : 0L;
        long modLen = 0L;
        long modTime = 0L;
        long modCrc = 0L;
        String resolvedPath = moduleApkPath != null ? moduleApkPath.trim() : "";
        if (resolvedPath.isEmpty() && !"org.telegram.wgplus.module".equals(appCtx.getPackageName())) {
            try {
                android.content.pm.ApplicationInfo modAi = appCtx.getPackageManager()
                        .getApplicationInfo("org.telegram.wgplus.module", 0);
                if (modAi != null && modAi.sourceDir != null) {
                    resolvedPath = modAi.sourceDir;
                }
            } catch (Throwable ignored) {
            }
        }
        if (!resolvedPath.isEmpty()) {
            if (resolvedPath.contains("!/")) {
                String[] parts = resolvedPath.split("!/", 2);
                File outerFile = new File(parts[0]);
                if (outerFile.exists()) {
                    modLen = outerFile.length();
                    modTime = outerFile.lastModified();
                    try (ZipFile outerZip = new ZipFile(outerFile)) {
                        ZipEntry inner = outerZip.getEntry(parts[1]);
                        if (inner != null) {
                            modCrc = inner.getCrc() ^ inner.getSize();
                        }
                    } catch (Throwable ignored) {
                    }
                }
            } else {
                File mf = new File(resolvedPath);
                if (mf.exists()) {
                    modLen = mf.length();
                    modTime = mf.lastModified();
                }
            }
        }
        String abi = (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0)
                ? Build.SUPPORTED_ABIS[0]
                : "unknown";
        return BuildConfigSafeVersion() + "|" + abi + "|" + hostMod + "|" + hostLen + "|" + modTime + "|" + modLen + "|" + modCrc;
    }

    private static String BuildConfigSafeVersion() {
        return WgStrings.VERSION_LABEL;
    }

    private static boolean isFastPathValid(Context appCtx, String moduleApkPath, File targetSo, File metaFile) {
        if (!targetSo.exists() || targetSo.length() <= 65536 || !metaFile.exists()) {
            return false;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(metaFile))) {
            String stored = br.readLine();
            if (stored == null) {
                return false;
            }
            String expected = computeHostFingerprint(appCtx, moduleApkPath) + "|" + targetSo.length();
            return expected.equals(stored.trim());
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void writeFastPathMeta(Context appCtx, String moduleApkPath, File targetSo, File metaFile) {
        if (!targetSo.exists() || targetSo.length() <= 0) {
            return;
        }
        String payload = computeHostFingerprint(appCtx, moduleApkPath) + "|" + targetSo.length();
        try (OutputStreamWriter ow = new OutputStreamWriter(new FileOutputStream(metaFile, false), StandardCharsets.UTF_8)) {
            ow.write(payload);
            ow.flush();
        } catch (Throwable ignored) {
        }
    }

    private static void applyReadOnlyExecPermissions(File file) {
        try {
            Os.chmod(file.getAbsolutePath(), 0500);
            return;
        } catch (Throwable ignored) {
        }
        file.setReadable(true, false);
        file.setExecutable(true, false);
        file.setWritable(false, false);
    }

    private static void makeWritableForDelete(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        try {
            Os.chmod(file.getAbsolutePath(), 0700);
        } catch (Throwable ignored) {
        }
        file.setWritable(true, true);
    }

    private static boolean tryExtractFromCandidates(Context appCtx, String moduleApkPath, File targetSo) {
        // 1. Direct moduleApkPath or outerApk!/innerEntry notation
        if (moduleApkPath != null && !moduleApkPath.trim().isEmpty()) {
            String path = moduleApkPath.trim();
            if (path.contains("!/")) {
                String[] parts = path.split("!/", 2);
                if (extractFromNestedApkEntry(new File(parts[0]), parts[1], targetSo)) {
                    return true;
                }
            } else if (extractFromZipFile(new File(path), targetSo)) {
                return true;
            }
        }

        // 2. Host APK and embedded LSPatch module payloads (fast direct Zip lookup, zero media scanning)
        String hostSourceDir = appCtx.getApplicationInfo() != null ? appCtx.getApplicationInfo().sourceDir : null;
        if (hostSourceDir != null) {
            File hostApk = new File(hostSourceDir);
            if (extractFromZipFile(hostApk, targetSo)) {
                return true;
            }
            if (extractFromEmbeddedLspatchAssets(hostApk, targetSo)) {
                return true;
            }
        }

        // 3. Targeted code_cache / LSPatch cache fallback (never scanning media directories)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            if (extractFromDirectoryArchives(appCtx.getCodeCacheDir(), targetSo, 0)) {
                return true;
            }
        }
        File lspatchCache = new File(appCtx.getCacheDir(), "lspatch");
        if (lspatchCache.isDirectory() && extractFromDirectoryArchives(lspatchCache, targetSo, 0)) {
            return true;
        }
        if (extractFromDirectoryArchives(appCtx.getCacheDir(), targetSo, 0)) {
            return true;
        }

        return targetSo.exists() && targetSo.length() > 0;
    }

    private static boolean shouldSkipCacheScanDir(String dirName) {
        if (dirName == null) {
            return false;
        }
        String low = dirName.toLowerCase(Locale.ROOT);
        return "images".equals(low)
                || "video".equals(low)
                || "audio".equals(low)
                || "stickers".equals(low)
                || "voice".equals(low)
                || "documents".equals(low)
                || "stories".equals(low)
                || "thumbs".equals(low)
                || "emoji".equals(low)
                || "webview".equals(low)
                || low.contains("chromium")
                || low.contains("telegram images");
    }

    private static boolean extractFromDirectoryArchives(File dir, File targetSo, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 3) {
            return false;
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return false;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                if (shouldSkipCacheScanDir(child.getName())) {
                    continue;
                }
                if (extractFromDirectoryArchives(child, targetSo, depth + 1)) {
                    return true;
                }
            } else if (child.length() > 65536) {
                String lower = child.getName().toLowerCase(Locale.ROOT);
                if (lower.endsWith(".apk") || lower.endsWith(".bin") || lower.endsWith(".jar") || lower.endsWith(".zip")) {
                    if (extractFromZipFile(child, targetSo)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean extractFromZipFile(File apkFile, File targetSo) {
        if (apkFile == null || !apkFile.isFile() || !apkFile.canRead()) {
            return false;
        }
        try (ZipFile zip = new ZipFile(apkFile)) {
            ZipEntry matchedEntry = findBestAbiEntry(zip);
            if (matchedEntry == null) {
                return false;
            }
            long expectedSize = matchedEntry.getSize();
            long expectedCrc = matchedEntry.getCrc();
            if (targetSo.exists() && expectedSize > 0 && targetSo.length() == expectedSize
                    && matchesExtractedEntryVersionAndCrc(targetSo, expectedCrc)) {
                return true;
            }
            try (InputStream in = zip.getInputStream(matchedEntry)) {
                writeStreamAtomically(in, targetSo);
                writeExtractedCrcMarker(targetSo, expectedCrc);
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean extractFromNestedApkEntry(File outerApk, String innerEntryPath, File targetSo) {
        if (outerApk == null || !outerApk.isFile()) {
            return false;
        }
        try (ZipFile outerZip = new ZipFile(outerApk)) {
            ZipEntry innerApkEntry = outerZip.getEntry(innerEntryPath);
            if (innerApkEntry == null) {
                return false;
            }
            return extractSoFromNestedApkStream(outerZip.getInputStream(innerApkEntry), targetSo);
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean extractFromEmbeddedLspatchAssets(File hostApk, File targetSo) {
        if (hostApk == null || !hostApk.isFile()) {
            return false;
        }
        try (ZipFile outerZip = new ZipFile(hostApk)) {
            Enumeration<? extends ZipEntry> entries = outerZip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name != null && name.startsWith("assets/lspatch/") && !entry.isDirectory()) {
                    if (extractSoFromNestedApkStream(outerZip.getInputStream(entry), targetSo)) {
                        return true;
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "extractFromEmbeddedLspatchAssets warning: " + t.getMessage());
        }
        return false;
    }

    private static boolean extractSoFromNestedApkStream(InputStream apkStream, File targetSo) {
        String[] candidatePaths = getOrderedAbiEntryPaths();
        try (ZipInputStream zis = new ZipInputStream(apkStream)) {
            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                String entryName = ze.getName();
                for (String wanted : candidatePaths) {
                    if (wanted.equals(entryName)) {
                        long expectedSize = ze.getSize();
                        long expectedCrc = ze.getCrc();
                        if (expectedSize > 0 && targetSo.exists() && targetSo.length() == expectedSize
                                && matchesExtractedEntryVersionAndCrc(targetSo, expectedCrc)) {
                            return true;
                        }
                        writeStreamAtomically(zis, targetSo);
                        writeExtractedCrcMarker(targetSo, expectedCrc);
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean matchesExtractedEntryVersionAndCrc(File targetSo, long expectedCrc) {
        if (targetSo == null || !targetSo.exists()) {
            return false;
        }
        File crcFile = new File(targetSo.getParentFile(), LIB_NAME + ".crc");
        if (!crcFile.exists()) {
            return false;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(crcFile))) {
            String line = br.readLine();
            String want = BuildConfigSafeVersion() + "|" + expectedCrc;
            return want.equals(line != null ? line.trim() : "");
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void writeExtractedCrcMarker(File targetSo, long expectedCrc) {
        if (targetSo == null) {
            return;
        }
        File crcFile = new File(targetSo.getParentFile(), LIB_NAME + ".crc");
        try (OutputStreamWriter ow = new OutputStreamWriter(new FileOutputStream(crcFile, false), StandardCharsets.UTF_8)) {
            ow.write(BuildConfigSafeVersion() + "|" + expectedCrc);
            ow.flush();
        } catch (Throwable ignored) {
        }
    }

    private static void writeStreamAtomically(InputStream in, File targetSo) throws Exception {
        File parent = targetSo.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        File tempFile = new File(parent, LIB_NAME + ".tmp");
        makeWritableForDelete(tempFile);
        tempFile.delete();

        try (FileOutputStream out = new FileOutputStream(tempFile, false)) {
            byte[] buffer = new byte[16384];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.flush();
            out.getFD().sync();
        }
        if (targetSo.exists()) {
            makeWritableForDelete(targetSo);
            if (!targetSo.delete()) {
                Log.w(TAG, "Could not delete previous libgojni.so before rename");
            }
        }
        if (!tempFile.renameTo(targetSo)) {
            throw new IllegalStateException("Failed renaming " + tempFile + " to " + targetSo);
        }
    }

    private static String[] getOrderedAbiEntryPaths() {
        String[] supported = Build.SUPPORTED_ABIS;
        if (supported != null && supported.length > 0) {
            String[] paths = new String[supported.length + 2];
            int idx = 0;
            for (String abi : supported) {
                if (abi != null && !abi.isEmpty()) {
                    paths[idx++] = "lib/" + abi + "/" + LIB_NAME;
                }
            }
            paths[idx++] = "lib/arm64-v8a/" + LIB_NAME;
            paths[idx++] = "lib/armeabi-v7a/" + LIB_NAME;
            String[] trimmed = new String[idx];
            System.arraycopy(paths, 0, trimmed, 0, idx);
            return trimmed;
        }
        return new String[]{
                "lib/arm64-v8a/" + LIB_NAME,
                "lib/armeabi-v7a/" + LIB_NAME
        };
    }

    private static ZipEntry findBestAbiEntry(ZipFile zip) {
        for (String path : getOrderedAbiEntryPaths()) {
            ZipEntry entry = zip.getEntry(path);
            if (entry != null) {
                return entry;
            }
        }
        return null;
    }
}
