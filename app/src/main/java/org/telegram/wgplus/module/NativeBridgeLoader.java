package org.telegram.wgplus.module;

import android.content.Context;
import android.os.Build;
import android.system.Os;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import go.Seq;
import wgbridge.Wgbridge;

public final class NativeBridgeLoader {
    private static final String TAG = "WGPlusNativeLoader";
    private static final String LIB_NAME = "libgojni.so";

    private static volatile boolean sLoaded = false;
    private static volatile Throwable sLoadFailure = null;

    private NativeBridgeLoader() {
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

        Context appCtx = hostContext.getApplicationContext() != null
                ? hostContext.getApplicationContext()
                : hostContext;

        File nativeDir = new File(appCtx.getFilesDir(), "wg_native");
        if (!nativeDir.exists() && !nativeDir.mkdirs()) {
            Log.w(TAG, "Could not create wg_native directory: " + nativeDir);
        }
        File targetSo = new File(nativeDir, LIB_NAME);

        try {
            boolean extracted = tryExtractFromCandidates(appCtx, moduleApkPath, targetSo);
            if (extracted && targetSo.exists()) {
                applyReadOnlyExecPermissions(targetSo);
                System.load(targetSo.getAbsolutePath());
            } else {
                System.loadLibrary("gojni");
            }

            // Initialize gomobile JNI bindings immediately inside synchronized block
            Seq.touch();
            Seq.setContext(appCtx);
            Wgbridge.touch();

            sLoaded = true;
            Log.i(TAG, "Successfully initialized libgojni.so and wgbridge JNI");
        } catch (Throwable t) {
            sLoadFailure = t;
            Log.e(TAG, "Failed loading native WireGuard bridge", t);
            throw new IllegalStateException(
                    t.getClass().getSimpleName() + ": " + t.getMessage(),
                    t
            );
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

        // 2. Check LSPatch cache / code_cache directories (.apk, .bin, .jar, .zip)
        if (extractFromDirectoryArchives(appCtx.getCacheDir(), targetSo, 0)) {
            return true;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            if (extractFromDirectoryArchives(appCtx.getCodeCacheDir(), targetSo, 0)) {
                return true;
            }
        }

        // 3. Check host APK's assets/lspatch/modules/* (.apk or .bin in LSPatch Portable/Integrated mode)
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

        return targetSo.exists() && targetSo.length() > 0;
    }

    private static boolean extractFromDirectoryArchives(File dir, File targetSo, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 5) {
            return false;
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return false;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                if (extractFromDirectoryArchives(child, targetSo, depth + 1)) {
                    return true;
                }
            } else if (child.length() > 65536) {
                String lower = child.getName().toLowerCase();
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
            if (targetSo.exists() && expectedSize > 0 && targetSo.length() == expectedSize) {
                return true;
            }
            try (InputStream in = zip.getInputStream(matchedEntry)) {
                writeStreamAtomically(in, targetSo);
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
                        writeStreamAtomically(zis, targetSo);
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
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
