package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Fully independent Sovereign Privilege Bridge without any external Shizuku dependency.
 * Coordinates:
 * 1) Direct self-privileged Binder transactions ({@code SET_PROCESS_LIMIT} / {@code WRITE_SECURE_SETTINGS}).
 * 2) Detached loopback-authenticated {@code wgplus_daemon} ({@link DaemonProcessHelper}).
 * 3) Built-in Wireless ADB ({@link WgAdbConnectionManager}) with one-time pairing and dynamic TCP heal.
 * 4) Root kernel boost ({@code su}) when running on a rooted device.
 */
public final class PrivilegeBridge {

    private static final String TAG = "WGPlusPrivilege";
    private static final String DESCRIPTOR_ACTIVITY_MANAGER = "android.app.IActivityManager";

    private static final IBinder sProcessImportanceToken = new Binder();

    private static final String PRIVILEGE_CACHE_PREFS = "wg_plus_privilege_cache";
    private static final String KEY_DAEMON_PORT = "daemon_port";
    private static final String KEY_DAEMON_PID = "daemon_pid";
    private static final String KEY_DAEMON_UID = "daemon_uid";
    private static final String KEY_DAEMON_TOKEN = "daemon_token";
    private static final String KEY_DAEMON_SEEN_MS = "daemon_seen_ms";

    private static final ExecutorService DAEMON_EXEC = Executors.newSingleThreadExecutor();
    private static volatile IBinder sCachedActivityBinder;
    private static volatile int sCachedSetProcessImportantTx = -1;
    private static volatile long sLastRootCheckMs;
    private static volatile boolean sLastRootAvailable;
    private static volatile long sLastDaemonPingMs;
    private static volatile boolean sLastDaemonAlive;
    private static volatile int sLastDaemonUid = -1;
    private static volatile long sLastDaemonLaunchMs;

    public static final class ShellResult {
        public final int exitCode;
        public final String output;
        public final boolean ok;

        public ShellResult(int exitCode, String output, boolean ok) {
            this.exitCode = exitCode;
            this.output = output != null ? output : "";
            this.ok = ok;
        }
    }

    private PrivilegeBridge() {
    }

    private static SharedPreferences cachePrefs(Context context) {
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        return appCtx.getSharedPreferences(PRIVILEGE_CACHE_PREFS, Context.MODE_PRIVATE);
    }

    public static boolean hasSelfProcessLimitPermission(Context context) {
        if (context == null) {
            return false;
        }
        try {
            return context.checkSelfPermission("android.permission.SET_PROCESS_LIMIT")
                    == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean hasSelfWriteSecureSettingsPermission(Context context) {
        if (context == null) {
            return false;
        }
        try {
            return context.checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS")
                    == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean selfHealNotificationListener(Context context) {
        if (context == null) {
            return false;
        }
        if (KeepaliveBridgeListenerService.isNotificationListenerEnabled(context)) {
            return true;
        }
        if (!hasSelfWriteSecureSettingsPermission(context)) {
            return false;
        }
        try {
            String targetComp = context.getPackageName() + "/" + KeepaliveBridgeListenerService.class.getName();
            String existing = Settings.Secure.getString(
                    context.getContentResolver(),
                    "enabled_notification_listeners"
            );
            String updated = (existing == null || existing.trim().isEmpty())
                    ? targetComp
                    : existing + ":" + targetComp;
            return Settings.Secure.putString(
                    context.getContentResolver(),
                    "enabled_notification_listeners",
                    updated
            );
        } catch (Throwable t) {
            Log.w(TAG, "selfHealNotificationListener warning: " + t.getMessage());
            return false;
        }
    }

    public static boolean hasRootAccess() {
        long now = System.currentTimeMillis();
        if (sLastRootCheckMs > 0 && (now - sLastRootCheckMs) < 30000L) {
            return sLastRootAvailable;
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return sLastRootAvailable;
        }
        boolean foundBin = false;
        for (String path : new String[]{"/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su", "/data/local/tmp/su"}) {
            if (new File(path).exists()) {
                foundBin = true;
                break;
            }
        }
        if (!foundBin) {
            ShellResult res = runLocalProcess(new String[]{"/system/bin/sh", "-c", "command -v su"}, 800);
            foundBin = res.ok && !res.output.isEmpty();
        }
        boolean rootOk = false;
        if (foundBin) {
            ShellResult idRes = runRootCommand("id", 1500);
            rootOk = idRes.ok && idRes.output.contains("uid=0");
        }
        sLastRootAvailable = rootOk;
        sLastRootCheckMs = System.currentTimeMillis();
        return rootOk;
    }

    public static boolean isRootAvailableCached() {
        return sLastRootAvailable;
    }

    public static ShellResult runRootCommand(String command, int timeoutMs) {
        return runLocalProcess(new String[]{"su", "-c", command + " 2>&1"}, timeoutMs);
    }

    public static boolean applyRootKernelBoost(int pid) {
        if (pid <= 0 || !hasRootAccess()) {
            return false;
        }
        String cmd = "echo -800 > /proc/" + pid + "/oom_score_adj 2>/dev/null; "
                + "echo " + pid + " > /dev/cpuset/foreground/tasks 2>/dev/null || true";
        return runRootCommand(cmd, 2500).ok;
    }

    private static ShellResult runLocalProcess(String[] argv, int timeoutMs) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            pb.redirectErrorStream(true);
            java.lang.Process p = pb.start();
            ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream is = p.getInputStream()) {
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = is.read(buf)) > 0) {
                        if (outBuf.size() < 32768) {
                            outBuf.write(buf, 0, Math.min(n, 32768 - outBuf.size()));
                        }
                    }
                } catch (Throwable ignored) {
                }
            }, "wgplus-local-io");
            reader.start();
            boolean finished = p.waitFor(Math.max(400, timeoutMs), TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                return new ShellResult(-2, "timeout", false);
            }
            reader.join(350);
            int code = p.exitValue();
            String text = new String(outBuf.toByteArray(), StandardCharsets.UTF_8).trim();
            return new ShellResult(code, text, code == 0);
        } catch (Throwable t) {
            return new ShellResult(-1, t.getMessage(), false);
        }
    }

    public static void registerDaemonEndpoint(
            Context context,
            int port,
            int pid,
            int uid,
            int txCode,
            String token
    ) {
        if (context == null || port <= 0 || token == null || token.isEmpty()) {
            return;
        }
        cachePrefs(context).edit()
                .putInt(KEY_DAEMON_PORT, port)
                .putInt(KEY_DAEMON_PID, pid)
                .putInt(KEY_DAEMON_UID, uid)
                .putString(KEY_DAEMON_TOKEN, token)
                .putLong(KEY_DAEMON_SEEN_MS, System.currentTimeMillis())
                .apply();
        cacheResolvedTxCode(context, txCode);
        sLastDaemonAlive = true;
        sLastDaemonUid = uid;
        sLastDaemonPingMs = System.currentTimeMillis();
    }

    public static void cacheResolvedTxCode(Context context, int txCode) {
        if (txCode <= 0) {
            return;
        }
        sCachedSetProcessImportantTx = txCode;
        if (context != null) {
            cachePrefs(context).edit()
                    .putInt("tx_imp_" + Build.FINGERPRINT, txCode)
                    .apply();
        }
    }

    public static int getLastDaemonUid() {
        return sLastDaemonUid;
    }

    public static boolean isStandaloneDaemonAlive(Context context) {
        if (context == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        if (sLastDaemonAlive && (now - sLastDaemonPingMs) < 15000L) {
            return true;
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return sLastDaemonAlive && (now - sLastDaemonPingMs) < 45000L;
        }
        String resp = sendDaemonCommand(context, "PING", 700);
        boolean ok = resp != null && resp.startsWith("OK");
        sLastDaemonAlive = ok;
        sLastDaemonPingMs = System.currentTimeMillis();
        if (ok) {
            int idx = resp.indexOf("uid=");
            if (idx >= 0) {
                try {
                    String tail = resp.substring(idx + 4).split("\\s+")[0];
                    sLastDaemonUid = Integer.parseInt(tail);
                } catch (Throwable ignored) {
                }
            }
        }
        return ok;
    }

    private static String sendDaemonCommand(Context context, String cmdLine, int timeoutMs) {
        if (context == null || Looper.myLooper() == Looper.getMainLooper()) {
            return null;
        }
        SharedPreferences p = cachePrefs(context);
        int port = p.getInt(KEY_DAEMON_PORT, -1);
        String token = p.getString(KEY_DAEMON_TOKEN, null);
        if (port <= 0 || token == null || token.isEmpty()) {
            return null;
        }
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress("127.0.0.1", port), Math.min(500, timeoutMs));
            sock.setSoTimeout(Math.max(400, timeoutMs));
            PrintWriter w = new PrintWriter(new OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8), true);
            BufferedReader r = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            w.println(token + " " + cmdLine);
            String line = r.readLine();
            if (line != null && (line.startsWith("OK") || line.startsWith("EXIT="))) {
                p.edit().putLong(KEY_DAEMON_SEEN_MS, System.currentTimeMillis()).apply();
                sLastDaemonAlive = true;
                sLastDaemonPingMs = System.currentTimeMillis();
            }
            return line;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static ShellResult runCommandViaDaemon(Context context, String command, int timeoutMs) {
        String b64 = Base64.encodeToString(command.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        String resp = sendDaemonCommand(context, "SH_B64 " + b64, timeoutMs);
        if (resp == null || !resp.startsWith("EXIT=")) {
            return null;
        }
        int sp = resp.indexOf(' ');
        int code = -1;
        String output = "";
        try {
            String codeStr = sp > 5 ? resp.substring(5, sp) : resp.substring(5);
            code = Integer.parseInt(codeStr.trim());
            if (sp > 5 && sp + 1 < resp.length()) {
                byte[] decoded = Base64.decode(resp.substring(sp + 1).trim(), Base64.NO_WRAP);
                output = new String(decoded, StandardCharsets.UTF_8).trim();
            }
        } catch (Throwable ignored) {
        }
        return new ShellResult(code, output, code == 0);
    }

    static String buildDaemonLaunchCommand(Context context, List<String> targets) {
        if (context == null || context.getApplicationInfo() == null) {
            return "";
        }
        String apkPath = context.getApplicationInfo().sourceDir;
        if (apkPath == null || apkPath.isEmpty()) {
            return "";
        }
        StringBuilder csv = new StringBuilder();
        if (targets != null) {
            for (String t : targets) {
                if (DaemonProcessHelper.isSafeToken(t)) {
                    if (csv.length() > 0) {
                        csv.append(',');
                    }
                    csv.append(t);
                }
            }
        }
        String targetArg = csv.length() > 0 ? csv.toString() : "org.telegram.plus,org.telegram.messenger,org.telegram.gold";
        return "setsid /system/bin/env CLASSPATH=" + apkPath
                + " /system/bin/app_process /system/bin --nice-name=wgplus_daemon "
                + DaemonProcessHelper.class.getName()
                + " --daemon " + context.getPackageName() + " " + targetArg
                + " </dev/null >/dev/null 2>&1 &";
    }

    public static void bootstrapStandaloneDaemonAsync(Context context, List<String> targets) {
        if (context == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - sLastDaemonLaunchMs < 20000L) {
            return;
        }
        sLastDaemonLaunchMs = now;
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        DAEMON_EXEC.execute(() -> {
            try {
                if (isStandaloneDaemonAlive(appCtx)) {
                    return;
                }
                String launchCmd = buildDaemonLaunchCommand(appCtx, targets);
                if (launchCmd.isEmpty()) {
                    return;
                }
                if (hasRootAccess()) {
                    runRootCommand(launchCmd, 3000);
                } else if (BuiltinAdbKeyManager.isPaired(appCtx)) {
                    WgAdbConnectionManager.getInstance(appCtx).bootstrapSovereignShell(true);
                }
            } catch (Throwable ignored) {
            }
        });
    }

    public static ShellResult runShellCommand(Context context, String command, int timeoutMs) {
        if (hasRootAccess()) {
            ShellResult rootRes = runRootCommand(command, timeoutMs);
            if (rootRes.ok) {
                return rootRes;
            }
        }
        if (context != null && isStandaloneDaemonAlive(context)) {
            ShellResult daemonRes = runCommandViaDaemon(context, command, timeoutMs);
            if (daemonRes != null) {
                return daemonRes;
            }
        }
        if (context != null && BuiltinAdbKeyManager.isPaired(context)) {
            try {
                ShellResult adbRes = WgAdbConnectionManager.getInstance(context).runShellCommand(command, timeoutMs);
                if (adbRes != null && adbRes.ok) {
                    return adbRes;
                }
            } catch (Throwable ignored) {
            }
        }
        return runLocalProcess(new String[]{"/system/bin/sh", "-c", command + " 2>&1"}, timeoutMs);
    }

    public static boolean applyProcessImportant(Context context, int pid, boolean important) {
        if (pid <= 0 || context == null) {
            return false;
        }
        boolean rootBoosted = false;
        if (hasRootAccess() && important) {
            rootBoosted = applyRootKernelBoost(pid);
        }

        IBinder activityBinder = resolveActivityManagerBinder();
        int txCode = resolveSetProcessImportantTxCode(context);

        // Tier 1: Direct self-privilege Binder call using SET_PROCESS_LIMIT
        if (hasSelfProcessLimitPermission(context) && activityBinder != null && txCode > 0) {
            if (transactSetProcessImportant(activityBinder, txCode, pid, important)) {
                return true;
            }
        }

        // Tier 2: Built-in standalone wgplus_daemon over authenticated loopback TCP
        if (isStandaloneDaemonAlive(context)) {
            String resp = sendDaemonCommand(context, "IMP " + pid + " " + (important ? "1" : "0"), 1500);
            if (resp != null && resp.startsWith("OK")) {
                return true;
            }
        }

        return rootBoosted;
    }

    private static boolean transactSetProcessImportant(
            IBinder activityBinder,
            int txCode,
            int pid,
            boolean important
    ) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_ACTIVITY_MANAGER);
            data.writeStrongBinder(sProcessImportanceToken);
            data.writeInt(pid);
            data.writeInt(important ? 1 : 0);
            data.writeString("setProcessImportant()");
            if (!activityBinder.transact(txCode, data, reply, 0)) {
                return false;
            }
            reply.readException();
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "transactSetProcessImportant warning for pid=" + pid + ": " + t.getMessage());
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static boolean applyOsContinuityExemptions(
            Context context,
            List<String> targetPackages,
            String listenerComponent,
            boolean grantListener
    ) {
        if (context == null || targetPackages == null || targetPackages.isEmpty()) {
            return false;
        }
        boolean listenerOk = !grantListener || selfHealNotificationListener(context);
        boolean root = hasRootAccess();
        boolean daemon = !root && isStandaloneDaemonAlive(context);
        boolean pairedAdb = !root && !daemon && BuiltinAdbKeyManager.isPaired(context);
        if (!root && !daemon && !pairedAdb) {
            return listenerOk;
        }

        if (!root && !daemon) {
            // Let bootstrapSovereignShell launch wgplus_daemon cleanly in <1s; the daemon
            // itself runs the full 70-command deep exemptions asynchronously under uid=2000.
            boolean booted = false;
            try {
                booted = WgAdbConnectionManager.getInstance(context).bootstrapSovereignShell(true);
            } catch (Throwable t) {
                Log.w(TAG, "applyOsContinuityExemptions bootstrap warning: " + t.getMessage());
            }
            return booted || listenerOk || grantListener == KeepaliveBridgeListenerService.isNotificationListenerEnabled(context);
        }

        String script = DaemonProcessHelper.buildDeepExemptionsShellScript(
                context.getPackageName(),
                targetPackages,
                listenerComponent,
                grantListener
        );
        ShellResult res = runRootOrDaemonCommand(context, script, 12000);
        return (res != null && res.ok) || listenerOk || grantListener == KeepaliveBridgeListenerService.isNotificationListenerEnabled(context);
    }

    private static ShellResult runRootOrDaemonCommand(Context context, String command, int timeoutMs) {
        if (hasRootAccess()) {
            ShellResult rootRes = runRootCommand(command, timeoutMs);
            if (rootRes.ok) {
                return rootRes;
            }
        }
        if (context != null && isStandaloneDaemonAlive(context)) {
            return runCommandViaDaemon(context, command, timeoutMs);
        }
        return null;
    }

    private static IBinder resolveActivityManagerBinder() {
        IBinder cached = sCachedActivityBinder;
        if (cached != null && cached.pingBinder()) {
            return cached;
        }
        try {
            Method getMethod = Class.class.getDeclaredMethod("getMethod", String.class, Class[].class);
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = (Method) getMethod.invoke(smClass, "getService", new Class[]{String.class});
            IBinder binder = (IBinder) getService.invoke(null, "activity");
            if (binder != null && binder.pingBinder()) {
                sCachedActivityBinder = binder;
                return binder;
            }
        } catch (Throwable t) {
            Log.w(TAG, "resolveActivityManagerBinder failed: " + t.getMessage());
        }
        return null;
    }

    private static int resolveSetProcessImportantTxCode(Context context) {
        int cached = sCachedSetProcessImportantTx;
        if (cached > 0) {
            return cached;
        }
        if (context == null) {
            return -1;
        }
        SharedPreferences prefs = cachePrefs(context);
        String prefKey = "tx_imp_" + Build.FINGERPRINT;
        int stored = prefs.getInt(prefKey, -1);
        if (stored > 0) {
            sCachedSetProcessImportantTx = stored;
            return stored;
        }
        try {
            Class<?> stub = Class.forName("android.app.IActivityManager$Stub");
            Field f;
            try {
                Method getDeclaredField = Class.class.getDeclaredMethod("getDeclaredField", String.class);
                f = (Field) getDeclaredField.invoke(stub, "TRANSACTION_setProcessImportant");
            } catch (Throwable ignored) {
                f = stub.getDeclaredField("TRANSACTION_setProcessImportant");
            }
            f.setAccessible(true);
            int code = f.getInt(null);
            if (code > 0) {
                cacheResolvedTxCode(context, code);
                return code;
            }
        } catch (Throwable ignored) {
        }

        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            String apkPath = appCtx.getApplicationInfo().sourceDir;
            if (apkPath == null || apkPath.isEmpty()) {
                return -1;
            }
            ShellResult res = null;
            if (hasRootAccess()) {
                res = runRootCommand(
                        "/system/bin/env CLASSPATH=" + apkPath + " /system/bin/app_process /system/bin " + DaemonProcessHelper.class.getName(),
                        4000
                );
            } else if (BuiltinAdbKeyManager.isPaired(appCtx)) {
                res = WgAdbConnectionManager.getInstance(appCtx).runShellCommand(
                        "/system/bin/env CLASSPATH=" + apkPath + " /system/bin/app_process /system/bin " + DaemonProcessHelper.class.getName(),
                        4000
                );
            }
            if (res != null) {
                String out = res.output;
                int idx = out.indexOf(DaemonProcessHelper.PREFIX);
                if (idx >= 0) {
                    String tail = out.substring(idx + DaemonProcessHelper.PREFIX.length()).trim();
                    int end = 0;
                    while (end < tail.length() && Character.isDigit(tail.charAt(end))) {
                        end++;
                    }
                    if (end > 0) {
                        int code = Integer.parseInt(tail.substring(0, end));
                        if (code > 0) {
                            cacheResolvedTxCode(context, code);
                            return code;
                        }
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "resolveSetProcessImportantTxCode failed: " + t.getMessage());
        }
        return -1;
    }
}
