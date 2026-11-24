package org.telegram.wgplus.module;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.util.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Dual-mode platform helper executed via {@code /system/bin/app_process} under {@code uid=2000}
 * (Built-in Wireless ADB) or {@code uid=0} (Root):
 * 1) No arguments: prints {@code TX_SET_PROCESS_IMPORTANT=<code>} and exits cleanly.
 * 2) {@code --daemon <modulePkg> <targetCsv>}: runs a detached loopback-authenticated
 *    {@code wgplus_daemon} maintaining deep OS exemptions, self-permissions, and direct
 *    {@code IActivityManager.setProcessImportant} (plus {@code oom_score_adj=-800} when Root).
 */
public final class DaemonProcessHelper {

    public static final String PREFIX = "TX_SET_PROCESS_IMPORTANT=";
    private static final String STATUS_PROVIDER_URI = "content://org.telegram.wgplus.module.status";
    private static final String DESCRIPTOR_ACTIVITY_MANAGER = "android.app.IActivityManager";

    static final String[] DEV_PERMISSIONS = new String[]{
            "android.permission.SET_PROCESS_LIMIT",
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.GET_PROCESS_STATE_AND_OOM_SCORE",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.DUMP",
            "android.permission.BATTERY_STATS",
            "android.permission.INTERACT_ACROSS_USERS"
    };

    private static final String[] DEEP_APPOPS = new String[]{
            "RUN_IN_BACKGROUND",
            "RUN_ANY_IN_BACKGROUND",
            "START_FOREGROUND",
            "WAKE_LOCK",
            "ACCESS_RESTRICTED_SETTINGS",
            "SYSTEM_EXEMPT_FROM_SUSPENSION",
            "SYSTEM_EXEMPT_FROM_HIBERNATION",
            "SYSTEM_EXEMPT_FROM_POWER_RESTRICTIONS",
            "SYSTEM_EXEMPT_FROM_ACTIVITY_BG_START_RESTRICTION",
            "WRITE_SETTINGS",
            "SCHEDULE_EXACT_ALARM",
            "GET_USAGE_STATS",
            "LOADER_USAGE_STATS",
            "ACTIVATE_VPN",
            "ACTIVATE_PLATFORM_VPN"
    };

    private static final Binder sDaemonToken = new Binder();
    private static volatile boolean sRunning = true;

    private DaemonProcessHelper() {
    }

    public static void main(String[] args) {
        if (args != null && args.length >= 1 && "--daemon".equals(args[0])) {
            String modulePkg = args.length >= 2 && isSafeToken(args[1])
                    ? args[1]
                    : "org.telegram.wgplus.module";
            String targetsCsv = args.length >= 3
                    ? args[2]
                    : "org.telegram.plus,org.telegram.messenger,org.telegram.gold";
            runDaemon(modulePkg, parseSafePackages(targetsCsv));
            return;
        }
        try {
            int code = resolveTxCode();
            System.out.println(PREFIX + code);
        } catch (Throwable t) {
            System.err.println("ERR=" + t);
            System.exit(1);
        }
    }

    private static int resolveTxCode() throws Throwable {
        Class<?> stub = Class.forName("android.app.IActivityManager$Stub");
        Field f = stub.getDeclaredField("TRANSACTION_setProcessImportant");
        f.setAccessible(true);
        return f.getInt(null);
    }

    private static IBinder resolveActivityBinder() {
        try {
            Method getMethod = Class.class.getDeclaredMethod("getMethod", String.class, Class[].class);
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method getService = (Method) getMethod.invoke(sm, "getService", new Class[]{String.class});
            return (IBinder) getService.invoke(null, "activity");
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean invokeSetProcessImportant(IBinder activityBinder, int txCode, int pid, boolean important) {
        if (activityBinder == null || txCode <= 0 || pid <= 0) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_ACTIVITY_MANAGER);
            data.writeStrongBinder(sDaemonToken);
            data.writeInt(pid);
            data.writeInt(important ? 1 : 0);
            data.writeString("setProcessImportant()");
            if (!activityBinder.transact(txCode, data, reply, 0)) {
                return false;
            }
            reply.readException();
            return true;
        } catch (Throwable ignored) {
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private static void setNiceName(String name) {
        try {
            Class<?> c = Class.forName("android.os.Process");
            Method m = c.getDeclaredMethod("setArgV0", String.class);
            m.setAccessible(true);
            m.invoke(null, name);
        } catch (Throwable ignored) {
        }
        try {
            Class<?> ddm = Class.forName("android.ddm.DdmHandleAppName");
            Method m = ddm.getDeclaredMethod("setAppName", String.class, int.class);
            m.setAccessible(true);
            m.invoke(null, name, 0);
        } catch (Throwable ignored) {
        }
    }

    private static void runDaemon(String modulePkg, List<String> targets) {
        setNiceName("wgplus_daemon");
        int myPid = Process.myPid();
        int myUid = Process.myUid();

        int txCode = -1;
        try {
            txCode = resolveTxCode();
        } catch (Throwable ignored) {
        }
        final int finalTxCode = txCode;

        byte[] rawSecret = new byte[32];
        new SecureRandom().nextBytes(rawSecret);
        final String secretHex = toHex(rawSecret);
        final byte[] secretBytes = secretHex.getBytes(StandardCharsets.UTF_8);

        ServerSocket server = null;
        try {
            server = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
            final int localPort = server.getLocalPort();

            registerWithModuleProvider(localPort, myPid, myUid, finalTxCode, secretHex);

            Thread exemptionsInit = new Thread(() -> {
                try {
                    applyDeepPermissionsAndExemptions(modulePkg, targets, myUid);
                } catch (Throwable ignored) {
                }
            }, "wgplus-daemon-init");
            exemptionsInit.setDaemon(true);
            exemptionsInit.start();

            final ServerSocket finalServer = server;
            Thread watchdog = new Thread(() -> runWatchdogLoop(
                    modulePkg, targets, myPid, myUid, localPort, finalTxCode, secretHex
            ), "wgplus-daemon-watchdog");
            watchdog.setDaemon(true);
            watchdog.start();

            while (sRunning) {
                try {
                    Socket client = finalServer.accept();
                    handleClient(client, secretBytes, modulePkg, targets, myPid, myUid, finalTxCode, finalServer);
                } catch (Throwable t) {
                    if (!sRunning) {
                        break;
                    }
                }
            }
        } catch (Throwable t) {
            System.err.println("DAEMON_ERR=" + t);
            System.exit(2);
        } finally {
            if (server != null) {
                try {
                    server.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static void handleClient(
            Socket client,
            byte[] secretBytes,
            String modulePkg,
            List<String> targets,
            int myPid,
            int myUid,
            int txCode,
            ServerSocket server
    ) {
        try (Socket sock = client) {
            sock.setSoTimeout(8000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8), true);

            String line = reader.readLine();
            if (line == null) {
                return;
            }
            int sp1 = line.indexOf(' ');
            if (sp1 <= 0) {
                writer.println("ERR_AUTH");
                return;
            }
            String token = line.substring(0, sp1);
            if (!MessageDigest.isEqual(token.getBytes(StandardCharsets.UTF_8), secretBytes)) {
                writer.println("ERR_AUTH");
                return;
            }
            String rest = line.substring(sp1 + 1).trim();
            if ("PING".equals(rest)) {
                writer.println("OK uid=" + myUid + " pid=" + myPid + " tx=" + txCode);
                return;
            }
            if ("STOP".equals(rest)) {
                sRunning = false;
                writer.println("OK");
                try {
                    server.close();
                } catch (Throwable ignored) {
                }
                return;
            }
            if ("EXEMPT".equals(rest)) {
                applyDeepPermissionsAndExemptions(modulePkg, targets, myUid);
                writer.println("OK");
                return;
            }
            if (rest.startsWith("IMP ")) {
                String[] parts = rest.split("\\s+");
                if (parts.length < 3) {
                    writer.println("ERR_ARGS");
                    return;
                }
                int targetPid = Integer.parseInt(parts[1]);
                boolean important = "1".equals(parts[2]) || "true".equalsIgnoreCase(parts[2]);
                IBinder am = resolveActivityBinder();
                boolean ok = invokeSetProcessImportant(am, txCode, targetPid, important);
                if (myUid == 0 && important) {
                    applyRootOomBoost(targetPid);
                    ok = true;
                }
                writer.println(ok ? "OK" : "ERR_IMP");
                return;
            }
            if (rest.startsWith("SH_B64 ")) {
                String b64 = rest.substring(7).trim();
                byte[] decoded = Base64.decode(b64, Base64.NO_WRAP);
                String cmd = new String(decoded, StandardCharsets.UTF_8);
                ShellOut out = execShell(cmd, 8000);
                String outB64 = Base64.encodeToString(out.output.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
                writer.println("EXIT=" + out.exitCode + " " + outB64);
                return;
            }
            writer.println("ERR_UNKNOWN_CMD");
        } catch (Throwable t) {
            // Connection closed cleanly
        }
    }

    private static void runWatchdogLoop(
            String modulePkg,
            List<String> targets,
            int myPid,
            int myUid,
            int localPort,
            int txCode,
            String secretHex
    ) {
        HashMap<String, Integer> lastPids = new HashMap<>();
        int tick = 0;
        while (sRunning) {
            try {
                IBinder am = resolveActivityBinder();
                for (String pkg : targets) {
                    int pid = resolveSinglePid(pkg);
                    if (pid > 0) {
                        Integer prev = lastPids.get(pkg);
                        if (prev == null || prev != pid || (tick % 3 == 0)) {
                            invokeSetProcessImportant(am, txCode, pid, true);
                            if (myUid == 0) {
                                applyRootOomBoost(pid);
                            }
                            lastPids.put(pkg, pid);
                        }
                    }
                }
                int modPid = resolveSinglePid(modulePkg);
                if (modPid > 0) {
                    invokeSetProcessImportant(am, txCode, modPid, true);
                    if (myUid == 0) {
                        applyRootOomBoost(modPid);
                    }
                }
                if (tick % 6 == 0) {
                    registerWithModuleProvider(localPort, myPid, myUid, txCode, secretHex);
                }
                tick++;
                Thread.sleep(20000L);
            } catch (InterruptedException ie) {
                break;
            } catch (Throwable ignored) {
            }
        }
    }

    private static void registerWithModuleProvider(int port, int pid, int uid, int txCode, String secretHex) {
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                ProcessBuilder pb = new ProcessBuilder(
                        "/system/bin/content", "call",
                        "--uri", STATUS_PROVIDER_URI,
                        "--method", "register_daemon",
                        "--extra", "port:i:" + port,
                        "--extra", "pid:i:" + pid,
                        "--extra", "uid:i:" + uid,
                        "--extra", "tx:i:" + txCode,
                        "--extra", "token:s:" + secretHex
                );
                pb.redirectErrorStream(true);
                java.lang.Process p = pb.start();
                boolean done = p.waitFor(4, TimeUnit.SECONDS);
                if (done && p.exitValue() == 0) {
                    return;
                }
                if (!done) {
                    p.destroyForcibly();
                }
            } catch (Throwable ignored) {
            }
            try {
                Thread.sleep(600L);
            } catch (InterruptedException ignored) {
                return;
            }
        }
    }

    private static void applyDeepPermissionsAndExemptions(String modulePkg, List<String> targets, int myUid) {
        String listenerComp = modulePkg + "/" + modulePkg + ".KeepaliveBridgeListenerService";
        StringBuilder sb = new StringBuilder(
                buildDeepExemptionsShellScript(modulePkg, targets, listenerComp, true)
        );
        if (myUid == 0) {
            sb.append("echo -1000 > /proc/self/oom_score_adj 2>/dev/null || true; ");
        }
        execShell(sb.toString(), 12000);
    }

    static String buildDeepExemptionsShellScript(
            String modulePkg,
            List<String> targets,
            String listenerComp,
            boolean grantListener
    ) {
        StringBuilder sb = new StringBuilder();
        if (isSafeToken(modulePkg)) {
            for (String perm : DEV_PERMISSIONS) {
                sb.append("pm grant ").append(modulePkg).append(' ').append(perm).append(" 2>/dev/null || true; ");
            }
        }
        if (grantListener && isSafeComponent(listenerComp)) {
            sb.append("cmd notification allow_listener ").append(listenerComp).append(" 2>/dev/null || true; ");
        }

        ArrayList<String> allPkgs = new ArrayList<>();
        if (isSafeToken(modulePkg)) {
            allPkgs.add(modulePkg);
        }
        if (targets != null) {
            for (String t : targets) {
                if (isSafeToken(t) && !allPkgs.contains(t)) {
                    allPkgs.add(t);
                }
            }
        }

        for (String pkg : allPkgs) {
            sb.append("cmd deviceidle whitelist +").append(pkg).append(" 2>/dev/null || true; ");
            sb.append("cmd activity set-standby-bucket ").append(pkg).append(" exempted 2>/dev/null || ")
                    .append("cmd activity set-standby-bucket ").append(pkg).append(" active 2>/dev/null || true; ");
            for (String op : DEEP_APPOPS) {
                sb.append("cmd appops set ").append(pkg).append(' ').append(op).append(" allow 2>/dev/null || true; ");
            }
            sb.append("u=$(pm list packages -U ").append(pkg).append(" 2>/dev/null | sed -n 's/.*uid:\\([0-9]*\\).*/\\1/p' | head -n 1); ")
                    .append("if [ -n \"$u\" ] && [ \"$u\" -gt 1000 ]; then ")
                    .append("cmd netpolicy add restrict-background-whitelist \"$u\" 2>/dev/null || true; ")
                    .append("cmd connectivity set-background-networking-enabled-for-uid \"$u\" true 2>/dev/null || true; ")
                    .append("fi; ");
        }

        sb.append("device_config set_sync_disabled_for_tests persistent 2>/dev/null || true; ");
        sb.append("device_config put activity_manager max_phantom_processes 2147483647 2>/dev/null || true; ");
        sb.append("settings put global settings_enable_monitor_phantom_procs false 2>/dev/null || true; ");
        return sb.toString();
    }

    private static void applyRootOomBoost(int pid) {
        if (pid <= 0) {
            return;
        }
        writeSysFile("/proc/" + pid + "/oom_score_adj", "-800");
        if (new java.io.File("/dev/cpuset/foreground/tasks").exists()) {
            writeSysFile("/dev/cpuset/foreground/tasks", Integer.toString(pid));
        }
    }

    private static void writeSysFile(String path, String value) {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(value.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable ignored) {
        }
    }

    private static int resolveSinglePid(String pkg) {
        if (!isSafeToken(pkg)) {
            return -1;
        }
        ShellOut out = execShell("pidof " + pkg, 2500);
        if (out.exitCode != 0 || out.output.isEmpty()) {
            return -1;
        }
        for (String part : out.output.trim().split("\\s+")) {
            try {
                int pid = Integer.parseInt(part.trim());
                if (pid > 0) {
                    return pid;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return -1;
    }

    private static final class ShellOut {
        final int exitCode;
        final String output;

        ShellOut(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    private static ShellOut execShell(String cmd, int timeoutMs) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            java.lang.Process p = pb.start();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream is = p.getInputStream()) {
                    byte[] b = new byte[4096];
                    int n;
                    while ((n = is.read(b)) > 0) {
                        if (buf.size() < 65536) {
                            buf.write(b, 0, Math.min(n, 65536 - buf.size()));
                        }
                    }
                } catch (Throwable ignored) {
                }
            }, "wgplus-daemon-io");
            reader.start();
            boolean finished = p.waitFor(Math.max(500, timeoutMs), TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                return new ShellOut(-2, "timeout");
            }
            reader.join(400);
            return new ShellOut(p.exitValue(), new String(buf.toByteArray(), StandardCharsets.UTF_8));
        } catch (Throwable t) {
            return new ShellOut(-1, t.getMessage() != null ? t.getMessage() : "error");
        }
    }

    private static List<String> parseSafePackages(String csv) {
        ArrayList<String> list = new ArrayList<>();
        if (csv != null) {
            for (String p : csv.split(",")) {
                String trimmed = p.trim();
                if (isSafeToken(trimmed) && !list.contains(trimmed)) {
                    list.add(trimmed);
                }
            }
        }
        return list;
    }

    static boolean isSafeToken(String pkg) {
        if (pkg == null || pkg.isEmpty() || pkg.length() > 128) {
            return false;
        }
        for (int i = 0; i < pkg.length(); i++) {
            char c = pkg.charAt(i);
            boolean valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '_';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    static boolean isSafeComponent(String comp) {
        if (comp == null) {
            return false;
        }
        int slash = comp.indexOf('/');
        if (slash <= 0 || slash >= comp.length() - 1) {
            return false;
        }
        return isSafeToken(comp.substring(0, slash)) && isSafeToken(comp.substring(slash + 1));
    }

    private static String toHex(byte[] bytes) {
        char[] hex = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = hex[v >>> 4];
            out[i * 2 + 1] = hex[v & 0x0F];
        }
        return new String(out);
    }
}
