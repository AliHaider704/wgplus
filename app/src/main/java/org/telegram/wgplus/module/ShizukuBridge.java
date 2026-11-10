package org.telegram.wgplus.module;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Pure Android-SDK Shizuku v13 binder client without AndroidX or external AAR dependencies.
 * Receives the {@code IShizukuService} binder via {@link ShizukuClientProvider} ({@code sendBinder})
 * and explicit {@code REQUEST_BINDER} reply callback, then executes uid=2000 remote Binder
 * transactions and shell exemption commands cleanly.
 */
public final class ShizukuBridge {

    private static final String TAG = "WGPlusShizuku";

    public static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";
    private static final String SHIZUKU_RECEIVER_CLASS = "moe.shizuku.manager.receiver.ShizukuReceiver";
    private static final String ACTION_REQUEST_BINDER = "rikka.shizuku.intent.action.REQUEST_BINDER";

    private static final String DESCRIPTOR_SERVICE = "moe.shizuku.server.IShizukuService";
    private static final String DESCRIPTOR_APPLICATION = "moe.shizuku.server.IShizukuApplication";
    private static final String DESCRIPTOR_REMOTE_PROCESS = "moe.shizuku.server.IRemoteProcess";
    private static final String DESCRIPTOR_ACTIVITY_MANAGER = "android.app.IActivityManager";

    private static final int CLIENT_API_VERSION = 13;

    private static final int TX_TRANSACT_REMOTE = 1;
    private static final int TX_GET_VERSION = 3;
    private static final int TX_GET_UID = 4;
    private static final int TX_NEW_PROCESS = 8;
    private static final int TX_ATTACH_APPLICATION_LEGACY = 14;
    private static final int TX_REQUEST_PERMISSION = 15;
    private static final int TX_CHECK_SELF_PERMISSION = 16;
    private static final int TX_ATTACH_APPLICATION_V13 = 18;

    private static final int TX_APP_BIND_APPLICATION = 2;
    private static final int TX_APP_DISPATCH_PERMISSION = 3;

    private static final int TX_PROC_GET_INPUT = 2;
    private static final int TX_PROC_EXIT_VALUE = 5;
    private static final int TX_PROC_DESTROY = 6;
    private static final int TX_PROC_WAIT_FOR_TIMEOUT = 8;

    private static final Object LOCK = new Object();
    private static final IBinder sProcessImportanceToken = new Binder();
    private static final ConcurrentHashMap<Integer, PermissionCallback> sPendingCallbacks = new ConcurrentHashMap<>();
    private static final CopyOnWriteArrayList<BinderListener> sBinderListeners = new CopyOnWriteArrayList<>();

    private static volatile IBinder sServiceBinder;
    private static volatile boolean sApplicationAttached;
    private static volatile boolean sPermissionGranted;
    private static volatile int sServerApiVersion = -1;
    private static volatile int sServerUid = -1;
    private static volatile IBinder sCachedActivityBinder;
    private static volatile int sCachedSetProcessImportantTx = -1;
    private static volatile int sNextReqCode = 9001;
    private static volatile long sLastRequestBinderMs;

    public interface PermissionCallback {
        void onResult(boolean granted);
    }

    public interface BinderListener {
        void onBinderChanged(boolean alive);
    }

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

    private ShizukuBridge() {
    }

    public static void addBinderListener(BinderListener listener) {
        if (listener != null && !sBinderListeners.contains(listener)) {
            sBinderListeners.add(listener);
        }
    }

    public static void removeBinderListener(BinderListener listener) {
        if (listener != null) {
            sBinderListeners.remove(listener);
        }
    }

    private static void notifyBinderListeners(boolean alive) {
        for (BinderListener l : sBinderListeners) {
            try {
                l.onBinderChanged(alive);
            } catch (Throwable ignored) {
            }
        }
    }

    private static final Binder sApplicationCallback = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws android.os.RemoteException {
            if (code == INTERFACE_TRANSACTION && reply != null) {
                reply.writeString(DESCRIPTOR_APPLICATION);
                return true;
            }
            if (code == TX_APP_BIND_APPLICATION) {
                data.enforceInterface(DESCRIPTOR_APPLICATION);
                Bundle bundle = data.readInt() != 0 ? Bundle.CREATOR.createFromParcel(data) : null;
                if (bundle != null) {
                    sPermissionGranted = bundle.getBoolean("shizuku:attach-reply-permission-granted", sPermissionGranted);
                    sServerApiVersion = bundle.getInt("shizuku:attach-reply-version", sServerApiVersion);
                    sServerUid = bundle.getInt("shizuku:attach-reply-uid", sServerUid);
                }
                return true;
            }
            if (code == TX_APP_DISPATCH_PERMISSION) {
                data.enforceInterface(DESCRIPTOR_APPLICATION);
                int reqCode = data.readInt();
                Bundle bundle = data.readInt() != 0 ? Bundle.CREATOR.createFromParcel(data) : null;
                boolean allowed = bundle != null && bundle.getBoolean("shizuku:request-permission-reply-allowed", false);
                sPermissionGranted = allowed;
                PermissionCallback cb = sPendingCallbacks.remove(reqCode);
                if (cb != null) {
                    try {
                        cb.onResult(allowed);
                    } catch (Throwable ignored) {
                    }
                }
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    private static final IBinder.DeathRecipient sDeathRecipient = () -> {
        synchronized (LOCK) {
            resetBinderStateLocked();
        }
        notifyBinderListeners(false);
    };

    public static boolean isShizukuInstalled(Context context) {
        if (context == null) {
            return false;
        }
        try {
            PackageManager pm = context.getPackageManager();
            if (pm == null) {
                return false;
            }
            pm.getPackageInfo(SHIZUKU_PACKAGE, 0);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static IBinder peekLiveBinder() {
        IBinder current = sServiceBinder;
        return (current != null && current.pingBinder()) ? current : null;
    }

    public static boolean isRunning(Context context) {
        return getServiceBinder(context) != null;
    }

    public static int getServerUid() {
        return sServerUid;
    }

    public static void onBinderReceived(Context context, IBinder binder) {
        if (binder == null || !binder.pingBinder()) {
            return;
        }
        boolean changed;
        synchronized (LOCK) {
            changed = (sServiceBinder != binder);
            if (changed) {
                resetBinderStateLocked();
                try {
                    binder.linkToDeath(sDeathRecipient, 0);
                } catch (Throwable ignored) {
                }
                sServiceBinder = binder;
            }
            if (context != null) {
                ensureAttachedLocked(context, binder);
            }
        }
        if (changed) {
            notifyBinderListeners(true);
        }
    }

    public static void requestBinderBroadcastAsync(Context context) {
        if (context == null || !isShizukuInstalled(context)) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - sLastRequestBinderMs < 350L) {
            return;
        }
        sLastRequestBinderMs = now;
        sendBinderRequestInternal(context, null);
    }

    public static IBinder getServiceBinder(Context context) {
        IBinder current = sServiceBinder;
        if (current != null && current.pingBinder()) {
            ensureAttachedLocked(context, current);
            return current;
        }
        if (context == null || !isShizukuInstalled(context)) {
            synchronized (LOCK) {
                resetBinderStateLocked();
            }
            return null;
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            // Never block UI thread waiting for broadcast reply; fire async request and let listener refresh.
            requestBinderBroadcastAsync(context);
            return peekLiveBinder();
        }
        CountDownLatch latch = new CountDownLatch(1);
        sendBinderRequestInternal(context, latch);
        try {
            latch.await(350, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
        }
        current = sServiceBinder;
        if (current != null && current.pingBinder()) {
            ensureAttachedLocked(context, current);
            return current;
        }
        return null;
    }

    private static void sendBinderRequestInternal(Context context, CountDownLatch latch) {
        try {
            final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            Binder replyBinder = new Binder() {
                @Override
                protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                        throws android.os.RemoteException {
                    if (code == 1) {
                        // Match rikka.shizuku.An.g reply layout directly (strong binder + manager sourceDir)
                        IBinder binder = data.readStrongBinder();
                        if (binder != null && binder.pingBinder()) {
                            onBinderReceived(appCtx, binder);
                        }
                        if (latch != null) {
                            latch.countDown();
                        }
                        return true;
                    }
                    return super.onTransact(code, data, reply, flags);
                }
            };
            Bundle data = new Bundle();
            data.putBinder("binder", replyBinder);
            Intent intent = new Intent(ACTION_REQUEST_BINDER);
            intent.setComponent(new ComponentName(SHIZUKU_PACKAGE, SHIZUKU_RECEIVER_CLASS));
            intent.putExtra("data", data);
            appCtx.sendBroadcast(intent);
        } catch (Throwable t) {
            Log.w(TAG, "sendBinderRequestInternal warning: " + t.getMessage());
            if (latch != null) {
                latch.countDown();
            }
        }
    }

    private static void resetBinderStateLocked() {
        sServiceBinder = null;
        sApplicationAttached = false;
        sPermissionGranted = false;
        sServerApiVersion = -1;
        sServerUid = -1;
    }

    private static void ensureAttachedLocked(Context context, IBinder binder) {
        if (binder == null || sApplicationAttached || context == null) {
            return;
        }
        synchronized (LOCK) {
            if (sApplicationAttached || !binder.pingBinder()) {
                return;
            }
            try {
                int ver = queryIntNoArg(binder, TX_GET_VERSION, -1);
                sServerApiVersion = ver;
                sServerUid = queryIntNoArg(binder, TX_GET_UID, -1);

                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(DESCRIPTOR_SERVICE);
                    data.writeStrongBinder(sApplicationCallback);
                    if (ver >= 13 || ver < 0) {
                        Bundle args = new Bundle();
                        args.putInt("shizuku:attach-api-version", CLIENT_API_VERSION);
                        args.putString("shizuku:attach-package-name", context.getPackageName());
                        data.writeInt(1);
                        args.writeToParcel(data, 0);
                        binder.transact(TX_ATTACH_APPLICATION_V13, data, reply, 0);
                    } else {
                        data.writeString(context.getPackageName());
                        binder.transact(TX_ATTACH_APPLICATION_LEGACY, data, reply, 0);
                    }
                    reply.readException();
                    sApplicationAttached = true;
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            } catch (Throwable t) {
                Log.w(TAG, "attachApplication warning: " + t.getMessage());
            }
        }
    }

    private static int queryIntNoArg(IBinder binder, int txCode, int fallback) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_SERVICE);
            if (binder.transact(txCode, data, reply, 0)) {
                reply.readException();
                return reply.readInt();
            }
        } catch (Throwable ignored) {
        } finally {
            data.recycle();
            reply.recycle();
        }
        return fallback;
    }

    public static boolean hasPermission(Context context) {
        IBinder binder = getServiceBinder(context);
        if (binder == null) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_SERVICE);
            binder.transact(TX_CHECK_SELF_PERMISSION, data, reply, 0);
            reply.readException();
            boolean granted = reply.readInt() != 0;
            sPermissionGranted = granted;
            return granted;
        } catch (Throwable t) {
            return sPermissionGranted;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static boolean requestPermission(Context context, PermissionCallback callback) {
        IBinder binder = getServiceBinder(context);
        if (binder == null) {
            return false;
        }
        int reqCode = ++sNextReqCode;
        if (callback != null) {
            sPendingCallbacks.put(reqCode, callback);
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_SERVICE);
            data.writeInt(reqCode);
            binder.transact(TX_REQUEST_PERMISSION, data, reply, 0);
            reply.readException();
            return true;
        } catch (Throwable t) {
            sPendingCallbacks.remove(reqCode);
            Log.w(TAG, "requestPermission failed: " + t.getMessage());
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static boolean transactRemote(
            Context context,
            IBinder target,
            int code,
            Parcel data,
            Parcel reply,
            int flags
    ) {
        IBinder shizuku = getServiceBinder(context);
        if (shizuku == null || target == null) {
            return false;
        }
        Parcel wrapped = Parcel.obtain();
        try {
            wrapped.writeInterfaceToken(DESCRIPTOR_SERVICE);
            wrapped.writeStrongBinder(target);
            wrapped.writeInt(code);
            if (sServerApiVersion >= 13 || sServerApiVersion < 0) {
                wrapped.writeInt(flags);
            }
            if (data != null) {
                wrapped.appendFrom(data, 0, data.dataSize());
            }
            return shizuku.transact(TX_TRANSACT_REMOTE, wrapped, reply, 0);
        } catch (Throwable t) {
            Log.w(TAG, "transactRemote failed: " + t.getMessage());
            return false;
        } finally {
            wrapped.recycle();
        }
    }

    public static ShellResult runShellCommand(Context context, String command, int timeoutMs) {
        return runDirectCommand(context, new String[]{"sh", "-c", command + " 2>&1"}, timeoutMs);
    }

    public static ShellResult runDirectCommand(Context context, String[] argv, int timeoutMs) {
        if (!hasPermission(context)) {
            return new ShellResult(-1, "No Shizuku permission", false);
        }
        IBinder shizuku = getServiceBinder(context);
        if (shizuku == null) {
            return new ShellResult(-1, "Shizuku binder unavailable", false);
        }
        IBinder remoteProc = null;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_SERVICE);
            data.writeStringArray(argv);
            data.writeStringArray(null);
            data.writeString(null);
            shizuku.transact(TX_NEW_PROCESS, data, reply, 0);
            reply.readException();
            remoteProc = reply.readStrongBinder();
            if (remoteProc == null) {
                return new ShellResult(-1, "Null IRemoteProcess", false);
            }

            ParcelFileDescriptor stdoutPfd = getRemoteProcessStream(remoteProc, TX_PROC_GET_INPUT);
            ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
            Thread reader = null;
            if (stdoutPfd != null) {
                reader = new Thread(() -> {
                    try (InputStream is = new ParcelFileDescriptor.AutoCloseInputStream(stdoutPfd)) {
                        byte[] buf = new byte[4096];
                        int n;
                        while ((n = is.read(buf)) > 0) {
                            if (outBuf.size() < 32768) {
                                outBuf.write(buf, 0, Math.min(n, 32768 - outBuf.size()));
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }, "wgplus-shizuku-io");
                reader.start();
            }

            boolean exited = waitRemoteProcess(remoteProc, Math.max(500, timeoutMs));
            if (!exited) {
                destroyRemoteProcess(remoteProc);
                return new ShellResult(-2, "Command timeout", false);
            }
            if (reader != null) {
                try {
                    reader.join(500);
                } catch (InterruptedException ignored) {
                }
            }
            int exitCode = getRemoteProcessExitValue(remoteProc);
            String text = new String(outBuf.toByteArray(), StandardCharsets.UTF_8).trim();
            return new ShellResult(exitCode, text, exitCode == 0);
        } catch (Throwable t) {
            destroyRemoteProcess(remoteProc);
            return new ShellResult(-1, t.getMessage(), false);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private static ParcelFileDescriptor getRemoteProcessStream(IBinder proc, int tx) {
        Parcel d = Parcel.obtain();
        Parcel r = Parcel.obtain();
        try {
            d.writeInterfaceToken(DESCRIPTOR_REMOTE_PROCESS);
            proc.transact(tx, d, r, 0);
            r.readException();
            if (r.readInt() != 0) {
                return ParcelFileDescriptor.CREATOR.createFromParcel(r);
            }
        } catch (Throwable ignored) {
        } finally {
            d.recycle();
            r.recycle();
        }
        return null;
    }

    private static boolean waitRemoteProcess(IBinder proc, int timeoutMs) {
        Parcel d = Parcel.obtain();
        Parcel r = Parcel.obtain();
        try {
            d.writeInterfaceToken(DESCRIPTOR_REMOTE_PROCESS);
            d.writeLong(timeoutMs);
            d.writeString(TimeUnit.MILLISECONDS.name());
            proc.transact(TX_PROC_WAIT_FOR_TIMEOUT, d, r, 0);
            r.readException();
            return r.readInt() != 0;
        } catch (Throwable t) {
            return false;
        } finally {
            d.recycle();
            r.recycle();
        }
    }

    private static int getRemoteProcessExitValue(IBinder proc) {
        Parcel d = Parcel.obtain();
        Parcel r = Parcel.obtain();
        try {
            d.writeInterfaceToken(DESCRIPTOR_REMOTE_PROCESS);
            proc.transact(TX_PROC_EXIT_VALUE, d, r, 0);
            r.readException();
            return r.readInt();
        } catch (Throwable t) {
            return -1;
        } finally {
            d.recycle();
            r.recycle();
        }
    }

    private static void destroyRemoteProcess(IBinder proc) {
        if (proc == null) {
            return;
        }
        Parcel d = Parcel.obtain();
        Parcel r = Parcel.obtain();
        try {
            d.writeInterfaceToken(DESCRIPTOR_REMOTE_PROCESS);
            proc.transact(TX_PROC_DESTROY, d, r, IBinder.FLAG_ONEWAY);
        } catch (Throwable ignored) {
        } finally {
            d.recycle();
            r.recycle();
        }
    }

    public static boolean applyProcessImportant(Context context, int pid, boolean important) {
        if (pid <= 0 || !hasPermission(context)) {
            return false;
        }
        IBinder activityBinder = resolveActivityManagerBinder();
        int txCode = resolveSetProcessImportantTxCode(context);
        if (activityBinder == null || txCode <= 0) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR_ACTIVITY_MANAGER);
            data.writeStrongBinder(sProcessImportanceToken);
            data.writeInt(pid);
            data.writeInt(important ? 1 : 0);
            data.writeString("setProcessImportant()");
            if (!transactRemote(context, activityBinder, txCode, data, reply, 0)) {
                return false;
            }
            reply.readException();
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "applyProcessImportant failed for pid=" + pid + ": " + t.getMessage());
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
        if (!hasPermission(context) || targetPackages == null || targetPackages.isEmpty()) {
            return false;
        }
        PackageManager pm = context.getPackageManager();
        StringBuilder sb = new StringBuilder();
        for (String pkg : targetPackages) {
            if (!isSafeToken(pkg)) {
                continue;
            }
            sb.append("cmd deviceidle whitelist +").append(pkg).append("; ");
            sb.append("cmd activity set-standby-bucket ").append(pkg).append(" exempted 2>/dev/null || ")
                    .append("cmd activity set-standby-bucket ").append(pkg).append(" active 2>/dev/null; ");
            sb.append("cmd appops set ").append(pkg).append(" RUN_ANY_IN_BACKGROUND allow 2>/dev/null; ");
            sb.append("cmd appops set ").append(pkg).append(" RUN_IN_BACKGROUND allow 2>/dev/null; ");
            if (pm != null) {
                try {
                    int uid = pm.getApplicationInfo(pkg, 0).uid;
                    if (uid > 1000) {
                        sb.append("cmd netpolicy add restrict-background-whitelist ").append(uid).append(" 2>/dev/null; ");
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        if (grantListener && listenerComponent != null && isSafeComponent(listenerComponent)) {
            sb.append("cmd notification allow_listener ").append(listenerComponent).append("; ");
        }
        ShellResult res = runShellCommand(context, sb.toString(), 6000);
        return res.ok || grantListener == KeepaliveBridgeListenerService.isNotificationListenerEnabled(context);
    }

    private static boolean isSafeToken(String pkg) {
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

    private static boolean isSafeComponent(String comp) {
        int slash = comp.indexOf('/');
        if (slash <= 0 || slash >= comp.length() - 1) {
            return false;
        }
        return isSafeToken(comp.substring(0, slash)) && isSafeToken(comp.substring(slash + 1));
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
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        String prefKey = "tx_imp_" + Build.FINGERPRINT;
        SharedPreferences prefs = appCtx.getSharedPreferences("wg_plus_shizuku_cache", Context.MODE_PRIVATE);
        int stored = prefs.getInt(prefKey, -1);
        if (stored > 0) {
            sCachedSetProcessImportantTx = stored;
            return stored;
        }
        try {
            String apkPath = appCtx.getApplicationInfo().sourceDir;
            if (apkPath == null || apkPath.isEmpty()) {
                return -1;
            }
            ShellResult res = runDirectCommand(
                    appCtx,
                    new String[]{
                            "/system/bin/env",
                            "CLASSPATH=" + apkPath,
                            "/system/bin/app_process",
                            "/system/bin",
                            ShizukuProcessHelper.class.getName()
                    },
                    4000
            );
            String out = res.output;
            int idx = out.indexOf(ShizukuProcessHelper.PREFIX);
            if (idx >= 0) {
                String tail = out.substring(idx + ShizukuProcessHelper.PREFIX.length()).trim();
                int end = 0;
                while (end < tail.length() && Character.isDigit(tail.charAt(end))) {
                    end++;
                }
                if (end > 0) {
                    int code = Integer.parseInt(tail.substring(0, end));
                    if (code > 0) {
                        sCachedSetProcessImportantTx = code;
                        prefs.edit().putInt(prefKey, code).apply();
                        return code;
                    }
                }
            }
            Log.w(TAG, "resolveSetProcessImportantTxCode empty output: " + out);
        } catch (Throwable t) {
            Log.w(TAG, "resolveSetProcessImportantTxCode failed: " + t.getMessage());
        }
        return -1;
    }
}
