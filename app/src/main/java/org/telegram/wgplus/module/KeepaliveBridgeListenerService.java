package org.telegram.wgplus.module;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.IBinder;
import android.provider.Settings;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Zero-notification-capture silent NotificationListenerService acting as Android/Samsung
 * background capability anchor ({@code BIND_FOREGROUND_SERVICE | BIND_NOT_PERCEPTIBLE}) so
 * {@code NotificationsService} can remain silently elevated without creating a foreground
 * notification or triggering Samsung's "1 active app" Quick Panel banner.
 */
public class KeepaliveBridgeListenerService extends NotificationListenerService {

    private static final String TAG = "WGPlusBridgeListener";
    private static final int BIND_FLAGS_MODERN = Context.BIND_AUTO_CREATE
            | Context.BIND_IMPORTANT
            | 0x00001000; // Context.BIND_INCLUDE_CAPABILITIES (API 29+)
    private static final int BIND_FLAGS_LEGACY = Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT;

    private static volatile KeepaliveBridgeListenerService sInstance;
    private static volatile boolean sListenerConnected;

    private final ConcurrentHashMap<String, BridgeConnection> mConnections = new ConcurrentHashMap<>();

    private final class BridgeConnection implements ServiceConnection {
        final String targetPackage;
        volatile boolean binderConnected;
        volatile boolean attemptedBind;

        BridgeConnection(String pkg) {
            this.targetPackage = pkg;
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            binderConnected = true;
            attemptedBind = true;
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            binderConnected = false;
            evictDeadConnection(this);
        }

        @Override
        public void onBindingDied(ComponentName name) {
            binderConnected = false;
            evictDeadConnection(this);
        }

        @Override
        public void onNullBinding(ComponentName name) {
            attemptedBind = true;
        }
    }

    private void evictDeadConnection(BridgeConnection dead) {
        if (dead != null && mConnections.remove(dead.targetPackage, dead)) {
            try {
                unbindService(dead);
            } catch (Throwable ignored) {
            }
        }
    }

    @Override
    public void onListenerConnected() {
        super.onListenerConnected();
        sInstance = this;
        sListenerConnected = true;
        syncBindingsInternal();
        ContinuityBridgeManager.onListenerConnectedAsync(this);
    }

    @Override
    public void onListenerDisconnected() {
        sListenerConnected = false;
        unbindAllInternal();
        sInstance = null;
        super.onListenerDisconnected();
    }

    @Override
    public void onDestroy() {
        sListenerConnected = false;
        unbindAllInternal();
        if (sInstance == this) {
            sInstance = null;
        }
        super.onDestroy();
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        // Intentionally no-op: filter metadata disables all categories; zero notifications are inspected.
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        // Intentionally no-op.
    }

    public static boolean isConnected() {
        return sListenerConnected && sInstance != null;
    }

    public static boolean isBoundForPackage(String pkg) {
        KeepaliveBridgeListenerService inst = sInstance;
        if (!sListenerConnected || inst == null || pkg == null) {
            return false;
        }
        BridgeConnection conn = inst.mConnections.get(pkg);
        return conn != null && conn.attemptedBind;
    }

    public static Set<String> getBoundPackages() {
        KeepaliveBridgeListenerService inst = sInstance;
        if (!sListenerConnected || inst == null) {
            return Collections.emptySet();
        }
        return new HashSet<>(inst.mConnections.keySet());
    }

    public static boolean isNotificationListenerEnabled(Context context) {
        if (context == null) {
            return false;
        }
        try {
            String flat = Settings.Secure.getString(
                    context.getContentResolver(),
                    "enabled_notification_listeners"
            );
            if (flat == null || flat.isEmpty()) {
                return false;
            }
            String myPkg = context.getPackageName();
            String clsName = KeepaliveBridgeListenerService.class.getName();
            String[] parts = flat.split(":");
            for (String part : parts) {
                ComponentName cn = ComponentName.unflattenFromString(part.trim());
                if (cn != null
                        && myPkg.equals(cn.getPackageName())
                        && clsName.equals(cn.getClassName())) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static boolean syncBindings() {
        KeepaliveBridgeListenerService inst = sInstance;
        if (!sListenerConnected || inst == null) {
            return false;
        }
        return inst.syncBindingsInternal();
    }

    private boolean syncBindingsInternal() {
        boolean stealthEnabled = ContinuityBridgeManager.isStealthHybridEnabled(this);
        Set<String> wanted = stealthEnabled
                ? ContinuityBridgeManager.getWantedPackages(this)
                : Collections.emptySet();

        Iterator<Map.Entry<String, BridgeConnection>> it = mConnections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, BridgeConnection> entry = it.next();
            if (!wanted.contains(entry.getKey())) {
                try {
                    unbindService(entry.getValue());
                } catch (Throwable ignored) {
                }
                it.remove();
            }
        }

        if (!stealthEnabled || wanted.isEmpty()) {
            return false;
        }

        int bindFlags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                ? BIND_FLAGS_MODERN
                : BIND_FLAGS_LEGACY;

        boolean anyBound = false;
        for (String pkg : wanted) {
            if (!ContinuityBridgeManager.isPackageInstalled(this, pkg)) {
                continue;
            }
            BridgeConnection conn = mConnections.get(pkg);
            if (conn == null) {
                conn = new BridgeConnection(pkg);
                try {
                    Intent intent = new Intent(WireGuardManager.ACTION_KEEPALIVE_BRIDGE);
                    intent.setClassName(pkg, ContinuityBridgeManager.TELEGRAM_KEEPALIVE_SERVICE);
                    boolean ok = bindService(intent, conn, bindFlags);
                    if (ok) {
                        conn.attemptedBind = true;
                        mConnections.put(pkg, conn);
                        anyBound = true;
                    } else {
                        try {
                            unbindService(conn);
                        } catch (Throwable ignored) {
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "bindService failed for " + pkg + ": " + t.getMessage());
                }
            } else {
                anyBound = true;
            }
        }
        return anyBound;
    }

    private void unbindAllInternal() {
        Iterator<Map.Entry<String, BridgeConnection>> it = mConnections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, BridgeConnection> entry = it.next();
            try {
                unbindService(entry.getValue());
            } catch (Throwable ignored) {
            }
            it.remove();
        }
    }
}
