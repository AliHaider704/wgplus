package org.telegram.wgplus.module;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Silent boot & package-upgrade continuity receiver.
 * Restores Layer 1 self-privilege immediately (even when strictly on Mobile Data without Wi-Fi),
 * schedules passive Wi-Fi/TCP daemon auto-healing via Built-in Wireless ADB (zero notifications),
 * and activates Kernel Root boosts if available.
 */
public class BootContinuityReceiver extends BroadcastReceiver {

    private static final String TAG = "WGPlusBoot";
    private static final ExecutorService BOOT_EXEC = Executors.newSingleThreadExecutor();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (context == null || intent == null) {
            return;
        }
        String action = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)
                && !"android.intent.action.QUICKBOOT_POWERON".equals(action)) {
            return;
        }
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        final PendingResult pending = goAsync();
        BOOT_EXEC.execute(() -> {
            try {
                Log.i(TAG, "Restoring Sovereign continuity silently on event: " + action);
                if (Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
                    try {
                        appCtx.getSharedPreferences("wgplus_shared_tunnel", Context.MODE_PRIVATE)
                                .edit().clear().commit();
                    } catch (Throwable ignored) {
                    }
                    try {
                        KeepaliveStatusProvider.requestRemoteHygieneLocal(appCtx);
                    } catch (Throwable ignored) {
                    }
                    try {
                        if (PrivilegeBridge.isStandaloneDaemonAlive(appCtx) || PrivilegeBridge.hasRootAccess()) {
                            for (String pkg : ContinuityBridgeManager.getInstalledTargetPackages(appCtx)) {
                                PrivilegeBridge.runShellCommand(appCtx, "am force-stop " + pkg, 2500);
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
                ContinuityBridgeManager.onDeviceBootOrPackageUpdated(appCtx);
            } catch (Throwable t) {
                Log.w(TAG, "Boot continuity restore warning: " + t.getMessage());
            } finally {
                if (pending != null) {
                    try {
                        pending.finish();
                    } catch (Throwable ignored) {
                    }
                }
            }
        });
    }
}
