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
