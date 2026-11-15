package org.telegram.wgplus.module;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.RemoteInput;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.github.muntashirakon.adb.android.AdbMdns;

/**
 * Ephemeral Wireless Debugging pairing service. Shows a temporary RemoteInput notification ONLY
 * during one-time 6-digit PIN entry while the user is in Developer Options, then immediately
 * removes the notification and exits cleanly so zero ongoing notifications remain.
 */
public class AdbPairingService extends Service {

    private static final String TAG = "WGPlusAdbPair";
    public static final String ACTION_START_PAIRING = "org.telegram.wgplus.module.ACTION_START_PAIRING";
    public static final String ACTION_STOP_PAIRING = "org.telegram.wgplus.module.ACTION_STOP_PAIRING";
    public static final String ACTION_SUBMIT_CODE = "org.telegram.wgplus.module.ACTION_SUBMIT_CODE";
    public static final String EXTRA_PAIRING_HOST = "host";
    public static final String EXTRA_PAIRING_PORT = "port";
    private static final String KEY_PAIRING_CODE = "pairing_code";
    private static final String CHANNEL_ID = "wgplus_one_time_pairing";
    private static final int NOTIFICATION_ID = 49201;

    private final ExecutorService mExec = Executors.newSingleThreadExecutor();
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final AtomicReference<String> mHostRef = new AtomicReference<>("127.0.0.1");
    private final AtomicInteger mPortRef = new AtomicInteger(-1);
    private volatile CountDownLatch mPortLatch = new CountDownLatch(1);
    private AdbMdns mAdbMdns;

    public static void startForPairing(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return;
        }
        Intent i = new Intent(context, AdbPairingService.class);
        i.setAction(ACTION_START_PAIRING);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(i);
        } else {
            context.startService(i);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP_PAIRING.equals(action)) {
            finishAndRemoveNotification();
            return START_NOT_STICKY;
        }
        if (ACTION_SUBMIT_CODE.equals(action)) {
            Bundle results = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH
                    ? RemoteInput.getResultsFromIntent(intent)
                    : null;
            CharSequence raw = results != null ? results.getCharSequence(KEY_PAIRING_CODE) : null;
            String extraHost = intent.getStringExtra(EXTRA_PAIRING_HOST);
            int extraPort = intent.getIntExtra(EXTRA_PAIRING_PORT, -1);
            handleCodeSubmission(raw != null ? raw.toString() : "", extraHost, extraPort);
            return START_NOT_STICKY;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            startDiscoveryAndPrompt();
        } else {
            finishAndRemoveNotification();
        }
        return START_NOT_STICKY;
    }

    private void startDiscoveryAndPrompt() {
        ensureNotificationChannel();
        mPortRef.set(-1);
        mPortLatch = new CountDownLatch(1);
        showPromptNotification(-1);
        try {
            if (mAdbMdns != null) {
                mAdbMdns.stop();
            }
            mAdbMdns = new AdbMdns(this, AdbMdns.SERVICE_TYPE_TLS_PAIRING, (address, port) -> {
                if (port > 1024 && port <= 65535) {
                    if (address != null && address.getHostAddress() != null) {
                        mHostRef.set(address.getHostAddress());
                    }
                    mPortRef.set(port);
                    mPortLatch.countDown();
                    mMain.post(() -> showPromptNotification(port));
                }
            });
            mAdbMdns.start();
        } catch (Throwable t) {
            Log.w(TAG, "AdbMdns pairing listener warning: " + t.getMessage());
        }
    }

    private void handleCodeSubmission(String rawInput, String overrideHost, int overridePort) {
        String[] parsed = BuiltinAdbKeyManager.parsePairingInput(rawInput);
        if (parsed == null) {
            boolean isAr = WireGuardManager.isArabic(this);
            mMain.post(() -> Toast.makeText(
                    getApplicationContext(),
                    WgStrings.adbPairingResultToast(isAr, false),
                    Toast.LENGTH_LONG
            ).show());
            showPromptNotification(mPortRef.get());
            return;
        }
        final String pin = parsed[0];
        int explicitPort = -1;
        if (!parsed[1].isEmpty()) {
            try {
                explicitPort = Integer.parseInt(parsed[1]);
            } catch (NumberFormatException ignored) {
            }
        } else if (overridePort > 1024) {
            explicitPort = overridePort;
        }
        final int fixedPort = explicitPort;
        mExec.execute(() -> {
            boolean paired = false;
            try {
                int port = fixedPort > 1024 ? fixedPort : mPortRef.get();
                if (port <= 1024) {
                    mPortLatch.await(4500L, TimeUnit.MILLISECONDS);
                    port = mPortRef.get();
                }
                String host = (overrideHost != null && !overrideHost.trim().isEmpty())
                        ? overrideHost.trim()
                        : mHostRef.get();
                if (port > 1024) {
                    paired = WgAdbConnectionManager.getInstance(this).pairWithCode(this, host, port, pin);
                }
                if (paired) {
                    ContinuityBridgeManager.activateHybridOneTap(this);
                }
            } catch (Throwable t) {
                Log.w(TAG, "Pairing submission failed: " + t.getMessage());
            } finally {
                final boolean success = paired;
                boolean isAr = WireGuardManager.isArabic(this);
                mMain.post(() -> {
                    Toast.makeText(
                            getApplicationContext(),
                            WgStrings.adbPairingResultToast(isAr, success),
                            Toast.LENGTH_LONG
                    ).show();
                    finishAndRemoveNotification();
                });
            }
        });
    }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) {
            return;
        }
        boolean isAr = WireGuardManager.isArabic(this);
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID,
                WgStrings.adbPairingChannelName(isAr),
                NotificationManager.IMPORTANCE_HIGH
        );
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }

    private void showPromptNotification(int discoveredPort) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return;
        }
        boolean isAr = WireGuardManager.isArabic(this);

        Intent replyIntent = new Intent(this, AdbPairingService.class);
        replyIntent.setAction(ACTION_SUBMIT_CODE);
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE;
        PendingIntent replyPending = PendingIntent.getService(this, 1, replyIntent, piFlags);

        RemoteInput remoteInput = new RemoteInput.Builder(KEY_PAIRING_CODE)
                .setLabel(WgStrings.adbPairingHint(isAr))
                .build();

        Notification.Action replyAction = new Notification.Action.Builder(
                android.R.drawable.ic_menu_send,
                WgStrings.adbPairingActionReply(isAr),
                replyPending
        ).addRemoteInput(remoteInput).build();

        Intent cancelIntent = new Intent(this, AdbPairingService.class);
        cancelIntent.setAction(ACTION_STOP_PAIRING);
        int immFlags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        PendingIntent cancelPending = PendingIntent.getService(this, 2, cancelIntent, immFlags);

        Notification.Builder nb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);

        nb.setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                .setContentTitle(WgStrings.adbPairingNotifTitle(isAr, discoveredPort))
                .setContentText(WgStrings.adbPairingNotifBody(isAr))
                .setOnlyAlertOnce(true)
                .setOngoing(false)
                .addAction(replyAction)
                .addAction(new Notification.Action.Builder(
                        android.R.drawable.ic_menu_close_clear_cancel,
                        WgStrings.adbPairingCancel(isAr),
                        cancelPending
                ).build());

        Notification notif = nb.build();
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIFICATION_ID, notif);
            }
        } catch (Throwable t) {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.notify(NOTIFICATION_ID, notif);
            }
        }
    }

    private void finishAndRemoveNotification() {
        try {
            if (mAdbMdns != null) {
                mAdbMdns.stop();
                mAdbMdns = null;
            }
        } catch (Throwable ignored) {
        }
        try {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // Replace without RemoteInput first so Android clears LIFETIME_EXTENDED_BY_DIRECT_REPLY immediately.
                Notification.Builder clearNb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                        ? new Notification.Builder(this, CHANNEL_ID)
                        : new Notification.Builder(this);
                clearNb.setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                        .setContentTitle(WgStrings.adbPairingChannelName(WireGuardManager.isArabic(this)))
                        .setOngoing(false);
                nm.notify(NOTIFICATION_ID, clearNb.build());
            }
        } catch (Throwable ignored) {
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } else {
                stopForeground(true);
            }
        } catch (Throwable ignored) {
        }
        try {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.cancel(NOTIFICATION_ID);
            }
        } catch (Throwable ignored) {
        }
        stopSelf();
    }

    @Override
    public void onDestroy() {
        try {
            if (mAdbMdns != null) {
                mAdbMdns.stop();
                mAdbMdns = null;
            }
        } catch (Throwable ignored) {
        }
        mExec.shutdownNow();
        super.onDestroy();
    }
}
