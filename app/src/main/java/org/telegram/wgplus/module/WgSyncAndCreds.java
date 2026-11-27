package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import wgbridge.Wgbridge;

/**
 * Cross-client sync bundle, deterministic HMAC loopback SOCKS5 credentials, hook heartbeats,
 * and Official Channel invite prompt extracted from {@link WireGuardManager}.
 */
final class WgSyncAndCreds {

    private WgSyncAndCreds() {
    }

    static Context getSocksPrefsContext() {
        return WireGuardManager.sSocksPrefsCtx;
    }

    /**
     * Derives deterministic 128-bit loopback SOCKS/WGP1 credentials from the active WireGuard
     * private key via HMAC-SHA256 so every local Telegram app configured with the same profile
     * authenticates identically without cross-sandbox race conditions or package-visibility failures.
     */
    static String deriveProfileSocksPass(String privateKey) {
        String trimmed = WireGuardManager.safeTrim(privateKey);
        if (trimmed.isEmpty()) {
            return "";
        }
        try {
            String privHex = WireGuardManager.normalizeKeyToHex(trimmed);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec("wgplus-loopback-socks-v2".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(privHex.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(32);
            for (int i = 0; i < 16 && i < digest.length; i++) {
                hex.append(String.format(Locale.US, "%02x", digest[i] & 0xff));
            }
            return hex.toString();
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SYNC", "DERIVE_SOCKS_PASS_ERR", t);
            return "";
        }
    }

    static String computeProfileSigHash(String profileSig) {
        String trimmed = WireGuardManager.safeTrim(profileSig);
        if (trimmed.isEmpty()) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(trimmed.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(12);
            for (int i = 0; i < 6 && i < digest.length; i++) {
                hex.append(String.format(Locale.US, "%02x", digest[i] & 0xff));
            }
            return hex.toString();
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SYNC", "DERIVE_SOCKS_PASS_ERR", t);
            return "";
        }
    }

    static void syncDeterministicSocksCredentialsForProfile(
            Context context,
            WireGuardManager.TunnelConfig cfg
    ) {
        synchronized (WireGuardManager.class) {
            if (context != null) {
                Context app = context.getApplicationContext();
                WireGuardManager.sSocksPrefsCtx = app != null ? app : context;
            }
            String detPass = cfg != null ? deriveProfileSocksPass(cfg.privateKey) : "";
            if (detPass.isEmpty()) {
                ensureSessionSocksCredentials(context);
                return;
            }
            WireGuardManager.SocksCredsSnapshot cur = WireGuardManager.sSocksCreds;
            boolean changed = !"wg".equals(cur.user) || !detPass.equals(cur.pass);
            WireGuardManager.updateLocalSocksCreds("wg", detPass);
            Context eff = context != null ? context : WireGuardManager.sSocksPrefsCtx;
            if (eff != null && changed) {
                try {
                    WireGuardManager.getPrefs(eff).edit()
                            .putString(WireGuardManager.KEY_PERSISTED_SOCKS_USER, "wg")
                            .putString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, detPass)
                            .commit();
                } catch (Throwable ignored) {
                }
            }
            recordAllowedSocksPass(eff, detPass);
            if (changed) {
                try {
                    if (NativeBridgeLoader.isLoaded()) {
                        Wgbridge.setSocksAuth("wg", detPass);
                        Wgbridge.resetSocksAuthRejectCount();
                    }
                } catch (Throwable ignored) {
                }
            }
            syncAllowedProfilePasswordsToNative(eff);
        }
    }

    static void recordAllowedSocksPass(Context context, String pass) {
        if (pass == null) {
            return;
        }
        String trimmed = pass.trim();
        if (trimmed.isEmpty()) {
            return;
        }
        Context eff = context != null ? context : WireGuardManager.sSocksPrefsCtx;
        if (eff != null) {
            try {
                SharedPreferences sp = WireGuardManager.getPrefs(eff);
                String raw = sp.getString(WireGuardManager.KEY_RECENT_SOCKS_PASSES_CSV, "");
                ArrayList<String> ring = new ArrayList<>();
                ring.add(trimmed);
                if (raw != null && !raw.isEmpty()) {
                    for (String tok : raw.split(",")) {
                        String t = tok.trim();
                        if (!t.isEmpty() && !ring.contains(t) && ring.size() < 12) {
                            ring.add(t);
                        }
                    }
                }
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < ring.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append(ring.get(i));
                }
                sp.edit().putString(WireGuardManager.KEY_RECENT_SOCKS_PASSES_CSV, sb.toString()).apply();
            } catch (Throwable ignored) {
            }
        }
    }

    static void syncAllowedProfilePasswordsToNative(Context context) {
        try {
            if (!NativeBridgeLoader.isLoaded()) {
                return;
            }
            Context eff = context != null ? context : WireGuardManager.sSocksPrefsCtx;
            Set<String> passes = new LinkedHashSet<>();
            WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
            WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
            if (!creds.pass.trim().isEmpty()) {
                passes.add(creds.pass.trim());
            }
            if (!hub.pass.trim().isEmpty()) {
                passes.add(hub.pass.trim());
            }
            if (eff != null) {
                SharedPreferences sp = WireGuardManager.getPrefs(eff);
                String saved = sp.getString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, "");
                if (saved != null && !saved.trim().isEmpty()) {
                    passes.add(saved.trim());
                }
                String recentCsv = sp.getString(WireGuardManager.KEY_RECENT_SOCKS_PASSES_CSV, "");
                if (recentCsv != null && !recentCsv.trim().isEmpty()) {
                    for (String part : recentCsv.split(",")) {
                        String t = part.trim();
                        if (!t.isEmpty()) {
                            passes.add(t);
                        }
                    }
                }
                List<WireGuardManager.TunnelConfig> profiles = WireGuardManager.loadProfiles(eff);
                if (profiles != null) {
                    for (WireGuardManager.TunnelConfig p : profiles) {
                        if (p == null) {
                            continue;
                        }
                        String derived = deriveProfileSocksPass(p.privateKey);
                        if (!derived.isEmpty()) {
                            passes.add(derived);
                        }
                    }
                }
            }
            StringBuilder csv = new StringBuilder();
            for (String p : passes) {
                if (csv.length() > 0) {
                    csv.append(',');
                }
                csv.append(p);
            }
            Wgbridge.setSocksExtraPasswords(csv.toString());
        } catch (Throwable ignored) {
        }
    }

    static void ensureSessionSocksCredentials() {
        ensureSessionSocksCredentials(WireGuardManager.sSocksPrefsCtx);
    }

    static void ensureSessionSocksCredentials(Context context) {
        synchronized (WireGuardManager.class) {
            if (context != null) {
                Context app = context.getApplicationContext();
                WireGuardManager.sSocksPrefsCtx = app != null ? app : context;
            }
            Context eff = context != null ? context : WireGuardManager.sSocksPrefsCtx;
            if (eff == null) {
                // Never mint an unpersisted ephemeral password in memory before Application Context exists;
                // otherwise mainconfig/proxyList desyncs from wg_plus_isolated_prefs.
                return;
            }
            try {
                WireGuardManager.TunnelConfig activeCfg = WireGuardManager.loadConfig(eff);
                String detPass = deriveProfileSocksPass(activeCfg != null ? activeCfg.privateKey : "");
                if (!detPass.isEmpty()) {
                    WireGuardManager.SocksCredsSnapshot cur = WireGuardManager.sSocksCreds;
                    boolean changed = !"wg".equals(cur.user) || !detPass.equals(cur.pass);
                    WireGuardManager.updateLocalSocksCreds("wg", detPass);
                    if (changed) {
                        WireGuardManager.getPrefs(eff).edit()
                                .putString(WireGuardManager.KEY_PERSISTED_SOCKS_USER, "wg")
                                .putString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, detPass)
                                .commit();
                    }
                    syncAllowedProfilePasswordsToNative(eff);
                    return;
                }
            } catch (Throwable ignored) {
            }
            WireGuardManager.SocksCredsSnapshot existingCreds = WireGuardManager.sSocksCreds;
            if (!existingCreds.user.isEmpty() && !existingCreds.pass.isEmpty()) {
                syncAllowedProfilePasswordsToNative(eff);
                return;
            }
            try {
                SharedPreferences sp = WireGuardManager.getPrefs(eff);
                String u = sp.getString(WireGuardManager.KEY_PERSISTED_SOCKS_USER, "");
                String p = sp.getString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, "");
                if (u != null && !u.isEmpty() && p != null && !p.isEmpty()) {
                    WireGuardManager.updateLocalSocksCreds(u, p);
                    syncAllowedProfilePasswordsToNative(eff);
                    return;
                }
            } catch (Throwable ignored) {
            }
            byte[] raw = new byte[16];
            new SecureRandom().nextBytes(raw);
            String randPass = null;
            try {
                randPass = Base64.encodeToString(raw, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            } catch (Throwable ignored) {
            }
            if (randPass == null || randPass.isEmpty()) {
                randPass = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            }
            WireGuardManager.updateLocalSocksCreds("wg", randPass);
            try {
                WireGuardManager.getPrefs(eff).edit()
                        .putString(WireGuardManager.KEY_PERSISTED_SOCKS_USER, "wg")
                        .putString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, randPass)
                        .commit();
            } catch (Throwable ignored) {
            }
            syncAllowedProfilePasswordsToNative(eff);
        }
    }

    static String getActiveSocksUser() {
        return getActiveSocksUser(WireGuardManager.sSocksPrefsCtx);
    }

    static String getActiveSocksUser(Context context) {
        WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
        if (!hub.isOwner) {
            if ((hub.port <= 0 || hub.user.isEmpty()) && context != null) {
                WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(context);
                hub = WireGuardManager.sSharedHub;
            }
            if (hub.port > 0 && !hub.user.isEmpty()) {
                return hub.user;
            }
        }
        ensureSessionSocksCredentials(context);
        return WireGuardManager.sSocksCreds.user;
    }

    static String getClientSocksUser(Context context) {
        String base = getActiveSocksUser(context);
        if (base == null || base.isEmpty()) {
            return "";
        }
        int colonIdx = base.indexOf(':');
        if (colonIdx > 0) {
            base = base.substring(0, colonIdx);
        }
        Context pkgCtx = context != null ? context : WireGuardManager.sSocksPrefsCtx;
        String pkg = pkgCtx != null ? pkgCtx.getPackageName() : "";
        if ("wg".equals(base) && pkg != null && !pkg.isEmpty() && !"org.telegram.wgplus.module".equals(pkg)) {
            return base + ":" + pkg;
        }
        return base;
    }

    static String getActiveSocksPass() {
        return getActiveSocksPass(WireGuardManager.sSocksPrefsCtx);
    }

    static String getActiveSocksPass(Context context) {
        WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
        if (!hub.isOwner) {
            if ((hub.port <= 0 || hub.pass.isEmpty()) && context != null) {
                WgSharedHubAndVoip.queryAnyLiveSharedTunnelPort(context);
                hub = WireGuardManager.sSharedHub;
            }
            if (hub.port > 0 && !hub.pass.isEmpty()) {
                return hub.pass;
            }
        }
        ensureSessionSocksCredentials(context);
        return WireGuardManager.sSocksCreds.pass;
    }

    static boolean openOfficialChannel(final Context ctx, final Runnable onBeforeRedirect) {
        if (ctx == null) {
            return false;
        }
        final Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
        Activity resolvedAct = null;
        Context cur = ctx;
        for (int depth = 0; depth < 8 && cur != null; depth++) {
            if (cur instanceof Activity) {
                resolvedAct = (Activity) cur;
                break;
            }
            if (cur instanceof ContextWrapper) {
                cur = ((ContextWrapper) cur).getBaseContext();
            } else {
                break;
            }
        }
        if (resolvedAct != null && resolvedAct.isFinishing()) {
            resolvedAct = null;
        }

        if (onBeforeRedirect != null) {
            try {
                onBeforeRedirect.run();
            } catch (Throwable ignored) {
            }
        }

        final String channelUri = "tg://resolve?domain=wgplus_official";
        final String pkg = resolvedAct != null ? resolvedAct.getPackageName() : appCtx.getPackageName();
        final boolean inModuleApp = "org.telegram.wgplus.module".equals(pkg);
        if (!inModuleApp) {
            if (resolvedAct != null) {
                // Primary path inside hooked Telegram: invoke Telegram's internal Browser.openUrl directly
                try {
                    Class<?> browserCls = XposedHelpers.findClassIfExists(
                            "org.telegram.messenger.browser.Browser",
                            resolvedAct.getClassLoader()
                    );
                    if (browserCls != null) {
                        XposedHelpers.callStaticMethod(browserCls, "openUrl", resolvedAct, channelUri);
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
            try {
                Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(channelUri));
                if (pkg != null && !pkg.isEmpty()) {
                    i.setPackage(pkg);
                }
                if (resolvedAct != null) {
                    i.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                    resolvedAct.startActivity(i);
                } else {
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    appCtx.startActivity(i);
                }
                return true;
            } catch (Throwable ignored) {
            }
            return false;
        }

        // Inside companion app: target installed Telegram clients directly (never launch a web browser)
        PackageManager pm = appCtx.getPackageManager();
        for (String tgPkg : ContinuityBridgeManager.DEFAULT_TARGET_PACKAGES) {
            try {
                Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(channelUri));
                i.setPackage(tgPkg);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                if (pm != null && i.resolveActivity(pm) != null) {
                    appCtx.startActivity(i);
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(channelUri));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            appCtx.startActivity(i);
            return true;
        } catch (Throwable ignored) {
        }
        return false;
    }

    static void maybeInviteToOfficialChannel(
            final Context ctx,
            final boolean isAr,
            final Runnable onBeforeRedirect
    ) {
        if (ctx == null) {
            return;
        }
        try {
            if (WireGuardManager.getPrefs(ctx).getBoolean(WireGuardManager.KEY_CHANNEL_INVITED_V2, false)) {
                return;
            }
            final Context appCtx = ctx.getApplicationContext() != null ? ctx.getApplicationContext() : ctx;
            Activity resolvedAct = null;
            Context cur = ctx;
            for (int depth = 0; depth < 8 && cur != null; depth++) {
                if (cur instanceof Activity) {
                    resolvedAct = (Activity) cur;
                    break;
                }
                if (cur instanceof ContextWrapper) {
                    cur = ((ContextWrapper) cur).getBaseContext();
                } else {
                    break;
                }
            }
            if (resolvedAct == null || resolvedAct.isFinishing()) {
                return;
            }
            final Activity act = resolvedAct;
            final Runnable openChannel = () -> {
                WireGuardManager.getPrefs(appCtx).edit().putBoolean(WireGuardManager.KEY_CHANNEL_INVITED_V2, true).apply();
                openOfficialChannel(act, onBeforeRedirect);
            };
            final WgTheme th = WgTheme.of(WireGuardManager.isDarkTheme(ctx));
            final Dialog d = new Dialog(act);
            d.requestWindowFeature(Window.FEATURE_NO_TITLE);
            d.setCancelable(false);
            d.setCanceledOnTouchOutside(false);

            int p = WgTheme.dp(act, 20);
            LinearLayout card = new LinearLayout(act);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(p, p, p, p);
            card.setBackground(WgTheme.cardBackground(act, th.surfaceCard, th.borderSubtle, 16));
            card.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);

            TextView badge = new TextView(act);
            badge.setText("@wgplus_official");
            badge.setTextSize(12);
            badge.setTextColor(th.accentPrimary);
            badge.setTypeface(Typeface.DEFAULT_BOLD);
            badge.setPadding(WgTheme.dp(act, 10), WgTheme.dp(act, 3), WgTheme.dp(act, 10), WgTheme.dp(act, 3));
            badge.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 99));
            card.addView(badge, new LinearLayout.LayoutParams(-2, -2));

            TextView title = new TextView(act);
            title.setText(isAr ? "\u0627\u0644\u0642\u0646\u0627\u0629 \u0627\u0644\u0631\u0633\u0645\u064A\u0629 \u0644\u0640 \u0648\u0627\u064A\u0631\u062C\u0627\u0631\u062F \u0628\u0644\u0633" : "Official WireGuard Plus Channel");
            title.setTextSize(18);
            title.setTextColor(th.textPrimary);
            title.setTypeface(Typeface.DEFAULT_BOLD);
            title.setPadding(0, WgTheme.dp(act, 12), 0, WgTheme.dp(act, 6));
            card.addView(title);

            TextView body = new TextView(act);
            body.setText(isAr
                    ? "\u0627\u0646\u0636\u0645 \u0625\u0644\u0649 \u0642\u0646\u0627\u0629 \u062A\u064A\u0644\u064A\u062C\u0631\u0627\u0645 \u0627\u0644\u0631\u0633\u0645\u064A\u0629 \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u0623\u062D\u062F\u062B \u0627\u0644\u0625\u0635\u062F\u0627\u0631\u0627\u062A \u0648\u0625\u0635\u0644\u0627\u062D\u0627\u062A \u0627\u0644\u0627\u062A\u0635\u0627\u0644.\n\n\u0647\u0644 \u0623\u0646\u062A \u0645\u0634\u062A\u0631\u0643 \u0641\u064A \u0627\u0644\u0642\u0646\u0627\u0629 \u062D\u0627\u0644\u064A\u064B\u0627\u061F"
                    : "Join our official Telegram channel for the latest releases and connection updates.\n\nAre you subscribed to the channel?");
            body.setTextSize(13.5f);
            body.setTextColor(th.textSecondary);
            body.setPadding(0, 0, 0, WgTheme.dp(act, 14));
            card.addView(body);

            Button openBtn = new Button(act);
            openBtn.setAllCaps(false);
            openBtn.setTextColor(th.onAccent);
            openBtn.setText(isAr ? "\u0641\u062A\u062D \u0627\u0644\u0642\u0646\u0627\u0629 \u0639\u0644\u0649 \u062A\u064A\u0644\u064A\u062C\u0631\u0627\u0645" : "Open Channel on Telegram");
            openBtn.setBackground(WgTheme.cardBackground(act, th.accentPrimary, th.accentPrimary, 10));
            openBtn.setOnClickListener(v -> {
                d.dismiss();
                openChannel.run();
            });
            LinearLayout.LayoutParams openLp = new LinearLayout.LayoutParams(-1, WgTheme.dp(act, 46));
            openLp.bottomMargin = WgTheme.dp(act, 8);
            card.addView(openBtn, openLp);

            LinearLayout row = new LinearLayout(act);
            row.setOrientation(LinearLayout.HORIZONTAL);

            Button yesBtn = new Button(act);
            yesBtn.setAllCaps(false);
            yesBtn.setTextColor(th.textPrimary);
            yesBtn.setText(isAr ? "\u0646\u0639\u0645\u060C \u0645\u0634\u062A\u0631\u0643" : "Yes, subscribed");
            yesBtn.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 10));
            yesBtn.setOnClickListener(v -> {
                WireGuardManager.getPrefs(appCtx).edit().putBoolean(WireGuardManager.KEY_CHANNEL_INVITED_V2, true).apply();
                d.dismiss();
            });
            LinearLayout.LayoutParams yLp = new LinearLayout.LayoutParams(0, WgTheme.dp(act, 44), 1f);
            yLp.setMarginEnd(WgTheme.dp(act, 6));
            row.addView(yesBtn, yLp);

            Button noBtn = new Button(act);
            noBtn.setAllCaps(false);
            noBtn.setTextColor(th.textSecondary);
            noBtn.setText(isAr ? "\u0644\u0627\u060C \u0644\u064A\u0633 \u0628\u0639\u062F" : "No, not yet");
            noBtn.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 10));
            noBtn.setOnClickListener(v -> {
                Toast.makeText(
                        act,
                        isAr ? "\u064A\u0631\u062C\u0649 \u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643 \u0641\u064A \u0627\u0644\u0642\u0646\u0627\u0629 \u0623\u0648\u0644\u064B\u0627 \u0644\u0644\u0645\u062A\u0627\u0628\u0639\u0629" : "Please subscribe to the channel first to continue",
                        Toast.LENGTH_SHORT
                ).show();
                d.dismiss();
                openChannel.run();
            });
            row.addView(noBtn, new LinearLayout.LayoutParams(0, WgTheme.dp(act, 44), 1f));
            card.addView(row, new LinearLayout.LayoutParams(-1, -2));

            d.setContentView(card);
            Window w = d.getWindow();
            if (w != null) {
                w.setBackgroundDrawable(new ColorDrawable(0));
                w.setLayout((int) (act.getResources().getDisplayMetrics().widthPixels * 0.90f),
                        ViewGroup.LayoutParams.WRAP_CONTENT);
                w.setGravity(Gravity.CENTER);
                w.setDimAmount(0.75f);
            }
            d.show();
        } catch (Throwable t) {
            Log.e(WireGuardManager.TAG, "maybeInviteToOfficialChannel failed", t);
        }
    }

    static String exportSharedSyncBundleJson(Context context) {
        return exportSharedSyncBundleJson(context, true);
    }

    static String exportSharedSyncBundleJson(Context context, boolean includeSecrets) {
        synchronized (WireGuardManager.class) {
            if (context == null) {
                return "{}";
            }
            SharedPreferences prefs = WireGuardManager.getPrefs(context);
            List<WireGuardManager.TunnelConfig> profiles = WireGuardManager.loadProfiles(context);
            JSONObject root = new JSONObject();
            try {
                root.put("stateRev", prefs.getLong(WireGuardManager.KEY_SHARED_STATE_REV, 0L));
                root.put("hasSecrets", includeSecrets);
                root.put("activeProfileId", prefs.getString(WireGuardManager.KEY_ACTIVE_PROFILE_ID, ""));
                root.put("enabled", WireGuardManager.isAutoConnectEnabled(context));
                root.put("routeCalls", WireGuardManager.isRouteCallsEnabled(context));
                root.put("killSwitch", WireGuardManager.isKillSwitchEnabled(context));
                root.put("autoFailover", WireGuardManager.isAutoFailoverEnabled(context));
                root.put("dohEnabled", WireGuardManager.isDohEnabled(context));
                root.put("smartKeepalive", WireGuardManager.isSmartKeepaliveEnabled(context));
                root.put("telemetryDecided", WgTelemetryReporter.isConsentDecided(context));
                root.put("telemetryOptIn", WgTelemetryReporter.isOptedIn(context));
                root.put("uiLang", prefs.getString(WireGuardManager.KEY_UI_LANG, ""));
                root.put("uiDark", prefs.contains(WireGuardManager.KEY_UI_DARK) ? (prefs.getBoolean(WireGuardManager.KEY_UI_DARK, true) ? 1 : 0) : -1);
                if (includeSecrets) {
                    ensureSessionSocksCredentials(context);
                    WireGuardManager.SocksCredsSnapshot creds = WireGuardManager.sSocksCreds;
                    if (!creds.user.isEmpty() && !creds.pass.isEmpty()) {
                        root.put("socksUser", creds.user);
                        root.put("socksPass", creds.pass);
                    }
                }
                JSONArray arr = new JSONArray();
                for (WireGuardManager.TunnelConfig cfg : profiles) {
                    JSONObject obj = WgConfigCodec.configToJsonObject(cfg, false);
                    if (!includeSecrets) {
                        obj.remove("privateKey");
                        obj.remove("presharedKey");
                    }
                    arr.put(obj);
                }
                root.put("profiles", arr);
            } catch (Throwable t) {
                WgDiagnosticsLog.handleCriticalCatch("SYNC", "EXPORT_BUNDLE_ERR", t);
            }
            return root.toString();
        }
    }

    static long importSharedSyncBundleJson(Context context, String rawJson, boolean keepIncomingRev) {
        synchronized (WireGuardManager.class) {
            if (context == null || rawJson == null || rawJson.trim().isEmpty()) {
                return -1L;
            }
            try {
                JSONObject root = new JSONObject(rawJson);
                SharedPreferences prefs = WireGuardManager.getPrefs(context);
                long localRev = prefs.getLong(WireGuardManager.KEY_SHARED_STATE_REV, 0L);
                long incomingRev = root.optLong("stateRev", 0L);
                String localActiveId = prefs.getString(WireGuardManager.KEY_ACTIVE_PROFILE_ID, "").trim();
                String incomingActiveId = root.optString("activeProfileId", "").trim();
                boolean equalRevProfileDrift = (incomingRev == localRev)
                        && !incomingActiveId.isEmpty() && !incomingActiveId.equals(localActiveId);
                if (keepIncomingRev && incomingRev <= localRev && !equalRevProfileDrift && WireGuardManager.hasAnyConfiguredProfile(context)) {
                    return localRev;
                }
                JSONArray arr = root.optJSONArray("profiles");
                List<WireGuardManager.TunnelConfig> profiles = new ArrayList<>();
                boolean hasKeyedProfile = false;
                if (arr != null) {
                    for (int i = 0; i < arr.length(); i++) {
                        JSONObject item = arr.optJSONObject(i);
                        if (item != null) {
                            WireGuardManager.TunnelConfig cfg = WgConfigCodec.configFromJsonObject(item, false);
                            if (cfg != null) {
                                profiles.add(cfg);
                                if (!WireGuardManager.safeTrim(cfg.privateKey).isEmpty()) {
                                    hasKeyedProfile = true;
                                }
                            }
                        }
                    }
                }
                boolean hasSecrets = root.optBoolean("hasSecrets", hasKeyedProfile);
                if (keepIncomingRev && !hasSecrets && !profiles.isEmpty() && WireGuardManager.hasAnyConfiguredProfile(context)) {
                    return localRev;
                }
                long nextRev = keepIncomingRev ? incomingRev : Math.max(localRev + 1L, incomingRev + 1L);
                WireGuardManager.sSuppressSyncPush = true;
                try {
                    boolean enabled = root.optBoolean("enabled", WireGuardManager.isAutoConnectEnabled(context));
                    boolean routeCalls = root.optBoolean("routeCalls", WireGuardManager.isRouteCallsEnabled(context));
                    String activeId = root.optString("activeProfileId", "");
                    if (activeId.isEmpty() && !profiles.isEmpty()) {
                        activeId = profiles.get(0).id;
                    }
                    if (hasSecrets || !profiles.isEmpty()) {
                        WireGuardManager.persistProfilesLocked(prefs, profiles, activeId, enabled, routeCalls);
                    }
                    SharedPreferences.Editor ed = prefs.edit()
                            .putBoolean(WireGuardManager.KEY_ENABLED, enabled)
                            .putBoolean(WireGuardManager.KEY_ROUTE_CALLS, routeCalls)
                            .putBoolean(WireGuardManager.KEY_KILL_SWITCH, root.optBoolean("killSwitch", false))
                            .putBoolean(WireGuardManager.KEY_AUTO_FAILOVER, root.optBoolean("autoFailover", false))
                            .putBoolean(WireGuardManager.KEY_DOH_ENABLED, root.optBoolean("dohEnabled", true))
                            .putBoolean(WireGuardManager.KEY_SMART_KEEPALIVE, root.optBoolean("smartKeepalive", false))
                            .putBoolean(WireGuardManager.KEY_MIGRATED_FORCED_CONTINUITY_V1, true);
                    if (!keepIncomingRev || hasSecrets || profiles.isEmpty()) {
                        ed.putLong(WireGuardManager.KEY_SHARED_STATE_REV, nextRev);
                    }
                    if (hasSecrets) {
                        WireGuardManager.TunnelConfig selectedActive = null;
                        for (WireGuardManager.TunnelConfig p : profiles) {
                            if (activeId.equals(p.id)) {
                                selectedActive = p;
                                break;
                            }
                        }
                        if (selectedActive == null && !profiles.isEmpty()) {
                            selectedActive = profiles.get(0);
                        }
                        String detPass = selectedActive != null ? deriveProfileSocksPass(selectedActive.privateKey) : "";
                        String syncUser = !detPass.isEmpty() ? "wg" : root.optString("socksUser", "").trim();
                        String syncPass = !detPass.isEmpty() ? detPass : root.optString("socksPass", "").trim();
                        if (!syncUser.isEmpty() && !syncPass.isEmpty()) {
                            WireGuardManager.updateLocalSocksCreds(syncUser, syncPass);
                            ed.putString(WireGuardManager.KEY_PERSISTED_SOCKS_USER, syncUser);
                            ed.putString(WireGuardManager.KEY_PERSISTED_SOCKS_PASS, syncPass);
                            recordAllowedSocksPass(context, syncPass);
                            try {
                                if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                                    Wgbridge.setSocksAuth(syncUser, syncPass);
                                    syncAllowedProfilePasswordsToNative(context);
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    }
                    String uiLang = root.optString("uiLang", "");
                    if (!uiLang.isEmpty()) {
                        ed.putString(WireGuardManager.KEY_UI_LANG, uiLang);
                    }
                    int uiDark = root.optInt("uiDark", -1);
                    if (uiDark == 0 || uiDark == 1) {
                        ed.putBoolean(WireGuardManager.KEY_UI_DARK, uiDark == 1);
                    }
                    if (root.has("telemetryDecided") && root.optBoolean("telemetryDecided", false)) {
                        boolean localDecided = prefs.getBoolean(WgTelemetryReporter.KEY_TELEMETRY_DECIDED, false);
                        if (!localDecided || !keepIncomingRev) {
                            ed.putBoolean(WgTelemetryReporter.KEY_TELEMETRY_DECIDED, true);
                            ed.putBoolean(WgTelemetryReporter.KEY_TELEMETRY_OPT_IN, root.optBoolean("telemetryOptIn", false));
                        }
                    }
                    ed.commit();
                } finally {
                    WireGuardManager.sSuppressSyncPush = false;
                }
                return nextRev;
            } catch (Throwable t) {
                WgDiagnosticsLog.handleCriticalCatch("SYNC", "IMPORT_BUNDLE_ERR", t);
                return -1L;
            }
        }
    }

    static boolean syncPullSharedStateFromProvider(Context context, boolean force) {
        if (context == null || "org.telegram.wgplus.module".equals(context.getPackageName())) {
            return false;
        }
        long now = SystemClock.elapsedRealtime();
        if (!force && now - WireGuardManager.sLastSyncPullMs < 8_000L) {
            return false;
        }
        WireGuardManager.sLastSyncPullMs = now;
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            String json = null;
            try {
                Bundle res = appCtx.getContentResolver().call(
                        WireGuardManager.STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_SYNC_PULL_STATE,
                        appCtx.getPackageName(),
                        null
                );
                if (res != null) {
                    json = res.getString(KeepaliveStatusProvider.RESULT_JSON, "");
                }
            } catch (Throwable ignored) {
            }
            // Prefer full-secret local root mirror BEFORE XSharedPreferences (which strips keys).
            if (json == null || json.isEmpty()) {
                json = readSyncBundleFromLocalMirrorFile(appCtx);
            }
            if (json == null || json.isEmpty()) {
                json = readSyncBundleFromXSharedPrefs();
            }
            if (json == null || json.isEmpty()) {
                return false;
            }
            JSONObject obj = new JSONObject(json);
            long remoteRev = obj.optLong("stateRev", 0L);
            long localRev = WireGuardManager.getPrefs(appCtx).getLong(WireGuardManager.KEY_SHARED_STATE_REV, 0L);
            String remoteActiveId = obj.optString("activeProfileId", "").trim();
            String localActiveId = WireGuardManager.getPrefs(appCtx).getString(WireGuardManager.KEY_ACTIVE_PROFILE_ID, "").trim();
            boolean equalRevProfileDrift = (remoteRev == localRev)
                    && !remoteActiveId.isEmpty() && !remoteActiveId.equals(localActiveId);
            JSONArray remoteProfiles = obj.optJSONArray("profiles");
            boolean remoteHasPeer = false;
            if (remoteProfiles != null) {
                for (int i = 0; i < remoteProfiles.length(); i++) {
                    JSONObject p = remoteProfiles.optJSONObject(i);
                    if (p != null && !p.optString("endpoint", "").trim().isEmpty()) {
                        remoteHasPeer = true;
                        break;
                    }
                }
            }
            if (remoteRev > localRev || equalRevProfileDrift || (remoteHasPeer && !WireGuardManager.hasAnyConfiguredProfile(appCtx))) {
                long applied = importSharedSyncBundleJson(appCtx, json, true);
                return applied >= 0L;
            }
            if (localRev > remoteRev && WireGuardManager.hasAnyConfiguredProfile(appCtx)) {
                scheduleSyncPushToProvider(appCtx);
            } else if (remoteRev == 0L && !remoteHasPeer && WireGuardManager.hasAnyConfiguredProfile(appCtx)) {
                scheduleSyncPushToProvider(appCtx);
            }
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SYNC", "PULL_STATE_ERR", t);
        }
        return false;
    }

    static void scheduleSyncPushToProvider(Context context) {
        if (WireGuardManager.sSuppressSyncPush) {
            return;
        }
        final Context appCtx = context != null
                ? (context.getApplicationContext() != null ? context.getApplicationContext() : context)
                : WireGuardManager.sSyncContext;
        if (appCtx == null) {
            return;
        }
        SharedPreferences prefs = WireGuardManager.getPrefs(appCtx);
        long nextRev = prefs.getLong(WireGuardManager.KEY_SHARED_STATE_REV, 0L) + 1L;
        prefs.edit().putLong(WireGuardManager.KEY_SHARED_STATE_REV, nextRev).apply();
        if ("org.telegram.wgplus.module".equals(appCtx.getPackageName())) {
            publishWorldReadableSyncBundle(appCtx);
            return;
        }
        WireGuardManager.SYNC_EXEC.execute(() -> {
            try {
                Bundle extras = new Bundle();
                extras.putString(KeepaliveStatusProvider.EXTRA_JSON, exportSharedSyncBundleJson(appCtx));
                Bundle res = appCtx.getContentResolver().call(
                        WireGuardManager.STATUS_PROVIDER_URI,
                        KeepaliveStatusProvider.METHOD_SYNC_PUSH_STATE,
                        appCtx.getPackageName(),
                        extras
                );
                if (res != null) {
                    long canonicalRev = res.getLong("stateRev", -1L);
                    if (canonicalRev > 0L) {
                        WireGuardManager.getPrefs(appCtx).edit().putLong(WireGuardManager.KEY_SHARED_STATE_REV, canonicalRev).apply();
                    }
                }
            } catch (Throwable t) {
                WgDiagnosticsLog.handleCriticalCatch("SYNC", "PUSH_STATE_ERR", t);
            }
            publishWorldReadableSyncBundle(appCtx);
        });
    }

    @SuppressWarnings("deprecation")
    static void publishWorldReadableSyncBundle(Context appCtx) {
        if (appCtx == null) {
            return;
        }
        final String fullJson = exportSharedSyncBundleJson(appCtx, true);
        final String safeMetadataJson = exportSharedSyncBundleJson(appCtx, false);
        try {
            // Never write PrivateKey/PresharedKey into MODE_WORLD_READABLE storage;
            // secrets sync exclusively over authenticated Binder IPC and 0600 UID-owned mirrors.
            SharedPreferences sp = appCtx.getSharedPreferences("wg_plus_xshared_sync", Context.MODE_WORLD_READABLE);
            sp.edit().putString("bundle_json", safeMetadataJson).apply();
        } catch (SecurityException ignored) {
            // MODE_WORLD_READABLE is only allowed when LSPosed/Vector hooks ContextImpl for this module
        } catch (Throwable ignored) {
        }
        mirrorSyncBundleToClientsAsync(appCtx, fullJson);
    }

    private static void mirrorSyncBundleToClientsAsync(final Context appCtx, final String json) {
        if (appCtx == null || json == null || json.isEmpty()) {
            return;
        }
        WireGuardManager.SYNC_EXEC.execute(() -> {
            try {
                if (!PrivilegeBridge.hasRootAccess()) {
                    return;
                }
                List<String> targets = ContinuityBridgeManager.getInstalledTargetPackages(appCtx);
                if (targets == null || targets.isEmpty()) {
                    return;
                }
                String b64 = Base64.encodeToString(
                        json.getBytes(StandardCharsets.UTF_8),
                        Base64.NO_WRAP
                );
                StringBuilder cmd = new StringBuilder();
                for (String pkg : targets) {
                    if (pkg == null || !pkg.matches("[a-zA-Z0-9._]+") || "org.telegram.wgplus.module".equals(pkg)) {
                        continue;
                    }
                    int uid;
                    try {
                        uid = appCtx.getPackageManager().getPackageUid(pkg, 0);
                    } catch (Throwable ignored) {
                        continue;
                    }
                    String dir = "/data/data/" + pkg + "/files";
                    String path = dir + "/wg_plus_sync_mirror.json";
                    cmd.append("mkdir -p ").append(dir)
                            .append(" && printf '%s' '").append(b64).append("' | base64 -d > ").append(path)
                            .append(" && chown ").append(uid).append(':').append(uid).append(' ').append(path)
                            .append(" && chmod 600 ").append(path).append("; ");
                }
                if (cmd.length() > 0) {
                    PrivilegeBridge.runRootCommand(cmd.toString(), 4000);
                }
            } catch (Throwable t) {
                WgDiagnosticsLog.handleCriticalCatch("SYNC", "MIRROR_CLIENTS_ERR", t);
            }
        });
    }

    private static String readSyncBundleFromLocalMirrorFile(Context appCtx) {
        if (appCtx == null) {
            return "";
        }
        try {
            File file = new File(appCtx.getFilesDir(), "wg_plus_sync_mirror.json");
            if (!file.isFile() || file.length() <= 0 || file.length() > 1_048_576L) {
                return "";
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (FileInputStream in = new FileInputStream(file)) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SYNC", "DERIVE_SOCKS_PASS_ERR", t);
            return "";
        }
    }

    private static String readSyncBundleFromXSharedPrefs() {
        try {
            ClassLoader xposedCl = XposedBridge.class.getClassLoader();
            Class<?> xspClass = xposedCl != null
                    ? xposedCl.loadClass("de.robv.android.xposed.XSharedPreferences")
                    : Class.forName("de.robv.android.xposed.XSharedPreferences");
            Object xsp = xspClass.getConstructor(String.class, String.class)
                    .newInstance("org.telegram.wgplus.module", "wg_plus_xshared_sync");
            try {
                xspClass.getMethod("reload").invoke(xsp);
            } catch (Throwable ignored) {
            }
            Object val = xspClass.getMethod("getString", String.class, String.class)
                    .invoke(xsp, "bundle_json", "");
            return val instanceof String ? (String) val : "";
        } catch (Throwable t) {
            WgDiagnosticsLog.handleCriticalCatch("SYNC", "DERIVE_SOCKS_PASS_ERR", t);
            return "";
        }
    }

    static void reportHookActiveToProvider(Context context, String hostPkg) {
        if (context == null || hostPkg == null || hostPkg.isEmpty()) {
            return;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            Bundle extras = new Bundle();
            try {
                PackageInfo pi = appCtx.getPackageManager().getPackageInfo(hostPkg, 0);
                if (pi != null && pi.versionName != null) {
                    extras.putString("host_ver", pi.versionName);
                }
            } catch (Throwable ignored) {
            }
            extras.putString("mode", WireGuardManager.detectInjectionMode(appCtx));
            boolean localUp = false;
            int localPort = 0;
            try {
                if (NativeBridgeLoader.isLoaded() && Wgbridge.isRunning()) {
                    localUp = true;
                    localPort = (int) Wgbridge.getActivePort();
                }
            } catch (Throwable ignored) {
            }
            WireGuardManager.SharedHubSnapshot hub = WireGuardManager.sSharedHub;
            int effPort = localPort > 0 ? localPort : (hub.port > 0 ? hub.port : WireGuardManager.sLastBoundPort);
            boolean running = localUp || hub.port > 0;
            String role = localUp
                    ? (hub.isOwner ? "shared_owner" : "local_owner")
                    : (hub.port > 0 ? "shared_client" : "standby");
            extras.putInt("port", effPort);
            extras.putBoolean("running", running);
            extras.putBoolean("shared", hub.port > 0 && !localUp);
            extras.putString("role", role);
            if (!"org.telegram.wgplus.module".equals(hostPkg)) {
                String tgState = WireGuardManager.inspectTelegramProxyHealthSummary(appCtx);
                if (tgState != null && !tgState.isEmpty() && !tgState.startsWith("n/a")) {
                    if (tgState.length() > 160) {
                        tgState = tgState.substring(0, 160);
                    }
                    extras.putString("tg_state", tgState);
                }
            }
            List<String> evs = WgDiagnosticsLog.snapshotEvents();
            if (!evs.isEmpty()) {
                String lastEv = evs.get(evs.size() - 1);
                if (lastEv.length() > 140) {
                    lastEv = lastEv.substring(0, 140);
                }
                extras.putString("last_event", lastEv);
            }
            appCtx.getContentResolver().call(
                    WireGuardManager.STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_REPORT_HOOK_ACTIVE,
                    hostPkg,
                    extras
            );
            WireGuardManager.sLastHookHeartbeatMs = SystemClock.elapsedRealtime();
        } catch (Throwable ignored) {
        }
    }

    static void scheduleHookHeartbeatThrottled(Context context) {
        if (context == null) {
            return;
        }
        String pkg = context.getPackageName();
        if (pkg == null || pkg.isEmpty() || "org.telegram.wgplus.module".equals(pkg)) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        if (now - WireGuardManager.sLastHookHeartbeatMs < 15_000L) {
            return;
        }
        WireGuardManager.sLastHookHeartbeatMs = now;
        final Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        WireGuardManager.SYNC_EXEC.execute(() -> reportHookActiveToProvider(appCtx, pkg));
    }

    static Bundle queryHookStatusFromProvider(Context context) {
        if (context == null || Looper.myLooper() == Looper.getMainLooper()) {
            return null;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            return appCtx.getContentResolver().call(
                    WireGuardManager.STATUS_PROVIDER_URI,
                    KeepaliveStatusProvider.METHOD_QUERY_HOOK_STATUS,
                    appCtx.getPackageName(),
                    null
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    static void pollAndRunRemoteHygieneIfRequested(Context context) {
        if (context == null || Looper.myLooper() == Looper.getMainLooper()) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        if (now - WireGuardManager.sLastRemoteHygieneCheckMs < 15_000L) {
            return;
        }
        WireGuardManager.sLastRemoteHygieneCheckMs = now;
        try {
            Bundle b = queryHookStatusFromProvider(context);
            if (b != null) {
                long reqTs = b.getLong(KeepaliveStatusProvider.RESULT_HYGIENE_REQ_MS, 0L);
                if (reqTs > 0L && reqTs > WireGuardManager.sLastHandledHygieneReqMs) {
                    WireGuardManager.sLastHandledHygieneReqMs = reqTs;
                    ModuleHygieneManager.cleanCachesSafely(context, true);
                }
            }
        } catch (Throwable ignored) {
        }
    }
}
