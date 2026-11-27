package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fetches the latest GitHub release. If a newer APK exists, shows a non-dismissable
 * "Update required" dialog. After updating, shows the release notes once.
 * Fails open: offline or API errors never block the app.
 */
final class UpdateGate {
    private static final String API = "https://api.github.com/repos/AliHaider704/wgplus/releases/latest";
    private static final String ALLOWED_RELEASE_PREFIX = "https://github.com/AliHaider704/wgplus/releases/";
    private static final String PREFS = "wgplus_update";
    private static final String KEY_SEEN = "last_seen_version";
    private static final String MODULE_PKG = "org.telegram.wgplus.module";
    private static final long CACHE_TTL_MS = 3 * 60 * 1000L;
    private static final Pattern APK = Pattern.compile("WireGuardPlus-(\\d+(?:\\.\\d+)*)\\.apk");

    private static volatile Release sCachedRelease;
    private static volatile long sLastFetchMs;
    private static volatile boolean sUpdateBlocked;

    private UpdateGate() {}

    static boolean isUpdateBlocked() {
        return sUpdateBlocked;
    }

    private static String resolveModuleVersion(Context ctx) {
        try {
            if (ctx != null) {
                return ctx.getPackageManager().getPackageInfo(MODULE_PKG, 0).versionName;
            }
        } catch (Throwable ignored) {
        }
        return "2.0.3";
    }

    private static Activity unwrapActivity(Context ctx) {
        Context cur = ctx;
        for (int i = 0; i < 8 && cur != null; i++) {
            if (cur instanceof Activity) {
                return (Activity) cur;
            }
            if (cur instanceof ContextWrapper) {
                cur = ((ContextWrapper) cur).getBaseContext();
            } else {
                break;
            }
        }
        return null;
    }

    private static Release fetchCached() throws Exception {
        long now = System.currentTimeMillis();
        Release cached = sCachedRelease;
        if (cached != null && (now - sLastFetchMs) < CACHE_TTL_MS) {
            return cached;
        }
        Release fresh = fetch();
        if (fresh != null) {
            sCachedRelease = fresh;
            sLastFetchMs = now;
        }
        return fresh != null ? fresh : cached;
    }

    private static final class Release {
        String version;
        String apkUrl;
        String pageUrl;
        List<String> en = new ArrayList<>();
        List<String> ar = new ArrayList<>();
    }

    static void check(final Activity act) {
        new Thread(() -> {
            try {
                final Release r = fetchCached();
                if (r == null) return;
                final String cur = resolveModuleVersion(act);
                final SharedPreferences sp = act.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                if (newer(r.version, cur)) {
                    sUpdateBlocked = true;
                    act.runOnUiThread(() -> { if (!act.isFinishing()) showDialog(act, r, true, null); });
                } else {
                    sUpdateBlocked = false;
                    if (r.version.equals(cur) && !cur.equals(sp.getString(KEY_SEEN, null))) {
                        act.runOnUiThread(() -> {
                            if (!act.isFinishing()) {
                                showDialog(act, r, false, () -> sp.edit().putString(KEY_SEEN, cur).apply());
                            }
                        });
                    }
                }
            } catch (Throwable ignored) {
                // offline or malformed response: never block
            }
        }, "wg-update-check").start();
    }

    static void checkInModule(final Context ctx, final Dialog hostDialog) {
        final Activity act = unwrapActivity(ctx);
        if (act == null) return;
        if (sUpdateBlocked && sCachedRelease != null) {
            final Release cached = sCachedRelease;
            new Handler(Looper.getMainLooper()).post(() -> {
                if (hostDialog != null && hostDialog.isShowing()) {
                    try { hostDialog.dismiss(); } catch (Throwable ignored) {}
                }
                if (!act.isFinishing()) showDialog(act, cached, true, null);
            });
            return;
        }
        new Thread(() -> {
            try {
                final Release r = fetchCached();
                if (r == null) return;
                final String cur = resolveModuleVersion(act);
                if (newer(r.version, cur)) {
                    sUpdateBlocked = true;
                    try {
                        ClassLoader hostCl = act.getClassLoader();
                        if (WireGuardManager.isKillSwitchEnabled(act)) {
                            WireGuardManager.enforceKillSwitchIfDisconnected(act, null, hostCl);
                        } else {
                            WireGuardManager.stopAndUnbind(act, null, hostCl);
                        }
                    } catch (Throwable ignored) {
                    }
                    new Handler(Looper.getMainLooper()).post(() -> {
                        if (hostDialog != null && hostDialog.isShowing()) {
                            try { hostDialog.dismiss(); } catch (Throwable ignored) {}
                        }
                        if (!act.isFinishing()) showDialog(act, r, true, null);
                    });
                } else {
                    sUpdateBlocked = false;
                }
            } catch (Throwable ignored) {
            }
        }, "wg-module-update-check").start();
    }

    static boolean isTrustedReleaseUrl(String rawUrl) {
        if (rawUrl == null) {
            return false;
        }
        String trimmed = rawUrl.trim();
        if (!trimmed.startsWith(ALLOWED_RELEASE_PREFIX)) {
            return false;
        }
        if (trimmed.contains("..") || trimmed.contains("\\") || trimmed.contains("@")) {
            return false;
        }
        for (int i = 0; i < trimmed.length(); i++) {
            if (Character.isWhitespace(trimmed.charAt(i))) {
                return false;
            }
        }
        return trimmed.length() > ALLOWED_RELEASE_PREFIX.length();
    }

    private static Release fetch() throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(API).openConnection();
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        c.setRequestProperty("Accept", "application/vnd.github+json");
        c.setRequestProperty("User-Agent", "WireGuardPlus-Android");
        if (c.getResponseCode() != 200) return null;
        StringBuilder sb = new StringBuilder();
        try (InputStream in = c.getInputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) sb.append(new String(buf, 0, n, "UTF-8"));
        }
        JSONObject j = new JSONObject(sb.toString());
        Release r = new Release();
        String rawPageUrl = j.optString("html_url", "").trim();
        r.pageUrl = isTrustedReleaseUrl(rawPageUrl) ? rawPageUrl : ALLOWED_RELEASE_PREFIX + "latest";
        r.apkUrl = r.pageUrl;
        String tagVer = j.optString("tag_name", "").trim();
        if (tagVer.startsWith("v") || tagVer.startsWith("V")) {
            tagVer = tagVer.substring(1).trim();
        }
        String deviceAbi = (android.os.Build.SUPPORTED_ABIS != null && android.os.Build.SUPPORTED_ABIS.length > 0)
                ? android.os.Build.SUPPORTED_ABIS[0] : "";
        String abiApkUrl = null;
        String universalApkUrl = null;
        JSONArray assets = j.optJSONArray("assets");
        for (int i = 0; assets != null && i < assets.length(); i++) {
            JSONObject a = assets.getJSONObject(i);
            String assetName = a.optString("name");
            String url = a.optString("browser_download_url", "").trim();
            if (!isTrustedReleaseUrl(url)) {
                url = "";
            }
            Matcher m = APK.matcher(assetName);
            if (m.matches()) {
                r.version = m.group(1);
                if (!url.isEmpty()) universalApkUrl = url;
            } else if (!deviceAbi.isEmpty() && assetName.endsWith("-" + deviceAbi + ".apk")) {
                if (!url.isEmpty()) abiApkUrl = url;
            }
        }
        if (r.version == null && !tagVer.isEmpty()) {
            r.version = tagVer;
        }
        if (abiApkUrl != null) {
            r.apkUrl = abiApkUrl;
        } else if (universalApkUrl != null) {
            r.apkUrl = universalApkUrl;
        }
        if (r.version == null || !isTrustedReleaseUrl(r.apkUrl)) return null;
        boolean inAr = false;
        for (String line : j.optString("body").split("\n")) {
            String s = line.trim();
            if (s.contains("[AR]")) { inAr = true; continue; }
            if (s.startsWith("- ") || s.startsWith("* ")) {
                String item = s.substring(2).replace("**", "").trim();
                (inAr ? r.ar : r.en).add(item);
            }
        }
        if (r.ar.isEmpty()) r.ar = r.en;
        return r;
    }

    static boolean newer(String a, String b) {
        String[] pa = a.split("\\."), pb = b.split("\\.");
        for (int i = 0; i < 3; i++) {
            int x = i < pa.length ? parse(pa[i]) : 0;
            int y = i < pb.length ? parse(pb[i]) : 0;
            if (x != y) return x > y;
        }
        return false;
    }

    private static int parse(String s) {
        if (s == null) return 0;
        String digits = s.trim().replaceFirst("\\D.*$", "");
        if (digits.isEmpty()) return 0;
        try { return Integer.parseInt(digits); } catch (Exception e) { return 0; }
    }

    private static void showDialog(final Activity act, final Release r, final boolean force, final Runnable onDone) {
        final boolean ar = WireGuardManager.isArabic(act);
        final WgTheme th = WgTheme.of(WireGuardManager.isDarkTheme(act));
        final List<String> notes = ar ? r.ar : r.en;
        if (!force && notes.isEmpty()) { if (onDone != null) onDone.run(); return; }

        final Dialog d = new Dialog(act);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        d.setCancelable(false);
        d.setCanceledOnTouchOutside(false);

        int p = WgTheme.dp(act, 22);
        LinearLayout card = new LinearLayout(act);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(p, p, p, p);
        card.setBackground(WgTheme.cardBackground(act, th.surfaceCard, th.borderSubtle, 16));
        card.setLayoutDirection(ar ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);

        TextView badge = text(act, "v" + r.version, 12, th.accentPrimary, true);
        badge.setPadding(WgTheme.dp(act, 10), WgTheme.dp(act, 3), WgTheme.dp(act, 10), WgTheme.dp(act, 3));
        badge.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.borderSubtle, 99));
        card.addView(badge, new LinearLayout.LayoutParams(-2, -2));

        TextView title = text(act, force ? (ar ? "تحديث مطلوب" : "Update required")
                : (ar ? "ما الجديد" : "What's new"), 20, th.textPrimary, true);
        title.setPadding(0, WgTheme.dp(act, 12), 0, WgTheme.dp(act, 4));
        card.addView(title);

        TextView sub = text(act, force
                ? (ar ? "يتوفر إصدار جديد. حدّث للاستمرار باستخدام التطبيق."
                      : "A new version is available. Update to keep using the app.")
                : (ar ? "تم تحديث التطبيق. هذه أبرز التغييرات."
                      : "The app was updated. Here is what changed."), 13, th.textSecondary, false);
        sub.setPadding(0, 0, 0, WgTheme.dp(act, 14));
        card.addView(sub);

        LinearLayout list = new LinearLayout(act);
        list.setOrientation(LinearLayout.VERTICAL);
        for (String n : notes) {
            TextView t = text(act, "\u2022  " + n, 13, th.textPrimary, false);
            t.setPadding(WgTheme.dp(act, 12), WgTheme.dp(act, 9), WgTheme.dp(act, 12), WgTheme.dp(act, 9));
            t.setBackground(WgTheme.cardBackground(act, th.surfaceInput, th.surfaceInput, 8));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.bottomMargin = WgTheme.dp(act, 8);
            list.addView(t, lp);
        }
        ScrollView sv = new ScrollView(act);
        sv.addView(list);
        card.addView(sv, new LinearLayout.LayoutParams(-1, 0, 1f));

        Button primary = new Button(act);
        primary.setAllCaps(false);
        primary.setTextColor(th.onAccent);
        primary.setText(force ? (ar ? "تنزيل التحديث" : "Download update") : (ar ? "متابعة" : "Continue"));
        primary.setBackground(WgTheme.cardBackground(act, th.accentPrimary, th.accentPrimary, 10));
        primary.setOnClickListener(v -> {
            if (force) {
                if (isTrustedReleaseUrl(r.apkUrl)) {
                    act.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(r.apkUrl)));
                }
            } else {
                if (onDone != null) onDone.run();
                d.dismiss();
            }
        });
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, WgTheme.dp(act, 48));
        blp.topMargin = WgTheme.dp(act, 8);
        card.addView(primary, blp);

        if (force) {
            Button quit = new Button(act);
            quit.setAllCaps(false);
            quit.setTextColor(th.textSecondary);
            quit.setText(ar ? "إغلاق" : "Quit");
            quit.setBackground(null);
            quit.setOnClickListener(v -> {
                d.dismiss();
                if (act instanceof ModuleLauncherActivity) {
                    act.finishAffinity();
                }
            });
            card.addView(quit, new LinearLayout.LayoutParams(-1, WgTheme.dp(act, 44)));
        }

        d.setContentView(card);
        Window w = d.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(0));
            w.setLayout((int) (act.getResources().getDisplayMetrics().widthPixels * 0.92f),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            w.setGravity(Gravity.CENTER);
            w.setDimAmount(0.8f);
        }
        d.show();
    }

    private static TextView text(Context c, String s, float sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }
}
