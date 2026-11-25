package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.ContextWrapper;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * First-install opt-in consent modal asking permission to send sanitized diagnostic logs
 * automatically on connection or call anomalies, synced across all WireGuard Plus surfaces.
 */
public final class TelemetryConsentDialog {

    private static final AtomicBoolean sShowingOrChecking = new AtomicBoolean(false);
    private static volatile WeakReference<Dialog> sActiveDialogRef = new WeakReference<>(null);

    private TelemetryConsentDialog() {
    }

    public static void dismissActiveIfShowing() {
        Dialog active = sActiveDialogRef != null ? sActiveDialogRef.get() : null;
        if (active != null && active.isShowing()) {
            try {
                active.dismiss();
            } catch (Throwable ignored) {
            }
        }
        sShowingOrChecking.set(false);
    }

    public static void maybeShowFirstRun(
            final Context activityContext,
            final String moduleApkPath,
            final Runnable onDecisionSaved
    ) {
        final Activity act = unwrapActivity(activityContext);
        if (act == null || act.isFinishing() || (Build.VERSION.SDK_INT >= 17 && act.isDestroyed())) {
            return;
        }
        if (WgTelemetryReporter.isOptedIn(act) || UpdateGate.isUpdateBlocked()) {
            return;
        }
        if (!sShowingOrChecking.compareAndSet(false, true)) {
            return;
        }

        final String pkg = act.getPackageName();
        final Handler mainHandler = new Handler(Looper.getMainLooper());

        if ("org.telegram.wgplus.module".equals(pkg)) {
            mainHandler.post(() -> {
                if (act.isFinishing() || (Build.VERSION.SDK_INT >= 17 && act.isDestroyed())
                        || WgTelemetryReporter.isOptedIn(act) || UpdateGate.isUpdateBlocked()) {
                    sShowingOrChecking.set(false);
                    return;
                }
                showConsentDialogInternal(act, onDecisionSaved);
            });
            return;
        }

        // Inside hooked Telegram apps, sync first from KeepaliveStatusProvider so answering once covers all apps.
        new Thread(() -> {
            try {
                WireGuardManager.syncPullSharedStateFromProvider(act, false);
            } catch (Throwable ignored) {
            }
            mainHandler.post(() -> {
                if (act.isFinishing() || (Build.VERSION.SDK_INT >= 17 && act.isDestroyed())
                        || WgTelemetryReporter.isOptedIn(act) || UpdateGate.isUpdateBlocked()) {
                    sShowingOrChecking.set(false);
                    return;
                }
                showConsentDialogInternal(act, onDecisionSaved);
            });
        }, "wgplus-telemetry-consent-sync").start();
    }

    private static void showConsentDialogInternal(final Activity act, final Runnable onDecisionSaved) {
        final Dialog dialog = new Dialog(act);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setCanceledOnTouchOutside(false);

        final LinearLayout containerHost = new LinearLayout(act);
        containerHost.setOrientation(LinearLayout.VERTICAL);

        final Runnable[] renderModal = new Runnable[1];
        renderModal[0] = () -> {
            boolean isAr = WireGuardManager.isArabic(act);
            WgTheme theme = WgTheme.of(WireGuardManager.isDarkTheme(act));
            containerHost.removeAllViews();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                containerHost.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
            }
            containerHost.setBackground(WgTheme.cardBackground(act, theme.surfaceCard, theme.borderSubtle, 16f));
            int pad = WgTheme.dp(act, 20);
            containerHost.setPadding(pad, pad, pad, pad);

            LinearLayout headerRow = new LinearLayout(act);
            headerRow.setOrientation(LinearLayout.HORIZONTAL);
            headerRow.setGravity(Gravity.CENTER_VERTICAL);

            TextView title = new TextView(act);
            styleProse(title, isAr, theme.textPrimary, 17.5f, true);
            title.setText(WgStrings.telemetryConsentTitle(isAr));
            LinearLayout.LayoutParams tLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            setMarginEndCompat(tLp, WgTheme.dp(act, 8), isAr);
            headerRow.addView(title, tLp);

            Button langChip = new Button(act);
            langChip.setAllCaps(false);
            langChip.setText(WgStrings.langToggleLabel(isAr));
            langChip.setTextColor(theme.textPrimary);
            langChip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
            langChip.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            int minChip = WgTheme.dp(act, 44);
            langChip.setMinHeight(minChip);
            langChip.setMinimumHeight(minChip);
            langChip.setMinWidth(minChip);
            langChip.setMinimumWidth(minChip);
            langChip.setFocusable(true);
            langChip.setPadding(WgTheme.dp(act, 12), WgTheme.dp(act, 7), WgTheme.dp(act, 12), WgTheme.dp(act, 7));
            langChip.setBackground(WgTheme.interactiveBackground(
                    act,
                    theme.surfaceSecondaryBtn,
                    theme.surfaceSecondaryBtnPressed,
                    theme.borderSubtle,
                    theme.accentPrimary,
                    8f
            ));
            langChip.setOnClickListener(v -> {
                WireGuardManager.setArabic(act, !isAr);
                renderModal[0].run();
            });
            headerRow.addView(langChip);
            containerHost.addView(headerRow);

            ScrollView bodyScroll = new ScrollView(act);
            LinearLayout bodyCol = new LinearLayout(act);
            bodyCol.setOrientation(LinearLayout.VERTICAL);

            TextView intro = new TextView(act);
            styleProse(intro, isAr, theme.textSecondary, 13.5f, false);
            intro.setText(WgStrings.telemetryConsentIntro(isAr));
            LinearLayout.LayoutParams introLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            introLp.topMargin = WgTheme.dp(act, 12);
            introLp.bottomMargin = WgTheme.dp(act, 12);
            bodyCol.addView(intro, introLp);

            LinearLayout privacyBox = new LinearLayout(act);
            privacyBox.setOrientation(LinearLayout.VERTICAL);
            privacyBox.setBackground(WgTheme.cardBackground(act, theme.surfaceInput, theme.borderSubtle, 10f));
            int pBoxPad = WgTheme.dp(act, 12);
            privacyBox.setPadding(pBoxPad, pBoxPad, pBoxPad, pBoxPad);

            TextView privHead = new TextView(act);
            styleProse(privHead, isAr, theme.textPrimary, 13f, true);
            privHead.setText(WgStrings.telemetryConsentPrivacyHeading(isAr));
            LinearLayout.LayoutParams phLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            phLp.bottomMargin = WgTheme.dp(act, 6);
            privacyBox.addView(privHead, phLp);

            String[] points = new String[]{
                    WgStrings.telemetryConsentPointKeys(isAr),
                    WgStrings.telemetryConsentPointNoPersonal(isAr),
                    WgStrings.telemetryConsentPointControl(isAr)
            };
            for (int i = 0; i < points.length; i++) {
                TextView pTv = new TextView(act);
                styleProse(pTv, isAr, theme.textSecondary, 12.5f, false);
                pTv.setText(points[i]);
                LinearLayout.LayoutParams pLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                if (i < points.length - 1) {
                    pLp.bottomMargin = WgTheme.dp(act, 5);
                }
                privacyBox.addView(pTv, pLp);
            }

            bodyCol.addView(privacyBox, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));

            bodyScroll.addView(bodyCol, new ScrollView.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));
            LinearLayout.LayoutParams scLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    0,
                    1f
            );
            scLp.bottomMargin = WgTheme.dp(act, 14);
            containerHost.addView(bodyScroll, scLp);

            Button acceptBtn = buildConsentButton(act, WgStrings.telemetryConsentAcceptBtn(isAr), theme, true);
            acceptBtn.setContentDescription("wgplus_btn_telemetry_accept");
            acceptBtn.setOnClickListener(v -> {
                WgTelemetryReporter.setConsentDecision(act, true);
                dialog.dismiss();
                if (onDecisionSaved != null) {
                    onDecisionSaved.run();
                }
            });
            LinearLayout.LayoutParams aLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            aLp.bottomMargin = WgTheme.dp(act, 8);
            containerHost.addView(acceptBtn, aLp);

            Button declineBtn = buildConsentButton(act, WgStrings.telemetryConsentDeclineBtn(isAr), theme, false);
            declineBtn.setContentDescription("wgplus_btn_telemetry_decline");
            declineBtn.setOnClickListener(v -> {
                WgTelemetryReporter.setConsentDecision(act, false);
                dialog.dismiss();
                if (onDecisionSaved != null) {
                    onDecisionSaved.run();
                }
            });
            containerHost.addView(declineBtn, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));
        };

        renderModal[0].run();
        dialog.setContentView(containerHost);
        dialog.setOnDismissListener(d -> {
            sShowingOrChecking.set(false);
            sActiveDialogRef = new WeakReference<>(null);
        });
        sActiveDialogRef = new WeakReference<>(dialog);

        Window w = dialog.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            DisplayMetrics dm = act.getResources().getDisplayMetrics();
            int targetWidth = Math.min(dm.widthPixels - WgTheme.dp(act, 28), WgTheme.dp(act, 460));
            if (targetWidth > 0) {
                w.setLayout(targetWidth, ViewGroup.LayoutParams.WRAP_CONTENT);
            }
            w.setGravity(Gravity.CENTER);
            w.setDimAmount(0.75f);
        }
        dialog.show();
    }

    private static Button buildConsentButton(Context ctx, String label, WgTheme theme, boolean primary) {
        Button btn = new Button(ctx);
        btn.setAllCaps(false);
        btn.setText(label);
        btn.setTextColor(primary ? theme.onAccent : theme.textPrimary);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        btn.setGravity(Gravity.CENTER);
        int minH = WgTheme.dp(ctx, 48);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 14), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 14), WgTheme.dp(ctx, 10));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            btn.setLetterSpacing(0f);
        }
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                primary ? theme.accentPrimary : theme.surfaceSecondaryBtn,
                primary ? theme.accentPressed : theme.surfaceSecondaryBtnPressed,
                primary ? theme.accentPrimary : theme.borderSubtle,
                theme.textPrimary,
                10f
        ));
        return btn;
    }

    private static void styleProse(TextView tv, boolean isAr, int color, float sp, boolean bold) {
        tv.setTextColor(color);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        tv.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL);
        tv.setGravity(isAr ? Gravity.RIGHT : Gravity.LEFT);
        tv.setLineSpacing(WgTheme.dp(tv.getContext(), isAr ? 4f : 2f), isAr ? 1.12f : 1.06f);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            tv.setLetterSpacing(0f);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            tv.setTextDirection(isAr ? View.TEXT_DIRECTION_RTL : View.TEXT_DIRECTION_LTR);
        }
    }

    private static void setMarginEndCompat(LinearLayout.LayoutParams lp, int px, boolean isAr) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginEnd(px);
        } else if (isAr) {
            lp.leftMargin = px;
        } else {
            lp.rightMargin = px;
        }
    }

    private static Activity unwrapActivity(Context ctx) {
        Context cur = ctx;
        for (int i = 0; i < 10 && cur != null; i++) {
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
}
