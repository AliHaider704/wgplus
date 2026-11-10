package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Clean, icon-free standalone companion screen for WireGuard Plus.
 */
public class ModuleLauncherActivity extends Activity {

    private volatile boolean mResumedActivationInFlight;
    private volatile boolean mDestroyed;
    private final ShizukuBridge.BinderListener mShizukuBinderListener = alive -> runOnUiThread(() -> {
        if (!mDestroyed) {
            if (alive && ContinuityBridgeManager.isStealthHybridEnabled(this)
                    && ShizukuBridge.hasPermission(this)
                    && !mResumedActivationInFlight) {
                triggerHybridActivation(WireGuardManager.isArabic(this));
            } else {
                renderScreen();
            }
        }
    });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ensureLauncherComponentVisible();
        ShizukuBridge.addBinderListener(mShizukuBinderListener);
        ShizukuBridge.requestBinderBroadcastAsync(this);
        renderScreen();
    }

    @Override
    protected void onDestroy() {
        mDestroyed = true;
        ShizukuBridge.removeBinderListener(mShizukuBinderListener);
        super.onDestroy();
    }

    private void ensureLauncherComponentVisible() {
        try {
            PackageManager pm = getPackageManager();
            ComponentName cn = new ComponentName(this, ModuleLauncherActivity.class);
            if (pm != null && pm.getComponentEnabledSetting(cn) != PackageManager.COMPONENT_ENABLED_STATE_ENABLED) {
                pm.setComponentEnabledSetting(
                        cn,
                        PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                        PackageManager.DONT_KILL_APP
                );
            }
        } catch (Throwable ignored) {
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        ShizukuBridge.requestBinderBroadcastAsync(this);
        renderScreen();
        if (!mResumedActivationInFlight && ContinuityBridgeManager.isStealthHybridEnabled(this)) {
            ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(this);
            if (snap.shizukuGranted && (!snap.forcedImportant || !snap.listenerConnected)) {
                mResumedActivationInFlight = true;
                ContinuityBridgeManager.activateHybridAsync(this, () -> runOnUiThread(() -> {
                    mResumedActivationInFlight = false;
                    if (!mDestroyed) {
                        renderScreen();
                    }
                }));
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == WireGuardDialog.REQ_IMPORT_CONF_FILE
                || requestCode == WireGuardDialog.REQ_IMPORT_QR_IMAGE) {
            WireGuardDialog.onPickerActivityResult(this, requestCode, resultCode, data);
        }
    }

    private void renderScreen() {
        final boolean isAr = WireGuardManager.isArabic(this);
        final boolean isDark = WireGuardManager.isDarkTheme(this);
        final WgTheme theme = WgTheme.of(isDark);
        final String sourceApk = getApplicationInfo() != null ? getApplicationInfo().sourceDir : null;

        String localizedTitle = WgStrings.appTitle(isAr);
        setTitle(localizedTitle);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                setTaskDescription(new ActivityManager.TaskDescription(localizedTitle));
            } catch (Throwable ignored) {
            }
        }

        applySystemBars(theme);

        LinearLayout screenRoot = new LinearLayout(this);
        screenRoot.setOrientation(LinearLayout.VERTICAL);
        screenRoot.setBackgroundColor(theme.surfaceBase);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            screenRoot.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        }

        int padH = WgTheme.dp(this, 20);

        // Minimal Icon-Free Top Bar
        LinearLayout topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        topBar.setPadding(padH, WgTheme.dp(this, 16), padH, WgTheme.dp(this, 14));

        TextView h1 = new TextView(this);
        styleText(h1, isAr, theme.textPrimary, 19f, true);
        h1.setText(localizedTitle);
        topBar.addView(h1, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button themeToggle = createHeaderChip(WgStrings.themeToggleLabel(isAr, isDark), theme);
        LinearLayout.LayoutParams themeLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        setMarginStart(themeLp, WgTheme.dp(this, 6), isAr);
        themeToggle.setOnClickListener(v -> {
            WireGuardManager.setDarkTheme(this, !isDark);
            renderScreen();
        });
        topBar.addView(themeToggle, themeLp);

        Button langToggle = createHeaderChip(WgStrings.langToggleLabel(isAr), theme);
        LinearLayout.LayoutParams langLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        setMarginStart(langLp, WgTheme.dp(this, 6), isAr);
        langToggle.setOnClickListener(v -> {
            WireGuardManager.setArabic(this, !isAr);
            renderScreen();
        });
        topBar.addView(langToggle, langLp);

        screenRoot.addView(topBar);

        View topRule = new View(this);
        topRule.setBackgroundColor(theme.borderSubtle);
        screenRoot.addView(topRule, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                Math.max(1, WgTheme.dp(this, 1))
        ));

        ScrollView scrollView = new ScrollView(this);
        scrollView.setFillViewport(true);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padH, WgTheme.dp(this, 20), padH, WgTheme.dp(this, 28));
        scrollView.addView(content, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        screenRoot.addView(scrollView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
        ));

        // 1. Focal Status + Direct Launch Card
        LinearLayout statusCard = new LinearLayout(this);
        statusCard.setOrientation(LinearLayout.VERTICAL);
        statusCard.setBackground(WgTheme.cardBackground(this, theme.surfaceCard, theme.borderSubtle, 12f));
        int cardPad = WgTheme.dp(this, 16);
        statusCard.setPadding(cardPad, cardPad, cardPad, cardPad);

        TextView statusHeading = new TextView(this);
        styleText(statusHeading, isAr, theme.textSecondary, 12.5f, true);
        statusHeading.setText(WgStrings.launcherStatusHeading(isAr));
        LinearLayout.LayoutParams shLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        shLp.bottomMargin = WgTheme.dp(this, 8);
        statusCard.addView(statusHeading, shLp);

        boolean active = WireGuardManager.isTunnelRunning(this, sourceApk);
        boolean guarded = !active && WireGuardManager.isKillSwitchGuardActiveNow(this, sourceApk);
        int port = active ? WireGuardManager.getActivePort(this, sourceApk) : 0;
        WireGuardManager.TunnelConfig shownProfile = active
                ? WireGuardManager.getConnectedProfile(this, sourceApk)
                : WireGuardManager.loadConfig(this);
        String profileName = (shownProfile != null && shownProfile.name != null) ? shownProfile.name : "";

        LinearLayout stateRow = new LinearLayout(this);
        stateRow.setOrientation(LinearLayout.HORIZONTAL);
        stateRow.setGravity(Gravity.CENTER_VERTICAL);

        View dot = new View(this);
        int dotPx = WgTheme.dp(this, 8);
        int dotCol = (active && port > 0) ? theme.activeDot : (guarded ? theme.pendingDot : theme.stoppedDot);
        dot.setBackground(WgTheme.statusDot(this, dotCol));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotPx, dotPx);
        setMarginEnd(dotLp, WgTheme.dp(this, 9), isAr);
        stateRow.addView(dot, dotLp);

        TextView stateLabel = new TextView(this);
        int labelCol = (active && port > 0) ? theme.activeText : (guarded ? theme.pendingText : theme.stoppedText);
        styleText(stateLabel, isAr, labelCol, 15f, true);
        if (active && port > 0) {
            stateLabel.setText(WgStrings.statusActiveWithProfile(isAr, profileName, port));
        } else if (guarded) {
            stateLabel.setText(WgStrings.statusKillSwitchGuarded(isAr, profileName));
        } else {
            stateLabel.setText(WgStrings.statusStoppedWithProfile(isAr, profileName));
        }
        stateRow.addView(stateLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        statusCard.addView(stateRow);

        TextView helper = new TextView(this);
        styleText(helper, isAr, theme.textSecondary, 13f, false);
        if (active && port > 0) {
            WireGuardManager.TunnelStats stats = WireGuardManager.getLiveStats(this, sourceApk);
            helper.setText(WgStrings.liveStatsLine(isAr, stats.rxBytes, stats.txBytes, stats.lastHandshakeSec));
        } else if (guarded) {
            helper.setText(WgStrings.statusKillSwitchSubline(isAr));
        } else {
            helper.setText(WgStrings.statusEmptyHint(isAr));
        }
        LinearLayout.LayoutParams helpLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        helpLp.topMargin = WgTheme.dp(this, 6);
        statusCard.addView(helper, helpLp);

        Button openConfigBtn = new Button(this);
        openConfigBtn.setAllCaps(false);
        openConfigBtn.setText(WgStrings.launcherOpenConfigBtn(isAr));
        openConfigBtn.setTextColor(theme.onAccent);
        openConfigBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f);
        openConfigBtn.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);
        int ctaMinH = WgTheme.dp(this, 46);
        openConfigBtn.setMinHeight(ctaMinH);
        openConfigBtn.setMinimumHeight(ctaMinH);
        openConfigBtn.setFocusable(true);
        openConfigBtn.setPadding(WgTheme.dp(this, 16), WgTheme.dp(this, 11), WgTheme.dp(this, 16), WgTheme.dp(this, 11));
        openConfigBtn.setBackground(WgTheme.interactiveBackground(
                this,
                theme.accentPrimary,
                theme.accentPressed,
                theme.accentPrimary,
                theme.textPrimary,
                10f
        ));
        openConfigBtn.setOnClickListener(v ->
                WireGuardDialog.show(this, null, sourceApk, this::renderScreen)
        );
        LinearLayout.LayoutParams openBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        openBtnLp.topMargin = WgTheme.dp(this, 14);
        statusCard.addView(openConfigBtn, openBtnLp);

        LinearLayout.LayoutParams statusCardLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        statusCardLp.bottomMargin = WgTheme.dp(this, 16);
        content.addView(statusCard, statusCardLp);

        // 2. Silent Hybrid Continuity (Shizuku + Boot Guard Listener) Card
        content.addView(buildHybridContinuityCard(isAr, theme, cardPad), createCardParamsWithBottom(16));

        // 3. Real 4-Step Activation Guide Card
        LinearLayout guideCard = new LinearLayout(this);
        guideCard.setOrientation(LinearLayout.VERTICAL);
        guideCard.setBackground(WgTheme.cardBackground(this, theme.surfaceCard, theme.borderSubtle, 12f));
        guideCard.setPadding(cardPad, cardPad, cardPad, cardPad);

        TextView guideTitle = new TextView(this);
        styleText(guideTitle, isAr, theme.textPrimary, 15f, true);
        guideTitle.setText(WgStrings.launcherGuideHeading(isAr));
        LinearLayout.LayoutParams gtLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        gtLp.bottomMargin = WgTheme.dp(this, 10);
        guideCard.addView(guideTitle, gtLp);

        String[] steps = WgStrings.launcherSteps(isAr);
        for (int i = 0; i < steps.length; i++) {
            TextView stepView = new TextView(this);
            styleText(stepView, isAr, theme.textSecondary, 13.5f, false);
            stepView.setLineSpacing(WgTheme.dp(this, 3), 1.0f);
            stepView.setText(steps[i]);
            LinearLayout.LayoutParams stepLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            if (i < steps.length - 1) {
                stepLp.bottomMargin = WgTheme.dp(this, 9);
            }
            guideCard.addView(stepView, stepLp);
        }

        content.addView(guideCard, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        setContentView(screenRoot);
    }

    private LinearLayout buildHybridContinuityCard(boolean isAr, WgTheme theme, int cardPad) {
        LinearLayout hybridCard = new LinearLayout(this);
        hybridCard.setOrientation(LinearLayout.VERTICAL);
        hybridCard.setBackground(WgTheme.cardBackground(this, theme.surfaceCard, theme.borderSubtle, 12f));
        hybridCard.setPadding(cardPad, cardPad, cardPad, cardPad);

        TextView heading = new TextView(this);
        styleText(heading, isAr, theme.textSecondary, 12.5f, true);
        heading.setText(WgStrings.hybridHeading(isAr));
        LinearLayout.LayoutParams hLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        hLp.bottomMargin = WgTheme.dp(this, 8);
        hybridCard.addView(heading, hLp);

        ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(this);

        LinearLayout tierRow = new LinearLayout(this);
        tierRow.setOrientation(LinearLayout.HORIZONTAL);
        tierRow.setGravity(Gravity.CENTER_VERTICAL);

        View dot = new View(this);
        int dotPx = WgTheme.dp(this, 8);
        int dotCol = snap.tier == ContinuityBridgeManager.ContinuityTier.HYBRID_FULL
                ? theme.activeDot
                : (snap.stealthProtected ? theme.pendingDot : theme.stoppedDot);
        dot.setBackground(WgTheme.statusDot(this, dotCol));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotPx, dotPx);
        setMarginEnd(dotLp, WgTheme.dp(this, 9), isAr);
        tierRow.addView(dot, dotLp);

        TextView tierLabel = new TextView(this);
        int tierColor = snap.tier == ContinuityBridgeManager.ContinuityTier.HYBRID_FULL
                ? theme.activeText
                : (snap.stealthProtected ? theme.pendingText : theme.textPrimary);
        styleText(tierLabel, isAr, tierColor, 14.5f, true);
        tierLabel.setText(WgStrings.hybridTierLabel(isAr, snap.tier));
        tierRow.addView(tierLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        hybridCard.addView(tierRow);

        TextView detailView = new TextView(this);
        styleText(detailView, isAr, theme.textSecondary, 12.5f, false);
        detailView.setText(WgStrings.hybridDetailLine(isAr, snap));
        LinearLayout.LayoutParams detLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        detLp.topMargin = WgTheme.dp(this, 5);
        hybridCard.addView(detailView, detLp);

        LinearLayout toggleRow = new LinearLayout(this);
        toggleRow.setOrientation(LinearLayout.HORIZONTAL);
        toggleRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams trLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        trLp.topMargin = WgTheme.dp(this, 10);

        TextView toggleLabel = new TextView(this);
        styleText(toggleLabel, isAr, theme.textPrimary, 13.5f, false);
        toggleLabel.setText(WgStrings.hybridStealthToggleTitle(isAr));
        LinearLayout.LayoutParams tlLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEnd(tlLp, WgTheme.dp(this, 8), isAr);
        toggleRow.addView(toggleLabel, tlLp);

        Switch stealthSwitch = new Switch(this);
        stealthSwitch.setChecked(snap.stealthHybridEnabled);
        stealthSwitch.setMinHeight(WgTheme.dp(this, 44));
        stealthSwitch.setOnCheckedChangeListener((btn, isChecked) -> {
            ContinuityBridgeManager.setStealthHybridEnabled(this, isChecked);
            renderScreen();
        });
        toggleRow.addView(stealthSwitch);
        hybridCard.addView(toggleRow, trLp);

        Button primaryBtn = createActionButton(
                snap.shizukuGranted
                        ? WgStrings.hybridActionActivateNow(isAr)
                        : (snap.shizukuRunning
                            ? WgStrings.hybridActionGrantShizuku(isAr)
                            : WgStrings.hybridActionOpenShizuku(isAr)),
                theme,
                !snap.shizukuInstalled || !snap.shizukuRunning
        );
        primaryBtn.setOnClickListener(v -> {
            if (!snap.shizukuInstalled || !snap.shizukuRunning) {
                openShizukuOrToast(isAr);
            } else if (!snap.shizukuGranted) {
                ShizukuBridge.requestPermission(this, granted -> runOnUiThread(() -> {
                    if (mDestroyed) {
                        return;
                    }
                    if (granted) {
                        triggerHybridActivation(isAr);
                    } else {
                        renderScreen();
                    }
                }));
            } else {
                triggerHybridActivation(isAr);
            }
        });
        LinearLayout.LayoutParams pLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        pLp.topMargin = WgTheme.dp(this, 10);
        hybridCard.addView(primaryBtn, pLp);

        if (!snap.listenerEnabled && (!snap.shizukuRunning || !snap.shizukuGranted)) {
            Button listenerBtn = createActionButton(
                    WgStrings.hybridActionOpenListenerSettings(isAr),
                    theme,
                    true
            );
            listenerBtn.setOnClickListener(v -> {
                try {
                    startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS));
                } catch (Throwable ignored) {
                }
            });
            LinearLayout.LayoutParams lLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            lLp.topMargin = WgTheme.dp(this, 8);
            hybridCard.addView(listenerBtn, lLp);
        }

        TextView noteView = new TextView(this);
        styleText(noteView, isAr, theme.textHint, 12f, false);
        noteView.setLineSpacing(WgTheme.dp(this, 2), 1.0f);
        noteView.setText(WgStrings.hybridHelperNote(isAr));
        LinearLayout.LayoutParams nLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        nLp.topMargin = WgTheme.dp(this, 10);
        hybridCard.addView(noteView, nLp);

        return hybridCard;
    }

    private void triggerHybridActivation(boolean isAr) {
        ContinuityBridgeManager.activateHybridAsync(this, () -> runOnUiThread(() -> {
            if (mDestroyed) {
                return;
            }
            ContinuityBridgeManager.StealthSnapshot now = ContinuityBridgeManager.captureStatusSnapshot(this);
            Toast.makeText(
                    this,
                    WgStrings.hybridAppliedToast(isAr, now.stealthProtected),
                    Toast.LENGTH_SHORT
            ).show();
            renderScreen();
        }));
    }

    private void openShizukuOrToast(boolean isAr) {
        try {
            Intent launch = getPackageManager() != null
                    ? getPackageManager().getLaunchIntentForPackage(ShizukuBridge.SHIZUKU_PACKAGE)
                    : null;
            if (launch != null) {
                startActivity(launch);
            }
        } catch (Throwable ignored) {
        }
        Toast.makeText(this, WgStrings.hybridOpenShizukuHintToast(isAr), Toast.LENGTH_LONG).show();
    }

    private Button createActionButton(String text, WgTheme theme, boolean secondary) {
        Button btn = new Button(this);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(secondary ? theme.textPrimary : theme.onAccent);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        btn.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);
        int minH = WgTheme.dp(this, 44);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(this, 14), WgTheme.dp(this, 9), WgTheme.dp(this, 14), WgTheme.dp(this, 9));
        btn.setBackground(WgTheme.interactiveBackground(
                this,
                secondary ? theme.surfaceSecondaryBtn : theme.accentPrimary,
                secondary ? theme.surfaceSecondaryBtnPressed : theme.accentPressed,
                secondary ? theme.borderSubtle : theme.accentPrimary,
                theme.textPrimary,
                10f
        ));
        return btn;
    }

    private LinearLayout.LayoutParams createCardParamsWithBottom(int bottomDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lp.bottomMargin = WgTheme.dp(this, bottomDp);
        return lp;
    }

    private Button createHeaderChip(String text, WgTheme theme) {
        Button btn = new Button(this);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(theme.textPrimary);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        btn.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);
        int minSize = WgTheme.dp(this, 44);
        btn.setMinHeight(minSize);
        btn.setMinimumHeight(minSize);
        btn.setMinWidth(minSize);
        btn.setMinimumWidth(minSize);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(this, 10), WgTheme.dp(this, 6), WgTheme.dp(this, 10), WgTheme.dp(this, 6));
        btn.setBackground(WgTheme.interactiveBackground(
                this,
                theme.surfaceSecondaryBtn,
                theme.surfaceSecondaryBtnPressed,
                theme.borderSubtle,
                theme.accentPrimary,
                8f
        ));
        return btn;
    }

    private void applySystemBars(WgTheme theme) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = getWindow();
            if (window != null) {
                window.setStatusBarColor(theme.surfaceBase);
                window.setNavigationBarColor(theme.surfaceBase);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    View decor = window.getDecorView();
                    int flags = decor.getSystemUiVisibility();
                    if (theme.isDark) {
                        flags &= ~View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                    } else {
                        flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                    }
                    decor.setSystemUiVisibility(flags);
                }
            }
        }
    }

    private static void styleText(TextView tv, boolean isAr, int color, float sizeSp, boolean bold) {
        tv.setTextColor(color);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        tv.setTypeface(Typeface.SANS_SERIF, bold ? Typeface.BOLD : Typeface.NORMAL);
        tv.setGravity(isAr ? Gravity.RIGHT : Gravity.LEFT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            tv.setTextDirection(isAr ? View.TEXT_DIRECTION_RTL : View.TEXT_DIRECTION_LTR);
        }
    }

    private static void setMarginEnd(LinearLayout.LayoutParams lp, int px, boolean isAr) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginEnd(px);
        } else if (isAr) {
            lp.leftMargin = px;
        } else {
            lp.rightMargin = px;
        }
    }

    private static void setMarginStart(LinearLayout.LayoutParams lp, int px, boolean isAr) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginStart(px);
        } else if (isAr) {
            lp.rightMargin = px;
        } else {
            lp.leftMargin = px;
        }
    }
}
