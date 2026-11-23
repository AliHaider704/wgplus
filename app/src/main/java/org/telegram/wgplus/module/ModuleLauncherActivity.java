package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
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

    private static final int REQ_POST_NOTIFICATIONS = 7102;
    private static final long STALLED_HANDSHAKE_THRESHOLD_MS = 10_000L;
    private static final long STALE_HANDSHAKE_THRESHOLD_SEC = 150L;

    private static volatile boolean sAutoContinuityAttemptedThisSession = false;

    private final Handler mUiHandler = new Handler(Looper.getMainLooper());
    private volatile boolean mResumedActivationInFlight;
    private volatile boolean mDestroyed;
    private volatile boolean mQuickWarpBusy;
    private volatile boolean mCleaningCache;
    private boolean mPendingPairingAfterNotifPermission;
    private boolean mContinuityExpanded = false;
    private boolean mGuideUserToggled = false;
    private boolean mGuideExpanded = true;
    private long mObservedActiveNoHsAtMs = 0L;
    private Runnable mLiveRefreshTicker;
    private ScrollView mScrollView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ensureLauncherComponentVisible();
        mLiveRefreshTicker = new Runnable() {
            @Override
            public void run() {
                if (mDestroyed) {
                    return;
                }
                if (mObservedActiveNoHsAtMs > 0L) {
                    renderScreen();
                    if (mObservedActiveNoHsAtMs > 0L) {
                        mUiHandler.postDelayed(this, 2500L);
                    }
                }
            }
        };
        renderScreen();
        UpdateGate.check(this);
    }

    @Override
    protected void onDestroy() {
        mDestroyed = true;
        mUiHandler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    protected void onPause() {
        super.onPause();
        mUiHandler.removeCallbacksAndMessages(null);
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
        ContinuityBridgeManager.registerPassiveWifiRecovery(this);
        renderScreen();
        if (mLiveRefreshTicker != null) {
            mUiHandler.removeCallbacks(mLiveRefreshTicker);
            mUiHandler.postDelayed(mLiveRefreshTicker, 2500L);
        }
        // Only perform automatic continuity activation once per process session and NEVER re-spawn su per resume
        if (!sAutoContinuityAttemptedThisSession
                && !mResumedActivationInFlight
                && ContinuityBridgeManager.isStealthHybridEnabled(this)) {
            sAutoContinuityAttemptedThisSession = true;
            mResumedActivationInFlight = true;
            new Thread(() -> {
                try {
                    boolean daemonAlive = PrivilegeBridge.isStandaloneDaemonAlive(this);
                    ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(this);
                    boolean sovereignReady = daemonAlive || ContinuityBridgeManager.hasAnyPrivilegeBackend(this);
                    if (sovereignReady && (!daemonAlive || !snap.forcedImportant || !snap.listenerConnected)) {
                        ContinuityBridgeManager.activateHybridOneTap(this);
                    }
                } catch (Throwable ignored) {
                } finally {
                    runOnUiThread(() -> {
                        mResumedActivationInFlight = false;
                        if (!mDestroyed) {
                            renderScreen();
                        }
                    });
                }
            }, "wgplus-resume-continuity").start();
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
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                setTaskDescription(new ActivityManager.TaskDescription.Builder()
                        .setLabel(localizedTitle)
                        .setIcon(R.mipmap.ic_launcher)
                        .build());
            } catch (Throwable ignored) {
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                setTaskDescription(new ActivityManager.TaskDescription(localizedTitle, R.mipmap.ic_launcher));
            } catch (Throwable ignored) {
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
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
        themeToggle.setContentDescription("wgplus_btn_theme");
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
        langToggle.setContentDescription("wgplus_btn_lang");
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

        final int prevScrollY = mScrollView != null ? mScrollView.getScrollY() : 0;
        final ScrollView scrollView = new ScrollView(this);
        scrollView.setFillViewport(true);
        mScrollView = scrollView;

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
        boolean sharedObserved = active && WireGuardManager.isSharedTunnelObserved(this, sourceApk);
        boolean guarded = !active && WireGuardManager.isKillSwitchGuardActiveNow(this, sourceApk);
        boolean hasProfile = WireGuardManager.hasAnyConfiguredProfile(this);
        int port = active ? WireGuardManager.getActivePort(this, sourceApk) : 0;
        WireGuardManager.TunnelConfig shownProfile = active
                ? WireGuardManager.getConnectedProfile(this, sourceApk)
                : WireGuardManager.loadConfig(this);
        String profileName = (shownProfile != null && shownProfile.name != null)
                ? WgStrings.localizeProfileName(shownProfile.name, isAr)
                : "";

        WireGuardManager.TunnelStats stats = (active && port > 0 && !sharedObserved)
                ? WireGuardManager.getLiveStats(this, sourceApk)
                : new WireGuardManager.TunnelStats();
        int handshakeStateCode = 0; // 0=idle, 1=handshaking, 2=verified, 3=stalled
        if (active && port > 0) {
            if (sharedObserved) {
                mObservedActiveNoHsAtMs = 0L;
                handshakeStateCode = 2;
            } else {
                long nowEpoch = System.currentTimeMillis() / 1000L;
                boolean recentHs = stats.lastHandshakeSec > 0
                        && Math.max(0L, nowEpoch - stats.lastHandshakeSec) < STALE_HANDSHAKE_THRESHOLD_SEC;
                if (recentHs) {
                    mObservedActiveNoHsAtMs = 0L;
                    handshakeStateCode = 2;
                } else {
                    long startedAtMs = WireGuardManager.getTunnelStartedAtMs();
                    if (startedAtMs <= 0L) {
                        if (mObservedActiveNoHsAtMs <= 0L) {
                            mObservedActiveNoHsAtMs = SystemClock.elapsedRealtime();
                        }
                        startedAtMs = mObservedActiveNoHsAtMs;
                    }
                    long elapsedNoHs = Math.max(0L, SystemClock.elapsedRealtime() - startedAtMs);
                    boolean staleOldHs = stats.lastHandshakeSec > 0
                            && (nowEpoch - stats.lastHandshakeSec) >= STALE_HANDSHAKE_THRESHOLD_SEC;
                    handshakeStateCode = (elapsedNoHs >= STALLED_HANDSHAKE_THRESHOLD_MS || staleOldHs) ? 3 : 1;
                }
            }
        } else {
            mObservedActiveNoHsAtMs = 0L;
        }

        LinearLayout stateRow = new LinearLayout(this);
        stateRow.setOrientation(LinearLayout.HORIZONTAL);
        stateRow.setGravity(Gravity.CENTER_VERTICAL);

        View dot = new View(this);
        dot.setContentDescription("wgplus_status_dot");
        int dotPx = WgTheme.dp(this, 8);
        int dotCol = (handshakeStateCode == 2)
                ? theme.activeDot
                : ((handshakeStateCode == 1 || handshakeStateCode == 3 || guarded) ? theme.pendingDot : theme.stoppedDot);
        dot.setBackground(WgTheme.statusDot(this, dotCol));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotPx, dotPx);
        setMarginEnd(dotLp, WgTheme.dp(this, 9), isAr);
        stateRow.addView(dot, dotLp);

        TextView stateLabel = new TextView(this);
        stateLabel.setContentDescription("wgplus_status_headline");
        int labelCol = (handshakeStateCode == 2)
                ? theme.activeText
                : ((handshakeStateCode == 1 || handshakeStateCode == 3 || guarded) ? theme.pendingText : theme.stoppedText);
        styleText(stateLabel, isAr, labelCol, 15f, true);
        if (handshakeStateCode == 2) {
            stateLabel.setText(WgStrings.statusActiveWithProfile(isAr, profileName, port));
        } else if (handshakeStateCode == 1) {
            stateLabel.setText(WgStrings.statusAwaitingHandshakeWithProfile(isAr, profileName));
        } else if (handshakeStateCode == 3) {
            stateLabel.setText(WgStrings.statusStalledWithProfile(isAr, profileName));
        } else if (guarded) {
            stateLabel.setText(WgStrings.statusKillSwitchGuarded(isAr, profileName));
        } else {
            stateLabel.setText(WgStrings.statusStoppedWithProfile(isAr, profileName));
        }
        stateRow.addView(stateLabel, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        statusCard.addView(stateRow);

        TextView helper = new TextView(this);
        styleText(helper, isAr, theme.textSecondary, 13f, false);
        if (sharedObserved) {
            helper.setText(WgStrings.sharedTunnelActiveSubline(isAr, port));
        } else if (handshakeStateCode == 2 || handshakeStateCode == 1) {
            helper.setText(WgStrings.liveStatsLine(isAr, stats.rxBytes, stats.txBytes, stats.lastHandshakeSec));
        } else if (handshakeStateCode == 3) {
            helper.setText(WgStrings.statusStalledHint(isAr));
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

        if (handshakeStateCode == 3) {
            LinearLayout recoveryBox = new LinearLayout(this);
            recoveryBox.setOrientation(LinearLayout.VERTICAL);
            recoveryBox.setBackground(WgTheme.cardBackground(this, theme.pendingBg, theme.pendingBorder, 8f));
            int recPad = WgTheme.dp(this, 10);
            recoveryBox.setPadding(recPad, recPad, recPad, recPad);
            LinearLayout.LayoutParams recLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            recLp.topMargin = WgTheme.dp(this, 10);

            Button recAwgBtn = createActionButton(WgStrings.recoverAwgBtn(isAr), theme, true);
            recAwgBtn.setContentDescription("wgplus_btn_recover_awg");
            recAwgBtn.setEnabled(!mQuickWarpBusy);
            recAwgBtn.setOnClickListener(v -> {
                if (mQuickWarpBusy) {
                    return;
                }
                mQuickWarpBusy = true;
                renderScreen();
                new Thread(() -> {
                    try {
                        int recPort = WireGuardManager.applyAwg15AndReconnect(this, sourceApk, null);
                        mObservedActiveNoHsAtMs = 0L;
                        runOnUiThread(() -> {
                            mQuickWarpBusy = false;
                            if (!mDestroyed) {
                                Toast.makeText(this, WgStrings.toastAwgRecovered(isAr, recPort), Toast.LENGTH_SHORT).show();
                                renderScreen();
                                WireGuardManager.maybeInviteToOfficialChannel(this, isAr);
                            }
                        });
                    } catch (final Throwable err) {
                        runOnUiThread(() -> {
                            mQuickWarpBusy = false;
                            if (!mDestroyed) {
                                Toast.makeText(this, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                                renderScreen();
                            }
                        });
                    }
                }, "wgplus-recover-awg").start();
            });
            recoveryBox.addView(recAwgBtn, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));

            Button recWarpBtn = createActionButton(WgStrings.recoverWarpBtn(isAr), theme, true);
            recWarpBtn.setContentDescription("wgplus_btn_recover_warp");
            recWarpBtn.setEnabled(!mQuickWarpBusy);
            recWarpBtn.setOnClickListener(v -> launchQuickWarpFlow(isAr, sourceApk));
            LinearLayout.LayoutParams rwLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            rwLp.topMargin = WgTheme.dp(this, 6);
            recoveryBox.addView(recWarpBtn, rwLp);

            statusCard.addView(recoveryBox, recLp);
        }

        String manageLabel = hasProfile
                ? WgStrings.launcherOpenConfigBtn(isAr)
                : WgStrings.launcherManageSecondaryBtn(isAr);
        Button openConfigBtn = createActionButton(manageLabel, theme, !hasProfile);
        openConfigBtn.setContentDescription("wgplus_btn_manage");
        openConfigBtn.setOnClickListener(v ->
                WireGuardDialog.show(this, null, sourceApk, this::renderScreen)
        );

        Button quickWarpBtn = createActionButton(WgStrings.quickWarpBtn(isAr, mQuickWarpBusy), theme, hasProfile);
        quickWarpBtn.setContentDescription("wgplus_btn_quick_warp");
        quickWarpBtn.setEnabled(!mQuickWarpBusy);
        quickWarpBtn.setOnClickListener(v -> launchQuickWarpFlow(isAr, sourceApk));

        // Adaptive single accentPrimary button: promote 1-Tap Free WARP when zero servers exist
        Button firstBtn = hasProfile ? openConfigBtn : quickWarpBtn;
        Button secondBtn = hasProfile ? quickWarpBtn : openConfigBtn;

        LinearLayout.LayoutParams firstLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        firstLp.topMargin = WgTheme.dp(this, 14);
        statusCard.addView(firstBtn, firstLp);

        LinearLayout.LayoutParams secondLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        secondLp.topMargin = WgTheme.dp(this, 10);
        statusCard.addView(secondBtn, secondLp);

        LinearLayout.LayoutParams statusCardLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        statusCardLp.bottomMargin = WgTheme.dp(this, 16);
        content.addView(statusCard, statusCardLp);

        // 2. Live Setup Readiness Checklist + Collapsible Quick Guide + Safe Cache Optimizer
        content.addView(
                buildReadinessChecklistCard(isAr, theme, cardPad, hasProfile, handshakeStateCode),
                createCardParamsWithBottom(16)
        );

        // 3. Optional Advanced Background Stability Card (collapsed by default)
        content.addView(buildHybridContinuityCard(isAr, theme, cardPad), createCardParamsWithBottom(12));

        // 4. Sanitized Diagnostics & GitHub Issue Reporter Entry
        Button diagEntryBtn = createActionButton(WgStrings.diagnosticsBtn(isAr), theme, false);
        diagEntryBtn.setContentDescription("wgplus_btn_diagnostics");
        diagEntryBtn.setOnClickListener(v ->
                WireGuardDialog.showDiagnosticsModal(this, sourceApk, isAr, theme)
        );
        LinearLayout.LayoutParams diagLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        diagLp.bottomMargin = WgTheme.dp(this, 10);
        content.addView(diagEntryBtn, diagLp);

        // 5. Direct Official Channel Link (@wgplus_official)
        Button channelEntryBtn = createActionButton(WgStrings.officialChannelBtn(isAr), theme, true);
        channelEntryBtn.setContentDescription("wgplus_btn_channel");
        channelEntryBtn.setOnClickListener(v ->
                WireGuardManager.openOfficialChannel(this, null)
        );
        content.addView(channelEntryBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        String verName = "1.9.0";
        try {
            verName = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Throwable ignored) {
        }
        TextView versionFooter = new TextView(this);
        versionFooter.setText("WireGuard Plus \u00B7 v" + verName);
        versionFooter.setTextColor(theme.textSecondary);
        versionFooter.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f);
        versionFooter.setTypeface(Typeface.MONOSPACE);
        versionFooter.setAlpha(0.65f);
        versionFooter.setGravity(Gravity.CENTER);
        versionFooter.setPadding(0, WgTheme.dp(this, 16), 0, WgTheme.dp(this, 6));
        content.addView(versionFooter, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        setContentView(screenRoot);
        if (prevScrollY > 0) {
            scrollView.post(() -> scrollView.scrollTo(0, prevScrollY));
        }
    }

    private void launchQuickWarpFlow(final boolean isAr, final String sourceApk) {
        if (mQuickWarpBusy) {
            return;
        }
        mQuickWarpBusy = true;
        renderScreen();
        new Thread(() -> {
            try {
                final WireGuardManager.QuickWarpResult res =
                        WireGuardManager.quickConnectFreeWarp(this, sourceApk, null, false);
                mObservedActiveNoHsAtMs = 0L;
                runOnUiThread(() -> {
                    mQuickWarpBusy = false;
                    if (!mDestroyed) {
                        Toast.makeText(
                                this,
                                WgStrings.toastQuickWarpConnected(isAr, res.createdNew, res.localPort),
                                Toast.LENGTH_SHORT
                        ).show();
                        renderScreen();
                        WireGuardManager.maybeInviteToOfficialChannel(this, isAr);
                    }
                });
            } catch (final Throwable err) {
                runOnUiThread(() -> {
                    mQuickWarpBusy = false;
                    if (!mDestroyed) {
                        Toast.makeText(this, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                        renderScreen();
                    }
                });
            }
        }, "wg-plus-launcher-warp").start();
    }

    private LinearLayout buildReadinessChecklistCard(
            final boolean isAr,
            WgTheme theme,
            int cardPad,
            boolean hasProfile,
            int handshakeStateCode
    ) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(WgTheme.cardBackground(this, theme.surfaceCard, theme.borderSubtle, 12f));
        card.setPadding(cardPad, cardPad, cardPad, cardPad);

        TextView heading = new TextView(this);
        styleText(heading, isAr, theme.textPrimary, 15f, true);
        heading.setText(WgStrings.readinessHeading(isAr));
        LinearLayout.LayoutParams hLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        hLp.bottomMargin = WgTheme.dp(this, 10);
        card.addView(heading, hLp);

        Bundle hookBundle = KeepaliveStatusProvider.readHookTelemetryBundle(this);
        String hookedPkg = hookBundle.getString(KeepaliveStatusProvider.RESULT_HOOK_PKG, "");
        boolean hookVerified = hookedPkg != null && !hookedPkg.trim().isEmpty();
        if (!mGuideUserToggled) {
            mGuideExpanded = !hookVerified;
        }

        addChecklistItem(
                card, isAr, theme,
                hasProfile ? theme.activeDot : theme.stoppedDot,
                hasProfile ? theme.textPrimary : theme.textSecondary,
                WgStrings.readinessItemServer(isAr, hasProfile)
        );
        addChecklistItem(
                card, isAr, theme,
                hookVerified ? theme.activeDot : theme.pendingDot,
                hookVerified ? theme.textPrimary : theme.textSecondary,
                WgStrings.readinessItemHook(isAr, hookedPkg)
        );
        int hsDot = (handshakeStateCode == 2)
                ? theme.activeDot
                : ((handshakeStateCode == 1 || handshakeStateCode == 3) ? theme.pendingDot : theme.stoppedDot);
        addChecklistItem(
                card, isAr, theme,
                hsDot,
                handshakeStateCode == 2 ? theme.activeText : theme.textSecondary,
                WgStrings.readinessItemHandshake(isAr, handshakeStateCode)
        );

        Button toggleGuideBtn = createActionButton(WgStrings.launcherStepsToggleBtn(isAr, mGuideExpanded), theme, true);
        toggleGuideBtn.setContentDescription("wgplus_toggle_guide");
        toggleGuideBtn.setOnClickListener(v -> {
            mGuideUserToggled = true;
            mGuideExpanded = !mGuideExpanded;
            renderScreen();
        });
        LinearLayout.LayoutParams tgLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tgLp.topMargin = WgTheme.dp(this, 6);
        card.addView(toggleGuideBtn, tgLp);

        if (mGuideExpanded) {
            LinearLayout guideBox = new LinearLayout(this);
            guideBox.setOrientation(LinearLayout.VERTICAL);
            LinearLayout.LayoutParams gbLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            gbLp.topMargin = WgTheme.dp(this, 10);

            String[] steps = WgStrings.launcherSteps(isAr);
            for (int i = 0; i < steps.length; i++) {
                TextView stepView = new TextView(this);
                styleText(stepView, isAr, theme.textSecondary, 13f, false);
                stepView.setLineSpacing(WgTheme.dp(this, 3), 1.0f);
                stepView.setText(steps[i]);
                LinearLayout.LayoutParams stepLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                if (i < steps.length - 1) {
                    stepLp.bottomMargin = WgTheme.dp(this, 7);
                }
                guideBox.addView(stepView, stepLp);
            }
            card.addView(guideBox, gbLp);
        }

        Button cleanCacheBtn = createActionButton(WgStrings.cleanCacheBtn(isAr, mCleaningCache), theme, true);
        cleanCacheBtn.setContentDescription("wgplus_btn_clean_cache");
        cleanCacheBtn.setEnabled(!mCleaningCache);
        cleanCacheBtn.setOnClickListener(v -> {
            if (mCleaningCache) {
                return;
            }
            mCleaningCache = true;
            renderScreen();
            new Thread(() -> {
                KeepaliveStatusProvider.requestRemoteHygieneLocal(this);
                ModuleHygieneManager.HygieneReport report = ModuleHygieneManager.cleanCachesSafely(this, true);
                runOnUiThread(() -> {
                    mCleaningCache = false;
                    if (!mDestroyed) {
                        Toast.makeText(
                                this,
                                WgStrings.toastCacheCleaned(isAr, report.freedBytes, report.filesDeleted),
                                Toast.LENGTH_SHORT
                        ).show();
                        renderScreen();
                    }
                });
            }, "wgplus-clean-cache").start();
        });
        LinearLayout.LayoutParams ccLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        ccLp.topMargin = WgTheme.dp(this, 8);
        card.addView(cleanCacheBtn, ccLp);

        return card;
    }

    private void addChecklistItem(
            LinearLayout parent,
            boolean isAr,
            WgTheme theme,
            int dotColor,
            int textColor,
            String text
    ) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        rLp.bottomMargin = WgTheme.dp(this, 7);

        View dot = new View(this);
        int dotPx = WgTheme.dp(this, 8);
        dot.setBackground(WgTheme.statusDot(this, dotColor));
        LinearLayout.LayoutParams dLp = new LinearLayout.LayoutParams(dotPx, dotPx);
        setMarginEnd(dLp, WgTheme.dp(this, 9), isAr);
        row.addView(dot, dLp);

        TextView tv = new TextView(this);
        styleText(tv, isAr, textColor, 13.5f, false);
        tv.setText(text);
        row.addView(tv, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        parent.addView(row, rLp);
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
        hLp.bottomMargin = WgTheme.dp(this, 4);
        hybridCard.addView(heading, hLp);

        TextView optNote = new TextView(this);
        styleText(optNote, isAr, theme.textHint, 12.2f, false);
        optNote.setText(WgStrings.hybridOptionalNote(isAr));
        LinearLayout.LayoutParams optLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        optLp.bottomMargin = WgTheme.dp(this, 8);
        hybridCard.addView(optNote, optLp);

        Button collapseBtn = createActionButton(WgStrings.hybridToggleCardBtn(isAr, mContinuityExpanded), theme, true);
        collapseBtn.setContentDescription("wgplus_toggle_continuity");
        collapseBtn.setOnClickListener(v -> {
            mContinuityExpanded = !mContinuityExpanded;
            renderScreen();
        });
        hybridCard.addView(collapseBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        if (!mContinuityExpanded) {
            return hybridCard;
        }

        ContinuityBridgeManager.StealthSnapshot snap = ContinuityBridgeManager.captureStatusSnapshot(this);

        LinearLayout tierRow = new LinearLayout(this);
        tierRow.setOrientation(LinearLayout.HORIZONTAL);
        tierRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams trHeadLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        trHeadLp.topMargin = WgTheme.dp(this, 12);

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
        hybridCard.addView(tierRow, trHeadLp);

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
        styleSwitchColors(stealthSwitch, theme);
        stealthSwitch.setOnCheckedChangeListener((btn, isChecked) -> {
            ContinuityBridgeManager.setStealthHybridEnabled(this, isChecked);
            renderScreen();
        });
        toggleRow.addView(stealthSwitch);
        hybridCard.addView(toggleRow, trLp);

        LinearLayout tcpToggleRow = new LinearLayout(this);
        tcpToggleRow.setOrientation(LinearLayout.HORIZONTAL);
        tcpToggleRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams tcpLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tcpLp.topMargin = WgTheme.dp(this, 6);

        TextView tcpLabel = new TextView(this);
        styleText(tcpLabel, isAr, theme.textPrimary, 13.0f, false);
        tcpLabel.setText(WgStrings.hybridMobileTcpToggleTitle(isAr));
        LinearLayout.LayoutParams tcpLblLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEnd(tcpLblLp, WgTheme.dp(this, 8), isAr);
        tcpToggleRow.addView(tcpLabel, tcpLblLp);

        Switch tcpSwitch = new Switch(this);
        tcpSwitch.setChecked(BuiltinAdbKeyManager.isMobileTcpHealEnabled(this));
        tcpSwitch.setMinHeight(WgTheme.dp(this, 44));
        styleSwitchColors(tcpSwitch, theme);
        tcpSwitch.setOnCheckedChangeListener((btn, isChecked) -> {
            BuiltinAdbKeyManager.setMobileTcpHealEnabled(this, isChecked);
            renderScreen();
        });
        tcpToggleRow.addView(tcpSwitch);
        hybridCard.addView(tcpToggleRow, tcpLp);

        final boolean sovereignReady = ContinuityBridgeManager.hasAnyPrivilegeBackend(this);
        final boolean wirelessPairingAvailable = !snap.rootActive
                && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                && !snap.builtinAdbPaired;
        final boolean needsOneTimeSetup = !sovereignReady && wirelessPairingAvailable;
        String primaryLabel = needsOneTimeSetup
                ? WgStrings.hybridActionOneTimeSetup(isAr)
                : WgStrings.hybridActionActivateNow(isAr);
        Button primaryBtn = createActionButton(primaryLabel, theme, false);
        primaryBtn.setOnClickListener(v -> {
            if (needsOneTimeSetup) {
                startBuiltinWirelessPairingFlow(isAr);
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

        if (sovereignReady && wirelessPairingAvailable) {
            Button pairBtn = createActionButton(
                    WgStrings.hybridActionOneTimeSetup(isAr),
                    theme,
                    true
            );
            pairBtn.setOnClickListener(v -> startBuiltinWirelessPairingFlow(isAr));
            LinearLayout.LayoutParams pairLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            pairLp.topMargin = WgTheme.dp(this, 8);
            hybridCard.addView(pairBtn, pairLp);
        }

        if (!snap.listenerEnabled && !sovereignReady) {
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

    private void startBuiltinWirelessPairingFlow(boolean isAr) {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            mPendingPairingAfterNotifPermission = true;
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, REQ_POST_NOTIFICATIONS);
            return;
        }
        launchPairingServiceAndDevSettings(isAr);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_POST_NOTIFICATIONS && mPendingPairingAfterNotifPermission) {
            mPendingPairingAfterNotifPermission = false;
            boolean granted = grantResults != null
                    && grantResults.length > 0
                    && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            if (granted) {
                launchPairingServiceAndDevSettings(WireGuardManager.isArabic(this));
            } else {
                Toast.makeText(
                        this,
                        WgStrings.hybridPairingHintToast(WireGuardManager.isArabic(this)),
                        Toast.LENGTH_LONG
                ).show();
            }
        }
    }

    private void launchPairingServiceAndDevSettings(boolean isAr) {
        AdbPairingService.startForPairing(this);
        try {
            Intent devSettings = new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
            devSettings.putExtra(":settings:fragment_args_key", "toggle_adb_wireless");
            devSettings.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(devSettings);
        } catch (Throwable ignored) {
        }
        Toast.makeText(this, WgStrings.hybridPairingHintToast(isAr), Toast.LENGTH_LONG).show();
    }

    private Button createActionButton(String text, WgTheme theme, boolean secondary) {
        Button btn = new Button(this);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(secondary ? theme.textPrimary : theme.onAccent);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        btn.setLineSpacing(WgTheme.dp(this, 2), 1.06f);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            btn.setLetterSpacing(0f);
        }
        int minH = WgTheme.dp(this, 46);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(this, 14), WgTheme.dp(this, 10), WgTheme.dp(this, 14), WgTheme.dp(this, 10));
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
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            btn.setLetterSpacing(0f);
        }
        int minSize = WgTheme.dp(this, 44);
        btn.setMinHeight(minSize);
        btn.setMinimumHeight(minSize);
        btn.setMinWidth(minSize);
        btn.setMinimumWidth(minSize);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(this, 12), WgTheme.dp(this, 7), WgTheme.dp(this, 12), WgTheme.dp(this, 7));
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

    private static void styleSwitchColors(Switch sw, WgTheme theme) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_checked},
                    new int[]{}
            };
            int thumbOn = theme.isDark ? theme.activeDot : theme.accentPrimary;
            int thumbOff = theme.isDark ? theme.textSecondary : theme.surfaceCard;
            int trackOn = theme.isDark ? theme.activeBorder : theme.pendingBorder;
            int trackOff = theme.borderSubtle;
            sw.setThumbTintList(new ColorStateList(states, new int[]{thumbOn, thumbOff}));
            sw.setTrackTintList(new ColorStateList(states, new int[]{trackOn, trackOff}));
        }
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
