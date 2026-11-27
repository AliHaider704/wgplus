package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.telegram.wgplus.module.WgDialogModals.promptBackupPassphraseModal;
import static org.telegram.wgplus.module.WgDialogModals.renderTelemetryBox;
import static org.telegram.wgplus.module.WgDialogModals.showDeleteConfirmDialog;
import static org.telegram.wgplus.module.WgDialogWidgets.applyProseTextStyle;
import static org.telegram.wgplus.module.WgDialogWidgets.createCardMarginParams;
import static org.telegram.wgplus.module.WgDialogWidgets.createChipButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createDangerChipButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createDisconnectButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createDivider;
import static org.telegram.wgplus.module.WgDialogWidgets.createPrimaryAccentButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createSecondaryButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createSwitchRow;
import static org.telegram.wgplus.module.WgDialogWidgets.setMarginEndCompat;
import static org.telegram.wgplus.module.WgDialogWidgets.setMarginStartCompat;
import static org.telegram.wgplus.module.WgDialogWidgets.shouldUseSplitColumns;
import static org.telegram.wgplus.module.WgDialogWidgets.unwrapActivity;

/**
 * Icon-free, sticker-free bilingual WireGuard & AmneziaWG control dialog using progressive disclosure.
 */
public final class WireGuardDialog {

    public static final int REQ_IMPORT_CONF_FILE = 0x5747;
    public static final int REQ_IMPORT_QR_IMAGE = 0x5748;

    public interface ConfFileSelectedCallback {
        void onConfContentRead(String fileNameHint, String confText);
    }

    private static volatile ConfFileSelectedCallback sPendingFileCallback = null;

    private WireGuardDialog() {
    }

    enum VerifyUiState {
        IDLE,
        LOADING,
        SUCCESS,
        ERROR
    }

    static final class DialogSessionState {
        WireGuardManager.TunnelConfig draft;
        boolean networkOptionsExpanded = false;
        boolean configExpanded = false;
        boolean advancedExpanded = false;
        boolean rawAwgFieldsExpanded = false;
        boolean showPrivateKey = false;
        boolean showPresharedKey = false;
        boolean connecting = false;
        boolean pingingAll = false;
        boolean discoveringMtu = false;
        boolean generatingWarp = false;
        String switchingTargetName = "";
        boolean scrollToEditorNextRender = false;
        long observedActiveNoHsAtMs = 0L;
        VerifyUiState verifyState = VerifyUiState.IDLE;
        WireGuardManager.TunnelVerifyResult verifyResult = null;
        Throwable lastVerifyError = null;
    }

    public static void onFilePickerActivityResult(final Context ctx, int resultCode, Intent data) {
        onPickerActivityResult(ctx, REQ_IMPORT_CONF_FILE, resultCode, data);
    }

    public static void onPickerActivityResult(final Context ctx, final int requestCode, int resultCode, Intent data) {
        final ConfFileSelectedCallback cb = sPendingFileCallback;
        sPendingFileCallback = null;
        if (ctx == null || resultCode != Activity.RESULT_OK || data == null) {
            return;
        }
        final Uri uri = data.getData();
        if (uri == null) {
            return;
        }
        final boolean isAr = WireGuardManager.isArabic(ctx);
        final Handler mainHandler = new Handler(Looper.getMainLooper());

        new Thread(() -> {
            try {
                final String displayName = queryUriDisplayName(ctx, uri);
                final String confContent;
                if (requestCode == REQ_IMPORT_QR_IMAGE) {
                    confContent = WgQrCodec.decodeFromImageUri(ctx, uri);
                } else {
                    try (InputStream in = ctx.getContentResolver().openInputStream(uri)) {
                        if (in == null) {
                            throw new WgStrings.WgException(WgStrings.ErrorCode.FILE_READ_FAILED);
                        }
                        StringBuilder sb = new StringBuilder();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                        String line;
                        int totalChars = 0;
                        while ((line = reader.readLine()) != null && totalChars < 131072) {
                            sb.append(line).append('\n');
                            totalChars += line.length();
                        }
                        confContent = sb.toString();
                    }
                }

                mainHandler.post(() -> {
                    if (cb != null) {
                        cb.onConfContentRead(displayName, confContent);
                    } else {
                        try {
                            WireGuardManager.TunnelConfig added = WireGuardManager.importConfAsProfile(
                                    ctx,
                                    confContent,
                                    displayName,
                                    WireGuardManager.isAutoConnectEnabled(ctx),
                                    WireGuardManager.isRouteCallsEnabled(ctx)
                            );
                            Toast.makeText(ctx, WgStrings.toastImportedNamedProfile(isAr, added.name), Toast.LENGTH_SHORT).show();
                        } catch (Throwable err) {
                            Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                        }
                    }
                });
            } catch (final Throwable err) {
                mainHandler.post(() ->
                        Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show()
                );
            }
        }, "wg-plus-picker-decode").start();
    }

    private static String queryUriDisplayName(Context ctx, Uri uri) {
        try (Cursor cursor = ctx.getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    String name = cursor.getString(idx);
                    if (name != null) {
                        return name.trim();
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        String lastSeg = uri.getLastPathSegment();
        return lastSeg != null ? lastSeg.trim() : "";
    }

    public static void show(Context activityContext, ClassLoader telegramClassLoader) {
        show(activityContext, telegramClassLoader, XposedInit.getModulePath(), null);
    }

    public static void show(Context activityContext, ClassLoader telegramClassLoader, String moduleApkPath) {
        show(activityContext, telegramClassLoader, moduleApkPath, null);
    }

    public static void show(
            final Context activityContext,
            final ClassLoader telegramClassLoader,
            final String moduleApkPath,
            final Runnable onUiPreferenceChanged
    ) {
        if (activityContext == null) {
            return;
        }

        final Handler mainHandler = new Handler(Looper.getMainLooper());
        final DialogSessionState state = new DialogSessionState();
        state.draft = WireGuardManager.loadConfig(activityContext);
        state.configExpanded = false;
        state.advancedExpanded = state.draft.hasAwgConfigured();

        final FrameLayout dialogHost = new FrameLayout(activityContext);

        final AlertDialog dialog = new AlertDialog.Builder(activityContext)
                .setView(dialogHost)
                .setCancelable(true)
                .create();

        final Runnable[] statsTickerRef = new Runnable[1];
        final Runnable[] latestStatsRefreshRef = new Runnable[1];

        final Runnable[] renderRef = new Runnable[1];
        renderRef[0] = () -> {
            boolean isAr = WireGuardManager.isArabic(activityContext);
            boolean isDark = WireGuardManager.isDarkTheme(activityContext);
            WgTheme theme = WgTheme.of(isDark);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                dialogHost.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
            }
            dialogHost.setBackground(WgTheme.cardBackground(activityContext, theme.surfaceBase, theme.borderSubtle, 16f));
            dialogHost.removeAllViews();

            View content = buildDialogContent(
                    activityContext,
                    telegramClassLoader,
                    moduleApkPath,
                    mainHandler,
                    dialog,
                    state,
                    isAr,
                    theme,
                    latestStatsRefreshRef,
                    () -> {
                        if (onUiPreferenceChanged != null) {
                            onUiPreferenceChanged.run();
                        }
                        if (dialog.isShowing()) {
                            renderRef[0].run();
                        }
                    }
            );
            dialogHost.addView(content, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));
        };

        renderRef[0].run();

        new Thread(() -> {
            boolean pulled = WireGuardManager.syncPullSharedStateFromProvider(activityContext, true);
            mainHandler.post(() -> {
                if (dialog.isShowing()) {
                    if (pulled) {
                        state.draft = WireGuardManager.loadConfig(activityContext);
                        renderRef[0].run();
                    }
                    TelemetryConsentDialog.maybeShowFirstRun(activityContext, moduleApkPath, renderRef[0]);
                }
            });
        }, "wg-plus-dialog-sync").start();

        statsTickerRef[0] = () -> {
            if (!dialog.isShowing()) {
                return;
            }
            if (latestStatsRefreshRef[0] != null) {
                latestStatsRefreshRef[0].run();
            }
            mainHandler.postDelayed(statsTickerRef[0], 2000L);
        };

        dialog.setOnDismissListener(d -> {
            TelemetryConsentDialog.dismissActiveIfShowing();
            mainHandler.removeCallbacksAndMessages(null);
            if (onUiPreferenceChanged != null) {
                onUiPreferenceChanged.run();
            }
        });

        dialog.show();
        UpdateGate.checkInModule(activityContext, dialog);
        mainHandler.postDelayed(statsTickerRef[0], 2000L);

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            dialog.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                    | WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM);
            dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);

            DisplayMetrics dm = activityContext.getResources().getDisplayMetrics();
            int targetWidth = Math.min(dm.widthPixels - WgTheme.dp(activityContext, 24), WgTheme.dp(activityContext, 480));
            if (targetWidth > 0) {
                dialog.getWindow().setLayout(targetWidth, ViewGroup.LayoutParams.WRAP_CONTENT);
            }
        }
    }

    private static View buildDialogContent(
            final Context ctx,
            final ClassLoader telegramClassLoader,
            final String moduleApkPath,
            final Handler mainHandler,
            final AlertDialog dialog,
            final DialogSessionState state,
            final boolean isAr,
            final WgTheme theme,
            final Runnable[] latestStatsRefreshRef,
            final Runnable rebuildUi
    ) {
        LinearLayout root = new LinearLayout(ctx);
        root.setOrientation(LinearLayout.VERTICAL);

        int padH = WgTheme.dp(ctx, 16);

        // 1. Clean Minimal Top Bar (Title on start, Theme + Language text buttons on end; zero icons/stickers)
        LinearLayout header = new LinearLayout(ctx);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(padH, WgTheme.dp(ctx, 12), padH, WgTheme.dp(ctx, 10));

        TextView titleView = new TextView(ctx);
        applyProseTextStyle(titleView, isAr, theme.textPrimary, 16.5f, true);
        titleView.setText(WgStrings.appTitle(isAr));
        header.addView(titleView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button themeBtn = createChipButton(ctx, WgStrings.themeToggleLabel(isAr, theme.isDark), theme, false);
        LinearLayout.LayoutParams themeBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        setMarginStartCompat(themeBtnLp, WgTheme.dp(ctx, 6), isAr);
        header.addView(themeBtn, themeBtnLp);

        Button langBtn = createChipButton(ctx, WgStrings.langToggleLabel(isAr), theme, false);
        LinearLayout.LayoutParams langBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        setMarginStartCompat(langBtnLp, WgTheme.dp(ctx, 6), isAr);
        header.addView(langBtn, langBtnLp);

        root.addView(header, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        root.addView(createDivider(ctx, theme));

        // 2. Scrollable Main Body
        final ScrollView scrollView = new ScrollView(ctx);
        scrollView.setFillViewport(true);

        LinearLayout body = new LinearLayout(ctx);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(padH, WgTheme.dp(ctx, 14), padH, WgTheme.dp(ctx, 14));
        scrollView.addView(body, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        root.addView(scrollView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
        ));

        // 2A. Focal Point Card: Status, Live UAPI Traffic, Connect/Disconnect & Route Verification
        final LinearLayout statusCard = new LinearLayout(ctx);
        statusCard.setOrientation(LinearLayout.VERTICAL);
        statusCard.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 12f));
        int cardPad = WgTheme.dp(ctx, 14);
        statusCard.setPadding(cardPad, WgTheme.dp(ctx, 13), cardPad, WgTheme.dp(ctx, 13));
        body.addView(statusCard, createCardMarginParams(ctx, 10));

        LinearLayout statusHeaderRow = new LinearLayout(ctx);
        statusHeaderRow.setOrientation(LinearLayout.HORIZONTAL);
        statusHeaderRow.setGravity(Gravity.CENTER_VERTICAL);

        final View statusDot = new View(ctx);
        int dotPx = WgTheme.dp(ctx, 8);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotPx, dotPx);
        setMarginEndCompat(dotLp, WgTheme.dp(ctx, 9), isAr);
        statusHeaderRow.addView(statusDot, dotLp);

        final TextView statusHeadline = new TextView(ctx);
        statusHeadline.setContentDescription("wgplus_dlg_status_headline");
        applyProseTextStyle(statusHeadline, isAr, theme.textPrimary, 14.5f, true);
        statusHeaderRow.addView(statusHeadline, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        statusCard.addView(statusHeaderRow);

        final TextView statusSubline = new TextView(ctx);
        applyProseTextStyle(statusSubline, isAr, theme.textSecondary, 12.5f, false);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        subLp.topMargin = WgTheme.dp(ctx, 5);
        statusCard.addView(statusSubline, subLp);

        final boolean hasConfiguredAtRender = WireGuardManager.hasAnyConfiguredProfile(ctx);

        LinearLayout actionRow = new LinearLayout(ctx);
        actionRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams actionRowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        actionRowLp.topMargin = WgTheme.dp(ctx, 12);

        // Single accentPrimary CTA rule: promote 1-Tap Free WARP when no configured profile exists;
        // otherwise Connect holds the single accentPrimary role.
        final Button connectBtn = hasConfiguredAtRender
                ? createPrimaryAccentButton(ctx, WgStrings.connectPrimaryBtn(isAr), theme)
                : createSecondaryButton(ctx, WgStrings.connectPrimaryBtn(isAr), theme);
        connectBtn.setContentDescription("wgplus_dlg_btn_connect");
        final Button disconnectBtn = createDisconnectButton(ctx, WgStrings.disconnectBtn(isAr), theme);
        disconnectBtn.setContentDescription("wgplus_dlg_btn_disconnect");

        final LinearLayout.LayoutParams connLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(connLp, 0, isAr);
        final LinearLayout.LayoutParams discLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        disconnectBtn.setVisibility(View.GONE);

        actionRow.addView(connectBtn, connLp);
        actionRow.addView(disconnectBtn, discLp);
        statusCard.addView(actionRow, actionRowLp);

        final Button quickWarpBtn = hasConfiguredAtRender
                ? createSecondaryButton(ctx, WgStrings.quickWarpBtn(isAr, state.generatingWarp), theme)
                : createPrimaryAccentButton(ctx, WgStrings.quickWarpBtn(isAr, state.generatingWarp), theme);
        quickWarpBtn.setContentDescription("wgplus_dlg_btn_quick_warp");
        LinearLayout.LayoutParams quickWarpLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        quickWarpLp.topMargin = WgTheme.dp(ctx, 8);
        statusCard.addView(quickWarpBtn, quickWarpLp);

        final LinearLayout recoveryBox = new LinearLayout(ctx);
        recoveryBox.setOrientation(LinearLayout.VERTICAL);
        recoveryBox.setBackground(WgTheme.cardBackground(ctx, theme.pendingBg, theme.pendingBorder, 8f));
        int recPad = WgTheme.dp(ctx, 10);
        recoveryBox.setPadding(recPad, recPad, recPad, recPad);
        recoveryBox.setVisibility(View.GONE);
        LinearLayout.LayoutParams recoveryBoxLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        recoveryBoxLp.topMargin = WgTheme.dp(ctx, 8);

        TextView recoveryHint = new TextView(ctx);
        applyProseTextStyle(recoveryHint, isAr, theme.pendingText, 12.2f, false);
        recoveryHint.setText(WgStrings.statusStalledHint(isAr));
        recoveryBox.addView(recoveryHint, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        final Button recoveryAwgBtn = createSecondaryButton(ctx, WgStrings.recoverAwgBtn(isAr), theme);
        recoveryAwgBtn.setContentDescription("wgplus_dlg_btn_recover_awg");
        LinearLayout.LayoutParams recAwgLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        recAwgLp.topMargin = WgTheme.dp(ctx, 8);
        recoveryBox.addView(recoveryAwgBtn, recAwgLp);

        final Button recoveryWarpBtn = createSecondaryButton(ctx, WgStrings.recoverWarpBtn(isAr), theme);
        recoveryWarpBtn.setContentDescription("wgplus_dlg_btn_recover_warp");
        LinearLayout.LayoutParams recWarpLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        recWarpLp.topMargin = WgTheme.dp(ctx, 6);
        recoveryBox.addView(recoveryWarpBtn, recWarpLp);
        statusCard.addView(recoveryBox, recoveryBoxLp);

        final Button verifyBtn = createSecondaryButton(ctx, WgStrings.verifyBtnLabel(isAr), theme);
        verifyBtn.setContentDescription("wgplus_dlg_btn_verify");
        LinearLayout.LayoutParams verifyLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        verifyLp.topMargin = WgTheme.dp(ctx, 8);
        statusCard.addView(verifyBtn, verifyLp);

        final LinearLayout telemetryBox = new LinearLayout(ctx);
        telemetryBox.setOrientation(LinearLayout.VERTICAL);
        telemetryBox.setPadding(WgTheme.dp(ctx, 12), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 12), WgTheme.dp(ctx, 10));
        LinearLayout.LayoutParams telemetryLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        telemetryLp.topMargin = WgTheme.dp(ctx, 8);
        statusCard.addView(telemetryBox, telemetryLp);

        // 2B. Routing, Protection & Battery Preferences Card
        LinearLayout optionsCard = new LinearLayout(ctx);
        optionsCard.setOrientation(LinearLayout.VERTICAL);
        optionsCard.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 12f));
        optionsCard.setPadding(cardPad, WgTheme.dp(ctx, 6), cardPad, WgTheme.dp(ctx, 10));
        body.addView(optionsCard, createCardMarginParams(ctx, 10));

        final Switch routeCallsSwitch = new Switch(ctx);
        routeCallsSwitch.setChecked(state.draft.routeCalls);
        optionsCard.addView(createSwitchRow(ctx, WgStrings.routeCallsLabel(isAr), routeCallsSwitch, isAr, theme));
        optionsCard.addView(createDivider(ctx, theme));

        final Switch autoStartSwitch = new Switch(ctx);
        autoStartSwitch.setChecked(state.draft.enabled);
        optionsCard.addView(createSwitchRow(ctx, WgStrings.autoStartLabel(isAr), autoStartSwitch, isAr, theme));
        optionsCard.addView(createDivider(ctx, theme));

        final Switch killSwitchToggle = new Switch(ctx);
        killSwitchToggle.setChecked(WireGuardManager.isKillSwitchEnabled(ctx));
        optionsCard.addView(createSwitchRow(ctx, WgStrings.killSwitchLabel(isAr), killSwitchToggle, isAr, theme));
        optionsCard.addView(createDivider(ctx, theme));

        final Switch autoFailoverToggle = new Switch(ctx);
        autoFailoverToggle.setChecked(WireGuardManager.isAutoFailoverEnabled(ctx));
        optionsCard.addView(createSwitchRow(ctx, WgStrings.autoFailoverLabel(isAr), autoFailoverToggle, isAr, theme));

        Button netBatteryToggleBtn = createSecondaryButton(
                ctx,
                WgStrings.networkBatteryToggleBtn(isAr, state.networkOptionsExpanded),
                theme
        );
        LinearLayout.LayoutParams nbBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        nbBtnLp.topMargin = WgTheme.dp(ctx, 6);
        optionsCard.addView(netBatteryToggleBtn, nbBtnLp);

        final Switch dohToggle = new Switch(ctx);
        dohToggle.setChecked(WireGuardManager.isDohEnabled(ctx));
        final Switch smartKeepaliveToggle = new Switch(ctx);
        smartKeepaliveToggle.setChecked(WireGuardManager.isSmartKeepaliveEnabled(ctx));

        if (state.networkOptionsExpanded) {
            LinearLayout nbBox = new LinearLayout(ctx);
            nbBox.setOrientation(LinearLayout.VERTICAL);
            LinearLayout.LayoutParams nbBoxLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            nbBoxLp.topMargin = WgTheme.dp(ctx, 6);
            nbBox.addView(createDivider(ctx, theme));
            nbBox.addView(createSwitchRow(ctx, WgStrings.encryptedDohLabel(isAr), dohToggle, isAr, theme));
            nbBox.addView(createDivider(ctx, theme));
            nbBox.addView(createSwitchRow(ctx, WgStrings.smartKeepaliveLabel(isAr), smartKeepaliveToggle, isAr, theme));
            Button cleanCacheDlgBtn = createSecondaryButton(ctx, WgStrings.cleanCacheBtn(isAr, false), theme);
            cleanCacheDlgBtn.setContentDescription("wgplus_dlg_btn_clean_cache");
            cleanCacheDlgBtn.setOnClickListener(v -> {
                cleanCacheDlgBtn.setEnabled(false);
                cleanCacheDlgBtn.setText(WgStrings.cleanCacheBtn(isAr, true));
                new Thread(() -> {
                    ModuleHygieneManager.HygieneReport report = ModuleHygieneManager.cleanCachesSafely(ctx, true);
                    mainHandler.post(() -> {
                        Toast.makeText(
                                ctx,
                                WgStrings.toastCacheCleaned(isAr, report.freedBytes, report.filesDeleted),
                                Toast.LENGTH_SHORT
                        ).show();
                        rebuildUi.run();
                    });
                }, "wg-plus-dlg-hygiene").start();
            });
            LinearLayout.LayoutParams ccDlgLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            ccDlgLp.topMargin = WgTheme.dp(ctx, 8);
            nbBox.addView(cleanCacheDlgBtn, ccDlgLp);
            optionsCard.addView(nbBox, nbBoxLp);
        }

        // Pre-create editor inputs (including AmneziaWG fields) so captureDraftInputs works from any action
        final WgDialogWidgets.EditorForm editorForm = new WgDialogWidgets.EditorForm(ctx, state, isAr, theme);
        final Runnable captureDraftInputs = () -> state.draft = editorForm.captureInto(
                state.draft,
                autoStartSwitch.isChecked(),
                routeCallsSwitch.isChecked()
        );

        // 2C. Saved Profiles, Multi-Server Ping, QR Image Import & Backup Card
        final List<WireGuardManager.TunnelConfig> allProfiles = WireGuardManager.loadProfiles(ctx);
        final boolean isRunningAtRender = WireGuardManager.isTunnelRunning(ctx, moduleApkPath);
        final String connectedIdAtRender = WireGuardManager.getConnectedProfileId(ctx, moduleApkPath);

        LinearLayout profilesCard = new LinearLayout(ctx);
        profilesCard.setOrientation(LinearLayout.VERTICAL);
        profilesCard.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 12f));
        profilesCard.setPadding(cardPad, WgTheme.dp(ctx, 12), cardPad, WgTheme.dp(ctx, 12));
        body.addView(profilesCard, createCardMarginParams(ctx, 10));

        LinearLayout profilesHeaderRow = new LinearLayout(ctx);
        profilesHeaderRow.setOrientation(LinearLayout.HORIZONTAL);
        profilesHeaderRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView profilesHeading = new TextView(ctx);
        applyProseTextStyle(profilesHeading, isAr, theme.textPrimary, 13.5f, true);
        profilesHeading.setText(WgStrings.profilesSectionCountLabel(isAr, allProfiles.size()));
        profilesHeaderRow.addView(profilesHeading, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        final Button pingFastestBtn = createChipButton(
                ctx,
                WgStrings.pingFastestBtn(isAr, state.pingingAll),
                theme,
                false
        );
        pingFastestBtn.setEnabled(!state.pingingAll && !state.connecting);
        LinearLayout.LayoutParams pfBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        setMarginStartCompat(pfBtnLp, WgTheme.dp(ctx, 8), isAr);
        profilesHeaderRow.addView(pingFastestBtn, pfBtnLp);
        profilesCard.addView(profilesHeaderRow);

        TextView profilesHint = new TextView(ctx);
        applyProseTextStyle(profilesHint, isAr, theme.textSecondary, 12f, false);
        profilesHint.setText(WgStrings.profileTapHint(isAr));
        LinearLayout.LayoutParams pHintLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        pHintLp.topMargin = WgTheme.dp(ctx, 4);
        profilesCard.addView(profilesHint, pHintLp);

        // Row 1 Toolbar: New / Import file / Paste
        LinearLayout profileToolbar1 = new LinearLayout(ctx);
        profileToolbar1.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams toolbarLp1 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        toolbarLp1.topMargin = WgTheme.dp(ctx, 10);

        Button newProfileBtn = createChipButton(ctx, WgStrings.newProfileBtn(isAr), theme, false);
        Button importFileBtn = createChipButton(ctx, WgStrings.importFileBtn(isAr), theme, false);
        Button pasteClipBtn = createChipButton(ctx, WgStrings.importClipboardBtn(isAr), theme, false);

        LinearLayout.LayoutParams tb1a = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(tb1a, WgTheme.dp(ctx, 6), isAr);
        LinearLayout.LayoutParams tb1b = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.05f);
        setMarginEndCompat(tb1b, WgTheme.dp(ctx, 6), isAr);
        LinearLayout.LayoutParams tb1c = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.9f);

        profileToolbar1.addView(newProfileBtn, tb1a);
        profileToolbar1.addView(importFileBtn, tb1b);
        profileToolbar1.addView(pasteClipBtn, tb1c);
        profilesCard.addView(profileToolbar1, toolbarLp1);

        // Row 2 Toolbar: QR image / Backup all / Restore
        LinearLayout profileToolbar2 = new LinearLayout(ctx);
        profileToolbar2.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams toolbarLp2 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        toolbarLp2.topMargin = WgTheme.dp(ctx, 6);
        toolbarLp2.bottomMargin = WgTheme.dp(ctx, 10);

        Button importQrBtn = createChipButton(ctx, WgStrings.importQrImageBtn(isAr), theme, false);
        Button backupAllBtn = createChipButton(ctx, WgStrings.exportBackupBtn(isAr), theme, false);
        Button restoreAllBtn = createChipButton(ctx, WgStrings.restoreBackupBtn(isAr), theme, false);

        LinearLayout.LayoutParams tb2a = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(tb2a, WgTheme.dp(ctx, 6), isAr);
        LinearLayout.LayoutParams tb2b = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.05f);
        setMarginEndCompat(tb2b, WgTheme.dp(ctx, 6), isAr);
        LinearLayout.LayoutParams tb2c = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.9f);

        profileToolbar2.addView(importQrBtn, tb2a);
        profileToolbar2.addView(backupAllBtn, tb2b);
        profileToolbar2.addView(restoreAllBtn, tb2c);
        profilesCard.addView(profileToolbar2, toolbarLp2);

        final Button newWarpBtn = createSecondaryButton(ctx, WgStrings.newWarpChipBtn(isAr), theme);
        newWarpBtn.setEnabled(!state.generatingWarp && !state.connecting);
        LinearLayout.LayoutParams nwBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        nwBtnLp.bottomMargin = WgTheme.dp(ctx, 8);
        profilesCard.addView(newWarpBtn, nwBtnLp);

        final LinearLayout profilesListContainer = new LinearLayout(ctx);
        profilesListContainer.setOrientation(LinearLayout.VERTICAL);
        profilesCard.addView(profilesListContainer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        // 2D. Progressive-Disclosure Server Configuration, Auto-MTU, AmneziaWG & QR Export Section
        final LinearLayout configCard = new LinearLayout(ctx);
        configCard.setOrientation(LinearLayout.VERTICAL);
        configCard.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 12f));
        configCard.setPadding(cardPad, WgTheme.dp(ctx, 10), cardPad, WgTheme.dp(ctx, 10));
        body.addView(configCard, createCardMarginParams(ctx, 4));

        Button toggleConfigBtn = createSecondaryButton(
                ctx,
                WgStrings.configSummaryEditRow(isAr, state.configExpanded, state.draft.summaryLabel()),
                theme
        );
        configCard.addView(toggleConfigBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        if (state.configExpanded) {
            editorForm.appendExpandedView(
                    ctx,
                    telegramClassLoader,
                    moduleApkPath,
                    mainHandler,
                    configCard,
                    state,
                    isAr,
                    theme,
                    captureDraftInputs,
                    rebuildUi
            );
        }

        // 3. Clean Footer with Close button
        root.addView(createDivider(ctx, theme));

        LinearLayout footer = new LinearLayout(ctx);
        footer.setOrientation(LinearLayout.VERTICAL);
        footer.setBackgroundColor(theme.surfaceFooter);
        footer.setPadding(padH, WgTheme.dp(ctx, 10), padH, WgTheme.dp(ctx, 10));

        Button channelBtn = createSecondaryButton(ctx, WgStrings.officialChannelBtn(isAr), theme);
        channelBtn.setContentDescription("wgplus_dlg_channel");
        channelBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            WireGuardManager.openOfficialChannel(ctx, dialog::dismiss);
        });
        LinearLayout.LayoutParams chBtnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        chBtnLp.bottomMargin = WgTheme.dp(ctx, 8);
        footer.addView(channelBtn, chBtnLp);

        LinearLayout footerBtnRow = new LinearLayout(ctx);
        footerBtnRow.setOrientation(LinearLayout.HORIZONTAL);

        Button diagBtn = createSecondaryButton(ctx, WgStrings.diagnosticsBtn(isAr), theme);
        diagBtn.setOnClickListener(v -> showDiagnosticsModal(ctx, moduleApkPath, isAr, theme));
        LinearLayout.LayoutParams dBtnLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(dBtnLp, WgTheme.dp(ctx, 8), isAr);

        Button closeBtn = createSecondaryButton(ctx, WgStrings.closeBtn(isAr), theme);
        closeBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            dialog.dismiss();
        });
        footerBtnRow.addView(diagBtn, dBtnLp);
        footerBtnRow.addView(closeBtn, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        footer.addView(footerBtnRow, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        String dlgVer = "1.9.0";
        try {
            dlgVer = ctx.getPackageManager().getPackageInfo("org.telegram.wgplus.module", 0).versionName;
        } catch (Throwable ignored) {
        }
        TextView dlgVerView = new TextView(ctx);
        dlgVerView.setText("WireGuard Plus \u00B7 v" + dlgVer);
        dlgVerView.setTextColor(theme.textSecondary);
        dlgVerView.setTextSize(11f);
        dlgVerView.setTypeface(Typeface.MONOSPACE);
        dlgVerView.setAlpha(0.65f);
        dlgVerView.setGravity(Gravity.CENTER);
        dlgVerView.setPadding(0, WgTheme.dp(ctx, 8), 0, 0);
        footer.addView(dlgVerView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        root.addView(footer);

        // Live status + UAPI telemetry renderer
        final Runnable refreshStatusVisuals = () -> {
            boolean active = WireGuardManager.isTunnelRunning(ctx, moduleApkPath);
            boolean sharedObserved = active && WireGuardManager.isSharedTunnelObserved(ctx, moduleApkPath);
            boolean guarded = !active && WireGuardManager.isKillSwitchGuardActiveNow(ctx, moduleApkPath);
            int port = active ? WireGuardManager.getActivePort(ctx, moduleApkPath) : 0;
            WireGuardManager.TunnelConfig connectedCfg = active
                    ? WireGuardManager.getConnectedProfile(ctx, moduleApkPath)
                    : null;
            String connectedName = (connectedCfg != null && connectedCfg.name != null)
                    ? connectedCfg.name
                    : state.draft.name;
            boolean viewingDifferentFromConnected = active
                    && connectedCfg != null
                    && !connectedCfg.id.equals(state.draft.id);

            boolean showDisconnect = false;

            if (state.generatingWarp) {
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.pendingDot));
                statusHeadline.setText(WgStrings.statusGeneratingWarp(isAr));
                statusHeadline.setTextColor(theme.pendingText);
                statusSubline.setText(WgStrings.verifyLoadingBody(isAr));
                recoveryBox.setVisibility(View.GONE);
                connectBtn.setEnabled(false);
                quickWarpBtn.setEnabled(false);
                quickWarpBtn.setText(WgStrings.quickWarpBtn(isAr, true));
            } else if (state.connecting) {
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.pendingDot));
                statusHeadline.setText(!state.switchingTargetName.isEmpty()
                        ? WgStrings.statusSwitchingTo(isAr, state.switchingTargetName)
                        : WgStrings.statusConnecting(isAr));
                statusHeadline.setTextColor(theme.pendingText);
                statusSubline.setText(WgStrings.verifyLoadingBody(isAr));
                recoveryBox.setVisibility(View.GONE);
                connectBtn.setEnabled(false);
                connectBtn.setText(WgStrings.connectingBtn(isAr));
                quickWarpBtn.setEnabled(false);
                quickWarpBtn.setText(WgStrings.quickWarpBtn(isAr, false));
            } else if (active && port > 0) {
                showDisconnect = true;
                WireGuardManager.TunnelStats stats = sharedObserved
                        ? new WireGuardManager.TunnelStats()
                        : WireGuardManager.getLiveStats(ctx, moduleApkPath);
                long hsSec = sharedObserved
                        ? WireGuardManager.getSharedTunnelLastHandshakeSec(ctx)
                        : stats.lastHandshakeSec;
                stats.lastHandshakeSec = hsSec;
                long nowEpoch = System.currentTimeMillis() / 1000L;
                boolean recentHs = hsSec > 0L
                        && Math.max(0L, nowEpoch - hsSec) < WireGuardManager.HANDSHAKE_HEALTHY_WINDOW_SEC;
                final Runnable safeUiRefresh = () -> {
                    if (dialog.isShowing() && latestStatsRefreshRef[0] != null) {
                        latestStatsRefreshRef[0].run();
                    }
                };
                if (recentHs) {
                    state.observedActiveNoHsAtMs = 0L;
                    statusDot.setBackground(WgTheme.statusDot(ctx, theme.activeDot));
                    statusHeadline.setText(WgStrings.statusActiveWithProfile(isAr, connectedName, port));
                    statusHeadline.setTextColor(theme.activeText);
                    statusSubline.setText(sharedObserved
                            ? WgStrings.sharedTunnelActiveSubline(isAr, port)
                            : WgStrings.liveStatsLine(isAr, stats.rxBytes, stats.txBytes, stats.lastHandshakeSec));
                    recoveryBox.setVisibility(View.GONE);
                    if (Math.max(0L, nowEpoch - hsSec) >= WireGuardManager.PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC) {
                        WireGuardManager.nudgeTunnelHandshakeAsync(ctx, moduleApkPath, safeUiRefresh);
                    }
                } else {
                    if (state.observedActiveNoHsAtMs <= 0L) {
                        state.observedActiveNoHsAtMs = SystemClock.elapsedRealtime();
                    }
                    WireGuardManager.nudgeTunnelHandshakeAsync(ctx, moduleApkPath, safeUiRefresh);
                    long elapsedMs = Math.max(0L, SystemClock.elapsedRealtime() - state.observedActiveNoHsAtMs);
                    boolean stalled = elapsedMs >= 10_000L;

                    statusDot.setBackground(WgTheme.statusDot(ctx, theme.pendingDot));
                    statusHeadline.setText(stalled
                            ? WgStrings.statusStalledWithProfile(isAr, connectedName)
                            : WgStrings.statusAwaitingHandshakeWithProfile(isAr, connectedName));
                    statusHeadline.setTextColor(theme.pendingText);
                    statusSubline.setText(stalled
                            ? WgStrings.statusStalledHint(isAr)
                            : (sharedObserved
                            ? WgStrings.sharedTunnelActiveSubline(isAr, port)
                            : WgStrings.liveStatsLine(isAr, stats.rxBytes, stats.txBytes, stats.lastHandshakeSec)));
                    recoveryBox.setVisibility(stalled ? View.VISIBLE : View.GONE);
                }
                connectBtn.setEnabled(true);
                connectBtn.setText(viewingDifferentFromConnected
                        ? WgStrings.switchToProfileBtn(isAr)
                        : WgStrings.reconnectPrimaryBtn(isAr));
                quickWarpBtn.setEnabled(true);
                quickWarpBtn.setText(WgStrings.quickWarpBtn(isAr, false));
            } else if (guarded) {
                state.observedActiveNoHsAtMs = 0L;
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.pendingDot));
                statusHeadline.setText(WgStrings.statusKillSwitchGuarded(isAr, state.draft.name));
                statusHeadline.setTextColor(theme.pendingText);
                statusSubline.setText(WgStrings.statusKillSwitchSubline(isAr));
                recoveryBox.setVisibility(View.GONE);
                connectBtn.setEnabled(true);
                connectBtn.setText(WgStrings.connectPrimaryBtn(isAr));
                quickWarpBtn.setEnabled(true);
                quickWarpBtn.setText(WgStrings.quickWarpBtn(isAr, false));
            } else {
                state.observedActiveNoHsAtMs = 0L;
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.stoppedDot));
                statusHeadline.setText(WgStrings.statusStoppedWithProfile(isAr, state.draft.name));
                statusHeadline.setTextColor(theme.stoppedText);
                statusSubline.setText(WgStrings.statusEmptyHint(isAr));
                recoveryBox.setVisibility(View.GONE);
                connectBtn.setEnabled(true);
                connectBtn.setText(WgStrings.connectPrimaryBtn(isAr));
                quickWarpBtn.setEnabled(true);
                quickWarpBtn.setText(WgStrings.quickWarpBtn(isAr, false));
            }

            if (showDisconnect) {
                disconnectBtn.setVisibility(View.VISIBLE);
                disconnectBtn.setEnabled(true);
                setMarginEndCompat(connLp, WgTheme.dp(ctx, 8), isAr);
            } else {
                disconnectBtn.setVisibility(View.GONE);
                disconnectBtn.setEnabled(false);
                setMarginEndCompat(connLp, 0, isAr);
            }
            connectBtn.setLayoutParams(connLp);
            disconnectBtn.setLayoutParams(discLp);

            renderTelemetryBox(ctx, telemetryBox, verifyBtn, state, routeCallsSwitch.isChecked(), isAr, theme);
        };

        final Runnable triggerVerification = () -> {
            state.verifyState = VerifyUiState.LOADING;
            state.verifyResult = null;
            state.lastVerifyError = null;
            refreshStatusVisuals.run();
            scrollView.post(() -> scrollView.smoothScrollTo(0, 0));

            new Thread(() -> {
                try {
                    final WireGuardManager.TunnelVerifyResult vr = WireGuardManager.verifyTunnel(ctx, moduleApkPath);
                    mainHandler.post(() -> {
                        state.verifyState = VerifyUiState.SUCCESS;
                        state.verifyResult = vr;
                        state.lastVerifyError = null;
                        refreshStatusVisuals.run();
                    });
                } catch (final Throwable err) {
                    mainHandler.post(() -> {
                        state.verifyState = VerifyUiState.ERROR;
                        state.verifyResult = null;
                        state.lastVerifyError = err;
                        refreshStatusVisuals.run();
                    });
                }
            }, "wg-plus-verify").start();
        };

        final Runnable connectOrSwitchSelectedProfile = () -> {
            final boolean wasRunningBefore = WireGuardManager.isTunnelRunning(ctx, moduleApkPath);
            final String targetName = state.draft.name != null ? state.draft.name : "";

            state.connecting = true;
            state.switchingTargetName = wasRunningBefore ? targetName : "";
            refreshStatusVisuals.run();
            scrollView.post(() -> scrollView.smoothScrollTo(0, 0));

            new Thread(() -> {
                try {
                    final int port = WireGuardManager.startAndBind(ctx, moduleApkPath, telegramClassLoader);
                    mainHandler.post(() -> {
                        state.connecting = false;
                        state.switchingTargetName = "";
                        state.configExpanded = false;
                        Toast.makeText(
                                ctx,
                                wasRunningBefore
                                        ? WgStrings.toastSwitchedProfile(isAr, targetName, port)
                                        : WgStrings.toastConnected(isAr, port),
                                Toast.LENGTH_SHORT
                        ).show();
                        rebuildUi.run();
                        triggerVerification.run();
                        WireGuardManager.maybeInviteToOfficialChannel(ctx, isAr, dialog::dismiss);
                    });
                } catch (final Throwable err) {
                    mainHandler.post(() -> {
                        state.connecting = false;
                        state.switchingTargetName = "";
                        state.verifyState = VerifyUiState.ERROR;
                        state.lastVerifyError = err;
                        state.configExpanded = true;
                        rebuildUi.run();
                    });
                }
            }, "wg-plus-connect").start();
        };

        // Populate interactive vertical profile rows
        boolean compactRowActions = shouldUseSplitColumns(ctx);
        for (int i = 0; i < allProfiles.size(); i++) {
            final WireGuardManager.TunnelConfig item = allProfiles.get(i);
            final boolean isConnectedRow = isRunningAtRender && item.id.equals(connectedIdAtRender);
            final boolean isSelectedRow = item.id.equals(state.draft.id);
            final String displayLabel = WgStrings.localizeProfileName(item.name, isAr, i + 1);

            LinearLayout rowCard = new LinearLayout(ctx);
            rowCard.setOrientation(compactRowActions ? LinearLayout.HORIZONTAL : LinearLayout.VERTICAL);
            if (compactRowActions) {
                rowCard.setGravity(Gravity.CENTER_VERTICAL);
            }
            int rowFill = isConnectedRow ? theme.activeBg : theme.surfaceInput;
            int rowBorder = isConnectedRow
                    ? theme.activeBorder
                    : (isSelectedRow ? theme.accentPrimary : theme.borderSubtle);
            rowCard.setBackground(WgTheme.cardBackground(ctx, rowFill, rowBorder, 8f));
            int rPadH = WgTheme.dp(ctx, 10);
            int rPadV = WgTheme.dp(ctx, 8);
            rowCard.setPadding(rPadH, rPadV, rPadH, rPadV);

            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            if (i < allProfiles.size() - 1) {
                rowLp.bottomMargin = WgTheme.dp(ctx, 6);
            }

            LinearLayout infoArea = new LinearLayout(ctx);
            infoArea.setOrientation(LinearLayout.VERTICAL);
            infoArea.setClickable(true);
            infoArea.setFocusable(true);
            infoArea.setMinimumHeight(WgTheme.dp(ctx, 44));
            infoArea.setGravity(Gravity.CENTER_VERTICAL);
            infoArea.setPadding(WgTheme.dp(ctx, 4), WgTheme.dp(ctx, 2), WgTheme.dp(ctx, 4), WgTheme.dp(ctx, 2));
            infoArea.setBackground(WgTheme.interactiveBackground(
                    ctx,
                    Color.TRANSPARENT,
                    theme.surfaceSecondaryBtnPressed,
                    Color.TRANSPARENT,
                    theme.accentPrimary,
                    6f
            ));

            LinearLayout topLine = new LinearLayout(ctx);
            topLine.setOrientation(LinearLayout.HORIZONTAL);
            topLine.setGravity(Gravity.CENTER_VERTICAL);

            View pDot = new View(ctx);
            int pDotPx = WgTheme.dp(ctx, 8);
            int pDotColor = isConnectedRow
                    ? theme.activeDot
                    : (isSelectedRow ? theme.accentPrimary : theme.borderSubtle);
            pDot.setBackground(WgTheme.statusDot(ctx, pDotColor));
            LinearLayout.LayoutParams pDotLp = new LinearLayout.LayoutParams(pDotPx, pDotPx);
            setMarginEndCompat(pDotLp, WgTheme.dp(ctx, 8), isAr);
            topLine.addView(pDot, pDotLp);

            TextView pNameView = new TextView(ctx);
            applyProseTextStyle(
                    pNameView,
                    isAr,
                    isConnectedRow ? theme.activeText : theme.textPrimary,
                    13.5f,
                    true
            );
            pNameView.setSingleLine(true);
            pNameView.setEllipsize(TextUtils.TruncateAt.END);
            pNameView.setText(displayLabel);
            topLine.addView(pNameView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

            // Status / Ping / Obfuscation clean text indicator
            StringBuilder metaTag = new StringBuilder();
            Integer cachedPing = WireGuardManager.getCachedPingMs(item.id);
            if (cachedPing != null) {
                metaTag.append(WgStrings.profilePingTag(isAr, cachedPing));
            }
            if (item.hasAwgConfigured()) {
                if (metaTag.length() > 0) metaTag.append(" • ");
                metaTag.append(WgStrings.profileAwgTag(isAr));
            } else if (isConnectedRow) {
                if (metaTag.length() > 0) metaTag.append(" • ");
                metaTag.append(WgStrings.profileConnectedTag(isAr));
            } else if (isSelectedRow) {
                if (metaTag.length() > 0) metaTag.append(" • ");
                metaTag.append(WgStrings.profileSelectedTag(isAr));
            }

            if (metaTag.length() > 0) {
                TextView stateTag = new TextView(ctx);
                int tagColor = (cachedPing != null && cachedPing == -1)
                        ? theme.stoppedText
                        : (isConnectedRow ? theme.activeText : theme.textSecondary);
                applyProseTextStyle(stateTag, isAr, tagColor, 11.2f, true);
                stateTag.setText(metaTag.toString());
                LinearLayout.LayoutParams tagLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                setMarginStartCompat(tagLp, WgTheme.dp(ctx, 6), isAr);
                topLine.addView(stateTag, tagLp);
            }
            infoArea.addView(topLine);

            TextView pSubView = new TextView(ctx);
            String epTrim = item.endpoint == null ? "" : item.endpoint.trim();
            if (!epTrim.isEmpty()) {
                pSubView.setTextColor(theme.textSecondary);
                pSubView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
                pSubView.setTypeface(Typeface.MONOSPACE);
                pSubView.setGravity(isAr ? Gravity.RIGHT : Gravity.LEFT);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                    pSubView.setTextDirection(View.TEXT_DIRECTION_LTR);
                }
                pSubView.setText(WgStrings.ltr(epTrim));
            } else {
                applyProseTextStyle(pSubView, isAr, theme.textHint, 12f, false);
                pSubView.setText(WgStrings.profileEmptyEndpointHint(isAr));
            }
            pSubView.setSingleLine(true);
            pSubView.setEllipsize(TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams pSubLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            pSubLp.topMargin = WgTheme.dp(ctx, 2);
            infoArea.addView(pSubView, pSubLp);

            infoArea.setOnClickListener(v -> {
                if (state.connecting) {
                    return;
                }
                captureDraftInputs.run();
                WireGuardManager.saveConfig(ctx, state.draft);

                boolean wasAlreadySelected = item.id.equals(state.draft.id);
                state.draft = WireGuardManager.selectProfile(ctx, item.id);
                state.advancedExpanded = state.draft.hasAwgConfigured();

                if (!state.draft.hasPeerConfigured()) {
                    state.configExpanded = true;
                    state.scrollToEditorNextRender = true;
                    rebuildUi.run();
                    return;
                }

                boolean currentlyRunning = WireGuardManager.isTunnelRunning(ctx, moduleApkPath);
                String liveConnId = WireGuardManager.getConnectedProfileId(ctx, moduleApkPath);

                if (currentlyRunning && !item.id.equals(liveConnId)) {
                    connectOrSwitchSelectedProfile.run();
                } else if (!currentlyRunning && wasAlreadySelected) {
                    connectOrSwitchSelectedProfile.run();
                } else {
                    state.configExpanded = false;
                    state.verifyState = VerifyUiState.IDLE;
                    state.verifyResult = null;
                    state.lastVerifyError = null;
                    Toast.makeText(ctx, WgStrings.toastSelectedProfile(isAr, displayLabel), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                }
            });

            LinearLayout rowBtns = new LinearLayout(ctx);
            rowBtns.setOrientation(LinearLayout.HORIZONTAL);
            rowBtns.setGravity(Gravity.CENTER_VERTICAL);

            Button editRowBtn = createChipButton(ctx, WgStrings.editInlineBtn(isAr), theme, false);
            Button delRowBtn = createDangerChipButton(ctx, WgStrings.deleteInlineBtn(isAr), theme);

            editRowBtn.setOnClickListener(v -> {
                if (state.connecting) {
                    return;
                }
                captureDraftInputs.run();
                WireGuardManager.saveConfig(ctx, state.draft);
                state.draft = WireGuardManager.selectProfile(ctx, item.id);
                state.configExpanded = true;
                state.advancedExpanded = state.draft.hasAwgConfigured();
                state.scrollToEditorNextRender = true;
                rebuildUi.run();
            });

            delRowBtn.setOnClickListener(v -> {
                if (state.connecting) {
                    return;
                }
                showDeleteConfirmDialog(
                        ctx,
                        displayLabel,
                        isAr,
                        theme,
                        () -> {
                            if (!item.id.equals(state.draft.id)) {
                                captureDraftInputs.run();
                                WireGuardManager.saveConfig(ctx, state.draft);
                            }
                            boolean deletingLiveConnected = WireGuardManager.isTunnelRunning(ctx, moduleApkPath)
                                    && item.id.equals(WireGuardManager.getConnectedProfileId(ctx, moduleApkPath));
                            state.draft = WireGuardManager.deleteProfile(ctx, item.id);
                            state.configExpanded = !state.draft.hasPeerConfigured();
                            state.advancedExpanded = state.draft.hasAwgConfigured();
                            state.verifyState = VerifyUiState.IDLE;
                            state.verifyResult = null;
                            state.lastVerifyError = null;

                            if (deletingLiveConnected) {
                                new Thread(() -> {
                                    WireGuardManager.stopAndUnbind(ctx, moduleApkPath, telegramClassLoader);
                                    mainHandler.post(() -> {
                                        Toast.makeText(ctx, WgStrings.toastDeletedProfile(isAr), Toast.LENGTH_SHORT).show();
                                        rebuildUi.run();
                                    });
                                }, "wg-plus-del-stop").start();
                            } else {
                                Toast.makeText(ctx, WgStrings.toastDeletedProfile(isAr), Toast.LENGTH_SHORT).show();
                                rebuildUi.run();
                            }
                        }
                );
            });

            if (compactRowActions) {
                LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f
                );
                setMarginEndCompat(infoLp, WgTheme.dp(ctx, 8), isAr);
                rowCard.addView(infoArea, infoLp);

                LinearLayout.LayoutParams eBtnLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                setMarginEndCompat(eBtnLp, WgTheme.dp(ctx, 5), isAr);
                rowBtns.addView(editRowBtn, eBtnLp);
                rowBtns.addView(delRowBtn);
                rowCard.addView(rowBtns);
            } else {
                rowCard.addView(infoArea, new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                ));
                LinearLayout.LayoutParams rbWrapLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                rbWrapLp.topMargin = WgTheme.dp(ctx, 6);
                LinearLayout.LayoutParams eBtnLp = new LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f
                );
                setMarginEndCompat(eBtnLp, WgTheme.dp(ctx, 6), isAr);
                LinearLayout.LayoutParams delRowLp = new LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f
                );
                rowBtns.addView(editRowBtn, eBtnLp);
                rowBtns.addView(delRowBtn, delRowLp);
                rowCard.addView(rowBtns, rbWrapLp);
            }

            profilesListContainer.addView(rowCard, rowLp);
        }

        latestStatsRefreshRef[0] = refreshStatusVisuals;
        refreshStatusVisuals.run();

        if (state.scrollToEditorNextRender) {
            state.scrollToEditorNextRender = false;
            scrollView.post(() -> {
                scrollView.smoothScrollTo(0, configCard.getTop());
                editorForm.focusProfileName();
            });
        }

        // Toolbar & preference handlers
        themeBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            WireGuardManager.setDarkTheme(ctx, !theme.isDark);
            rebuildUi.run();
        });

        langBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            WireGuardManager.setArabic(ctx, !isAr);
            rebuildUi.run();
        });

        netBatteryToggleBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.networkOptionsExpanded = !state.networkOptionsExpanded;
            rebuildUi.run();
        });

        toggleConfigBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.configExpanded = !state.configExpanded;
            if (state.configExpanded) {
                state.scrollToEditorNextRender = true;
            }
            rebuildUi.run();
        });

        pingFastestBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.pingingAll = true;
            rebuildUi.run();

            new Thread(() -> {
                try {
                    final WireGuardManager.PingWinnerResult winner =
                            WireGuardManager.pingAllProfilesAndSelectFastest(ctx, moduleApkPath, telegramClassLoader);
                    mainHandler.post(() -> {
                        state.pingingAll = false;
                        state.draft = winner.winner;
                        state.advancedExpanded = state.draft.hasAwgConfigured();
                        Toast.makeText(
                                ctx,
                                WgStrings.toastPingWinner(isAr, winner.winner.name, winner.bestMs),
                                Toast.LENGTH_SHORT
                        ).show();
                        rebuildUi.run();
                        if (winner.switchedLive) {
                            triggerVerification.run();
                        }
                    });
                } catch (final Throwable err) {
                    mainHandler.post(() -> {
                        state.pingingAll = false;
                        Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                        rebuildUi.run();
                    });
                }
            }, "wg-plus-ping-all").start();
        });

        newProfileBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.draft = WireGuardManager.createNewProfile(ctx);
            state.configExpanded = true;
            state.advancedExpanded = false;
            state.scrollToEditorNextRender = true;
            Toast.makeText(ctx, WgStrings.toastCreatedNewProfile(isAr, state.draft.name), Toast.LENGTH_SHORT).show();
            rebuildUi.run();
        });

        final ConfFileSelectedCallback applyImportedConf = (fileNameHint, confText) -> {
            try {
                if (dialog.isShowing()) {
                    captureDraftInputs.run();
                    WireGuardManager.saveConfig(ctx, state.draft);
                }
                WireGuardManager.TunnelConfig imported = WireGuardManager.importConfAsProfile(
                        ctx,
                        confText,
                        fileNameHint,
                        autoStartSwitch.isChecked(),
                        routeCallsSwitch.isChecked()
                );
                state.draft = imported;
                state.configExpanded = false;
                state.advancedExpanded = imported.hasAwgConfigured();
                Toast.makeText(ctx, WgStrings.toastImportedNamedProfile(isAr, imported.name), Toast.LENGTH_SHORT).show();
                rebuildUi.run();
            } catch (Throwable err) {
                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            }
        };

        pasteClipBtn.setOnClickListener(v -> {
            try {
                ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm == null || !cm.hasPrimaryClip()) {
                    throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
                }
                ClipData clip = cm.getPrimaryClip();
                if (clip == null || clip.getItemCount() == 0) {
                    throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
                }
                CharSequence rawText = clip.getItemAt(0).coerceToText(ctx);
                String text = rawText != null ? rawText.toString().trim() : "";
                // Automatically handle multi-profile JSON backup if pasted here too
                if (WireGuardManager.isEncryptedBackupEnvelope(text)) {
                    promptBackupPassphraseModal(ctx, isAr, theme, false, pass -> {
                        try {
                            int count = WireGuardManager.importEncryptedBackupV1(ctx, moduleApkPath, text, pass);
                            state.draft = WireGuardManager.loadConfig(ctx);
                            state.configExpanded = false;
                            Toast.makeText(ctx, WgStrings.toastRestoredBackup(isAr, count), Toast.LENGTH_SHORT).show();
                            rebuildUi.run();
                        } catch (Throwable err) {
                            Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                        }
                    });
                } else if (text.startsWith("{") && text.contains("wgplus.profiles.v1")) {
                    int count = WireGuardManager.importProfilesBackupJson(ctx, text);
                    state.draft = WireGuardManager.loadConfig(ctx);
                    state.configExpanded = false;
                    Toast.makeText(ctx, WgStrings.toastRestoredBackup(isAr, count), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                } else {
                    applyImportedConf.onConfContentRead("", text);
                }
            } catch (Throwable err) {
                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            }
        });

        importFileBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            Activity hostAct = unwrapActivity(ctx);
            if (hostAct == null) {
                pasteClipBtn.performClick();
                return;
            }
            try {
                sPendingFileCallback = applyImportedConf;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                hostAct.startActivityForResult(intent, REQ_IMPORT_CONF_FILE);
            } catch (Throwable err) {
                sPendingFileCallback = null;
                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            }
        });

        importQrBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            Activity hostAct = unwrapActivity(ctx);
            if (hostAct == null) {
                Toast.makeText(
                        ctx,
                        WgStrings.localizeError(new WgStrings.WgException(WgStrings.ErrorCode.FILE_READ_FAILED), isAr),
                        Toast.LENGTH_LONG
                ).show();
                return;
            }
            try {
                sPendingFileCallback = applyImportedConf;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("image/*");
                hostAct.startActivityForResult(intent, REQ_IMPORT_QR_IMAGE);
            } catch (Throwable err) {
                sPendingFileCallback = null;
                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            }
        });

        backupAllBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            promptBackupPassphraseModal(ctx, isAr, theme, true, pass -> {
                try {
                    String encrypted = WireGuardManager.exportEncryptedBackupV1(ctx, moduleApkPath, pass);
                    ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        ClipData clip = ClipData.newPlainText("WireGuardPlusBackup", encrypted);
                        if (Build.VERSION.SDK_INT >= 33) {
                            android.os.PersistableBundle extras = new android.os.PersistableBundle();
                            extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
                            clip.getDescription().setExtras(extras);
                        }
                        cm.setPrimaryClip(clip);
                        int count = WireGuardManager.loadProfiles(ctx).size();
                        Toast.makeText(ctx, WgStrings.backupExportedEncryptedToast(isAr, count), Toast.LENGTH_SHORT).show();
                    }
                } catch (Throwable err) {
                    Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                }
            });
        });

        restoreAllBtn.setOnClickListener(v -> {
            try {
                captureDraftInputs.run();
                WireGuardManager.saveConfig(ctx, state.draft);
                ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm == null || !cm.hasPrimaryClip() || cm.getPrimaryClip() == null || cm.getPrimaryClip().getItemCount() == 0) {
                    throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
                }
                CharSequence rawText = cm.getPrimaryClip().getItemAt(0).coerceToText(ctx);
                final String payload = rawText != null ? rawText.toString().trim() : "";
                if (WireGuardManager.isEncryptedBackupEnvelope(payload)) {
                    promptBackupPassphraseModal(ctx, isAr, theme, false, pass -> {
                        try {
                            int count = WireGuardManager.importEncryptedBackupV1(ctx, moduleApkPath, payload, pass);
                            state.draft = WireGuardManager.loadConfig(ctx);
                            state.configExpanded = false;
                            state.advancedExpanded = state.draft.hasAwgConfigured();
                            Toast.makeText(ctx, WgStrings.toastRestoredBackup(isAr, count), Toast.LENGTH_SHORT).show();
                            rebuildUi.run();
                        } catch (Throwable err) {
                            Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                        }
                    });
                } else {
                    int count = WireGuardManager.importProfilesBackupJson(ctx, payload);
                    state.draft = WireGuardManager.loadConfig(ctx);
                    state.configExpanded = false;
                    state.advancedExpanded = state.draft.hasAwgConfigured();
                    Toast.makeText(ctx, WgStrings.toastRestoredBackup(isAr, count), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                }
            } catch (Throwable err) {
                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            }
        });

        routeCallsSwitch.setOnCheckedChangeListener((btn, checked) -> {
            state.draft.routeCalls = checked;
            WireGuardManager.setRouteCallsEnabled(ctx, checked);
            if (telegramClassLoader != null && WireGuardManager.isTunnelRunning(ctx, moduleApkPath)) {
                int port = WireGuardManager.getActivePort(ctx, moduleApkPath);
                if (port > 0) {
                    WireGuardManager.postBindTelegramProxy(ctx, telegramClassLoader, true, port, checked);
                }
            }
            refreshStatusVisuals.run();
        });

        autoStartSwitch.setOnCheckedChangeListener((btn, checked) -> {
            state.draft.enabled = checked;
            WireGuardManager.setEnabled(ctx, checked);
        });

        killSwitchToggle.setOnCheckedChangeListener((btn, checked) ->
                new Thread(() -> {
                    WireGuardManager.setKillSwitchEnabled(ctx, moduleApkPath, telegramClassLoader, checked);
                    mainHandler.post(refreshStatusVisuals);
                }, "wg-plus-ks-toggle").start()
        );

        autoFailoverToggle.setOnCheckedChangeListener((btn, checked) ->
                WireGuardManager.setAutoFailoverEnabled(ctx, moduleApkPath, telegramClassLoader, checked)
        );

        dohToggle.setOnCheckedChangeListener((btn, checked) ->
                WireGuardManager.setDohEnabled(ctx, checked)
        );

        smartKeepaliveToggle.setOnCheckedChangeListener((btn, checked) ->
                WireGuardManager.setSmartKeepaliveEnabled(ctx, moduleApkPath, checked)
        );

        verifyBtn.setOnClickListener(v -> triggerVerification.run());

        final Runnable startQuickWarpReuse = () -> {
            if (state.generatingWarp || state.connecting) {
                return;
            }
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.generatingWarp = true;
            state.connecting = true;
            refreshStatusVisuals.run();
            scrollView.post(() -> scrollView.smoothScrollTo(0, 0));

            new Thread(() -> {
                try {
                    final WireGuardManager.QuickWarpResult res = WireGuardManager.quickConnectFreeWarp(
                            ctx,
                            moduleApkPath,
                            telegramClassLoader,
                            false
                    );
                    mainHandler.post(() -> {
                        state.generatingWarp = false;
                        state.connecting = false;
                        state.draft = res.profile;
                        state.configExpanded = false;
                        state.advancedExpanded = state.draft.hasAwgConfigured();
                        Toast.makeText(
                                ctx,
                                WgStrings.toastQuickWarpConnected(isAr, res.createdNew, res.localPort),
                                Toast.LENGTH_SHORT
                        ).show();
                        rebuildUi.run();
                        triggerVerification.run();
                        WireGuardManager.maybeInviteToOfficialChannel(ctx, isAr, dialog::dismiss);
                    });
                } catch (final Throwable err) {
                    mainHandler.post(() -> {
                        state.generatingWarp = false;
                        state.connecting = false;
                        state.verifyState = VerifyUiState.ERROR;
                        state.lastVerifyError = err;
                        rebuildUi.run();
                    });
                }
            }, "wg-plus-quick-warp").start();
        };

        final Runnable startQuickWarpFresh = () -> {
            if (state.generatingWarp || state.connecting) {
                return;
            }
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.generatingWarp = true;
            state.connecting = true;
            refreshStatusVisuals.run();
            scrollView.post(() -> scrollView.smoothScrollTo(0, 0));

            new Thread(() -> {
                try {
                    final WireGuardManager.QuickWarpResult res = WireGuardManager.quickConnectFreeWarp(
                            ctx,
                            moduleApkPath,
                            telegramClassLoader,
                            true
                    );
                    mainHandler.post(() -> {
                        state.generatingWarp = false;
                        state.connecting = false;
                        state.draft = res.profile;
                        state.configExpanded = false;
                        state.advancedExpanded = state.draft.hasAwgConfigured();
                        Toast.makeText(
                                ctx,
                                WgStrings.toastQuickWarpConnected(isAr, res.createdNew, res.localPort),
                                Toast.LENGTH_SHORT
                        ).show();
                        rebuildUi.run();
                        triggerVerification.run();
                        WireGuardManager.maybeInviteToOfficialChannel(ctx, isAr, dialog::dismiss);
                    });
                } catch (final Throwable err) {
                    mainHandler.post(() -> {
                        state.generatingWarp = false;
                        state.connecting = false;
                        state.verifyState = VerifyUiState.ERROR;
                        state.lastVerifyError = err;
                        rebuildUi.run();
                    });
                }
            }, "wg-plus-new-warp").start();
        };

        quickWarpBtn.setOnClickListener(v -> startQuickWarpReuse.run());
        recoveryWarpBtn.setOnClickListener(v -> startQuickWarpReuse.run());
        recoveryAwgBtn.setOnClickListener(v -> {
            if (state.generatingWarp || state.connecting) {
                return;
            }
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            state.connecting = true;
            state.observedActiveNoHsAtMs = 0L;
            refreshStatusVisuals.run();
            new Thread(() -> {
                try {
                    final int port = WireGuardManager.applyAwg15AndReconnect(ctx, moduleApkPath, telegramClassLoader);
                    mainHandler.post(() -> {
                        state.connecting = false;
                        state.draft = WireGuardManager.loadConfig(ctx);
                        state.advancedExpanded = true;
                        Toast.makeText(ctx, WgStrings.toastAwgRecovered(isAr, port), Toast.LENGTH_SHORT).show();
                        rebuildUi.run();
                        triggerVerification.run();
                        WireGuardManager.maybeInviteToOfficialChannel(ctx, isAr, dialog::dismiss);
                    });
                } catch (final Throwable err) {
                    mainHandler.post(() -> {
                        state.connecting = false;
                        state.verifyState = VerifyUiState.ERROR;
                        state.lastVerifyError = err;
                        rebuildUi.run();
                    });
                }
            }, "wg-plus-dlg-recover-awg").start();
        });
        newWarpBtn.setOnClickListener(v -> startQuickWarpFresh.run());

        connectBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            WireGuardManager.selectProfile(ctx, state.draft.id);
            connectOrSwitchSelectedProfile.run();
        });

        disconnectBtn.setOnClickListener(v -> {
            disconnectBtn.setEnabled(false);
            new Thread(() -> {
                WireGuardManager.stopAndUnbind(ctx, moduleApkPath, telegramClassLoader);
                mainHandler.post(() -> {
                    state.verifyState = VerifyUiState.IDLE;
                    state.verifyResult = null;
                    state.lastVerifyError = null;
                    rebuildUi.run();
                    Toast.makeText(ctx, WgStrings.toastDisconnected(isAr), Toast.LENGTH_SHORT).show();
                });
            }, "wg-plus-disconnect").start();
        });

        return root;
    }

    public static void showDiagnosticsModal(
            final Context ctx,
            final String moduleApkPath,
            final boolean isAr,
            final WgTheme theme
    ) {
        WgDialogModals.showDiagnosticsModal(ctx, moduleApkPath, isAr, theme);
    }
}
