package org.telegram.wgplus.module;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.text.TextUtils;
import android.text.method.PasswordTransformationMethod;
import android.text.method.SingleLineTransformationMethod;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
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

    private enum VerifyUiState {
        IDLE,
        LOADING,
        SUCCESS,
        ERROR
    }

    private static final class DialogSessionState {
        WireGuardManager.TunnelConfig draft;
        boolean networkOptionsExpanded = false;
        boolean configExpanded = false;
        boolean advancedExpanded = false;
        boolean showPrivateKey = false;
        boolean showPresharedKey = false;
        boolean connecting = false;
        boolean pingingAll = false;
        boolean discoveringMtu = false;
        String switchingTargetName = "";
        boolean scrollToEditorNextRender = false;
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
        state.configExpanded = !state.draft.hasPeerConfigured();
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
            mainHandler.removeCallbacksAndMessages(null);
            if (onUiPreferenceChanged != null) {
                onUiPreferenceChanged.run();
            }
        });

        dialog.show();
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

        LinearLayout actionRow = new LinearLayout(ctx);
        actionRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams actionRowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        actionRowLp.topMargin = WgTheme.dp(ctx, 12);

        final Button connectBtn = createPrimaryAccentButton(ctx, WgStrings.connectPrimaryBtn(isAr), theme);
        final Button disconnectBtn = createDisconnectButton(ctx, WgStrings.disconnectBtn(isAr), theme);

        LinearLayout.LayoutParams connLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.3f);
        setMarginEndCompat(connLp, WgTheme.dp(ctx, 8), isAr);
        LinearLayout.LayoutParams discLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.95f);

        actionRow.addView(connectBtn, connLp);
        actionRow.addView(disconnectBtn, discLp);
        statusCard.addView(actionRow, actionRowLp);

        final Button verifyBtn = createSecondaryButton(ctx, WgStrings.verifyBtnLabel(isAr), theme);
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
            optionsCard.addView(nbBox, nbBoxLp);
        }

        // Pre-create editor inputs (including AmneziaWG fields) so captureDraftInputs works from any action
        final EditText profileNameInput = createProseEditText(
                ctx, WgStrings.hintProfileName(isAr), state.draft.name, isAr, theme
        );
        final EditText privateKeyInput = createSecretTechnicalEditText(
                ctx, WgStrings.hintPrivateKey(isAr), state.draft.privateKey, state.showPrivateKey, theme
        );
        final EditText addressInput = createTechnicalEditText(
                ctx, WgStrings.hintAddress(isAr), state.draft.address,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText dnsInput = createTechnicalEditText(
                ctx, WgStrings.hintDns(isAr), state.draft.dns,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText publicKeyInput = createTechnicalEditText(
                ctx, WgStrings.hintPublicKey(isAr), state.draft.publicKey,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText endpointInput = createTechnicalEditText(
                ctx, WgStrings.hintEndpoint(isAr), state.draft.endpoint,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText keepAliveInput = createTechnicalEditText(
                ctx, WgStrings.hintKeepAlive(isAr),
                String.valueOf(state.draft.keepAlive > 0 ? state.draft.keepAlive : 25),
                InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText presharedKeyInput = createSecretTechnicalEditText(
                ctx, WgStrings.hintPresharedKey(isAr), state.draft.presharedKey, state.showPresharedKey, theme
        );
        final EditText mtuInput = createTechnicalEditText(
                ctx, WgStrings.hintMtu(isAr),
                String.valueOf(state.draft.mtu > 0 ? state.draft.mtu : 1280),
                InputType.TYPE_CLASS_NUMBER, theme
        );

        final EditText jcInput = createTechnicalEditText(
                ctx, "0", state.draft.jc > 0 ? String.valueOf(state.draft.jc) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText jminInput = createTechnicalEditText(
                ctx, "50", state.draft.jmin > 0 ? String.valueOf(state.draft.jmin) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText jmaxInput = createTechnicalEditText(
                ctx, "250", state.draft.jmax > 0 ? String.valueOf(state.draft.jmax) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText s1Input = createTechnicalEditText(
                ctx, "0", state.draft.s1 > 0 ? String.valueOf(state.draft.s1) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText s2Input = createTechnicalEditText(
                ctx, "0", state.draft.s2 > 0 ? String.valueOf(state.draft.s2) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText s3Input = createTechnicalEditText(
                ctx, "0", state.draft.s3 > 0 ? String.valueOf(state.draft.s3) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText s4Input = createTechnicalEditText(
                ctx, "0", state.draft.s4 > 0 ? String.valueOf(state.draft.s4) : "", InputType.TYPE_CLASS_NUMBER, theme
        );
        final EditText h1Input = createTechnicalEditText(
                ctx, "100000-200000", state.draft.h1, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText h2Input = createTechnicalEditText(
                ctx, "200001-300000", state.draft.h2, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText h3Input = createTechnicalEditText(
                ctx, "300001-400000", state.draft.h3, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );
        final EditText h4Input = createTechnicalEditText(
                ctx, "400001-500000", state.draft.h4, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
        );

        final Runnable captureDraftInputs = () -> state.draft = collectInputs(
                state.draft.id,
                autoStartSwitch.isChecked(),
                routeCallsSwitch.isChecked(),
                profileNameInput,
                privateKeyInput,
                presharedKeyInput,
                addressInput,
                dnsInput,
                publicKeyInput,
                endpointInput,
                keepAliveInput,
                mtuInput,
                jcInput,
                jminInput,
                jmaxInput,
                s1Input,
                s2Input,
                s3Input,
                s4Input,
                h1Input,
                h2Input,
                h3Input,
                h4Input
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
            LinearLayout formWrap = new LinearLayout(ctx);
            formWrap.setOrientation(LinearLayout.VERTICAL);
            LinearLayout.LayoutParams fwLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            fwLp.topMargin = WgTheme.dp(ctx, 12);

            addFieldToContainer(formWrap, ctx, WgStrings.labelProfileName(isAr), profileNameInput, isAr, theme, WgTheme.dp(ctx, 10));

            addSecretFieldWithToggle(
                    formWrap,
                    ctx,
                    WgStrings.labelPrivateKey(isAr),
                    privateKeyInput,
                    state.showPrivateKey,
                    isAr,
                    theme,
                    WgTheme.dp(ctx, 10),
                    () -> {
                        captureDraftInputs.run();
                        state.showPrivateKey = !state.showPrivateKey;
                        rebuildUi.run();
                    }
            );

            boolean useTwoColumns = shouldUseSplitColumns(ctx);
            if (useTwoColumns) {
                formWrap.addView(createTwoColumnRow(
                        ctx,
                        WgStrings.labelAddress(isAr), addressInput, 1.15f,
                        WgStrings.labelDns(isAr), dnsInput, 1.0f,
                        isAr, theme, WgTheme.dp(ctx, 10)
                ));
            } else {
                addFieldToContainer(formWrap, ctx, WgStrings.labelAddress(isAr), addressInput, isAr, theme, WgTheme.dp(ctx, 10));
                addFieldToContainer(formWrap, ctx, WgStrings.labelDns(isAr), dnsInput, isAr, theme, WgTheme.dp(ctx, 10));
            }

            addFieldToContainer(formWrap, ctx, WgStrings.labelPublicKey(isAr), publicKeyInput, isAr, theme, WgTheme.dp(ctx, 10));

            if (useTwoColumns) {
                formWrap.addView(createTwoColumnRow(
                        ctx,
                        WgStrings.labelEndpoint(isAr), endpointInput, 1.45f,
                        WgStrings.labelKeepAlive(isAr), keepAliveInput, 0.85f,
                        isAr, theme, WgTheme.dp(ctx, 10)
                ));
            } else {
                addFieldToContainer(formWrap, ctx, WgStrings.labelEndpoint(isAr), endpointInput, isAr, theme, WgTheme.dp(ctx, 10));
                addFieldToContainer(formWrap, ctx, WgStrings.labelKeepAlive(isAr), keepAliveInput, isAr, theme, WgTheme.dp(ctx, 10));
            }

            Button saveDraftBtn = createSecondaryButton(ctx, WgStrings.saveChangesBtn(isAr), theme);
            saveDraftBtn.setOnClickListener(v -> {
                captureDraftInputs.run();
                WireGuardManager.saveConfig(ctx, state.draft);
                Toast.makeText(ctx, WgStrings.toastSaved(isAr), Toast.LENGTH_SHORT).show();
                rebuildUi.run();
            });
            LinearLayout.LayoutParams saveDraftLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            saveDraftLp.bottomMargin = WgTheme.dp(ctx, 8);
            formWrap.addView(saveDraftBtn, saveDraftLp);

            Button advToggleBtn = createSecondaryButton(
                    ctx,
                    WgStrings.advancedToggleLabel(isAr, state.advancedExpanded),
                    theme
            );
            advToggleBtn.setOnClickListener(v -> {
                captureDraftInputs.run();
                state.advancedExpanded = !state.advancedExpanded;
                rebuildUi.run();
            });
            formWrap.addView(advToggleBtn, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            ));

            if (state.advancedExpanded) {
                LinearLayout advBox = new LinearLayout(ctx);
                advBox.setOrientation(LinearLayout.VERTICAL);
                LinearLayout.LayoutParams advLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                advLp.topMargin = WgTheme.dp(ctx, 10);

                addSecretFieldWithToggle(
                        advBox,
                        ctx,
                        WgStrings.labelPresharedKey(isAr),
                        presharedKeyInput,
                        state.showPresharedKey,
                        isAr,
                        theme,
                        WgTheme.dp(ctx, 10),
                        () -> {
                            captureDraftInputs.run();
                            state.showPresharedKey = !state.showPresharedKey;
                            rebuildUi.run();
                        }
                );

                // MTU field + Auto-MTU Path Finder button
                addFieldToContainer(advBox, ctx, WgStrings.labelMtu(isAr), mtuInput, isAr, theme, WgTheme.dp(ctx, 6));

                Button autoMtuBtn = createSecondaryButton(ctx, WgStrings.autoMtuBtn(isAr, state.discoveringMtu), theme);
                autoMtuBtn.setEnabled(!state.discoveringMtu && !state.connecting);
                autoMtuBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    WireGuardManager.saveConfig(ctx, state.draft);
                    state.discoveringMtu = true;
                    rebuildUi.run();

                    new Thread(() -> {
                        try {
                            final int bestMtu = WireGuardManager.discoverAndApplyOptimalMtu(
                                    ctx,
                                    state.draft,
                                    moduleApkPath,
                                    telegramClassLoader
                            );
                            mainHandler.post(() -> {
                                state.discoveringMtu = false;
                                state.draft.mtu = bestMtu;
                                Toast.makeText(ctx, WgStrings.toastOptimalMtuFound(isAr, bestMtu), Toast.LENGTH_SHORT).show();
                                rebuildUi.run();
                            });
                        } catch (final Throwable err) {
                            mainHandler.post(() -> {
                                state.discoveringMtu = false;
                                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
                                rebuildUi.run();
                            });
                        }
                    }, "wg-plus-mtu-finder").start();
                });
                LinearLayout.LayoutParams autoMtuLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                autoMtuLp.bottomMargin = WgTheme.dp(ctx, 12);
                advBox.addView(autoMtuBtn, autoMtuLp);

                advBox.addView(createDivider(ctx, theme));

                // AmneziaWG DPI Obfuscation Subsection
                TextView awgHeading = new TextView(ctx);
                applyProseTextStyle(awgHeading, isAr, theme.textPrimary, 13f, true);
                awgHeading.setText(WgStrings.awgSectionHeading(isAr));
                LinearLayout.LayoutParams awgHeadLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                awgHeadLp.topMargin = WgTheme.dp(ctx, 10);
                advBox.addView(awgHeading, awgHeadLp);

                TextView awgHint = new TextView(ctx);
                applyProseTextStyle(awgHint, isAr, theme.textSecondary, 11.8f, false);
                awgHint.setText(WgStrings.awgSectionHint(isAr));
                LinearLayout.LayoutParams awgHintLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                awgHintLp.topMargin = WgTheme.dp(ctx, 3);
                awgHintLp.bottomMargin = WgTheme.dp(ctx, 8);
                advBox.addView(awgHint, awgHintLp);

                LinearLayout awgPresetRow = new LinearLayout(ctx);
                awgPresetRow.setOrientation(LinearLayout.HORIZONTAL);
                LinearLayout.LayoutParams awgPresetLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                awgPresetLp.bottomMargin = WgTheme.dp(ctx, 10);

                Button awgPresetBtn = createChipButton(ctx, WgStrings.awgPresetVanillaBtn(isAr), theme, false);
                Button awgClearBtn = createChipButton(ctx, WgStrings.awgClearBtn(isAr), theme, false);

                awgPresetBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    state.draft.jc = 4;
                    state.draft.jmin = 50;
                    state.draft.jmax = 250;
                    WireGuardManager.saveConfig(ctx, state.draft);
                    Toast.makeText(ctx, WgStrings.toastAwgPresetApplied(isAr), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                });

                awgClearBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    state.draft.jc = 0;
                    state.draft.jmin = 0;
                    state.draft.jmax = 0;
                    state.draft.s1 = 0;
                    state.draft.s2 = 0;
                    state.draft.s3 = 0;
                    state.draft.s4 = 0;
                    state.draft.h1 = "";
                    state.draft.h2 = "";
                    state.draft.h3 = "";
                    state.draft.h4 = "";
                    WireGuardManager.saveConfig(ctx, state.draft);
                    Toast.makeText(ctx, WgStrings.toastAwgCleared(isAr), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                });

                LinearLayout.LayoutParams prLp1 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.55f);
                setMarginEndCompat(prLp1, WgTheme.dp(ctx, 6), isAr);
                LinearLayout.LayoutParams prLp2 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.75f);
                awgPresetRow.addView(awgPresetBtn, prLp1);
                awgPresetRow.addView(awgClearBtn, prLp2);
                advBox.addView(awgPresetRow, awgPresetLp);

                if (useTwoColumns) {
                    advBox.addView(createTwoColumnRow(
                            ctx,
                            WgStrings.labelAwgJc(isAr), jcInput, 1f,
                            WgStrings.labelAwgJmin(isAr), jminInput, 1f,
                            isAr, theme, WgTheme.dp(ctx, 8)
                    ));
                    advBox.addView(createTwoColumnRow(
                            ctx,
                            WgStrings.labelAwgJmax(isAr), jmaxInput, 1f,
                            WgStrings.labelAwgS1(isAr), s1Input, 1f,
                            isAr, theme, WgTheme.dp(ctx, 8)
                    ));
                    advBox.addView(createTwoColumnRow(
                            ctx,
                            WgStrings.labelAwgS2(isAr), s2Input, 1f,
                            WgStrings.labelAwgS3(isAr), s3Input, 1f,
                            isAr, theme, WgTheme.dp(ctx, 8)
                    ));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgS4(isAr), s4Input, isAr, theme, WgTheme.dp(ctx, 8));
                    advBox.addView(createTwoColumnRow(
                            ctx,
                            WgStrings.labelAwgH1(isAr), h1Input, 1f,
                            WgStrings.labelAwgH2(isAr), h2Input, 1f,
                            isAr, theme, WgTheme.dp(ctx, 8)
                    ));
                    advBox.addView(createTwoColumnRow(
                            ctx,
                            WgStrings.labelAwgH3(isAr), h3Input, 1f,
                            WgStrings.labelAwgH4(isAr), h4Input, 1f,
                            isAr, theme, WgTheme.dp(ctx, 10)
                    ));
                } else {
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgJc(isAr), jcInput, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgJmin(isAr), jminInput, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgJmax(isAr), jmaxInput, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgS1(isAr), s1Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgS2(isAr), s2Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgS3(isAr), s3Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgS4(isAr), s4Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgH1(isAr), h1Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgH2(isAr), h2Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgH3(isAr), h3Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgH4(isAr), h4Input, isAr, theme, WgTheme.dp(ctx, 10));
                }

                // Export Row: Copy .conf + Show QR Code Modal
                LinearLayout exportRow = new LinearLayout(ctx);
                exportRow.setOrientation(LinearLayout.HORIZONTAL);

                Button copyConfBtn = createSecondaryButton(ctx, WgStrings.copyConfBtn(isAr), theme);
                Button showQrBtn = createSecondaryButton(ctx, WgStrings.showQrBtn(isAr), theme);

                copyConfBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    WireGuardManager.saveConfig(ctx, state.draft);
                    String conf = WireGuardManager.exportConfText(state.draft);
                    ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("WireGuard", conf));
                        Toast.makeText(ctx, WgStrings.toastCopiedConf(isAr), Toast.LENGTH_SHORT).show();
                    }
                });

                showQrBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    WireGuardManager.saveConfig(ctx, state.draft);
                    if (!state.draft.hasPeerConfigured()) {
                        Toast.makeText(
                                ctx,
                                WgStrings.localizeError(new WgStrings.WgException(WgStrings.ErrorCode.QR_ENCODE_FAILED), isAr),
                                Toast.LENGTH_LONG
                        ).show();
                        return;
                    }
                    showQrCodeModal(ctx, state.draft, isAr, theme);
                });

                LinearLayout.LayoutParams exLp1 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                setMarginEndCompat(exLp1, WgTheme.dp(ctx, 8), isAr);
                LinearLayout.LayoutParams exLp2 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                exportRow.addView(copyConfBtn, exLp1);
                exportRow.addView(showQrBtn, exLp2);
                advBox.addView(exportRow, new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                ));

                formWrap.addView(advBox, advLp);
            }

            configCard.addView(formWrap, fwLp);
        }

        // 3. Clean Footer with Close button
        root.addView(createDivider(ctx, theme));

        LinearLayout footer = new LinearLayout(ctx);
        footer.setOrientation(LinearLayout.VERTICAL);
        footer.setBackgroundColor(theme.surfaceFooter);
        footer.setPadding(padH, WgTheme.dp(ctx, 10), padH, WgTheme.dp(ctx, 10));

        Button closeBtn = createSecondaryButton(ctx, WgStrings.closeBtn(isAr), theme);
        closeBtn.setOnClickListener(v -> {
            captureDraftInputs.run();
            WireGuardManager.saveConfig(ctx, state.draft);
            dialog.dismiss();
        });
        footer.addView(closeBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        root.addView(footer);

        // Live status + UAPI telemetry renderer
        final Runnable refreshStatusVisuals = () -> {
            boolean active = WireGuardManager.isTunnelRunning(ctx, moduleApkPath);
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

            if (state.connecting) {
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.pendingDot));
                statusHeadline.setText(!state.switchingTargetName.isEmpty()
                        ? WgStrings.statusSwitchingTo(isAr, state.switchingTargetName)
                        : WgStrings.statusConnecting(isAr));
                statusHeadline.setTextColor(theme.pendingText);
                statusSubline.setText(WgStrings.verifyLoadingBody(isAr));
                connectBtn.setEnabled(false);
                connectBtn.setText(WgStrings.connectingBtn(isAr));
                disconnectBtn.setEnabled(false);
            } else if (active && port > 0) {
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.activeDot));
                statusHeadline.setText(WgStrings.statusActiveWithProfile(isAr, connectedName, port));
                statusHeadline.setTextColor(theme.activeText);
                WireGuardManager.TunnelStats stats = WireGuardManager.getLiveStats(ctx, moduleApkPath);
                statusSubline.setText(WgStrings.liveStatsLine(isAr, stats.rxBytes, stats.txBytes, stats.lastHandshakeSec));
                connectBtn.setEnabled(true);
                connectBtn.setText(viewingDifferentFromConnected
                        ? WgStrings.switchToProfileBtn(isAr)
                        : WgStrings.reconnectPrimaryBtn(isAr));
                disconnectBtn.setEnabled(true);
            } else if (guarded) {
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.pendingDot));
                statusHeadline.setText(WgStrings.statusKillSwitchGuarded(isAr, state.draft.name));
                statusHeadline.setTextColor(theme.pendingText);
                statusSubline.setText(WgStrings.statusKillSwitchSubline(isAr));
                connectBtn.setEnabled(true);
                connectBtn.setText(WgStrings.connectPrimaryBtn(isAr));
                disconnectBtn.setEnabled(false);
            } else {
                statusDot.setBackground(WgTheme.statusDot(ctx, theme.stoppedDot));
                statusHeadline.setText(WgStrings.statusStoppedWithProfile(isAr, state.draft.name));
                statusHeadline.setTextColor(theme.stoppedText);
                statusSubline.setText(WgStrings.statusEmptyHint(isAr));
                connectBtn.setEnabled(true);
                connectBtn.setText(WgStrings.connectPrimaryBtn(isAr));
                disconnectBtn.setEnabled(false);
            }

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
            final String displayLabel = (item.name == null || item.name.trim().isEmpty())
                    ? WgStrings.defaultProfileName(isAr, i + 1)
                    : item.name.trim();

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
                LinearLayout.LayoutParams dBtnLp = new LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f
                );
                rowBtns.addView(editRowBtn, eBtnLp);
                rowBtns.addView(delRowBtn, dBtnLp);
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
                profileNameInput.requestFocus();
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
                if (text.startsWith("{") && text.contains(WireGuardManager.BACKUP_SCHEMA)) {
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
            try {
                captureDraftInputs.run();
                WireGuardManager.saveConfig(ctx, state.draft);
                String backupJson = WireGuardManager.exportAllProfilesBackupJson(ctx);
                ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(ClipData.newPlainText("WireGuardPlusBackup", backupJson));
                    int count = WireGuardManager.loadProfiles(ctx).size();
                    Toast.makeText(ctx, WgStrings.toastExportedBackup(isAr, count), Toast.LENGTH_SHORT).show();
                }
            } catch (Throwable err) {
                Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            }
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
                String payload = rawText != null ? rawText.toString().trim() : "";
                int count = WireGuardManager.importProfilesBackupJson(ctx, payload);
                state.draft = WireGuardManager.loadConfig(ctx);
                state.configExpanded = false;
                state.advancedExpanded = state.draft.hasAwgConfigured();
                Toast.makeText(ctx, WgStrings.toastRestoredBackup(isAr, count), Toast.LENGTH_SHORT).show();
                rebuildUi.run();
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

    /**
     * Displays a crisp high-contrast scannable ISO QR code modal for the given profile (closable via Escape / Back).
     */
    private static void showQrCodeModal(
            Context ctx,
            WireGuardManager.TunnelConfig cfg,
            boolean isAr,
            WgTheme theme
    ) {
        final Bitmap qrBitmap;
        try {
            String confPayload = WireGuardManager.exportConfText(cfg);
            int qrPx = WgTheme.dp(ctx, 250);
            qrBitmap = WgQrCodec.encodeToBitmap(confPayload, qrPx);
        } catch (Throwable err) {
            Toast.makeText(ctx, WgStrings.localizeError(err, isAr), Toast.LENGTH_LONG).show();
            return;
        }

        LinearLayout box = new LinearLayout(ctx);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            box.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        }
        box.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 14f));
        int p = WgTheme.dp(ctx, 18);
        box.setPadding(p, p, p, p);

        TextView title = new TextView(ctx);
        applyProseTextStyle(title, isAr, theme.textPrimary, 15.5f, true);
        title.setText(WgStrings.qrModalTitle(isAr, cfg.name));
        box.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        TextView hint = new TextView(ctx);
        applyProseTextStyle(hint, isAr, theme.textSecondary, 12.5f, false);
        hint.setText(WgStrings.qrModalHint(isAr));
        LinearLayout.LayoutParams hintLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        hintLp.topMargin = WgTheme.dp(ctx, 4);
        hintLp.bottomMargin = WgTheme.dp(ctx, 14);
        box.addView(hint, hintLp);

        FrameLayout qrFrame = new FrameLayout(ctx);
        qrFrame.setBackground(WgTheme.cardBackground(ctx, Color.WHITE, theme.borderSubtle, 10f));
        int qPad = WgTheme.dp(ctx, 10);
        qrFrame.setPadding(qPad, qPad, qPad, qPad);

        ImageView qrImage = new ImageView(ctx);
        qrImage.setImageBitmap(qrBitmap);
        qrImage.setScaleType(ImageView.ScaleType.FIT_CENTER);
        int imgSide = WgTheme.dp(ctx, 230);
        qrFrame.addView(qrImage, new FrameLayout.LayoutParams(imgSide, imgSide, Gravity.CENTER));

        LinearLayout.LayoutParams frameLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        frameLp.bottomMargin = WgTheme.dp(ctx, 16);
        box.addView(qrFrame, frameLp);

        Button closeQrBtn = createSecondaryButton(ctx, WgStrings.closeBtn(isAr), theme);
        box.addView(closeQrBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        final AlertDialog qrDialog = new AlertDialog.Builder(ctx)
                .setView(box)
                .setCancelable(true)
                .create();

        closeQrBtn.setOnClickListener(v -> qrDialog.dismiss());
        qrDialog.setOnDismissListener(d -> {
            if (!qrBitmap.isRecycled()) {
                qrBitmap.recycle();
            }
        });

        qrDialog.show();
        if (qrDialog.getWindow() != null) {
            qrDialog.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        }
    }

    private static void showDeleteConfirmDialog(
            Context ctx,
            String profileName,
            boolean isAr,
            WgTheme theme,
            Runnable onConfirmed
    ) {
        LinearLayout box = new LinearLayout(ctx);
        box.setOrientation(LinearLayout.VERTICAL);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            box.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        }
        box.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 14f));
        int p = WgTheme.dp(ctx, 18);
        box.setPadding(p, p, p, p);

        TextView title = new TextView(ctx);
        applyProseTextStyle(title, isAr, theme.textPrimary, 15.5f, true);
        title.setText(WgStrings.confirmDeleteTitle(isAr));
        box.addView(title);

        TextView msg = new TextView(ctx);
        applyProseTextStyle(msg, isAr, theme.textSecondary, 13.5f, false);
        msg.setText(WgStrings.confirmDeleteMessage(isAr, profileName));
        LinearLayout.LayoutParams msgLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        msgLp.topMargin = WgTheme.dp(ctx, 8);
        msgLp.bottomMargin = WgTheme.dp(ctx, 16);
        box.addView(msg, msgLp);

        LinearLayout btnRow = new LinearLayout(ctx);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);

        Button cancelBtn = createSecondaryButton(ctx, WgStrings.cancelBtn(isAr), theme);
        Button confirmBtn = createDisconnectButton(ctx, WgStrings.deleteInlineBtn(isAr), theme);

        LinearLayout.LayoutParams c1 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(c1, WgTheme.dp(ctx, 8), isAr);
        LinearLayout.LayoutParams c2 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);

        btnRow.addView(cancelBtn, c1);
        btnRow.addView(confirmBtn, c2);
        box.addView(btnRow);

        final AlertDialog confirmDialog = new AlertDialog.Builder(ctx)
                .setView(box)
                .setCancelable(true)
                .create();

        cancelBtn.setOnClickListener(v -> confirmDialog.dismiss());
        confirmBtn.setOnClickListener(v -> {
            confirmDialog.dismiss();
            onConfirmed.run();
        });

        confirmDialog.show();
        if (confirmDialog.getWindow() != null) {
            confirmDialog.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        }
    }

    private static void renderTelemetryBox(
            Context ctx,
            LinearLayout box,
            Button verifyBtn,
            DialogSessionState state,
            boolean routeCallsEnabled,
            boolean isAr,
            WgTheme theme
    ) {
        box.removeAllViews();
        if (state.verifyState == VerifyUiState.IDLE) {
            verifyBtn.setEnabled(true);
            verifyBtn.setText(WgStrings.verifyBtnLabel(isAr));
            box.setVisibility(View.GONE);
            return;
        }

        box.setVisibility(View.VISIBLE);
        if (state.verifyState == VerifyUiState.LOADING) {
            verifyBtn.setEnabled(false);
            verifyBtn.setText(WgStrings.verifyBtnBusy(isAr));
            box.setBackground(WgTheme.cardBackground(ctx, theme.pendingBg, theme.pendingBorder, 8f));
            TextView loadingText = new TextView(ctx);
            applyProseTextStyle(loadingText, isAr, theme.pendingText, 12.5f, false);
            loadingText.setText(WgStrings.verifyLoadingBody(isAr));
            box.addView(loadingText);
            return;
        }

        verifyBtn.setEnabled(true);
        verifyBtn.setText(WgStrings.verifyBtnLabel(isAr));

        if (state.verifyState == VerifyUiState.SUCCESS && state.verifyResult != null) {
            WireGuardManager.TunnelVerifyResult vr = state.verifyResult;
            box.setBackground(WgTheme.cardBackground(ctx, theme.activeBg, theme.activeBorder, 8f));

            TextView okTitle = new TextView(ctx);
            applyProseTextStyle(okTitle, isAr, theme.activeText, 13f, true);
            okTitle.setText(WgStrings.verifySuccessTitle(isAr));
            LinearLayout.LayoutParams titleLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            titleLp.bottomMargin = WgTheme.dp(ctx, 6);
            box.addView(okTitle, titleLp);

            addTelemetryRow(box, ctx, WgStrings.verifyExitIpLabel(isAr), WgStrings.ltr(vr.exitIp), true, isAr, theme);
            addTelemetryRow(box, ctx, WgStrings.verifyCountryLabel(isAr), WgStrings.localizedCountryName(vr.countryCode, isAr), false, isAr, theme);
            addTelemetryRow(box, ctx, WgStrings.verifyLatencyLabel(isAr), WgStrings.formatLatency(isAr, vr.tunnelPingMs), false, isAr, theme);
            addTelemetryRow(box, ctx, WgStrings.verifyTelegramDcLabel(isAr), WgStrings.formatTelegramDcStatus(isAr, vr.telegramDcReachable, vr.telegramDcPingMs), false, isAr, theme);
            addTelemetryRow(box, ctx, WgStrings.verifyVoipUdpLabel(isAr), WgStrings.formatVoipUdpStatus(isAr, vr.udpCallsReady, vr.udpPingMs, routeCallsEnabled), false, isAr, theme);
            return;
        }

        box.setBackground(WgTheme.cardBackground(ctx, theme.stoppedBg, theme.stoppedBorder, 8f));
        TextView errTitle = new TextView(ctx);
        applyProseTextStyle(errTitle, isAr, theme.stoppedText, 13f, true);
        errTitle.setText(WgStrings.verifyFailedTitle(isAr));
        box.addView(errTitle);

        TextView errDetail = new TextView(ctx);
        applyProseTextStyle(errDetail, isAr, theme.stoppedText, 12.5f, false);
        errDetail.setText(WgStrings.localizeError(state.lastVerifyError, isAr));
        LinearLayout.LayoutParams detailLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        detailLp.topMargin = WgTheme.dp(ctx, 3);
        box.addView(errDetail, detailLp);
    }

    private static void addTelemetryRow(
            LinearLayout parent,
            Context ctx,
            String keyLabel,
            String valueText,
            boolean monoValue,
            boolean isAr,
            WgTheme theme
    ) {
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        rowLp.topMargin = WgTheme.dp(ctx, 3);

        TextView kView = new TextView(ctx);
        applyProseTextStyle(kView, isAr, theme.textSecondary, 12.5f, false);
        kView.setText(keyLabel);
        row.addView(kView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.9f));

        TextView vView = new TextView(ctx);
        applyProseTextStyle(vView, isAr, theme.textPrimary, 12.5f, true);
        if (monoValue) {
            vView.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                vView.setTextDirection(View.TEXT_DIRECTION_LTR);
            }
        }
        vView.setGravity(isAr ? Gravity.LEFT : Gravity.RIGHT);
        vView.setText(valueText);
        row.addView(vView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.15f));

        parent.addView(row, rowLp);
    }

    private static LinearLayout createSwitchRow(
            Context ctx,
            String labelText,
            final Switch sw,
            boolean isAr,
            WgTheme theme
    ) {
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(WgTheme.dp(ctx, 44));
        row.setClickable(true);
        row.setFocusable(true);
        row.setPadding(0, WgTheme.dp(ctx, 4), 0, WgTheme.dp(ctx, 4));

        TextView tv = new TextView(ctx);
        applyProseTextStyle(tv, isAr, theme.textPrimary, 13.5f, false);
        tv.setText(labelText);
        LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(tvLp, WgTheme.dp(ctx, 8), isAr);
        row.addView(tv, tvLp);

        row.addView(sw);
        row.setOnClickListener(v -> sw.toggle());
        return row;
    }

    private static View createTwoColumnRow(
            Context ctx,
            String label1,
            EditText input1,
            float weight1,
            String label2,
            EditText input2,
            float weight2,
            boolean isAr,
            WgTheme theme,
            int bottomMarginPx
    ) {
        LinearLayout splitRow = new LinearLayout(ctx);
        splitRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        rowLp.bottomMargin = bottomMarginPx;
        splitRow.setLayoutParams(rowLp);

        LinearLayout col1 = new LinearLayout(ctx);
        col1.setOrientation(LinearLayout.VERTICAL);
        LinearLayout col2 = new LinearLayout(ctx);
        col2.setOrientation(LinearLayout.VERTICAL);

        addFieldToContainer(col1, ctx, label1, input1, isAr, theme, 0);
        addFieldToContainer(col2, ctx, label2, input2, isAr, theme, 0);

        LinearLayout.LayoutParams c1Lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, weight1);
        setMarginEndCompat(c1Lp, WgTheme.dp(ctx, 8), isAr);
        LinearLayout.LayoutParams c2Lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, weight2);
        splitRow.addView(col1, c1Lp);
        splitRow.addView(col2, c2Lp);
        return splitRow;
    }

    private static void addSecretFieldWithToggle(
            LinearLayout container,
            Context ctx,
            String labelText,
            EditText secretInput,
            boolean visible,
            boolean isAr,
            WgTheme theme,
            int bottomMarginPx,
            Runnable onToggleVisibility
    ) {
        LinearLayout labelRow = new LinearLayout(ctx);
        labelRow.setOrientation(LinearLayout.HORIZONTAL);
        labelRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lrLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lrLp.bottomMargin = WgTheme.dp(ctx, 4);

        TextView label = new TextView(ctx);
        applyProseTextStyle(label, isAr, theme.textSecondary, 12f, false);
        label.setText(labelText);
        labelRow.addView(label, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button showBtn = createChipButton(ctx, WgStrings.showSecretBtn(isAr, visible), theme, false);
        showBtn.setOnClickListener(v -> onToggleVisibility.run());
        labelRow.addView(showBtn);
        container.addView(labelRow, lrLp);

        LinearLayout.LayoutParams eLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        eLp.bottomMargin = bottomMarginPx;
        container.addView(secretInput, eLp);
    }

    private static View createDivider(Context ctx, WgTheme theme) {
        View v = new View(ctx);
        v.setBackgroundColor(theme.borderSubtle);
        v.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                Math.max(1, WgTheme.dp(ctx, 1))
        ));
        return v;
    }

    private static LinearLayout.LayoutParams createCardMarginParams(Context ctx, float bottomDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lp.bottomMargin = WgTheme.dp(ctx, bottomDp);
        return lp;
    }

    private static EditText createProseEditText(
            Context ctx,
            String hintText,
            String initialValue,
            boolean isAr,
            WgTheme theme
    ) {
        EditText edit = new EditText(ctx);
        edit.setHint(hintText);
        edit.setHintTextColor(theme.textHint);
        edit.setTextColor(theme.textPrimary);
        edit.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        edit.setTypeface(Typeface.SANS_SERIF);
        edit.setSingleLine(true);
        edit.setInputType(InputType.TYPE_CLASS_TEXT);
        edit.setFocusable(true);
        edit.setFocusableInTouchMode(true);
        edit.setGravity((isAr ? Gravity.RIGHT : Gravity.LEFT) | Gravity.CENTER_VERTICAL);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            edit.setTextDirection(isAr ? View.TEXT_DIRECTION_RTL : View.TEXT_DIRECTION_LTR);
        }
        edit.setText(initialValue != null ? initialValue : "");
        edit.setBackground(WgTheme.inputWellBackground(ctx, theme));
        int pH = WgTheme.dp(ctx, 11);
        int pV = WgTheme.dp(ctx, 10);
        edit.setPadding(pH, pV, pH, pV);
        edit.setMinimumHeight(WgTheme.dp(ctx, 44));
        return edit;
    }

    private static EditText createSecretTechnicalEditText(
            Context ctx,
            String hintText,
            String initialValue,
            boolean visible,
            WgTheme theme
    ) {
        EditText edit = createTechnicalEditText(
                ctx,
                hintText,
                initialValue,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
                theme
        );
        edit.setTransformationMethod(visible
                ? SingleLineTransformationMethod.getInstance()
                : PasswordTransformationMethod.getInstance());
        edit.setTypeface(Typeface.MONOSPACE);
        return edit;
    }

    private static EditText createTechnicalEditText(
            Context ctx,
            String hintText,
            String initialValue,
            int inputType,
            WgTheme theme
    ) {
        EditText edit = new EditText(ctx);
        edit.setHint(hintText);
        edit.setHintTextColor(theme.textHint);
        edit.setTextColor(theme.textPrimary);
        edit.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        edit.setTypeface(Typeface.MONOSPACE);
        edit.setSingleLine(true);
        edit.setInputType(inputType);
        edit.setFocusable(true);
        edit.setFocusableInTouchMode(true);
        edit.setGravity(Gravity.LEFT | Gravity.CENTER_VERTICAL);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            edit.setTextDirection(View.TEXT_DIRECTION_LTR);
        }
        edit.setText(initialValue != null ? initialValue : "");
        edit.setBackground(WgTheme.inputWellBackground(ctx, theme));
        int pH = WgTheme.dp(ctx, 11);
        int pV = WgTheme.dp(ctx, 10);
        edit.setPadding(pH, pV, pH, pV);
        edit.setMinimumHeight(WgTheme.dp(ctx, 44));
        return edit;
    }

    private static void addFieldToContainer(
            LinearLayout container,
            Context ctx,
            String labelText,
            EditText editText,
            boolean isAr,
            WgTheme theme,
            int bottomMarginPx
    ) {
        TextView label = new TextView(ctx);
        applyProseTextStyle(label, isAr, theme.textSecondary, 12f, false);
        label.setText(labelText);
        LinearLayout.LayoutParams lLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lLp.bottomMargin = WgTheme.dp(ctx, 4);
        container.addView(label, lLp);

        LinearLayout.LayoutParams eLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        eLp.bottomMargin = bottomMarginPx;
        container.addView(editText, eLp);
    }

    private static Button createPrimaryAccentButton(Context ctx, String text, WgTheme theme) {
        Button btn = baseButton(ctx, text, theme.onAccent, 46);
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                theme.accentPrimary,
                theme.accentPressed,
                theme.accentPrimary,
                theme.textPrimary,
                10f
        ));
        return btn;
    }

    private static Button createDisconnectButton(Context ctx, String text, WgTheme theme) {
        Button btn = baseButton(ctx, text, theme.stoppedText, 46);
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                theme.stoppedBg,
                theme.stoppedBorder,
                theme.stoppedBorder,
                theme.accentPrimary,
                10f
        ));
        return btn;
    }

    private static Button createSecondaryButton(Context ctx, String text, WgTheme theme) {
        Button btn = baseButton(ctx, text, theme.textPrimary, 44);
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                theme.surfaceSecondaryBtn,
                theme.surfaceSecondaryBtnPressed,
                theme.borderSubtle,
                theme.accentPrimary,
                10f
        ));
        return btn;
    }

    private static Button createChipButton(Context ctx, String text, WgTheme theme, boolean selected) {
        Button btn = new Button(ctx);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(selected ? theme.onAccent : theme.textPrimary);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        btn.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);
        int minH = WgTheme.dp(ctx, 44);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setMinWidth(WgTheme.dp(ctx, 44));
        btn.setMinimumWidth(WgTheme.dp(ctx, 44));
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 6), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 6));
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                selected ? theme.accentPrimary : theme.surfaceSecondaryBtn,
                selected ? theme.accentPressed : theme.surfaceSecondaryBtnPressed,
                selected ? theme.accentPrimary : theme.borderSubtle,
                theme.accentPrimary,
                8f
        ));
        return btn;
    }

    private static Button createDangerChipButton(Context ctx, String text, WgTheme theme) {
        Button btn = new Button(ctx);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(theme.stoppedText);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        btn.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);
        int minH = WgTheme.dp(ctx, 44);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setMinWidth(WgTheme.dp(ctx, 44));
        btn.setMinimumWidth(WgTheme.dp(ctx, 44));
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 6), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 6));
        btn.setBackground(WgTheme.interactiveBackground(
                ctx,
                theme.stoppedBg,
                theme.stoppedBorder,
                theme.stoppedBorder,
                theme.accentPrimary,
                8f
        ));
        return btn;
    }

    private static Button baseButton(Context ctx, String text, int textColor, int minHeightDp) {
        Button btn = new Button(ctx);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(textColor);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        btn.setTypeface(Typeface.SANS_SERIF, Typeface.BOLD);
        int minH = WgTheme.dp(ctx, minHeightDp);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 12), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 12), WgTheme.dp(ctx, 10));
        return btn;
    }

    private static void applyProseTextStyle(TextView tv, boolean isAr, int color, float sizeSp, boolean bold) {
        tv.setTextColor(color);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        tv.setTypeface(Typeface.SANS_SERIF, bold ? Typeface.BOLD : Typeface.NORMAL);
        tv.setGravity(isAr ? Gravity.RIGHT : Gravity.LEFT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            tv.setTextDirection(isAr ? View.TEXT_DIRECTION_RTL : View.TEXT_DIRECTION_LTR);
        }
    }

    private static boolean shouldUseSplitColumns(Context ctx) {
        DisplayMetrics dm = ctx.getResources().getDisplayMetrics();
        float widthDp = dm.widthPixels / dm.density;
        float fontScale = ctx.getResources().getConfiguration().fontScale;
        return widthDp >= 360f && fontScale <= 1.25f;
    }

    private static Activity unwrapActivity(Context ctx) {
        Context cur = ctx;
        int guard = 0;
        while (cur instanceof ContextWrapper && guard++ < 12) {
            if (cur instanceof Activity) {
                return (Activity) cur;
            }
            cur = ((ContextWrapper) cur).getBaseContext();
        }
        return cur instanceof Activity ? (Activity) cur : null;
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

    private static void setMarginStartCompat(LinearLayout.LayoutParams lp, int px, boolean isAr) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginStart(px);
        } else if (isAr) {
            lp.rightMargin = px;
        } else {
            lp.leftMargin = px;
        }
    }

    private static WireGuardManager.TunnelConfig collectInputs(
            String id,
            boolean enabled,
            boolean routeCalls,
            EditText profileName,
            EditText privKey,
            EditText presharedKey,
            EditText address,
            EditText dns,
            EditText pubKey,
            EditText endpoint,
            EditText keepAlive,
            EditText mtu,
            EditText jc,
            EditText jmin,
            EditText jmax,
            EditText s1,
            EditText s2,
            EditText s3,
            EditText s4,
            EditText h1,
            EditText h2,
            EditText h3,
            EditText h4
    ) {
        WireGuardManager.TunnelConfig cfg = new WireGuardManager.TunnelConfig();
        cfg.id = id;
        cfg.enabled = enabled;
        cfg.routeCalls = routeCalls;
        cfg.name = textOf(profileName);
        cfg.privateKey = textOf(privKey);
        cfg.presharedKey = textOf(presharedKey);
        cfg.address = textOf(address).isEmpty() ? "10.0.0.2/32" : textOf(address);
        cfg.dns = textOf(dns).isEmpty() ? "1.1.1.1" : textOf(dns);
        cfg.publicKey = textOf(pubKey);
        cfg.endpoint = textOf(endpoint);
        cfg.keepAlive = parsePositiveIntOrDefault(textOf(keepAlive), 25);
        cfg.mtu = parsePositiveIntOrDefault(textOf(mtu), 1280);
        cfg.jc = Math.max(0, Math.min(15, parsePositiveIntOrDefault(textOf(jc), 0)));
        cfg.jmin = Math.max(0, Math.min(1200, parsePositiveIntOrDefault(textOf(jmin), 0)));
        cfg.jmax = Math.max(0, Math.min(1200, parsePositiveIntOrDefault(textOf(jmax), 0)));
        cfg.s1 = Math.max(0, Math.min(512, parsePositiveIntOrDefault(textOf(s1), 0)));
        cfg.s2 = Math.max(0, Math.min(512, parsePositiveIntOrDefault(textOf(s2), 0)));
        cfg.s3 = Math.max(0, Math.min(512, parsePositiveIntOrDefault(textOf(s3), 0)));
        cfg.s4 = Math.max(0, Math.min(512, parsePositiveIntOrDefault(textOf(s4), 0)));
        cfg.h1 = textOf(h1);
        cfg.h2 = textOf(h2);
        cfg.h3 = textOf(h3);
        cfg.h4 = textOf(h4);
        return cfg;
    }

    private static int parsePositiveIntOrDefault(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static String textOf(EditText editText) {
        return editText.getText() == null ? "" : editText.getText().toString().trim();
    }
}
