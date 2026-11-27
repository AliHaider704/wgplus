package org.telegram.wgplus.module;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Handler;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.text.method.SingleLineTransformationMethod;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Reusable styled controls, RTL layout helpers, and the progressive-disclosure server/AWG editor form
 * extracted from {@link WireGuardDialog}.
 */
final class WgDialogWidgets {

    private WgDialogWidgets() {
    }

    /** Holds the 20 server/AmneziaWG inputs so draft capture works regardless of collapse state. */
    static final class EditorForm {
        final EditText profileNameInput;
        final EditText privateKeyInput;
        final EditText addressInput;
        final EditText dnsInput;
        final EditText publicKeyInput;
        final EditText endpointInput;
        final EditText keepAliveInput;
        final EditText presharedKeyInput;
        final EditText mtuInput;
        final EditText jcInput;
        final EditText jminInput;
        final EditText jmaxInput;
        final EditText s1Input;
        final EditText s2Input;
        final EditText s3Input;
        final EditText s4Input;
        final EditText h1Input;
        final EditText h2Input;
        final EditText h3Input;
        final EditText h4Input;
        final EditText i1Input;
        final EditText reservedInput;

        EditorForm(
                Context ctx,
                WireGuardDialog.DialogSessionState state,
                boolean isAr,
                WgTheme theme
        ) {
            profileNameInput = createProseEditText(
                    ctx, WgStrings.hintProfileName(isAr), WgStrings.localizeProfileName(state.draft.name, isAr), isAr, theme
            );
            privateKeyInput = createSecretTechnicalEditText(
                    ctx, WgStrings.hintPrivateKey(isAr), state.draft.privateKey, state.showPrivateKey, theme
            );
            addressInput = createTechnicalEditText(
                    ctx, WgStrings.hintAddress(isAr), state.draft.address,
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            dnsInput = createTechnicalEditText(
                    ctx, WgStrings.hintDns(isAr), state.draft.dns,
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            publicKeyInput = createTechnicalEditText(
                    ctx, WgStrings.hintPublicKey(isAr), state.draft.publicKey,
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            endpointInput = createTechnicalEditText(
                    ctx, WgStrings.hintEndpoint(isAr), state.draft.endpoint,
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            keepAliveInput = createTechnicalEditText(
                    ctx, WgStrings.hintKeepAlive(isAr),
                    String.valueOf(state.draft.keepAlive > 0 ? state.draft.keepAlive : 25),
                    InputType.TYPE_CLASS_NUMBER, theme
            );
            presharedKeyInput = createSecretTechnicalEditText(
                    ctx, WgStrings.hintPresharedKey(isAr), state.draft.presharedKey, state.showPresharedKey, theme
            );
            mtuInput = createTechnicalEditText(
                    ctx, WgStrings.hintMtu(isAr),
                    String.valueOf(state.draft.mtu > 0 ? state.draft.mtu : 1280),
                    InputType.TYPE_CLASS_NUMBER, theme
            );

            jcInput = createTechnicalEditText(
                    ctx, "0", state.draft.jc > 0 ? String.valueOf(state.draft.jc) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            jminInput = createTechnicalEditText(
                    ctx, "50", state.draft.jmin > 0 ? String.valueOf(state.draft.jmin) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            jmaxInput = createTechnicalEditText(
                    ctx, "250", state.draft.jmax > 0 ? String.valueOf(state.draft.jmax) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            s1Input = createTechnicalEditText(
                    ctx, "0", state.draft.s1 > 0 ? String.valueOf(state.draft.s1) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            s2Input = createTechnicalEditText(
                    ctx, "0", state.draft.s2 > 0 ? String.valueOf(state.draft.s2) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            s3Input = createTechnicalEditText(
                    ctx, "0", state.draft.s3 > 0 ? String.valueOf(state.draft.s3) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            s4Input = createTechnicalEditText(
                    ctx, "0", state.draft.s4 > 0 ? String.valueOf(state.draft.s4) : "", InputType.TYPE_CLASS_NUMBER, theme
            );
            h1Input = createTechnicalEditText(
                    ctx, "100000-200000", state.draft.h1, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            h2Input = createTechnicalEditText(
                    ctx, "200001-300000", state.draft.h2, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            h3Input = createTechnicalEditText(
                    ctx, "300001-400000", state.draft.h3, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            h4Input = createTechnicalEditText(
                    ctx, "400001-500000", state.draft.h4, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            i1Input = createTechnicalEditText(
                    ctx, "<b 0xc70000000108><r 8><b 0x0000449e><r 1200>", state.draft.i1,
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
            reservedInput = createTechnicalEditText(
                    ctx, "12,34,56", state.draft.reserved,
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, theme
            );
        }

        WireGuardManager.TunnelConfig captureInto(WireGuardManager.TunnelConfig base, boolean enabled, boolean routeCalls) {
            return collectInputs(
                    base,
                    enabled,
                    routeCalls,
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
                    h4Input,
                    i1Input,
                    reservedInput
            );
        }

        void focusProfileName() {
            profileNameInput.requestFocus();
        }

        void appendExpandedView(
                final Context ctx,
                final ClassLoader telegramClassLoader,
                final String moduleApkPath,
                final Handler mainHandler,
                final LinearLayout configCard,
                final WireGuardDialog.DialogSessionState state,
                final boolean isAr,
                final WgTheme theme,
                final Runnable captureDraftInputs,
                final Runnable rebuildUi
        ) {
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

            addFieldToContainer(formWrap, ctx, WgStrings.labelEndpoint(isAr), endpointInput, isAr, theme, WgTheme.dp(ctx, 10));
            addFieldToContainer(formWrap, ctx, WgStrings.labelKeepAlive(isAr), keepAliveInput, isAr, theme, WgTheme.dp(ctx, 10));

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

                LinearLayout awgPresetRow1 = new LinearLayout(ctx);
                awgPresetRow1.setOrientation(LinearLayout.HORIZONTAL);
                LinearLayout.LayoutParams awgPresetLp1 = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                awgPresetLp1.bottomMargin = WgTheme.dp(ctx, 6);

                Button awgClearBtn = createChipButton(ctx, WgStrings.awgPresetOffBtn(isAr), theme, false);
                Button awgPresetBtn = createChipButton(ctx, WgStrings.awgPresetVanillaBtn(isAr), theme, false);
                Button awgQuic15Btn = createChipButton(ctx, WgStrings.awgPresetQuic15Btn(isAr), theme, false);

                awgPresetBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    state.draft.jc = 4;
                    state.draft.jmin = 50;
                    state.draft.jmax = 250;
                    WireGuardManager.saveConfig(ctx, state.draft);
                    Toast.makeText(ctx, WgStrings.toastAwgPresetApplied(isAr), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                });

                awgQuic15Btn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    state.draft.jc = 4;
                    state.draft.jmin = 40;
                    state.draft.jmax = 120;
                    state.draft.i1 = "<b 0xc70000000108><r 8><b 0x0000449e><r 1200>";
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
                    state.draft.i1 = "";
                    state.draft.i2 = "";
                    state.draft.i3 = "";
                    state.draft.i4 = "";
                    state.draft.i5 = "";
                    state.draft.reserved = "";
                    WireGuardManager.saveConfig(ctx, state.draft);
                    Toast.makeText(ctx, WgStrings.toastAwgCleared(isAr), Toast.LENGTH_SHORT).show();
                    rebuildUi.run();
                });

                LinearLayout.LayoutParams prLp1 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                setMarginEndCompat(prLp1, WgTheme.dp(ctx, 6), isAr);
                LinearLayout.LayoutParams prLp2 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                awgPresetRow1.addView(awgClearBtn, prLp1);
                awgPresetRow1.addView(awgPresetBtn, prLp2);
                advBox.addView(awgPresetRow1, awgPresetLp1);

                LinearLayout.LayoutParams prLpQ = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                prLpQ.bottomMargin = WgTheme.dp(ctx, 8);
                advBox.addView(awgQuic15Btn, prLpQ);

                Button rawAwgToggleBtn = createSecondaryButton(
                        ctx,
                        WgStrings.awgRawToggleLabel(isAr, state.rawAwgFieldsExpanded),
                        theme
                );
                rawAwgToggleBtn.setContentDescription("wgplus_dlg_toggle_raw_awg");
                rawAwgToggleBtn.setOnClickListener(v -> {
                    captureDraftInputs.run();
                    state.rawAwgFieldsExpanded = !state.rawAwgFieldsExpanded;
                    rebuildUi.run();
                });
                LinearLayout.LayoutParams rawToggleLp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                rawToggleLp.bottomMargin = WgTheme.dp(ctx, 10);
                advBox.addView(rawAwgToggleBtn, rawToggleLp);

                if (state.rawAwgFieldsExpanded) {
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
                        addFieldToContainer(advBox, ctx, WgStrings.labelAwgH4(isAr), h4Input, isAr, theme, WgTheme.dp(ctx, 8));
                    }
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgI1(isAr), i1Input, isAr, theme, WgTheme.dp(ctx, 8));
                    addFieldToContainer(advBox, ctx, WgStrings.labelAwgReserved(isAr), reservedInput, isAr, theme, WgTheme.dp(ctx, 10));
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
                    WgDialogModals.showQrCodeModal(ctx, state.draft, isAr, theme);
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
    }

    static LinearLayout createSwitchRow(
            Context ctx,
            String labelText,
            final Switch sw,
            boolean isAr,
            WgTheme theme
    ) {
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(WgTheme.dp(ctx, 46));
        row.setClickable(true);
        row.setFocusable(true);
        row.setPadding(0, WgTheme.dp(ctx, 7), 0, WgTheme.dp(ctx, 7));

        TextView tv = new TextView(ctx);
        applyProseTextStyle(tv, isAr, theme.textPrimary, 13.5f, false);
        tv.setText(labelText);
        LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(tvLp, WgTheme.dp(ctx, 10), isAr);
        row.addView(tv, tvLp);

        styleSwitchColors(sw, theme);
        row.addView(sw);
        row.setOnClickListener(v -> sw.toggle());
        return row;
    }

    static void styleSwitchColors(Switch sw, WgTheme theme) {
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

    static View createTwoColumnRow(
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

    static void addSecretFieldWithToggle(
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

    static View createDivider(Context ctx, WgTheme theme) {
        View v = new View(ctx);
        v.setBackgroundColor(theme.borderSubtle);
        v.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                Math.max(1, WgTheme.dp(ctx, 1))
        ));
        return v;
    }

    static LinearLayout.LayoutParams createCardMarginParams(Context ctx, float bottomDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        lp.bottomMargin = WgTheme.dp(ctx, bottomDp);
        return lp;
    }

    static EditText createProseEditText(
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
        edit.setTypeface(Typeface.DEFAULT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            edit.setLetterSpacing(0f);
        }
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
        int pH = WgTheme.dp(ctx, 12);
        int pV = WgTheme.dp(ctx, 11);
        edit.setPadding(pH, pV, pH, pV);
        edit.setMinimumHeight(WgTheme.dp(ctx, 46));
        return edit;
    }

    static EditText createSecretTechnicalEditText(
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
        syncTechnicalHintOrValueStyle(edit, hintText);
        return edit;
    }

    static EditText createTechnicalEditText(
            Context ctx,
            final String hintText,
            String initialValue,
            int inputType,
            WgTheme theme
    ) {
        final EditText edit = new EditText(ctx);
        edit.setHint(hintText);
        edit.setHintTextColor(theme.textHint);
        edit.setTextColor(theme.textPrimary);
        edit.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f);
        edit.setSingleLine(true);
        edit.setInputType(inputType);
        edit.setFocusable(true);
        edit.setFocusableInTouchMode(true);
        edit.setText(initialValue != null ? initialValue : "");
        syncTechnicalHintOrValueStyle(edit, hintText);
        if (containsArabicScript(hintText)) {
            edit.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override
                public void afterTextChanged(Editable s) {
                    syncTechnicalHintOrValueStyle(edit, hintText);
                }
            });
        }
        edit.setBackground(WgTheme.inputWellBackground(ctx, theme));
        int pH = WgTheme.dp(ctx, 12);
        int pV = WgTheme.dp(ctx, 11);
        edit.setPadding(pH, pV, pH, pV);
        edit.setMinimumHeight(WgTheme.dp(ctx, 46));
        return edit;
    }

    static void syncTechnicalHintOrValueStyle(EditText edit, String hintText) {
        boolean emptyWithArabicHint = (edit.getText() == null || edit.getText().length() == 0)
                && containsArabicScript(hintText);
        if (emptyWithArabicHint) {
            edit.setTypeface(Typeface.DEFAULT);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                edit.setLetterSpacing(0f);
            }
            edit.setGravity(Gravity.RIGHT | Gravity.CENTER_VERTICAL);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                edit.setTextDirection(View.TEXT_DIRECTION_RTL);
            }
        } else {
            edit.setTypeface(Typeface.MONOSPACE);
            edit.setGravity(Gravity.LEFT | Gravity.CENTER_VERTICAL);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                edit.setTextDirection(View.TEXT_DIRECTION_LTR);
            }
        }
    }

    static boolean containsArabicScript(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= '\u0600' && c <= '\u06FF') {
                return true;
            }
        }
        return false;
    }

    static void addFieldToContainer(
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

    static Button createPrimaryAccentButton(Context ctx, String text, WgTheme theme) {
        Button btn = baseButton(ctx, text, theme.onAccent, 48);
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

    static Button createDisconnectButton(Context ctx, String text, WgTheme theme) {
        Button btn = baseButton(ctx, text, theme.stoppedText, 48);
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

    static Button createSecondaryButton(Context ctx, String text, WgTheme theme) {
        Button btn = baseButton(ctx, text, theme.textPrimary, 48);
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

    static Button createChipButton(Context ctx, String text, WgTheme theme, boolean selected) {
        Button btn = new Button(ctx);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(selected ? theme.onAccent : theme.textPrimary);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        btn.setLineSpacing(WgTheme.dp(ctx, 2), 1.05f);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            btn.setLetterSpacing(0f);
        }
        int minH = WgTheme.dp(ctx, 44);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setMinWidth(WgTheme.dp(ctx, 44));
        btn.setMinimumWidth(WgTheme.dp(ctx, 44));
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 11), WgTheme.dp(ctx, 7), WgTheme.dp(ctx, 11), WgTheme.dp(ctx, 7));
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

    static Button createDangerChipButton(Context ctx, String text, WgTheme theme) {
        Button btn = new Button(ctx);
        btn.setAllCaps(false);
        btn.setText(text);
        btn.setTextColor(theme.stoppedText);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f);
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        btn.setLineSpacing(WgTheme.dp(ctx, 2), 1.05f);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            btn.setLetterSpacing(0f);
        }
        int minH = WgTheme.dp(ctx, 44);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setMinWidth(WgTheme.dp(ctx, 44));
        btn.setMinimumWidth(WgTheme.dp(ctx, 44));
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 11), WgTheme.dp(ctx, 7), WgTheme.dp(ctx, 11), WgTheme.dp(ctx, 7));
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
        btn.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        btn.setSingleLine(true);
        btn.setMaxLines(1);
        btn.setEllipsize(TextUtils.TruncateAt.END);
        btn.setGravity(Gravity.CENTER);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            btn.setLetterSpacing(0f);
        }
        int minH = WgTheme.dp(ctx, minHeightDp);
        btn.setMinHeight(minH);
        btn.setMinimumHeight(minH);
        btn.setFocusable(true);
        btn.setPadding(WgTheme.dp(ctx, 12), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 12), WgTheme.dp(ctx, 10));
        return btn;
    }

    static void applyProseTextStyle(TextView tv, boolean isAr, int color, float sizeSp, boolean bold) {
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

    static boolean shouldUseSplitColumns(Context ctx) {
        DisplayMetrics dm = ctx.getResources().getDisplayMetrics();
        float widthDp = dm.widthPixels / dm.density;
        float fontScale = ctx.getResources().getConfiguration().fontScale;
        return widthDp >= 360f && fontScale <= 1.25f;
    }

    static Activity unwrapActivity(Context ctx) {
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

    static void setMarginEndCompat(LinearLayout.LayoutParams lp, int px, boolean isAr) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginEnd(px);
        } else if (isAr) {
            lp.leftMargin = px;
        } else {
            lp.rightMargin = px;
        }
    }

    static void setMarginStartCompat(LinearLayout.LayoutParams lp, int px, boolean isAr) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginStart(px);
        } else if (isAr) {
            lp.rightMargin = px;
        } else {
            lp.leftMargin = px;
        }
    }

    static WireGuardManager.TunnelConfig collectInputs(
            WireGuardManager.TunnelConfig base,
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
            EditText h4,
            EditText i1,
            EditText reserved
    ) {
        WireGuardManager.TunnelConfig cfg = base != null ? base.copy() : new WireGuardManager.TunnelConfig();
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
        cfg.i1 = textOf(i1);
        cfg.reserved = textOf(reserved);
        return cfg;
    }

    static int parsePositiveIntOrDefault(String raw, int fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    static String textOf(EditText editText) {
        return editText.getText() == null ? "" : editText.getText().toString().trim();
    }
}
