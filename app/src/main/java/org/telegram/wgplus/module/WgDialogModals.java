package org.telegram.wgplus.module;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import static org.telegram.wgplus.module.WgDialogWidgets.applyProseTextStyle;
import static org.telegram.wgplus.module.WgDialogWidgets.createPrimaryAccentButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createSecondaryButton;
import static org.telegram.wgplus.module.WgDialogWidgets.createSwitchRow;
import static org.telegram.wgplus.module.WgDialogWidgets.setMarginEndCompat;

/**
 * Secondary modals (QR code, delete confirmation, backup passphrase, diagnostics) and telemetry box renderer
 * extracted from {@link WireGuardDialog}.
 */
final class WgDialogModals {

    interface PassphraseConsumer {
        void onPassphrase(String passphrase);
    }

    private WgDialogModals() {
    }

    /**
     * Displays a crisp high-contrast scannable ISO QR code modal for the given profile (closable via Escape / Back).
     */
    static void showQrCodeModal(
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

    static void showDeleteConfirmDialog(
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
        Button confirmBtn = WgDialogWidgets.createDisconnectButton(ctx, WgStrings.deleteInlineBtn(isAr), theme);

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

    static void promptBackupPassphraseModal(
            Context ctx,
            boolean isAr,
            WgTheme theme,
            boolean isExport,
            PassphraseConsumer consumer
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
        title.setText(WgStrings.backupPassphraseTitle(isAr, isExport));
        box.addView(title);

        EditText passInput = new EditText(ctx);
        passInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        passInput.setHint(WgStrings.backupPassphraseHint(isAr));
        passInput.setHintTextColor(theme.textSecondary);
        passInput.setTextColor(theme.textPrimary);
        passInput.setBackground(WgTheme.cardBackground(ctx, theme.surfaceInput, theme.borderSubtle, 8f));
        int ep = WgTheme.dp(ctx, 12);
        passInput.setPadding(ep, ep, ep, ep);
        LinearLayout.LayoutParams ipLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        ipLp.topMargin = WgTheme.dp(ctx, 12);
        ipLp.bottomMargin = WgTheme.dp(ctx, 14);
        box.addView(passInput, ipLp);

        LinearLayout btnRow = new LinearLayout(ctx);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        Button cancelBtn = createSecondaryButton(ctx, WgStrings.cancelBtn(isAr), theme);
        Button okBtn = createPrimaryAccentButton(ctx, isExport ? WgStrings.backupEncryptBtn(isAr) : WgStrings.backupDecryptBtn(isAr), theme);

        LinearLayout.LayoutParams c1 = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(c1, WgTheme.dp(ctx, 8), isAr);
        btnRow.addView(cancelBtn, c1);
        btnRow.addView(okBtn, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        box.addView(btnRow);

        final AlertDialog dlg = new AlertDialog.Builder(ctx)
                .setView(box)
                .setCancelable(true)
                .create();
        cancelBtn.setOnClickListener(v -> dlg.dismiss());
        okBtn.setOnClickListener(v -> {
            String val = passInput.getText() != null ? passInput.getText().toString() : "";
            dlg.dismiss();
            consumer.onPassphrase(val);
        });
        dlg.show();
        if (dlg.getWindow() != null) {
            dlg.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        }
    }

    static void showDiagnosticsModal(
            final Context ctx,
            final String moduleApkPath,
            final boolean isAr,
            final WgTheme theme
    ) {
        LinearLayout box = new LinearLayout(ctx);
        box.setOrientation(LinearLayout.VERTICAL);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            box.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        }
        box.setBackground(WgTheme.cardBackground(ctx, theme.surfaceCard, theme.borderSubtle, 16f));
        int p = WgTheme.dp(ctx, 18);
        box.setPadding(p, p, p, p);

        TextView title = new TextView(ctx);
        applyProseTextStyle(title, isAr, theme.textPrimary, 16f, true);
        title.setText(WgStrings.diagnosticsTitle(isAr));
        box.addView(title);

        TextView desc = new TextView(ctx);
        applyProseTextStyle(desc, isAr, theme.textSecondary, 12.5f, false);
        desc.setText(WgStrings.diagnosticsDesc(isAr));
        LinearLayout.LayoutParams descLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        descLp.topMargin = WgTheme.dp(ctx, 4);
        descLp.bottomMargin = WgTheme.dp(ctx, 10);
        box.addView(desc, descLp);

        LinearLayout telemetryCard = new LinearLayout(ctx);
        telemetryCard.setOrientation(LinearLayout.VERTICAL);
        telemetryCard.setBackground(WgTheme.cardBackground(ctx, theme.surfaceInput, theme.borderSubtle, 8f));
        telemetryCard.setPadding(WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 4), WgTheme.dp(ctx, 10), WgTheme.dp(ctx, 8));

        final Switch autoTelemetrySw = new Switch(ctx);
        autoTelemetrySw.setContentDescription("wgplus_sw_auto_telemetry");
        autoTelemetrySw.setChecked(WgTelemetryReporter.isOptedIn(ctx));
        telemetryCard.addView(createSwitchRow(ctx, WgStrings.telemetryAutoSwitchLabel(isAr), autoTelemetrySw, isAr, theme));

        final TextView autoSummaryTv = new TextView(ctx);
        applyProseTextStyle(autoSummaryTv, isAr, theme.textSecondary, 11.5f, false);
        autoSummaryTv.setText(WgStrings.telemetryAutoStatusSummary(isAr, autoTelemetrySw.isChecked()));
        telemetryCard.addView(autoSummaryTv);

        autoTelemetrySw.setOnCheckedChangeListener((btn, isChecked) -> {
            WgTelemetryReporter.setOptIn(ctx, isChecked);
            autoSummaryTv.setText(WgStrings.telemetryAutoStatusSummary(isAr, isChecked));
        });

        LinearLayout.LayoutParams tcLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        tcLp.bottomMargin = WgTheme.dp(ctx, 10);
        box.addView(telemetryCard, tcLp);

        ScrollView logScroll = new ScrollView(ctx);
        logScroll.setBackground(WgTheme.cardBackground(ctx, theme.surfaceInput, theme.borderSubtle, 8f));
        int lPad = WgTheme.dp(ctx, 10);
        logScroll.setPadding(lPad, lPad, lPad, lPad);
        final TextView reportView = new TextView(ctx);
        reportView.setText(WgStrings.diagnosticsLoading(isAr));
        reportView.setTextColor(theme.textPrimary);
        reportView.setTextSize(11.5f);
        reportView.setTypeface(Typeface.MONOSPACE);
        reportView.setTextIsSelectable(true);
        logScroll.addView(reportView, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));
        LinearLayout.LayoutParams scLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                WgTheme.dp(ctx, 185)
        );
        scLp.bottomMargin = WgTheme.dp(ctx, 12);
        box.addView(logScroll, scLp);

        final String[] latestReport = new String[]{""};
        final Handler h = new Handler(Looper.getMainLooper());
        final Runnable loadReport = () -> {
            reportView.setText(WgStrings.diagnosticsLoading(isAr));
            new Thread(() -> {
                String built;
                try {
                    built = WgDiagnosticsLog.buildMarkdownReport(ctx, moduleApkPath);
                } catch (Throwable t) {
                    built = WgStrings.diagnosticsEmpty(isAr);
                }
                final String finalBuilt = built;
                latestReport[0] = finalBuilt;
                h.post(() -> reportView.setText(finalBuilt));
            }, "wgplus-diag-build").start();
        };

        LinearLayout actionRow1 = new LinearLayout(ctx);
        actionRow1.setOrientation(LinearLayout.HORIZONTAL);
        Button copyBtn = createSecondaryButton(ctx, WgStrings.diagnosticsCopyBtn(isAr), theme);
        Button clearBtn = createSecondaryButton(ctx, WgStrings.diagnosticsClearBtn(isAr), theme);
        LinearLayout.LayoutParams r1a = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        setMarginEndCompat(r1a, WgTheme.dp(ctx, 8), isAr);
        actionRow1.addView(copyBtn, r1a);
        actionRow1.addView(clearBtn, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        LinearLayout.LayoutParams ar1Lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        ar1Lp.bottomMargin = WgTheme.dp(ctx, 8);
        box.addView(actionRow1, ar1Lp);

        final Button sendNowBtn = createPrimaryAccentButton(ctx, WgStrings.telemetrySendNowBtn(isAr, false), theme);
        sendNowBtn.setContentDescription("wgplus_btn_send_telemetry_now");
        LinearLayout.LayoutParams snLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        snLp.bottomMargin = WgTheme.dp(ctx, 8);
        box.addView(sendNowBtn, snLp);

        Button githubBtn = createSecondaryButton(ctx, WgStrings.diagnosticsGithubBtn(isAr), theme);
        LinearLayout.LayoutParams ghLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        ghLp.bottomMargin = WgTheme.dp(ctx, 8);
        box.addView(githubBtn, ghLp);

        Button closeBtn = createSecondaryButton(ctx, WgStrings.closeBtn(isAr), theme);
        box.addView(closeBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        final AlertDialog diagDialog = new AlertDialog.Builder(ctx)
                .setView(box)
                .setCancelable(true)
                .create();

        copyBtn.setOnClickListener(v -> {
            String txt = latestReport[0].isEmpty()
                    ? WgDiagnosticsLog.buildMarkdownReport(ctx, moduleApkPath)
                    : latestReport[0];
            ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("WireGuardPlusDiagnostics", txt));
                Toast.makeText(ctx, WgStrings.diagnosticsCopiedToast(isAr), Toast.LENGTH_SHORT).show();
            }
        });
        clearBtn.setOnClickListener(v -> {
            WgDiagnosticsLog.clear();
            Toast.makeText(ctx, WgStrings.diagnosticsClearedToast(isAr), Toast.LENGTH_SHORT).show();
            loadReport.run();
        });
        sendNowBtn.setOnClickListener(v -> {
            sendNowBtn.setEnabled(false);
            sendNowBtn.setText(WgStrings.telemetrySendNowBtn(isAr, true));
            WgTelemetryReporter.sendManualReportAsync(ctx, moduleApkPath, latestReport[0], statusCode -> h.post(() -> {
                sendNowBtn.setEnabled(true);
                sendNowBtn.setText(WgStrings.telemetrySendNowBtn(isAr, false));
                if (statusCode == WgTelemetryReporter.STATUS_SENT) {
                    Toast.makeText(ctx, WgStrings.telemetrySentSuccessToast(isAr), Toast.LENGTH_LONG).show();
                } else if (statusCode == WgTelemetryReporter.STATUS_RATE_LIMITED) {
                    Toast.makeText(ctx, WgStrings.telemetryRateLimitedToast(isAr), Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(ctx, WgStrings.telemetrySentFailedToast(isAr), Toast.LENGTH_LONG).show();
                }
            }));
        });
        githubBtn.setOnClickListener(v -> {
            String txt = latestReport[0].isEmpty()
                    ? WgDiagnosticsLog.buildMarkdownReport(ctx, moduleApkPath)
                    : latestReport[0];
            ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("WireGuardPlusDiagnostics", txt));
            }
            Toast.makeText(ctx, WgStrings.diagnosticsGithubToast(isAr), Toast.LENGTH_LONG).show();
            try {
                String env = Uri.encode(Build.MANUFACTURER + " " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ") - WireGuard Plus v" + WgStrings.VERSION_LABEL);
                Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/AliHaider704/wgplus/issues/new?template=bug_report.yml&environment=" + env));
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                ctx.startActivity(i);
            } catch (Throwable ignored) {
            }
        });
        closeBtn.setOnClickListener(v -> diagDialog.dismiss());

        diagDialog.show();
        if (diagDialog.getWindow() != null) {
            diagDialog.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        }
        loadReport.run();
    }

    static void renderTelemetryBox(
            Context ctx,
            LinearLayout box,
            Button verifyBtn,
            WireGuardDialog.DialogSessionState state,
            boolean routeCallsEnabled,
            boolean isAr,
            WgTheme theme
    ) {
        box.removeAllViews();
        if (state.verifyState == WireGuardDialog.VerifyUiState.IDLE) {
            verifyBtn.setEnabled(true);
            verifyBtn.setText(WgStrings.verifyBtnLabel(isAr));
            box.setVisibility(View.GONE);
            return;
        }

        box.setVisibility(View.VISIBLE);
        if (state.verifyState == WireGuardDialog.VerifyUiState.LOADING) {
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

        if (state.verifyState == WireGuardDialog.VerifyUiState.SUCCESS && state.verifyResult != null) {
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
        if (parent.getChildCount() > 1) {
            View divider = new View(ctx);
            divider.setBackgroundColor(theme.borderSubtle);
            divider.setAlpha(0.45f);
            LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    Math.max(1, WgTheme.dp(ctx, 1))
            );
            parent.addView(divider, divLp);
        }

        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            row.setLayoutDirection(isAr ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        }
        row.setPadding(0, WgTheme.dp(ctx, 7), 0, WgTheme.dp(ctx, 7));
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );

        TextView kView = new TextView(ctx);
        applyProseTextStyle(kView, isAr, theme.textSecondary, 12.5f, false);
        kView.setText(keyLabel);
        LinearLayout.LayoutParams kLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.9f);
        setMarginEndCompat(kLp, WgTheme.dp(ctx, 10), isAr);
        row.addView(kView, kLp);

        TextView vView = new TextView(ctx);
        applyProseTextStyle(vView, isAr, theme.textPrimary, 12.5f, true);
        if (monoValue) {
            vView.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                vView.setTextDirection(View.TEXT_DIRECTION_LTR);
            }
        } else if (isAr && Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            vView.setTextDirection(View.TEXT_DIRECTION_RTL);
        }
        vView.setGravity(isAr ? Gravity.LEFT : Gravity.RIGHT);
        vView.setText(valueText);
        row.addView(vView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.15f));

        parent.addView(row, rowLp);
    }
}
