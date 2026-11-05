package org.telegram.wgplus.module;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.TypedValue;

/**
 * Icon-free, sticker-free Dark and Light theme tokens (all foreground/background pairs >= 5.45:1 WCAG AA).
 */
public final class WgTheme {

    public final boolean isDark;

    // 3 core neutrals + 1 deliberate accent
    public final int surfaceBase;
    public final int surfaceCard;
    public final int surfaceInput;
    public final int surfaceFooter;
    public final int surfaceSecondaryBtn;
    public final int surfaceSecondaryBtnPressed;
    public final int borderSubtle;
    public final int textPrimary;
    public final int textSecondary;
    public final int textHint;

    public final int accentPrimary;
    public final int accentPressed;
    public final int onAccent;

    // Semantic state tokens strictly for real tunnel status and disconnect control
    public final int activeBg;
    public final int activeBorder;
    public final int activeText;
    public final int activeDot;

    public final int pendingBg;
    public final int pendingBorder;
    public final int pendingText;
    public final int pendingDot;

    public final int stoppedBg;
    public final int stoppedBorder;
    public final int stoppedText;
    public final int stoppedDot;

    private WgTheme(boolean dark) {
        this.isDark = dark;
        if (dark) {
            surfaceBase = Color.parseColor("#151E27");
            surfaceCard = Color.parseColor("#1E2936");
            surfaceInput = Color.parseColor("#10171E");
            surfaceFooter = Color.parseColor("#111921");
            surfaceSecondaryBtn = Color.parseColor("#253445");
            surfaceSecondaryBtnPressed = Color.parseColor("#2F4257");
            borderSubtle = Color.parseColor("#2D3D4F");
            textPrimary = Color.parseColor("#F1F5F9");
            textSecondary = Color.parseColor("#9FB1C4");
            textHint = Color.parseColor("#8295A9");

            accentPrimary = Color.parseColor("#1A6BB8");
            accentPressed = Color.parseColor("#155899");
            onAccent = Color.parseColor("#FFFFFF");

            activeBg = Color.parseColor("#122B24");
            activeBorder = Color.parseColor("#1F6F54");
            activeText = Color.parseColor("#6EE7B7");
            activeDot = Color.parseColor("#34D399");

            pendingBg = Color.parseColor("#1A293B");
            pendingBorder = Color.parseColor("#2B5B8C");
            pendingText = Color.parseColor("#BFDBFE");
            pendingDot = Color.parseColor("#60A5FA");

            stoppedBg = Color.parseColor("#2D191E");
            stoppedBorder = Color.parseColor("#7F2933");
            stoppedText = Color.parseColor("#FCA5A5");
            stoppedDot = Color.parseColor("#F87171");
        } else {
            surfaceBase = Color.parseColor("#F4F7FA");
            surfaceCard = Color.parseColor("#FFFFFF");
            surfaceInput = Color.parseColor("#EEF3F8");
            surfaceFooter = Color.parseColor("#E9EFF5");
            surfaceSecondaryBtn = Color.parseColor("#E4ECF4");
            surfaceSecondaryBtnPressed = Color.parseColor("#D5E2EE");
            borderSubtle = Color.parseColor("#CFD9E4");
            textPrimary = Color.parseColor("#0F172A");
            textSecondary = Color.parseColor("#475569");
            textHint = Color.parseColor("#526071");

            accentPrimary = Color.parseColor("#1664B0");
            accentPressed = Color.parseColor("#114F8C");
            onAccent = Color.parseColor("#FFFFFF");

            activeBg = Color.parseColor("#ECFDF5");
            activeBorder = Color.parseColor("#6EE7B7");
            activeText = Color.parseColor("#065F46");
            activeDot = Color.parseColor("#059669");

            pendingBg = Color.parseColor("#EFF6FF");
            pendingBorder = Color.parseColor("#93C5FD");
            pendingText = Color.parseColor("#1E3A8A");
            pendingDot = Color.parseColor("#2563EB");

            stoppedBg = Color.parseColor("#FEF2F2");
            stoppedBorder = Color.parseColor("#FCA5A5");
            stoppedText = Color.parseColor("#991B1B");
            stoppedDot = Color.parseColor("#DC2626");
        }
    }

    public static WgTheme of(boolean dark) {
        return new WgTheme(dark);
    }

    public static int dp(Context context, float value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP,
                value,
                context.getResources().getDisplayMetrics()
        ));
    }

    public static GradientDrawable cardBackground(Context ctx, int fillColor, int borderColor, float radiusDp) {
        GradientDrawable gd = new GradientDrawable();
        gd.setShape(GradientDrawable.RECTANGLE);
        gd.setColor(fillColor);
        gd.setCornerRadius(dp(ctx, radiusDp));
        gd.setStroke(Math.max(1, dp(ctx, 1)), borderColor);
        return gd;
    }

    public static GradientDrawable statusDot(Context ctx, int color) {
        return statusDot(ctx, color, 8f);
    }

    public static GradientDrawable statusDot(Context ctx, int color, float diameterDp) {
        GradientDrawable dot = new GradientDrawable();
        dot.setShape(GradientDrawable.OVAL);
        dot.setColor(color);
        int size = dp(ctx, diameterDp);
        dot.setSize(size, size);
        return dot;
    }

    /**
     * Interactive button/chip surface with explicit 2dp keyboard focus ring (R-32) and tactile press state.
     */
    public static StateListDrawable interactiveBackground(
            Context ctx,
            int normalFill,
            int pressedFill,
            int normalBorder,
            int focusBorder,
            float radiusDp
    ) {
        float r = dp(ctx, radiusDp);
        int strokeNormal = Math.max(1, dp(ctx, 1));
        int strokeFocus = Math.max(2, dp(ctx, 2));

        GradientDrawable pressed = new GradientDrawable();
        pressed.setShape(GradientDrawable.RECTANGLE);
        pressed.setColor(pressedFill);
        pressed.setCornerRadius(r);
        pressed.setStroke(strokeFocus, focusBorder);

        GradientDrawable focused = new GradientDrawable();
        focused.setShape(GradientDrawable.RECTANGLE);
        focused.setColor(normalFill);
        focused.setCornerRadius(r);
        focused.setStroke(strokeFocus, focusBorder);

        GradientDrawable normal = new GradientDrawable();
        normal.setShape(GradientDrawable.RECTANGLE);
        normal.setColor(normalFill);
        normal.setCornerRadius(r);
        normal.setStroke(strokeNormal, normalBorder);

        StateListDrawable sld = new StateListDrawable();
        sld.addState(new int[]{android.R.attr.state_pressed}, pressed);
        sld.addState(new int[]{android.R.attr.state_focused}, focused);
        sld.addState(new int[]{}, normal);
        return sld;
    }

    public static StateListDrawable inputWellBackground(Context ctx, WgTheme theme) {
        return interactiveBackground(
                ctx,
                theme.surfaceInput,
                theme.surfaceInput,
                theme.borderSubtle,
                theme.accentPrimary,
                8f
        );
    }
}
