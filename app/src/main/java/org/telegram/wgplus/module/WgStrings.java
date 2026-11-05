package org.telegram.wgplus.module;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Zero-leak bilingual localization catalog (Arabic RTL + English LTR).
 * Every UI label, state message, telemetry unit, country name, and error code is strictly localized.
 */
public final class WgStrings {

    public static final String LANG_AR = "ar";
    public static final String LANG_EN = "en";
    public static final String VERSION_LABEL = "1.3.0";

    private static final Map<String, String> AR_COUNTRIES = new HashMap<>();

    static {
        AR_COUNTRIES.put("AE", "الإمارات");
        AR_COUNTRIES.put("AL", "ألبانيا");
        AR_COUNTRIES.put("AM", "أرمينيا");
        AR_COUNTRIES.put("AR", "الأرجنتين");
        AR_COUNTRIES.put("AT", "النمسا");
        AR_COUNTRIES.put("AU", "أستراليا");
        AR_COUNTRIES.put("AZ", "أذربيجان");
        AR_COUNTRIES.put("BE", "بلجيكا");
        AR_COUNTRIES.put("BG", "بلغاريا");
        AR_COUNTRIES.put("BH", "البحرين");
        AR_COUNTRIES.put("BR", "البرازيل");
        AR_COUNTRIES.put("CA", "كندا");
        AR_COUNTRIES.put("CH", "سويسرا");
        AR_COUNTRIES.put("CY", "قبرص");
        AR_COUNTRIES.put("CZ", "التشيك");
        AR_COUNTRIES.put("DE", "ألمانيا");
        AR_COUNTRIES.put("DK", "الدنمارك");
        AR_COUNTRIES.put("EE", "إستونيا");
        AR_COUNTRIES.put("EG", "مصر");
        AR_COUNTRIES.put("ES", "إسبانيا");
        AR_COUNTRIES.put("FI", "فنلندا");
        AR_COUNTRIES.put("FR", "فرنسا");
        AR_COUNTRIES.put("GB", "المملكة المتحدة");
        AR_COUNTRIES.put("GE", "جورجيا");
        AR_COUNTRIES.put("GR", "اليونان");
        AR_COUNTRIES.put("HK", "هونغ كونغ");
        AR_COUNTRIES.put("HR", "كرواتيا");
        AR_COUNTRIES.put("HU", "المجر");
        AR_COUNTRIES.put("IE", "أيرلندا");
        AR_COUNTRIES.put("IN", "الهند");
        AR_COUNTRIES.put("IQ", "العراق");
        AR_COUNTRIES.put("IS", "آيسلندا");
        AR_COUNTRIES.put("IT", "إيطاليا");
        AR_COUNTRIES.put("JO", "الأردن");
        AR_COUNTRIES.put("JP", "اليابان");
        AR_COUNTRIES.put("KR", "كوريا الجنوبية");
        AR_COUNTRIES.put("KW", "الكويت");
        AR_COUNTRIES.put("KZ", "كازاخستان");
        AR_COUNTRIES.put("LB", "لبنان");
        AR_COUNTRIES.put("LT", "ليتوانيا");
        AR_COUNTRIES.put("LU", "لوكسمبورغ");
        AR_COUNTRIES.put("LV", "لاتفيا");
        AR_COUNTRIES.put("MD", "مولدوفا");
        AR_COUNTRIES.put("MY", "ماليزيا");
        AR_COUNTRIES.put("NL", "هولندا");
        AR_COUNTRIES.put("NO", "النرويج");
        AR_COUNTRIES.put("OM", "عُمان");
        AR_COUNTRIES.put("PL", "بولندا");
        AR_COUNTRIES.put("PT", "البرتغال");
        AR_COUNTRIES.put("QA", "قطر");
        AR_COUNTRIES.put("RO", "رومانيا");
        AR_COUNTRIES.put("RS", "صربيا");
        AR_COUNTRIES.put("SA", "السعودية");
        AR_COUNTRIES.put("SE", "السويد");
        AR_COUNTRIES.put("SG", "سنغافورة");
        AR_COUNTRIES.put("SI", "سلوفينيا");
        AR_COUNTRIES.put("SK", "سلوفاكيا");
        AR_COUNTRIES.put("TR", "تركيا");
        AR_COUNTRIES.put("UA", "أوكرانيا");
        AR_COUNTRIES.put("US", "الولايات المتحدة");
        AR_COUNTRIES.put("ZA", "جنوب أفريقيا");
    }

    private WgStrings() {
    }

    public enum ErrorCode {
        EMPTY_CLIPBOARD,
        INVALID_CONF,
        FILE_READ_FAILED,
        MISSING_PRIVATE_KEY,
        MISSING_PUBLIC_KEY,
        MISSING_ENDPOINT,
        MISSING_ADDRESS,
        INVALID_KEY_FORMAT,
        INVALID_KEY_LENGTH,
        TUNNEL_STOPPED,
        NO_ACTIVE_PORT,
        VERIFY_ROUTE_FAILED,
        NATIVE_BRIDGE_FAILED,
        QR_NOT_FOUND,
        QR_ENCODE_FAILED,
        BACKUP_INVALID,
        PING_ALL_FAILED,
        MTU_DISCOVERY_FAILED
    }

    public static final class WgException extends Exception {
        public final ErrorCode code;
        public final String detail;

        public WgException(ErrorCode code) {
            super(code.name());
            this.code = code;
            this.detail = "";
        }

        public WgException(ErrorCode code, String detail, Throwable cause) {
            super(code.name() + (detail != null && !detail.isEmpty() ? ": " + detail : ""), cause);
            this.code = code;
            this.detail = detail == null ? "" : detail;
        }
    }

    /**
     * Wraps technical LTR tokens (IP, CIDR, host:port) in Unicode Left-to-Right Isolate
     * so punctuation never flips inside RTL Arabic sentences.
     */
    public static String ltr(String token) {
        if (token == null || token.isEmpty()) {
            return "";
        }
        return "\u2066" + token + "\u2069";
    }

    public static String floatingTriggerLabel(boolean ar) {
        return ar ? "نفق وايرجارد" : "WireGuard";
    }

    public static String appTitle(boolean ar) {
        return ar ? "نفق وايرجارد بلس" : "WireGuard Plus";
    }

    public static String langToggleLabel(boolean ar) {
        // Displays target language in its own native script so users can always switch back
        return ar ? "English" : "العربية";
    }

    public static String themeToggleLabel(boolean ar, boolean isDark) {
        if (ar) {
            return isDark ? "فاتح" : "داكن";
        }
        return isDark ? "Light" : "Dark";
    }

    public static String statusActive(boolean ar, int port) {
        String addr = ltr("127.0.0.1:" + port);
        return ar ? ("متصل عبر " + addr) : ("Connected on " + addr);
    }

    public static String statusActiveWithProfile(boolean ar, String profileName, int port) {
        String addr = ltr("127.0.0.1:" + port);
        String cleanName = profileName == null ? "" : profileName.trim();
        if (cleanName.isEmpty()) {
            return statusActive(ar, port);
        }
        return ar
                ? ("متصل: " + cleanName + " (" + addr + ")")
                : ("Connected: " + cleanName + " (" + addr + ")");
    }

    public static String statusConnecting(boolean ar) {
        return ar ? "جارٍ بدء الاتصال..." : "Connecting...";
    }

    public static String statusSwitchingTo(boolean ar, String profileName) {
        String cleanName = profileName == null ? "" : profileName.trim();
        if (cleanName.isEmpty()) {
            return statusConnecting(ar);
        }
        return ar ? ("جارٍ التحويل إلى " + cleanName + "...") : ("Switching to " + cleanName + "...");
    }

    public static String statusStopped(boolean ar) {
        return ar ? "غير متصل" : "Disconnected";
    }

    public static String statusStoppedWithProfile(boolean ar, String profileName) {
        String cleanName = profileName == null ? "" : profileName.trim();
        if (cleanName.isEmpty()) {
            return statusStopped(ar);
        }
        return ar ? ("غير متصل  •  " + cleanName) : ("Disconnected  •  " + cleanName);
    }

    public static String statusKillSwitchGuarded(boolean ar, String profileName) {
        String cleanName = profileName == null ? "" : profileName.trim();
        if (cleanName.isEmpty()) {
            return ar ? "مانع التسريب نشط (الاتصال المباشر محجوب)" : "Kill switch active (direct traffic blocked)";
        }
        return ar
                ? ("مانع التسريب نشط  •  " + cleanName)
                : ("Kill switch active  •  " + cleanName);
    }

    public static String statusKillSwitchSubline(boolean ar) {
        return ar
                ? "جميع اتصالات ومكالمات تليجرام موقوفة مؤقتاً لمنع كشف عنوانك الحقيقي حتى يتصل النفق."
                : "All Telegram traffic and calls are held locally so your real IP cannot leak while disconnected.";
    }

    public static String statusEmptyHint(boolean ar) {
        return ar
                ? "استورد ملف إعدادات أو صورة رمز مربع أو الصق من الحافظة، ثم اضغط اتصال."
                : "Import a file, scan a QR screenshot, or paste from clipboard, then tap Connect.";
    }

    public static String liveStatsLine(boolean ar, long rxBytes, long txBytes, long lastHandshakeSec) {
        String rx = formatBytes(ar, rxBytes);
        String tx = formatBytes(ar, txBytes);
        String hs = formatHandshakeAge(ar, lastHandshakeSec);
        if (ar) {
            return "تنزيل " + rx + "  •  رفع " + tx + "  •  المصافحة: " + hs;
        }
        return "Down " + rx + "  •  Up " + tx + "  •  Handshake: " + hs;
    }

    public static String formatBytes(boolean ar, long bytes) {
        if (bytes <= 0) {
            return ar ? "0 ب" : "0 B";
        }
        if (bytes < 1024) {
            return ar ? (bytes + " ب") : (bytes + " B");
        }
        double kb = bytes / 1024.0;
        if (kb < 1024.0) {
            String v = String.format(Locale.US, "%.1f", kb);
            return ar ? (ltr(v) + " ك.ب") : (v + " KB");
        }
        double mb = kb / 1024.0;
        if (mb < 1024.0) {
            String v = String.format(Locale.US, "%.2f", mb);
            return ar ? (ltr(v) + " م.ب") : (v + " MB");
        }
        double gb = mb / 1024.0;
        String v = String.format(Locale.US, "%.2f", gb);
        return ar ? (ltr(v) + " غ.ب") : (v + " GB");
    }

    public static String formatHandshakeAge(boolean ar, long handshakeEpochSec) {
        if (handshakeEpochSec <= 0) {
            return ar ? "بانتظار أول رزمة" : "awaiting traffic";
        }
        long nowSec = System.currentTimeMillis() / 1000L;
        long diff = Math.max(0L, nowSec - handshakeEpochSec);
        if (diff < 60L) {
            return ar ? ("منذ " + diff + " ث") : (diff + "s ago");
        }
        long mins = diff / 60L;
        if (mins < 60L) {
            return ar ? ("منذ " + mins + " د") : (mins + "m ago");
        }
        long hrs = mins / 60L;
        return ar ? ("منذ " + hrs + " س") : (hrs + "h ago");
    }

    public static String routeCallsLabel(boolean ar) {
        return ar
                ? "تمرير المكالمات الصوتية والمرئية عبر النفق"
                : "Route voice and video calls through tunnel";
    }

    public static String autoStartLabel(boolean ar) {
        return ar
                ? "الاتصال التلقائي عند تشغيل تليجرام"
                : "Connect automatically on launch";
    }

    public static String killSwitchLabel(boolean ar) {
        return ar
                ? "مانع تسريب صارم (حجب تليجرام بدون نفق)"
                : "Strict kill switch (block Telegram without tunnel)";
    }

    public static String autoFailoverLabel(boolean ar) {
        return ar
                ? "التبديل التلقائي لخادم بديل عند انقطاع النفق"
                : "Auto-failover to backup server on drop";
    }

    public static String networkBatteryToggleBtn(boolean ar, boolean expanded) {
        if (ar) {
            return expanded ? "إخفاء خيارات النطاقات والبطارية" : "خيارات النطاقات وتوفير البطارية";
        }
        return expanded ? "Hide DNS & battery options" : "Encrypted DNS & battery options";
    }

    public static String encryptedDohLabel(boolean ar) {
        return ar
                ? "استعلام مشفّر لنطاقات الخوادم لتجاوز حجب المزود"
                : "Encrypted DNS-over-HTTPS for server domains";
    }

    public static String smartKeepaliveLabel(boolean ar) {
        return ar
                ? "توفير البطارية في الخلفية عند سكون تليجرام"
                : "Smart idle keepalive saver in background";
    }

    public static String connectPrimaryBtn(boolean ar) {
        return ar ? "اتصال" : "Connect";
    }

    public static String reconnectPrimaryBtn(boolean ar) {
        return ar ? "تحديث الاتصال" : "Apply and reconnect";
    }

    public static String switchToProfileBtn(boolean ar) {
        return ar ? "التحويل إلى هذا الخادم" : "Switch to this server";
    }

    public static String connectingBtn(boolean ar) {
        return ar ? "جارٍ الاتصال..." : "Connecting...";
    }

    public static String disconnectBtn(boolean ar) {
        return ar ? "قطع الاتصال" : "Disconnect";
    }

    public static String verifyBtnLabel(boolean ar) {
        return ar ? "فحص المسار والمكالمات" : "Verify route & calls";
    }

    public static String verifyBtnBusy(boolean ar) {
        return ar ? "جارٍ الفحص..." : "Verifying...";
    }

    public static String verifyLoadingBody(boolean ar) {
        return ar
                ? "جارٍ اختبار العنوان الخارجي وخوادم تليجرام ومسار المكالمات..."
                : "Checking exit IP, Telegram datacenter, and UDP call relay...";
    }

    public static String verifySuccessTitle(boolean ar) {
        return ar
                ? "تم التحقق من مرور البيانات عبر النفق المشفّر"
                : "Verified encrypted tunnel routing";
    }

    public static String verifyExitIpLabel(boolean ar) {
        return ar ? "العنوان الخارجي" : "Exit IP";
    }

    public static String verifyCountryLabel(boolean ar) {
        return ar ? "الموقع" : "Location";
    }

    public static String verifyLatencyLabel(boolean ar) {
        return ar ? "زمن الاستجابة" : "Tunnel latency";
    }

    public static String verifyTelegramDcLabel(boolean ar) {
        return ar ? "خوادم تليجرام" : "Telegram DC";
    }

    public static String verifyVoipUdpLabel(boolean ar) {
        return ar ? "مسار المكالمات" : "Voice & video calls";
    }

    public static String formatLatency(boolean ar, long ms) {
        return ar ? (ms + " مللي ثانية") : (ms + " ms");
    }

    public static String formatTelegramDcStatus(boolean ar, boolean reachable, long ms) {
        if (reachable) {
            return ar ? ("متصل (" + ms + " مللي ثانية)") : ("Reachable (" + ms + " ms)");
        }
        return ar ? "تعذّر الوصول" : "Unreachable";
    }

    public static String formatVoipUdpStatus(boolean ar, boolean ready, long ms, boolean routeCallsEnabled) {
        if (!routeCallsEnabled) {
            return ar ? "معطّل من الخيارات" : "Disabled in options";
        }
        if (ready) {
            return ar ? ("جاهز (" + ms + " مللي ثانية)") : ("Ready (" + ms + " ms)");
        }
        return ar ? "استجابة محدودة (يعمل عبر المسار البديل)" : "TCP fallback only (UDP blocked on peer)";
    }

    public static String verifyFailedTitle(boolean ar) {
        return ar ? "فشل فحص المسار" : "Route check failed";
    }

    public static String profilesSectionLabel(boolean ar) {
        return ar ? "الخوادم المحفوظة" : "Saved profiles";
    }

    public static String profilesSectionCountLabel(boolean ar, int count) {
        return ar ? ("الخوادم المحفوظة (" + count + ")") : ("Saved profiles (" + count + ")");
    }

    public static String pingFastestBtn(boolean ar, boolean running) {
        if (running) {
            return ar ? "جارٍ القياس..." : "Pinging...";
        }
        return ar ? "قياس الأسرع" : "Ping fastest";
    }

    public static String profileTapHint(boolean ar) {
        return ar
                ? "اضغط على أي خادم للتبديل إليه فوراً، أو قِس السرعة لاختيار الأقل زمناً."
                : "Tap any server to switch immediately, or ping all to pick the lowest latency.";
    }

    public static String profileConnectedTag(boolean ar) {
        return ar ? "متصل الآن" : "Connected";
    }

    public static String profileSelectedTag(boolean ar) {
        return ar ? "محدد" : "Selected";
    }

    public static String profileAwgTag(boolean ar) {
        return ar ? "تمويه نشط" : "Obfuscated";
    }

    public static String profilePingTag(boolean ar, int pingMs) {
        if (pingMs == -1) {
            return ar ? "لا يستجيب" : "Timeout";
        }
        return formatLatency(ar, pingMs);
    }

    public static String profileEmptyEndpointHint(boolean ar) {
        return ar ? "لم يُضبط عنوان الخادم بعد" : "No endpoint configured yet";
    }

    public static String editInlineBtn(boolean ar) {
        return ar ? "تعديل" : "Edit";
    }

    public static String deleteInlineBtn(boolean ar) {
        return ar ? "حذف" : "Delete";
    }

    public static String confirmDeleteTitle(boolean ar) {
        return ar ? "حذف الخادم المحفوظ" : "Delete saved profile";
    }

    public static String confirmDeleteMessage(boolean ar, String profileName) {
        String cleanName = profileName == null ? "" : profileName.trim();
        if (ar) {
            return "هل تريد حذف الخادم \"" + cleanName + "\" وإزالة مفاتيحه المشفرة نهائياً؟";
        }
        return "Delete profile \"" + cleanName + "\" and permanently remove its encrypted keys?";
    }

    public static String cancelBtn(boolean ar) {
        return ar ? "إلغاء" : "Cancel";
    }

    public static String defaultProfileName(boolean ar, int index) {
        return ar ? ("خادم " + index) : ("Server " + index);
    }

    public static String newProfileBtn(boolean ar) {
        return ar ? "خادم جديد" : "New";
    }

    public static String importFileBtn(boolean ar) {
        return ar ? "استيراد ملف" : "Import file";
    }

    public static String importClipboardBtn(boolean ar) {
        return ar ? "لصق" : "Paste";
    }

    public static String importQrImageBtn(boolean ar) {
        return ar ? "صورة رمز" : "QR image";
    }

    public static String exportBackupBtn(boolean ar) {
        return ar ? "نسخ الكل" : "Backup all";
    }

    public static String restoreBackupBtn(boolean ar) {
        return ar ? "استعادة" : "Restore";
    }

    public static String configSummaryEditRow(boolean ar, boolean expanded, String summary) {
        if (expanded) {
            return ar ? "إخفاء تفاصيل الخادم" : "Hide server details";
        }
        if (summary == null || summary.isEmpty()) {
            return ar ? "إدخال بيانات الخادم والمفاتيح" : "Enter server and key settings";
        }
        return ar ? ("تعديل الخادم: " + ltr(summary)) : ("Edit server: " + summary);
    }

    public static String labelProfileName(boolean ar) {
        return ar ? "اسم الخادم" : "Profile name";
    }

    public static String hintProfileName(boolean ar) {
        return ar ? "مثال: خادم جورجيا" : "Example: Georgia server";
    }

    public static String labelPrivateKey(boolean ar) {
        return ar ? "المفتاح الخاص للواجهة" : "Interface private key";
    }

    public static String hintPrivateKey(boolean ar) {
        return ar ? "مفتاح من 44 أو 64 محرفاً" : "44-char Base64 or 64-char hex";
    }

    public static String showSecretBtn(boolean ar, boolean currentlyVisible) {
        if (ar) {
            return currentlyVisible ? "إخفاء" : "إظهار";
        }
        return currentlyVisible ? "Hide" : "Show";
    }

    public static String labelAddress(boolean ar) {
        return ar ? "عنوان النفق الداخلي" : "Tunnel address";
    }

    public static String hintAddress(boolean ar) {
        return ltr("10.14.0.2/16");
    }

    public static String labelDns(boolean ar) {
        return ar ? "خادم النطاقات" : "DNS server";
    }

    public static String hintDns(boolean ar) {
        return ltr("1.1.1.1");
    }

    public static String labelPublicKey(boolean ar) {
        return ar ? "المفتاح العام للخادم" : "Peer public key";
    }

    public static String hintPublicKey(boolean ar) {
        return ar ? "المفتاح العام للطرف المقابل" : "44-char Base64 or 64-char hex";
    }

    public static String labelEndpoint(boolean ar) {
        return ar ? "عنوان الخادم والمنفذ" : "Endpoint host:port";
    }

    public static String hintEndpoint(boolean ar) {
        return ltr("host.example.com:51820");
    }

    public static String labelKeepAlive(boolean ar) {
        return ar ? "إبقاء الاتصال (ث)" : "Keepalive (s)";
    }

    public static String hintKeepAlive(boolean ar) {
        return "25";
    }

    public static String advancedToggleLabel(boolean ar, boolean expanded) {
        if (ar) {
            return expanded ? "إخفاء التمويه والخيارات المتقدمة" : "تمويه الحزم وحجم الرزمة والنسخ";
        }
        return expanded ? "Hide obfuscation & advanced options" : "DPI obfuscation, MTU & QR export";
    }

    public static String labelPresharedKey(boolean ar) {
        return ar ? "المفتاح المشترك المسبق (اختياري)" : "Preshared key (optional)";
    }

    public static String hintPresharedKey(boolean ar) {
        return ar ? "اتركه فارغاً إن لم يطلبه الخادم" : "Leave empty if unused";
    }

    public static String labelMtu(boolean ar) {
        return ar ? "حجم الرزمة الأقصى" : "Tunnel MTU";
    }

    public static String hintMtu(boolean ar) {
        return "1280";
    }

    public static String autoMtuBtn(boolean ar, boolean running) {
        if (running) {
            return ar ? "جارٍ فحص أنسب حجم رزمة..." : "Probing optimal MTU...";
        }
        return ar ? "ضبط حجم الرزمة تلقائياً للشبكة" : "Auto-detect optimal MTU";
    }

    public static String awgSectionHeading(boolean ar) {
        return ar
                ? "تمويه الحزم وتجاوز الفحص العميق (متوافق مع أمنيزيا)"
                : "Packet obfuscation & DPI evasion (AmneziaWG)";
    }

    public static String awgSectionHint(boolean ar) {
        return ar
                ? "نبضات التمويه العشوائية تعمل حتى مع خوادم وايرجارد العادية، بينما تُقرأ قيم الحشو والترويسات تلقائياً عند استيراد ملف أمنيزيا."
                : "Decoy junk bursts work even on standard WireGuard servers; padding and header values load automatically from AmneziaWG configs.";
    }

    public static String awgPresetVanillaBtn(boolean ar) {
        return ar ? "تعبئة تمويه متوافق مع كل الخوادم" : "Apply universal junk preset";
    }

    public static String awgClearBtn(boolean ar) {
        return ar ? "مسح التمويه" : "Clear";
    }

    public static String labelAwgJc(boolean ar) {
        return ar ? "عدد الحزم التمويهية" : "Junk count (Jc)";
    }

    public static String labelAwgJmin(boolean ar) {
        return ar ? "أدنى حجم تمويه" : "Min junk bytes (Jmin)";
    }

    public static String labelAwgJmax(boolean ar) {
        return ar ? "أقصى حجم تمويه" : "Max junk bytes (Jmax)";
    }

    public static String labelAwgS1(boolean ar) {
        return ar ? "حشو البدء الأول" : "Init pad (S1)";
    }

    public static String labelAwgS2(boolean ar) {
        return ar ? "حشو الاستجابة الثاني" : "Resp pad (S2)";
    }

    public static String labelAwgS3(boolean ar) {
        return ar ? "حشو التحقق الثالث" : "Cookie pad (S3)";
    }

    public static String labelAwgS4(boolean ar) {
        return ar ? "حشو البيانات الرابع" : "Data pad (S4)";
    }

    public static String labelAwgH1(boolean ar) {
        return ar ? "ترويسة البدء الأولى" : "Init header (H1)";
    }

    public static String labelAwgH2(boolean ar) {
        return ar ? "ترويسة الاستجابة الثانية" : "Resp header (H2)";
    }

    public static String labelAwgH3(boolean ar) {
        return ar ? "ترويسة التحقق الثالثة" : "Cookie header (H3)";
    }

    public static String labelAwgH4(boolean ar) {
        return ar ? "ترويسة البيانات الرابعة" : "Data header (H4)";
    }

    public static String copyConfBtn(boolean ar) {
        return ar ? "نسخ الإعدادات" : "Copy config";
    }

    public static String showQrBtn(boolean ar) {
        return ar ? "عرض الرمز المربع" : "Show QR code";
    }

    public static String qrModalTitle(boolean ar, String profileName) {
        String clean = profileName == null ? "" : profileName.trim();
        if (clean.isEmpty()) {
            return ar ? "الرمز المربع لإعدادات الخادم" : "Server configuration QR code";
        }
        return ar ? ("الرمز المربع: " + clean) : ("QR code: " + clean);
    }

    public static String qrModalHint(boolean ar) {
        return ar
                ? "امسح هذا الرمز من جهاز آخر أو التقط صورة للشاشة للاحتفاظ بنسخة سريعة."
                : "Scan this code from another device or take a screenshot for offline backup.";
    }

    public static String deleteProfileBtn(boolean ar) {
        return ar ? "حذف الخادم" : "Delete profile";
    }

    public static String closeBtn(boolean ar) {
        return ar ? "إغلاق" : "Close";
    }

    public static String saveChangesBtn(boolean ar) {
        return ar ? "حفظ التعديلات" : "Save changes";
    }

    public static String toastSaved(boolean ar) {
        return ar ? "تم حفظ إعدادات الخادم" : "Profile saved";
    }

    public static String toastImportedConf(boolean ar) {
        return ar ? "تمت إضافة إعدادات الخادم بنجاح" : "Profile imported and added";
    }

    public static String toastImportedNamedProfile(boolean ar, String profileName) {
        String cleanName = profileName == null ? "" : profileName.trim();
        if (cleanName.isEmpty()) {
            return toastImportedConf(ar);
        }
        return ar ? ("تمت إضافة الخادم: " + cleanName) : ("Added profile: " + cleanName);
    }

    public static String toastCreatedNewProfile(boolean ar, String profileName) {
        return ar ? ("تم إنشاء " + profileName) : ("Created " + profileName);
    }

    public static String toastSelectedProfile(boolean ar, String profileName) {
        return ar ? ("تم اختيار الخادم: " + profileName) : ("Selected profile: " + profileName);
    }

    public static String toastSwitchedProfile(boolean ar, String profileName, int port) {
        String addr = ltr("127.0.0.1:" + port);
        return ar
                ? ("تم التحويل إلى " + profileName + " (" + addr + ")")
                : ("Switched to " + profileName + " (" + addr + ")");
    }

    public static String toastFailoverSwitched(boolean ar, String profileName) {
        return ar
                ? ("انقطع الخادم السابق فتم التحويل تلقائياً إلى " + profileName)
                : ("Primary tunnel dropped; failed over to " + profileName);
    }

    public static String toastPingWinner(boolean ar, String profileName, int ms) {
        return ar
                ? ("الأسرع: " + profileName + " (" + ms + " مللي ثانية)")
                : ("Fastest: " + profileName + " (" + ms + " ms)");
    }

    public static String toastOptimalMtuFound(boolean ar, int mtu) {
        return ar
                ? ("تم ضبط أفضل حجم رزمة لشبكتك: " + mtu)
                : ("Optimal path MTU applied: " + mtu);
    }

    public static String toastAwgPresetApplied(boolean ar) {
        return ar
                ? "تم تفعيل نبضات التمويه لتجاوز فحص الحزم"
                : "Applied universal DPI junk preset";
    }

    public static String toastAwgCleared(boolean ar) {
        return ar ? "تمت إزالة قيم التمويه" : "Cleared obfuscation fields";
    }

    public static String toastCopiedConf(boolean ar) {
        return ar ? "تم نسخ إعدادات الخادم إلى الحافظة" : "Configuration copied to clipboard";
    }

    public static String toastExportedBackup(boolean ar, int count) {
        return ar
                ? ("تم نسخ الحزمة الاحتياطية للحافظة (" + count + " خوادم)")
                : ("Copied full backup to clipboard (" + count + " profiles)");
    }

    public static String toastRestoredBackup(boolean ar, int count) {
        return ar
                ? ("تمت استعادة " + count + " خوادم من الحافظة")
                : ("Restored " + count + " profiles from clipboard");
    }

    public static String toastDeletedProfile(boolean ar) {
        return ar ? "تم حذف الخادم المحفوظ" : "Profile deleted";
    }

    public static String toastConnected(boolean ar, int port) {
        String addr = ltr("127.0.0.1:" + port);
        return ar ? ("تم الاتصال عبر " + addr) : ("Connected on " + addr);
    }

    public static String toastDisconnected(boolean ar) {
        return ar ? "تم قطع الاتصال" : "Tunnel disconnected";
    }

    public static String launcherStatusHeading(boolean ar) {
        return ar ? "حالة نفق الاتصال" : "Tunnel status";
    }

    public static String launcherGuideHeading(boolean ar) {
        return ar ? "طريقة التشغيل داخل تليجرام" : "How to use inside Telegram";
    }

    public static String[] launcherSteps(boolean ar) {
        if (ar) {
            return new String[]{
                    "١. فعّل هذه الإضافة على تليجرام بلس أو تليجرام الرسمي من أداة الدمج جنباً إلى جنب مع إضافاتك الحالية.",
                    "٢. افتح تليجرام ثم ادخل إلى الإعدادات ثم البيانات والتخزين ثم إعدادات البروكسي.",
                    "٣. اضغط زر نفق وايرجارد أسفل الشاشة لاستيراد ملف أو صورة رمز مربع وتفعيل تمويه الحزم والمكالمات.",
                    "٤. اضغط فحص المسار والمكالمات للتأكد من تغيّر العنوان الخارجي وجاهزية المكالمات."
            };
        }
        return new String[]{
                "1. Enable this module for Telegram Plus or official Telegram in LSPatch or LSPosed alongside your other modules.",
                "2. Open Telegram and go to Settings, Data and Storage, then Proxy Settings.",
                "3. Tap the WireGuard button at the bottom corner to import a file or QR screenshot, enable DPI obfuscation, and route calls.",
                "4. Run Verify route & calls to confirm your exit IP and voice/video call relay readiness."
        };
    }

    public static String launcherOpenConfigBtn(boolean ar) {
        return ar ? "إدارة الخوادم وفحص النفق" : "Manage profiles & test tunnel";
    }

    public static String localizedCountryName(String isoCode, boolean ar) {
        if (isoCode == null || isoCode.trim().isEmpty()) {
            return ar ? "غير معروف" : "Unknown";
        }
        String upper = isoCode.trim().toUpperCase(Locale.ROOT);
        if (ar) {
            String mapped = AR_COUNTRIES.get(upper);
            if (mapped != null) {
                return mapped;
            }
            String display = new Locale("", upper).getDisplayCountry(new Locale("ar"));
            if (display != null && !display.trim().isEmpty() && !display.equalsIgnoreCase(upper)) {
                return display;
            }
            return "دولة أخرى";
        }
        String displayEn = new Locale("", upper).getDisplayCountry(Locale.ENGLISH);
        if (displayEn == null || displayEn.trim().isEmpty() || displayEn.equalsIgnoreCase(upper)) {
            return upper;
        }
        return displayEn + " (" + upper + ")";
    }

    public static String localizeError(Throwable t, boolean ar) {
        if (t instanceof WgException) {
            WgException we = (WgException) t;
            return localizeErrorCode(we.code, we.detail, ar);
        }
        String raw = t != null && t.getMessage() != null ? t.getMessage().trim() : "";
        String lower = raw.toLowerCase(Locale.ROOT);

        if (lower.contains("amneziawg") || lower.contains("header range") || lower.contains("junk")) {
            return ar
                    ? "إعدادات تمويه الحزم غير صالحة. تحقق من الأرقام المدخلة أو اضغط مسح التمويه."
                    : "Packet obfuscation values are invalid. Check numeric ranges or clear obfuscation fields.";
        }
        if (lower.contains("preshared key")) {
            return ar
                    ? "المفتاح المشترك المسبق غير صالح. تأكد من إدخاله كاملاً أو اتركه فارغاً."
                    : "Preshared key is invalid. Enter a valid 32-byte key or leave it empty.";
        }
        if (lower.contains("private key")) {
            return localizeErrorCode(ErrorCode.INVALID_KEY_FORMAT, "", ar);
        }
        if (lower.contains("public key")) {
            return ar
                    ? "المفتاح العام للخادم غير صالح. تأكد من نسخ المفتاح كاملاً."
                    : "Peer public key is invalid. Enter a complete 44-char Base64 or 64-char hex key.";
        }
        if (lower.contains("address")) {
            return ar
                    ? "عنوان النفق الداخلي غير صالح. اكتبه بصيغة مثل " + ltr("10.14.0.2/16") + "."
                    : "Tunnel address is invalid. Use CIDR format such as 10.14.0.2/16.";
        }
        if (lower.contains("dns")) {
            return ar
                    ? "عنوان خادم النطاقات غير صالح. استخدم عنواناً رقمياً مثل " + ltr("1.1.1.1") + "."
                    : "DNS server address is invalid. Enter an IP address such as 1.1.1.1.";
        }
        if (lower.contains("resolve endpoint") || lower.contains("unknownhost")) {
            return ar
                    ? "تعذّر الوصول إلى نطاق الخادم. فعّل الاستعلام المشفّر للنطاقات أو ضع عنوان الخادم الرقمي مباشرة."
                    : "Could not resolve endpoint hostname. Enable encrypted DoH or enter a direct server IP.";
        }
        if (lower.contains("endpoint")) {
            return ar
                    ? "صيغة عنوان الخادم غير صحيحة. اكتبه بصيغة " + ltr("host.com:51820") + "."
                    : "Endpoint format is invalid. Use host:port format such as host.com:51820.";
        }
        if (lower.contains("timeout") || lower.contains("timed out") || lower.contains("socks")) {
            return ar
                    ? "انتهت مهلة المصافحة مع الخادم. تحقق من المفاتيح أو جرّب تفعيل تمويه الحزم."
                    : "Handshake timed out. Verify your keys or try enabling packet obfuscation.";
        }
        if (ar) {
            return "تعذّر إتمام العملية. راجع بيانات الخادم وحاول مرة أخرى.";
        }
        return raw.isEmpty() ? "Operation failed. Check your configuration and try again." : raw;
    }

    private static String localizeErrorCode(ErrorCode code, String detail, boolean ar) {
        switch (code) {
            case EMPTY_CLIPBOARD:
                return ar
                        ? "الحافظة فارغة. انسخ محتوى الإعدادات أولاً ثم أعد المحاولة."
                        : "Clipboard is empty. Copy a WireGuard config or backup first, then try again.";
            case INVALID_CONF:
                return ar
                        ? "لم يُعثر على بيانات وايرجارد صالحة في النص المختار."
                        : "No valid WireGuard configuration fields were found.";
            case FILE_READ_FAILED:
                return ar
                        ? "تعذّرت قراءة الملف أو الصورة المختارة."
                        : "Could not read the selected file or image.";
            case MISSING_PRIVATE_KEY:
                return ar
                        ? "أدخل المفتاح الخاص للواجهة قبل بدء الاتصال."
                        : "Enter the interface private key before connecting.";
            case MISSING_PUBLIC_KEY:
                return ar
                        ? "أدخل المفتاح العام للخادم قبل بدء الاتصال."
                        : "Enter the peer public key before connecting.";
            case MISSING_ENDPOINT:
                return ar
                        ? "أدخل عنوان الخادم والمنفذ مثل " + ltr("host.com:51820") + "."
                        : "Enter the peer endpoint host and port (for example, host.com:51820).";
            case MISSING_ADDRESS:
                return ar
                        ? "أدخل عنوان النفق الداخلي مثل " + ltr("10.0.0.2/32") + "."
                        : "Enter the tunnel IP address (for example, 10.0.0.2/32).";
            case INVALID_KEY_FORMAT:
                return ar
                        ? "صيغة المفتاح غير صحيحة. يجب أن يتكون من 44 محرفاً أو 64 محرفاً ست عشرياً."
                        : "Invalid key encoding. Provide a 44-char Base64 or 64-char hex key.";
            case INVALID_KEY_LENGTH:
                return ar
                        ? "طول المفتاح غير مكتمل (32 بايت مطلوب). تأكد من نسخ المفتاح كاملاً."
                        : "Key length is incomplete (expected 32 bytes). Check that no characters are missing.";
            case TUNNEL_STOPPED:
                return ar
                        ? "النفق غير متصل حالياً. اضغط اتصال أولاً ثم أعد الفحص."
                        : "Tunnel is disconnected. Tap Connect first, then verify.";
            case NO_ACTIVE_PORT:
                return ar
                        ? "لا يوجد منفذ محلي نشط للنفق. أعد الاتصال وحاول ثانية."
                        : "No active local proxy port found. Reconnect and try again.";
            case VERIFY_ROUTE_FAILED:
                return ar
                        ? "لم تكتمل المصافحة عبر النفق خلال المهلة. تحقق من المفاتيح أو جرّب تفعيل تمويه الحزم."
                        : "No traffic passed through the tunnel before timeout. Verify keys or enable packet obfuscation.";
            case QR_NOT_FOUND:
                return ar
                        ? "لم يُعثر على رمز مربع واضح في الصورة المختارة."
                        : "No readable QR code was found in the selected image.";
            case QR_ENCODE_FAILED:
                return ar
                        ? "تعذّر إنشاء الرمز المربع. أكمل بيانات الخادم الأساسية أولاً."
                        : "Could not generate QR code. Fill in the required server fields first.";
            case BACKUP_INVALID:
                return ar
                        ? "النص المنسوخ في الحافظة ليس حزمة نسخ احتياطي صالحة للخوادم."
                        : "Clipboard does not contain a valid multi-profile backup bundle.";
            case PING_ALL_FAILED:
                return ar
                        ? "لم يستجب أي خادم محفوظ للمصافحة. تحقق من اتصال الإنترنت أو فعّل تمويه الحزم."
                        : "None of the saved servers completed a handshake. Check your network or enable obfuscation.";
            case MTU_DISCOVERY_FAILED:
                return ar
                        ? "تعذّر قياس حجم الرزمة عبر هذا الخادم. تأكد من صحة المفاتيح وعنوان الخادم."
                        : "Could not probe path MTU through this server. Verify keys and endpoint reachability.";
            case NATIVE_BRIDGE_FAILED:
            default:
                return ar
                        ? "تعذّر تشغيل المحرك الأصلي داخل التطبيق. أعد فتح تليجرام وحاول مجدداً."
                        : ("Native tunnel engine failed to initialize" + (detail.isEmpty() ? "." : (": " + detail)));
        }
    }
}
