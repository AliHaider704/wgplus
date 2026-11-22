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
    public static final String VERSION_LABEL = "1.7.3";

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

    /**
     * Normalizes auto-generated default profile names ("خادم N" / "Server N") to the active UI language
     * so switching languages never leaks a localized default name into the opposite language.
     */
    public static String localizeProfileName(String rawName, boolean ar) {
        String clean = rawName == null ? "" : rawName.trim();
        if (clean.isEmpty()) {
            return "";
        }
        String suffix = extractDefaultProfileSuffix(clean);
        if (suffix != null) {
            return (ar ? "خادم " : "Server ") + suffix;
        }
        return clean;
    }

    public static String localizeProfileName(String rawName, boolean ar, int fallbackIndex) {
        String localized = localizeProfileName(rawName, ar);
        return localized.isEmpty() ? defaultProfileName(ar, fallbackIndex) : localized;
    }

    public static boolean isDefaultProfileName(String rawName) {
        if (rawName == null) {
            return false;
        }
        return extractDefaultProfileSuffix(rawName.trim()) != null;
    }

    private static String extractDefaultProfileSuffix(String trimmed) {
        String rest = null;
        if (trimmed.startsWith("خادم ")) {
            rest = trimmed.substring(5).trim();
        } else if (trimmed.length() > 7 && trimmed.substring(0, 7).equalsIgnoreCase("server ")) {
            rest = trimmed.substring(7).trim();
        }
        if (rest == null || rest.isEmpty()) {
            return null;
        }
        String normalized = normalizeDigitsToAscii(rest);
        // Match "<digits>" or "<digits> (<digits>)" from uniqueProfileName deduplication
        int idx = 0;
        while (idx < normalized.length() && normalized.charAt(idx) >= '0' && normalized.charAt(idx) <= '9') {
            idx++;
        }
        if (idx == 0) {
            return null;
        }
        if (idx == normalized.length()) {
            return normalized;
        }
        String tail = normalized.substring(idx).trim();
        if (tail.startsWith("(") && tail.endsWith(")") && tail.length() > 2) {
            String inner = tail.substring(1, tail.length() - 1).trim();
            if (!inner.isEmpty() && isAllAsciiDigits(inner)) {
                return normalized.substring(0, idx) + " (" + inner + ")";
            }
        }
        return null;
    }

    private static String normalizeDigitsToAscii(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '\u0660' && c <= '\u0669') {
                sb.append((char) ('0' + (c - '\u0660')));
            } else if (c >= '\u06F0' && c <= '\u06F9') {
                sb.append((char) ('0' + (c - '\u06F0')));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isAllAsciiDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return !s.isEmpty();
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
        String cleanName = localizeProfileName(profileName, ar);
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
        String cleanName = localizeProfileName(profileName, ar);
        if (cleanName.isEmpty()) {
            return statusConnecting(ar);
        }
        return ar ? ("جارٍ التحويل إلى " + cleanName + "...") : ("Switching to " + cleanName + "...");
    }

    public static String statusStopped(boolean ar) {
        return ar ? "غير متصل" : "Disconnected";
    }

    public static String statusStoppedWithProfile(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        if (cleanName.isEmpty()) {
            return statusStopped(ar);
        }
        return ar ? ("غير متصل  •  " + cleanName) : ("Disconnected  •  " + cleanName);
    }

    public static String statusKillSwitchGuarded(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        if (cleanName.isEmpty()) {
            return ar ? "مانع التسريب نشط" : "Kill switch active";
        }
        return ar
                ? ("مانع التسريب  •  " + cleanName)
                : ("Kill switch  •  " + cleanName);
    }

    public static String statusKillSwitchSubline(boolean ar) {
        return ar
                ? "الاتصال المباشر محجوب مؤقتًا حتى يتصل النفق."
                : "Direct traffic is held until the tunnel connects.";
    }

    public static String statusEmptyHint(boolean ar) {
        return ar
                ? ("اضغط " + ltr("WARP") + " للاتصال الفوري، أو استورد ملفًا أو رمزًا مربعًا.")
                : "Tap Free WARP for instant setup, or import a config or QR.";
    }

    public static String sharedTunnelActiveSubline(boolean ar, int port) {
        String addr = ltr("127.0.0.1:" + port);
        return ar
                ? ("نفق مشترك نشط بين تطبيقات تيليجرام · " + addr)
                : ("Shared tunnel active across Telegram apps · " + addr);
    }

    public static String statusAwaitingHandshakeWithProfile(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        if (cleanName.isEmpty()) {
            return ar ? "جارٍ إتمام المصافحة..." : "Establishing handshake...";
        }
        return ar ? ("جارٍ إتمام المصافحة...  •  " + cleanName) : ("Establishing handshake...  •  " + cleanName);
    }

    public static String statusStalledWithProfile(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        if (cleanName.isEmpty()) {
            return ar ? "الخادم لا يستجيب (احتمال تقييد الشبكة)" : "Server unresponsive (possible restriction)";
        }
        return ar
                ? ("الخادم لا يستجيب (احتمال تقييد الشبكة)  •  " + cleanName)
                : ("Server unresponsive (possible restriction)  •  " + cleanName);
    }

    public static String statusStalledHint(boolean ar) {
        return ar
                ? "لم تصل استجابة من الخادم حتى الآن. جرّب تفعيل التمويه المتقدم أو التبديل إلى نفق بديل."
                : "No handshake response received yet. Try enabling strong DPI bypass or switching to Free WARP.";
    }

    public static String recoverAwgBtn(boolean ar) {
        return ar
                ? ("تفعيل التمويه المتقدم (" + ltr("AWG 1.5") + ") وإعادة الاتصال")
                : "Enable strong DPI bypass (AWG 1.5) & reconnect";
    }

    public static String recoverWarpBtn(boolean ar) {
        return ar
                ? ("التبديل إلى " + ltr("WARP") + " المجاني")
                : "Switch to Free WARP";
    }

    public static String toastAwgRecovered(boolean ar, int port) {
        String addr = ltr("127.0.0.1:" + port);
        return ar
                ? ("تم تفعيل التمويه المتقدم وإعادة الاتصال عبر " + addr)
                : ("Strong DPI bypass enabled and reconnected on " + addr);
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
                ? "تمرير المكالمات عبر النفق"
                : "Route voice & video calls";
    }

    public static String autoStartLabel(boolean ar) {
        return ar
                ? "الاتصال التلقائي عند تشغيل تيليجرام"
                : "Auto-connect on launch";
    }

    public static String killSwitchLabel(boolean ar) {
        return ar
                ? "مانع تسريب صارم (حجب عند الانقطاع)"
                : "Strict kill switch (block on drop)";
    }

    public static String autoFailoverLabel(boolean ar) {
        return ar
                ? "التبديل التلقائي عند الانقطاع"
                : "Auto-failover on drop";
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
                ? "توفير البطارية في الخلفية عند سكون تيليجرام"
                : "Smart idle keepalive saver in background";
    }

    public static String connectPrimaryBtn(boolean ar) {
        return ar ? "اتصال" : "Connect";
    }

    public static String reconnectPrimaryBtn(boolean ar) {
        return ar ? "تحديث الاتصال" : "Reconnect";
    }

    public static String switchToProfileBtn(boolean ar) {
        return ar ? "تحويل لهذا الخادم" : "Switch";
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
                ? "جارٍ فحص العنوان الخارجي وخوادم تيليجرام والمكالمات..."
                : "Testing exit IP, Telegram DC, and UDP calls...";
    }

    public static String verifySuccessTitle(boolean ar) {
        return ar
                ? "المسار المشفّر يعمل بنجاح"
                : "Encrypted tunnel verified";
    }

    public static String verifyExitIpLabel(boolean ar) {
        return ar ? "العنوان الخارجي" : "Exit IP";
    }

    public static String verifyCountryLabel(boolean ar) {
        return ar ? "الموقع" : "Location";
    }

    public static String verifyLatencyLabel(boolean ar) {
        return ar ? "زمن الاستجابة" : "Latency";
    }

    public static String verifyTelegramDcLabel(boolean ar) {
        return ar ? "خوادم تيليجرام" : "Telegram DC";
    }

    public static String verifyVoipUdpLabel(boolean ar) {
        return ar ? "مسار المكالمات" : "Calls (UDP)";
    }

    public static String formatLatency(boolean ar, long ms) {
        return ltr(ms + " ms");
    }

    public static String formatTelegramDcStatus(boolean ar, boolean reachable, long ms) {
        if (reachable) {
            return ar ? ("متصل · " + ltr(ms + " ms")) : ("Reachable · " + ms + " ms");
        }
        return ar ? "تعذّر الوصول" : "Unreachable";
    }

    public static String formatVoipUdpStatus(boolean ar, boolean ready, long ms, boolean routeCallsEnabled) {
        if (!routeCallsEnabled) {
            return ar ? "معطّل" : "Disabled";
        }
        if (ready) {
            return ar ? ("جاهز · " + ltr(ms + " ms")) : ("Ready · " + ms + " ms");
        }
        return ar ? "مسار بديل (TCP)" : "TCP fallback";
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
                ? "اضغط على أي خادم للتبديل فورًا."
                : "Tap any server to switch immediately.";
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
        String cleanName = localizeProfileName(profileName, ar);
        if (ar) {
            return "هل تريد حذف الخادم \"" + cleanName + "\" وإزالة مفاتيحه المشفرة نهائيًا؟";
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
        return ar ? "مفتاح من 44 أو 64 محرفًا" : "44-char Base64 or 64-char hex";
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
        return ar ? "اتركه فارغًا إن لم يطلبه الخادم" : "Leave empty if unused";
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
        return ar ? "ضبط حجم الرزمة تلقائيًا للشبكة" : "Auto-detect optimal MTU";
    }

    public static String awgSectionHeading(boolean ar) {
        return ar
                ? "تمويه الحزم وتجاوز الفحص العميق (متوافق مع أمنيزيا)"
                : "Packet obfuscation & DPI evasion (AmneziaWG)";
    }

    public static String awgSectionHint(boolean ar) {
        return ar
                ? "نبضات التمويه العشوائية تعمل حتى مع خوادم وايرجارد العادية، بينما تُقرأ قيم الحشو والترويسات تلقائيًا عند استيراد ملف أمنيزيا."
                : "Decoy junk bursts work even on standard WireGuard servers; padding and header values load automatically from AmneziaWG configs.";
    }

    public static String quickWarpBtn(boolean ar, boolean busy) {
        if (busy) {
            return ar ? ("جارٍ تجهيز نفق " + ltr("WARP") + " والاتصال...") : "Setting up Free WARP...";
        }
        return ar ? ("اتصال فوري: " + ltr("WARP") + " مجاني (" + ltr("AWG 1.5") + ")") : "1-Tap Free WARP (AWG 1.5)";
    }

    public static String newWarpChipBtn(boolean ar) {
        return ar ? ("+ " + ltr("WARP") + " مجاني") : "+ Free WARP";
    }

    public static String statusGeneratingWarp(boolean ar) {
        return ar ? ("جارٍ تسجيل نفق " + ltr("Cloudflare WARP (AWG 1.5)") + " وتشغيله...") : "Provisioning Free Cloudflare WARP (AWG 1.5)...";
    }

    public static String toastQuickWarpConnected(boolean ar, boolean createdNew, int port) {
        String addr = ltr("127.0.0.1:" + port);
        if (createdNew) {
            return ar
                    ? ("تم إنشاء وتشغيل نفق " + ltr("WARP (AWG 1.5)") + " على " + addr)
                    : ("Created and connected Free WARP (AWG 1.5) on " + addr);
        }
        return ar
                ? ("تم الاتصال بنفق " + ltr("WARP (AWG 1.5)") + " على " + addr)
                : ("Connected Free WARP (AWG 1.5) on " + addr);
    }

    public static String awgPresetQuic15Btn(boolean ar) {
        return ar ? ("تجاوز تقييد متقدم (" + ltr("AWG 1.5") + ")") : "Strong DPI bypass (AWG 1.5)";
    }

    public static String awgPresetOffBtn(boolean ar) {
        return ar ? "عادي (بدون تمويه)" : "Standard (none)";
    }

    public static String awgRawToggleLabel(boolean ar, boolean expanded) {
        if (ar) {
            return expanded ? "إخفاء المعاملات المتقدمة" : "المعاملات المتقدمة (للخبراء)";
        }
        return expanded ? "Hide raw parameters" : "Advanced parameters";
    }

    public static String labelAwgI1(boolean ar) {
        return ar ? ("توقيع البدء (" + ltr("I1") + ")") : "Init signature (I1)";
    }

    public static String labelAwgReserved(boolean ar) {
        return ar ? ("بايتات حجز " + ltr("WARP (Reserved)")) : "WARP Reserved bytes";
    }

    public static String awgPresetVanillaBtn(boolean ar) {
        return ar ? "تجاوز تقييد قياسي" : "Standard DPI bypass";
    }

    public static String awgClearBtn(boolean ar) {
        return ar ? "إلغاء التمويه" : "Clear";
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
        return ar ? ("نقل بالرمز المربع (" + ltr("QR") + ")") : "Transfer via QR";
    }

    public static String qrModalTitle(boolean ar, String profileName) {
        String clean = localizeProfileName(profileName, ar);
        if (clean.isEmpty()) {
            return ar ? "نقل الخادم عبر الرمز المربع" : "Transfer server QR code";
        }
        return ar ? ("نقل الخادم: " + clean) : ("Transfer QR: " + clean);
    }

    public static String qrModalHint(boolean ar) {
        return ar
                ? ("امسح هذا الرمز من " + appTitle(true) + " على ويندوز أو هاتف آخر لنقل الخادم فورًا.")
                : "Scan or paste this code in WireGuard Plus on Windows or another phone to transfer this server.";
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
        String cleanName = localizeProfileName(profileName, ar);
        if (cleanName.isEmpty()) {
            return toastImportedConf(ar);
        }
        return ar ? ("تمت إضافة الخادم: " + cleanName) : ("Added profile: " + cleanName);
    }

    public static String toastCreatedNewProfile(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        return ar ? ("تم إنشاء " + cleanName) : ("Created " + cleanName);
    }

    public static String toastSelectedProfile(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        return ar ? ("تم اختيار الخادم: " + cleanName) : ("Selected profile: " + cleanName);
    }

    public static String toastSwitchedProfile(boolean ar, String profileName, int port) {
        String cleanName = localizeProfileName(profileName, ar);
        String addr = ltr("127.0.0.1:" + port);
        return ar
                ? ("تم التحويل إلى " + cleanName + " (" + addr + ")")
                : ("Switched to " + cleanName + " (" + addr + ")");
    }

    public static String toastFailoverSwitched(boolean ar, String profileName) {
        String cleanName = localizeProfileName(profileName, ar);
        return ar
                ? ("انقطع الخادم السابق فتم التحويل تلقائيًا إلى " + cleanName)
                : ("Primary tunnel dropped; failed over to " + cleanName);
    }

    public static String toastPingWinner(boolean ar, String profileName, int ms) {
        String cleanName = localizeProfileName(profileName, ar);
        return ar
                ? ("الأسرع: " + cleanName + " (" + ms + " مللي ثانية)")
                : ("Fastest: " + cleanName + " (" + ms + " ms)");
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

    public static String channelInviteNotice(boolean ar) {
        return ar
                ? "تم الاتصال بنجاح. ندعوك بلطف للاشتراك في قناة تيليجرام الرسمية لمتابعة التحديثات والإصدارات الجديدة."
                : "Connected successfully. We warmly invite you to join our official Telegram channel for updates and new releases.";
    }

    public static String toastDisconnected(boolean ar) {
        return ar ? "تم قطع الاتصال" : "Tunnel disconnected";
    }

    public static String launcherStatusHeading(boolean ar) {
        return ar ? "حالة نفق الاتصال" : "Tunnel status";
    }

    public static String launcherGuideHeading(boolean ar) {
        return ar ? "طريقة التشغيل داخل تيليجرام" : "How to use inside Telegram";
    }

    public static String[] launcherSteps(boolean ar) {
        if (ar) {
            return new String[]{
                    "١. فعّل هذه الإضافة على تيليجرام أو تيليجرام بلس أو تليجراف أو " + ltr("AyuGram") + " أو " + ltr("Telegram X") + " من أداة الدمج.",
                    "٢. افتح تيليجرام ثم ادخل إلى الإعدادات ثم البيانات والتخزين ثم إعدادات البروكسي.",
                    "٣. اضغط زر نفق وايرجارد أسفل الشاشة لاستيراد ملف أو صورة رمز مربع أو تشغيل " + ltr("WARP") + " بضغطة واحدة.",
                    "٤. اضغط فحص المسار والمكالمات للتأكد من تغيّر العنوان الخارجي وجاهزية المكالمات."
            };
        }
        return new String[]{
                "1. Enable this module for Telegram, Plus Messenger, Telegraph, AyuGram, Web, or Telegram X in LSPosed or LSPatch.",
                "2. Open Telegram and go to Settings, Data and Storage, then Proxy Settings.",
                "3. Tap the WireGuard button at the bottom corner to start 1-Tap Free WARP, import a config file, or enable DPI bypass.",
                "4. Run Verify route & calls to confirm your exit IP and voice/video call relay readiness."
        };
    }

    public static String launcherOpenConfigBtn(boolean ar) {
        return ar ? "إدارة الخوادم وفحص النفق" : "Manage profiles & test tunnel";
    }

    public static String launcherManageSecondaryBtn(boolean ar) {
        return ar ? "إدارة الخوادم أو استيراد ملف" : "Manage profiles or import file";
    }

    public static String readinessHeading(boolean ar) {
        return ar ? "حالة الجاهزية والتشغيل" : "Readiness & setup status";
    }

    public static String readinessItemServer(boolean ar, boolean configured) {
        if (ar) {
            return configured ? "١. الخادم: مُعدّ وجاهز" : "١. الخادم: غير مُعدّ بعد";
        }
        return configured ? "1. Server profile: Configured" : "1. Server profile: Not configured";
    }

    public static String readinessItemHook(boolean ar, String hookedPkg) {
        boolean hasPkg = hookedPkg != null && !hookedPkg.trim().isEmpty();
        if (ar) {
            return hasPkg
                    ? ("٢. التكامل مع تيليجرام: مفعّل (" + ltr(hookedPkg.trim()) + ")")
                    : "٢. التكامل مع تيليجرام: بانتظار التفعيل من أداة الدمج";
        }
        return hasPkg
                ? ("2. Telegram integration: Active (" + hookedPkg.trim() + ")")
                : "2. Telegram integration: Enable in LSPosed or LSPatch";
    }

    public static String readinessItemHandshake(boolean ar, int stateCode) {
        switch (stateCode) {
            case 2:
                return ar ? "٣. حالة المصافحة: متصل ومُتحقّق" : "3. Tunnel state: Connected & verified";
            case 1:
                return ar ? "٣. حالة المصافحة: جارٍ إتمام المصافحة..." : "3. Tunnel state: Establishing handshake...";
            case 3:
                return ar ? "٣. حالة المصافحة: الخادم لا يستجيب" : "3. Tunnel state: Server unresponsive";
            default:
                return ar ? "٣. حالة المصافحة: متوقف" : "3. Tunnel state: Disconnected";
        }
    }

    public static String launcherStepsToggleBtn(boolean ar, boolean expanded) {
        if (ar) {
            return expanded ? "إخفاء خطوات التفعيل" : "عرض خطوات التفعيل";
        }
        return expanded ? "Hide setup guide" : "Show setup guide";
    }

    public static String cleanCacheBtn(boolean ar, boolean busy) {
        if (busy) {
            return ar ? "جارٍ تنظيف المؤقتات..." : "Cleaning cache...";
        }
        return ar ? "تنظيف الملفات المؤقتة" : "Clean temporary cache";
    }

    public static String toastCacheCleaned(boolean ar, long freedBytes, int filesDeleted) {
        if (freedBytes > 0L) {
            String sz = formatBytes(ar, freedBytes);
            return ar
                    ? ("تم تحرير " + sz + " وتفريغ الذاكرة المؤقتة لتيليجرام")
                    : ("Freed " + sz + " and trimmed Telegram memory caches");
        }
        return ar
                ? "تم تفريغ الذاكرة المؤقتة (التخزين نظيف بالفعل)"
                : "Memory caches trimmed (temporary storage already clean)";
    }

    public static String hybridHeading(boolean ar) {
        return ar ? "تحسين الاستقرار بالخلفية (اختياري)" : "Background stability (optional)";
    }

    public static String hybridToggleCardBtn(boolean ar, boolean expanded) {
        if (ar) {
            return expanded ? "إخفاء خيارات الاستقرار المتقدمة" : "إعدادات الاستقرار المتقدمة";
        }
        return expanded ? "Hide advanced stability options" : "Advanced stability options";
    }

    public static String hybridOptionalNote(boolean ar) {
        return ar
                ? "اختياري للمتقدمين: التطبيق يعمل بشكل كامل بدون تفعيل هذا القسم."
                : "Optional setting: the app works fully without enabling this section.";
    }

    public static String hybridTierLabel(boolean ar, ContinuityBridgeManager.ContinuityTier tier) {
        ContinuityBridgeManager.ContinuityTier safe = tier != null
                ? tier
                : ContinuityBridgeManager.ContinuityTier.STANDARD_FGS;
        switch (safe) {
            case HYBRID_FULL:
                return ar
                        ? "الحماية الدائمة نشطة (بدون إشعار)"
                        : "Always-on protection active (no notification)";
            case PRIVILEGED_ONLY:
                return ar
                        ? "الحماية الخلفية نشطة (بدون إشعار)"
                        : "Background protection active (no notification)";
            case LISTENER_BOOT_GUARD:
                return ar
                        ? "التشغيل التلقائي الصامت نشط (بدون إشعار)"
                        : "Silent auto-start active (no notification)";
            case STANDARD_FGS:
            default:
                return ar
                        ? "الوضع العادي (بإشعار النظام)"
                        : "Standard mode (system notification)";
        }
    }

    public static String hybridDetailLine(boolean ar, ContinuityBridgeManager.StealthSnapshot snap) {
        if (snap == null) {
            return ar
                    ? "حالة الحماية: قيد التحقق"
                    : "Protection status: checking";
        }
        String stabilityPart;
        if (snap.rootActive) {
            stabilityPart = ar ? "صلاحيات النظام الكاملة: مفعّلة" : "Full system access: active";
        } else if (snap.daemonActive || snap.selfPrivileged) {
            stabilityPart = ar ? "استقرار الخلفية: مفعّل وجاهز" : "Background stability: active";
        } else if (snap.builtinAdbPaired) {
            stabilityPart = ar ? "التفعيل محفوظ: قيد التشغيل التلقائي" : "Setup saved: activating automatically";
        } else {
            stabilityPart = ar ? "الإعداد السريع: يحتاج تفعيلًا لمرة واحدة" : "Quick setup: one-time activation needed";
        }
        String autoStartPart;
        if (snap.listenerConnected) {
            autoStartPart = ar ? "التشغيل التلقائي: نشط" : "Auto-start: active";
        } else if (snap.listenerEnabled) {
            autoStartPart = ar ? "التشغيل التلقائي: جاهز" : "Auto-start: ready";
        } else {
            autoStartPart = ar ? "التشغيل التلقائي: غير مفعّل" : "Auto-start: off";
        }
        return stabilityPart + " • " + autoStartPart;
    }

    public static String hybridStealthToggleTitle(boolean ar) {
        return ar
                ? "العمل بالخلفية بصمت بدون إشعار"
                : "Run silently in background without notification";
    }

    public static String hybridMobileTcpToggleTitle(boolean ar) {
        return ar
                ? "استمرار الحماية التلقائية على بيانات الهاتف"
                : "Keep automatic protection active on Mobile Data";
    }

    public static String hybridActionOneTimeSetup(boolean ar) {
        return ar ? "تفعيل الحماية المتقدمة لمرة واحدة" : "One-time protection setup";
    }

    public static String hybridActionActivateNow(boolean ar) {
        return ar ? "تنشيط الحماية واستثناءات البطارية الآن" : "Activate protection & battery exemptions";
    }

    public static String hybridActionOpenListenerSettings(boolean ar) {
        return ar ? "منح صلاحية التشغيل التلقائي بالخلفية" : "Enable background auto-start permission";
    }

    public static String hybridHelperNote(boolean ar) {
        return ar
                ? "يُفعّل لمرة واحدة فقط برمز من ٦ أرقام، وبعدها يستمر الاتصال تلقائيًا عند إعادة التشغيل وعلى الوايفاي وبيانات الهاتف بدون أي إشعارات دائمة."
                : "Set up once with a 6-digit code so your connection stays protected across reboots, Wi-Fi, and Mobile Data with zero ongoing notifications.";
    }

    public static String hybridAppliedToast(boolean ar, boolean protectedNow) {
        if (ar) {
            return protectedNow
                    ? "تم تفعيل الحماية الصامتة بنجاح"
                    : "تم تحديث حالة الحماية";
        }
        return protectedNow
                ? "Silent protection enabled"
                : "Protection status updated";
    }

    public static String hybridPairingHintToast(boolean ar) {
        return ar
                ? "فعّل تصحيح الأخطاء اللاسلكي من خيارات المطور ثم أدخل الرمز داخل الإشعار"
                : "Enable Wireless debugging in Developer options, then enter the 6-digit code in the notification.";
    }

    public static String adbPairingChannelName(boolean ar) {
        return ar ? "تفعيل الحماية لمرة واحدة" : "One-time protection setup";
    }

    public static String adbPairingNotifTitle(boolean ar, int discoveredPort) {
        if (ar) {
            return discoveredPort > 0
                    ? "جاهز لإدخال رمز التفعيل"
                    : "جاري التحضير للربط اللاسلكي...";
        }
        return discoveredPort > 0
                ? "Ready for setup code"
                : "Preparing wireless pairing...";
    }

    public static String adbPairingNotifBody(boolean ar) {
        return ar
                ? "افتح إقران الجهاز برمز الإقران ثم اضغط إدخال الرمز واكتب الأرقام الستة."
                : "Open 'Pair device with pairing code', tap Enter code, and type the 6-digit code.";
    }

    public static String adbPairingActionReply(boolean ar) {
        return ar ? "إدخال الرمز" : "Enter code";
    }

    public static String adbPairingHint(boolean ar) {
        return ar ? "اكتب الأرقام الستة" : "6-digit code";
    }

    public static String adbPairingCancel(boolean ar) {
        return ar ? "إغلاق" : "Cancel";
    }

    public static String adbPairingResultToast(boolean ar, boolean ok) {
        if (ar) {
            return ok
                    ? "تم التفعيل بنجاح! الحماية الدائمة تعمل الآن بصمت"
                    : "تعذر الإكمال، تأكد من الرمز وتفعيل تصحيح الأخطاء اللاسلكي";
        }
        return ok
                ? "Setup complete! Permanent silent protection is now active."
                : "Setup failed. Check the 6-digit code and ensure Wireless debugging is enabled.";
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
                    ? "المفتاح المشترك المسبق غير صالح. تأكد من إدخاله كاملًا أو اتركه فارغًا."
                    : "Preshared key is invalid. Enter a valid 32-byte key or leave it empty.";
        }
        if (lower.contains("private key")) {
            return localizeErrorCode(ErrorCode.INVALID_KEY_FORMAT, "", ar);
        }
        if (lower.contains("public key")) {
            return ar
                    ? "المفتاح العام للخادم غير صالح. تأكد من نسخ المفتاح كاملًا."
                    : "Peer public key is invalid. Enter a complete 44-char Base64 or 64-char hex key.";
        }
        if (lower.contains("address")) {
            return ar
                    ? "عنوان النفق الداخلي غير صالح. اكتبه بصيغة مثل " + ltr("10.14.0.2/16") + "."
                    : "Tunnel address is invalid. Use CIDR format such as 10.14.0.2/16.";
        }
        if (lower.contains("dns")) {
            return ar
                    ? "عنوان خادم النطاقات غير صالح. استخدم عنوانًا رقميًا مثل " + ltr("1.1.1.1") + "."
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
                        ? "الحافظة فارغة. انسخ محتوى الإعدادات أولًا ثم أعد المحاولة."
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
                        ? "صيغة المفتاح غير صحيحة. يجب أن يتكون من 44 محرفًا أو 64 محرفًا ست عشريًا."
                        : "Invalid key encoding. Provide a 44-char Base64 or 64-char hex key.";
            case INVALID_KEY_LENGTH:
                return ar
                        ? "طول المفتاح غير مكتمل (32 بايت مطلوب). تأكد من نسخ المفتاح كاملًا."
                        : "Key length is incomplete (expected 32 bytes). Check that no characters are missing.";
            case TUNNEL_STOPPED:
                return ar
                        ? "النفق غير متصل حاليًا. اضغط اتصال أولًا ثم أعد الفحص."
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
                        ? "تعذّر إنشاء الرمز المربع. أكمل بيانات الخادم الأساسية أولًا."
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
                        ? "تعذّر تشغيل المحرك الأصلي داخل التطبيق. أعد فتح تيليجرام وحاول مجددًا."
                        : ("Native tunnel engine failed to initialize" + (detail.isEmpty() ? "." : (": " + detail)));
        }
    }
}
