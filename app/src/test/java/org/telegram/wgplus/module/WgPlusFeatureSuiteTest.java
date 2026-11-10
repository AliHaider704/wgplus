package org.telegram.wgplus.module;

import org.junit.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class WgPlusFeatureSuiteTest {

    private static final String SAMPLE_PRIV_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private static final String SAMPLE_PUB_B64 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private static final String SAMPLE_PSK_B64 = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=";

    @Test
    public void testAmneziaWgConfParseAndExportRoundTrip() throws Exception {
        String rawConf = "[Interface]\n"
                + "# AmneziaWG obfuscated profile\n"
                + "PrivateKey = " + SAMPLE_PRIV_B64 + "\n"
                + "Address = 10.14.0.2/16\n"
                + "DNS = 1.1.1.1, 1.0.0.1\n"
                + "MTU = 1360\n"
                + "Jc = 5\n"
                + "Jmin = 50\n"
                + "Jmax = 250\n"
                + "S1 = 44\n"
                + "S2 = 36\n"
                + "S3 = 20\n"
                + "S4 = 16\n"
                + "H1 = 120000100-120000200\n"
                + "H2 = 220000100-220000200\n"
                + "H3 = 320000100-320000200\n"
                + "H4 = 420000100-420000200\n"
                + "\n"
                + "[Peer]\n"
                + "PublicKey = " + SAMPLE_PUB_B64 + "\n"
                + "PresharedKey = " + SAMPLE_PSK_B64 + "\n"
                + "Endpoint = de-fra.prod.surfshark.com:51820\n"
                + "AllowedIPs = 0.0.0.0/0, ::/0\n"
                + "PersistentKeepalive = 21\n";

        WireGuardManager.TunnelConfig parsed = WireGuardManager.parseConfText(rawConf, null);
        assertEquals(SAMPLE_PRIV_B64, parsed.privateKey);
        assertEquals(SAMPLE_PUB_B64, parsed.publicKey);
        assertEquals(SAMPLE_PSK_B64, parsed.presharedKey);
        assertEquals("10.14.0.2/16", parsed.address);
        assertEquals("1.1.1.1, 1.0.0.1", parsed.dns);
        assertEquals(1360, parsed.mtu);
        assertEquals(21, parsed.keepAlive);
        assertEquals("de-fra.prod.surfshark.com:51820", parsed.endpoint);
        assertTrue(parsed.hasAwgConfigured());
        assertEquals(5, parsed.jc);
        assertEquals(50, parsed.jmin);
        assertEquals(250, parsed.jmax);
        assertEquals(44, parsed.s1);
        assertEquals(36, parsed.s2);
        assertEquals(20, parsed.s3);
        assertEquals(16, parsed.s4);
        assertEquals("120000100-120000200", parsed.h1);
        assertEquals("220000100-220000200", parsed.h2);
        assertEquals("320000100-320000200", parsed.h3);
        assertEquals("420000100-420000200", parsed.h4);

        String awgParams = parsed.toAwgParamsString();
        assertTrue(awgParams.contains("Jc=5\n"));
        assertTrue(awgParams.contains("S1=44\n"));
        assertTrue(awgParams.contains("H1=120000100-120000200\n"));
        assertTrue(awgParams.contains("H4=420000100-420000200\n"));

        String exported = WireGuardManager.exportConfText(parsed);
        WireGuardManager.TunnelConfig reparsed = WireGuardManager.parseConfText(exported, null);
        assertEquals(parsed.privateKey, reparsed.privateKey);
        assertEquals(parsed.publicKey, reparsed.publicKey);
        assertEquals(parsed.presharedKey, reparsed.presharedKey);
        assertEquals(parsed.address, reparsed.address);
        assertEquals(parsed.dns, reparsed.dns);
        assertEquals(parsed.mtu, reparsed.mtu);
        assertEquals(parsed.keepAlive, reparsed.keepAlive);
        assertEquals(parsed.endpoint, reparsed.endpoint);
        assertEquals(parsed.toAwgParamsString(), reparsed.toAwgParamsString());
        assertEquals(parsed.toAwgParamsString(), parsed.toEffectiveAwgParamsString());

        WireGuardManager.TunnelConfig vanilla = new WireGuardManager.TunnelConfig();
        assertFalse(vanilla.hasAwgConfigured());
        assertEquals("", vanilla.toAwgParamsString());
        assertEquals("Jc=3\nJmin=48\nJmax=108\n", vanilla.toEffectiveAwgParamsString());
    }

    @Test
    public void testQrCodeEncodeAndDecodeRoundTripLightAndInvertedDark() throws Exception {
        WireGuardManager.TunnelConfig cfg = new WireGuardManager.TunnelConfig();
        cfg.privateKey = SAMPLE_PRIV_B64;
        cfg.publicKey = SAMPLE_PUB_B64;
        cfg.presharedKey = SAMPLE_PSK_B64;
        cfg.address = "10.66.66.2/32";
        cfg.dns = "1.1.1.1";
        cfg.mtu = 1360;
        cfg.endpoint = "nl-ams.prod.surfshark.com:51820";
        cfg.keepAlive = 25;
        cfg.jc = 4;
        cfg.jmin = 50;
        cfg.jmax = 250;
        cfg.h1 = "123456701";
        cfg.h2 = "123456702";
        cfg.h3 = "123456703";
        cfg.h4 = "123456704";

        String payload = WireGuardManager.exportConfText(cfg);
        WgQrCodec.ArgbFrame frame = WgQrCodec.encodeToArgbPixels(payload, 520);
        assertNotNull(frame);
        assertTrue(frame.width >= 240);
        assertEquals(frame.width * frame.height, frame.pixels.length);

        // 1. Standard light-background QR decode
        String decodedLight = WgQrCodec.decodeFromArgbPixels(frame.pixels, frame.width, frame.height);
        assertEquals(payload.trim(), decodedLight.trim());

        // 2. Inverted dark-mode screenshot QR decode (white modules on black background)
        int[] inverted = new int[frame.pixels.length];
        for (int i = 0; i < frame.pixels.length; i++) {
            int rgb = frame.pixels[i] & 0x00FFFFFF;
            inverted[i] = 0xFF000000 | (~rgb & 0x00FFFFFF);
        }
        String decodedDark = WgQrCodec.decodeFromArgbPixels(inverted, frame.width, frame.height);
        assertEquals(payload.trim(), decodedDark.trim());

        // 3. Blank frame must fail cleanly with QR_NOT_FOUND
        int[] blank = new int[300 * 300];
        for (int i = 0; i < blank.length; i++) {
            blank[i] = 0xFFFFFFFF;
        }
        try {
            WgQrCodec.decodeFromArgbPixels(blank, 300, 300);
            fail("Expected QR_NOT_FOUND on blank image");
        } catch (WgStrings.WgException e) {
            assertEquals(WgStrings.ErrorCode.QR_NOT_FOUND, e.code);
        }
    }

    @Test
    public void testMultiProfileBackupSerializeAndDeserialize() throws Exception {
        List<WireGuardManager.TunnelConfig> originals = new ArrayList<>();

        WireGuardManager.TunnelConfig p1 = new WireGuardManager.TunnelConfig();
        p1.name = "Frankfurt Primary";
        p1.privateKey = SAMPLE_PRIV_B64;
        p1.publicKey = SAMPLE_PUB_B64;
        p1.address = "10.0.0.2/32";
        p1.dns = "1.1.1.1";
        p1.endpoint = "198.51.100.10:51820";
        p1.mtu = 1420;
        originals.add(p1);

        WireGuardManager.TunnelConfig p2 = new WireGuardManager.TunnelConfig();
        p2.name = "Surfshark Tbilisi";
        p2.privateKey = SAMPLE_PRIV_B64;
        p2.publicKey = SAMPLE_PUB_B64;
        p2.presharedKey = SAMPLE_PSK_B64;
        p2.address = "10.14.0.2/16";
        p2.dns = "162.252.172.57";
        p2.endpoint = "ge-tbs.prod.surfshark.com:51820";
        p2.mtu = 1360;
        originals.add(p2);

        WireGuardManager.TunnelConfig p3 = new WireGuardManager.TunnelConfig();
        p3.name = "AmneziaWG Stealth";
        p3.privateKey = SAMPLE_PRIV_B64;
        p3.publicKey = SAMPLE_PUB_B64;
        p3.address = "10.8.1.2/24";
        p3.endpoint = "203.0.113.77:443";
        p3.jc = 6;
        p3.jmin = 64;
        p3.jmax = 320;
        p3.s1 = 30;
        p3.s2 = 40;
        p3.h1 = "110000000-110000999";
        p3.h2 = "210000000-210000999";
        p3.h3 = "310000000-310000999";
        p3.h4 = "410000000-410000999";
        originals.add(p3);

        String json = WireGuardManager.serializeProfilesBackupJson(originals);
        assertTrue(json.contains(WireGuardManager.BACKUP_SCHEMA));

        List<WireGuardManager.TunnelConfig> restored = WireGuardManager.deserializeProfilesBackupJson(json);
        assertEquals(3, restored.size());
        assertEquals("Frankfurt Primary", restored.get(0).name);
        assertEquals(1420, restored.get(0).mtu);
        assertEquals("Surfshark Tbilisi", restored.get(1).name);
        assertEquals(SAMPLE_PSK_B64, restored.get(1).presharedKey);
        assertEquals("AmneziaWG Stealth", restored.get(2).name);
        assertEquals(6, restored.get(2).jc);
        assertEquals(30, restored.get(2).s1);
        assertEquals("110000000-110000999", restored.get(2).h1);

        try {
            WireGuardManager.deserializeProfilesBackupJson("{\"schema\":\"wrong\",\"profiles\":[]}");
            fail("Expected BACKUP_INVALID for wrong schema");
        } catch (WgStrings.WgException e) {
            assertEquals(WgStrings.ErrorCode.BACKUP_INVALID, e.code);
        }
    }

    @Test
    public void testKeyNormalizationBase64AndHex() throws Exception {
        String hex = WireGuardManager.normalizeKeyToHex(SAMPLE_PRIV_B64);
        assertEquals(64, hex.length());
        assertEquals("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", hex);

        String fromUpperHex = WireGuardManager.normalizeKeyToHex(hex.toUpperCase(Locale.ROOT));
        assertEquals(hex, fromUpperHex);

        try {
            WireGuardManager.normalizeKeyToHex("dG9vc2hvcnQ=");
            fail("Expected INVALID_KEY_LENGTH");
        } catch (WgStrings.WgException e) {
            assertEquals(WgStrings.ErrorCode.INVALID_KEY_LENGTH, e.code);
        }

        try {
            WireGuardManager.normalizeKeyToHex("not!valid!base64!at!all!!!");
            fail("Expected INVALID_KEY_FORMAT");
        } catch (WgStrings.WgException e) {
            assertEquals(WgStrings.ErrorCode.INVALID_KEY_FORMAT, e.code);
        }
    }

    @Test
    public void testZeroLanguageLeakageZeroEmDashAndZeroBuzzwords() throws Exception {
        String[] bannedBuzzwords = new String[]{
                "ai powered", "next generation", "revolutionary", "seamless",
                "cutting edge", "intelligent", "ultimate", "effortless"
        };

        Pattern isolateSpan = Pattern.compile("\u2066.*?\u2069");
        Pattern latinLetters = Pattern.compile("[A-Za-z]");
        Pattern arabicLetters = Pattern.compile("[\\u0600-\\u06FF]");

        Method[] methods = WgStrings.class.getDeclaredMethods();
        int checkedMethods = 0;

        for (Method m : methods) {
            if (!Modifier.isPublic(m.getModifiers()) || !Modifier.isStatic(m.getModifiers())) {
                continue;
            }
            if (!String.class.equals(m.getReturnType())) {
                continue;
            }
            String name = m.getName();
            if ("ltr".equals(name)) {
                continue;
            }

            Class<?>[] paramTypes = m.getParameterTypes();
            if (paramTypes.length == 0 || paramTypes[0] != boolean.class) {
                continue;
            }

            checkedMethods++;
            for (boolean ar : new boolean[]{true, false}) {
                Object[] args = buildSampleArgs(name, paramTypes, ar);
                String out = (String) m.invoke(null, args);
                assertNotNull("Null string from " + name, out);

                // R-02: Zero em dashes anywhere
                assertFalse("Em dash found in " + name + " (ar=" + ar + "): " + out, out.contains("\u2014"));

                // No marketing buzzwords in UI copy
                String lower = out.toLowerCase(Locale.ROOT);
                for (String buzz : bannedBuzzwords) {
                    assertFalse("Banned buzzword '" + buzz + "' in " + name + ": " + out, lower.contains(buzz));
                }

                if ("langToggleLabel".equals(name)) {
                    if (ar) {
                        assertEquals("English", out);
                    } else {
                        assertEquals("العربية", out);
                    }
                    continue;
                }

                if (ar) {
                    String stripped = isolateSpan.matcher(out).replaceAll("");
                    Matcher lm = latinLetters.matcher(stripped);
                    if (lm.find()) {
                        fail("Latin leakage in Arabic string " + name + ": '" + out + "' (stripped: '" + stripped + "')");
                    }
                } else {
                    Matcher am = arabicLetters.matcher(out);
                    if (am.find()) {
                        fail("Arabic leakage in English string " + name + ": '" + out + "'");
                    }
                }
            }
        }
        assertTrue("Expected at least 60 localized methods checked, got " + checkedMethods, checkedMethods >= 60);
    }

    private static Object[] buildSampleArgs(String methodName, Class<?>[] types, boolean ar) {
        Object[] args = new Object[types.length];
        args[0] = ar;
        for (int i = 1; i < types.length; i++) {
            Class<?> t = types[i];
            if (t == boolean.class) {
                args[i] = true;
            } else if (t == int.class) {
                args[i] = 1080;
            } else if (t == long.class) {
                args[i] = 4096L;
            } else if (t == String.class) {
                if ("countryName".equals(methodName)) {
                    args[i] = "DE";
                } else {
                    args[i] = ar ? "خادم تجريبي" : "Test Server";
                }
            } else if (t == Throwable.class) {
                args[i] = new WgStrings.WgException(WgStrings.ErrorCode.INVALID_CONF);
            } else if (t == WireGuardManager.TunnelVerifyResult.class) {
                WireGuardManager.TunnelVerifyResult r = new WireGuardManager.TunnelVerifyResult();
                r.exitIp = "198.51.100.24";
                r.countryCode = "DE";
                r.colo = "FRA";
                r.tunnelPingMs = 48L;
                r.telegramDcReachable = true;
                r.telegramDcPingMs = 42L;
                r.udpCallsReady = true;
                r.udpPingMs = 39L;
                args[i] = r;
            }
        }
        return args;
    }

    @Test
    public void testWcagContrastDarkAndLightPalette() throws Exception {
        Path themeFile = resolveThemeFilePath();
        String src = new String(Files.readAllBytes(themeFile), StandardCharsets.UTF_8);

        int splitIdx = src.indexOf("} else {");
        assertTrue("Expected dark/light branches in WgTheme.java", splitIdx > 0);
        String darkBlock = src.substring(0, splitIdx);
        String lightBlock = src.substring(splitIdx);

        Map<String, Integer> dark = parseColorAssignments(darkBlock);
        Map<String, Integer> light = parseColorAssignments(lightBlock);

        assertPaletteContrast("Dark", dark);
        assertPaletteContrast("Light", light);
    }

    private static Path resolveThemeFilePath() {
        Path p1 = Paths.get("src/main/java/org/telegram/wgplus/module/WgTheme.java");
        if (Files.exists(p1)) {
            return p1;
        }
        Path p2 = Paths.get("app/src/main/java/org/telegram/wgplus/module/WgTheme.java");
        if (Files.exists(p2)) {
            return p2;
        }
        throw new IllegalStateException("Cannot locate WgTheme.java from working dir " + Paths.get("").toAbsolutePath());
    }

    private static Map<String, Integer> parseColorAssignments(String block) {
        Map<String, Integer> map = new HashMap<>();
        Pattern p = Pattern.compile("(\\w+)\\s*=\\s*Color\\.parseColor\\(\"#([0-9A-Fa-f]{6})\"\\)");
        Matcher m = p.matcher(block);
        while (m.find()) {
            String name = m.group(1);
            int rgb = Integer.parseInt(m.group(2), 16);
            map.put(name, rgb);
        }
        return map;
    }

    private static void assertPaletteContrast(String mode, Map<String, Integer> c) {
        String[] surfaces = new String[]{"surfaceBase", "surfaceCard", "surfaceInput", "surfaceFooter"};
        String[] texts = new String[]{"textPrimary", "textSecondary", "textHint"};

        for (String s : surfaces) {
            for (String t : texts) {
                double ratio = contrastRatio(c.get(t), c.get(s));
                assertTrue(mode + " contrast too low for " + t + " on " + s + ": " + String.format(Locale.US, "%.2f", ratio),
                        ratio >= 4.5);
            }
        }

        assertTrue(mode + " secondary button contrast < 4.5",
                contrastRatio(c.get("textPrimary"), c.get("surfaceSecondaryBtn")) >= 4.5);
        assertTrue(mode + " primary accent button contrast < 4.5",
                contrastRatio(c.get("onAccent"), c.get("accentPrimary")) >= 4.5);
        assertTrue(mode + " pressed accent button contrast < 4.5",
                contrastRatio(c.get("onAccent"), c.get("accentPressed")) >= 4.5);
        assertTrue(mode + " active status contrast < 4.5",
                contrastRatio(c.get("activeText"), c.get("activeBg")) >= 4.5);
        assertTrue(mode + " pending status contrast < 4.5",
                contrastRatio(c.get("pendingText"), c.get("pendingBg")) >= 4.5);
        assertTrue(mode + " stopped status contrast < 4.5",
                contrastRatio(c.get("stoppedText"), c.get("stoppedBg")) >= 4.5);
    }

    @Test
    public void testHybridContinuityTierResolutionAndVersionLabel() {
        assertEquals("1.4.0", WgStrings.VERSION_LABEL);

        assertEquals(
                ContinuityBridgeManager.ContinuityTier.HYBRID_FULL,
                ContinuityBridgeManager.computeContinuityTier(true, true, true)
        );
        assertEquals(
                ContinuityBridgeManager.ContinuityTier.SHIZUKU_ONLY,
                ContinuityBridgeManager.computeContinuityTier(true, true, false)
        );
        assertEquals(
                ContinuityBridgeManager.ContinuityTier.LISTENER_BOOT_GUARD,
                ContinuityBridgeManager.computeContinuityTier(true, false, true)
        );
        assertEquals(
                ContinuityBridgeManager.ContinuityTier.STANDARD_FGS,
                ContinuityBridgeManager.computeContinuityTier(true, false, false)
        );
        assertEquals(
                ContinuityBridgeManager.ContinuityTier.STANDARD_FGS,
                ContinuityBridgeManager.computeContinuityTier(false, true, true)
        );

        for (ContinuityBridgeManager.ContinuityTier tier : ContinuityBridgeManager.ContinuityTier.values()) {
            assertFalse(WgStrings.hybridTierLabel(true, tier).isEmpty());
            assertFalse(WgStrings.hybridTierLabel(false, tier).isEmpty());
        }
        ContinuityBridgeManager.StealthSnapshot snap = new ContinuityBridgeManager.StealthSnapshot(
                true, true, true, true, true, true, true, true,
                ContinuityBridgeManager.ContinuityTier.HYBRID_FULL
        );
        assertFalse(WgStrings.hybridDetailLine(true, snap).matches(".*[A-Za-z].*"));
        assertFalse(WgStrings.hybridDetailLine(false, snap).matches(".*[\\u0600-\\u06FF].*"));
    }

    private static double contrastRatio(int rgb1, int rgb2) {
        double l1 = relativeLuminance(rgb1);
        double l2 = relativeLuminance(rgb2);
        double lighter = Math.max(l1, l2);
        double darker = Math.min(l1, l2);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double relativeLuminance(int rgb) {
        double r = channelLinear((rgb >> 16) & 0xFF);
        double g = channelLinear((rgb >> 8) & 0xFF);
        double b = channelLinear(rgb & 0xFF);
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    }

    private static double channelLinear(int v8) {
        double s = v8 / 255.0;
        return s <= 0.03928 ? (s / 12.92) : Math.pow((s + 0.055) / 1.055, 2.4);
    }
}
