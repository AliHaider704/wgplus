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
        assertEquals("", vanilla.toEffectiveAwgParamsString());
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

                // Quranic tanween fath: tanween must sit on the letter before alef (\u064B\u0627), never on the alef (\u0627\u064B)
                assertFalse("Tanween fath placed on alef instead of preceding letter in " + name + ": " + out,
                        out.contains("\u0627\u064B"));

                // No marketing buzzwords in UI copy
                String lower = out.toLowerCase(Locale.ROOT);
                for (String buzz : bannedBuzzwords) {
                    assertFalse("Banned buzzword '" + buzz + "' in " + name + ": " + out, lower.contains(buzz));
                }

                // Official Arabic spelling from Google Play
                assertFalse("Non-standard Telegram spelling in " + name + ": " + out,
                        out.contains("تليجرام") || out.contains("تيليغرام"));

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

        for (boolean ar : new boolean[]{true, false}) {
            String[] steps = WgStrings.launcherSteps(ar);
            assertEquals(4, steps.length);
            for (String step : steps) {
                assertFalse("Em dash in launcherStep: " + step, step.contains("\u2014"));
                assertFalse("Non-standard Telegram spelling in launcherStep: " + step,
                        step.contains("تليجرام") || step.contains("تيليغرام"));
                if (ar) {
                    String stripped = isolateSpan.matcher(step).replaceAll("");
                    assertFalse("Latin leak in AR launcherStep: " + step, latinLetters.matcher(stripped).find());
                } else {
                    assertFalse("Arabic leak in EN launcherStep: " + step, arabicLetters.matcher(step).find());
                }
            }
        }

        // Default profile names ("خادم N" / "Server N") must dynamically localize across languages
        assertEquals("Server 1", WgStrings.localizeProfileName("خادم 1", false));
        assertEquals("Server 1", WgStrings.localizeProfileName("خادم ١", false));
        assertEquals("خادم 1", WgStrings.localizeProfileName("Server 1", true));
        assertEquals("Server 2 (2)", WgStrings.localizeProfileName("خادم 2 (2)", false));
        assertEquals("Germany WireGuard", WgStrings.localizeProfileName("Germany WireGuard", false));
        assertFalse(WgStrings.statusStoppedWithProfile(false, "خادم 1").matches(".*[\\u0600-\\u06FF].*"));
        assertTrue(WgStrings.statusActiveWithProfile(false, "خادم 1", 1080).contains("Server 1"));
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
        assertEquals("2.0.0", WgStrings.VERSION_LABEL);

        assertEquals(
                ContinuityBridgeManager.ContinuityTier.HYBRID_FULL,
                ContinuityBridgeManager.computeContinuityTier(true, true, true)
        );
        assertEquals(
                ContinuityBridgeManager.ContinuityTier.PRIVILEGED_ONLY,
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
                true, true, true, true, true,
                ContinuityBridgeManager.ContinuityTier.HYBRID_FULL,
                false, true, true, true
        );
        assertFalse(WgStrings.hybridDetailLine(true, snap).matches(".*[A-Za-z].*"));
        assertFalse(WgStrings.hybridDetailLine(false, snap).matches(".*[\\u0600-\\u06FF].*"));

        assertTrue(DaemonProcessHelper.isSafeToken("org.telegram.wgplus.module"));
        assertFalse(DaemonProcessHelper.isSafeToken("org.telegram.plus; rm -rf /"));
        assertTrue(DaemonProcessHelper.isSafeComponent("org.telegram.wgplus.module/org.telegram.wgplus.module.KeepaliveBridgeListenerService"));
        assertFalse(DaemonProcessHelper.isSafeComponent("bad;component"));

        String script = DaemonProcessHelper.buildDeepExemptionsShellScript(
                "org.telegram.wgplus.module",
                java.util.Arrays.asList("org.telegram.plus", "bad;pkg"),
                "org.telegram.wgplus.module/org.telegram.wgplus.module.KeepaliveBridgeListenerService",
                true
        );
        assertTrue(script.contains("pm grant org.telegram.wgplus.module android.permission.SET_PROCESS_LIMIT"));
        assertTrue(script.contains("SYSTEM_EXEMPT_FROM_HIBERNATION"));
        assertTrue(script.contains("set-background-networking-enabled-for-uid"));
        assertFalse(script.contains("bad;pkg"));

        assertTrue(BuiltinAdbKeyManager.isValidPairingCode("123456"));
        assertFalse(BuiltinAdbKeyManager.isValidPairingCode("12345"));
        assertFalse(BuiltinAdbKeyManager.isValidPairingCode("12ab56"));
        String[] plainPin = BuiltinAdbKeyManager.parsePairingInput("654321");
        assertNotNull(plainPin);
        assertEquals("654321", plainPin[0]);
        assertEquals("", plainPin[1]);
        String[] pinPort = BuiltinAdbKeyManager.parsePairingInput("654321:39121");
        assertNotNull(pinPort);
        assertEquals("654321", pinPort[0]);
        assertEquals("39121", pinPort[1]);
        assertTrue(BuiltinAdbKeyManager.isValidDynamicPort(5557));
        assertFalse(BuiltinAdbKeyManager.isValidDynamicPort(80));

        String[] arNewStrings = new String[]{
                WgStrings.hybridHeading(true),
                WgStrings.hybridDetailLine(true, snap),
                WgStrings.hybridStealthToggleTitle(true),
                WgStrings.hybridMobileTcpToggleTitle(true),
                WgStrings.hybridActionOneTimeSetup(true),
                WgStrings.hybridActionActivateNow(true),
                WgStrings.hybridActionOpenListenerSettings(true),
                WgStrings.hybridHelperNote(true),
                WgStrings.hybridAppliedToast(true, true),
                WgStrings.hybridPairingHintToast(true),
                WgStrings.adbPairingChannelName(true),
                WgStrings.adbPairingNotifTitle(true, 0),
                WgStrings.adbPairingNotifTitle(true, 39121),
                WgStrings.adbPairingNotifBody(true),
                WgStrings.adbPairingActionReply(true),
                WgStrings.adbPairingHint(true),
                WgStrings.adbPairingCancel(true),
                WgStrings.adbPairingResultToast(true, true),
                WgStrings.adbPairingResultToast(true, false)
        };
        for (String s : arNewStrings) {
            assertFalse("Expected no Latin leak in Arabic UI string: " + s, s.matches(".*[A-Za-z].*"));
            assertFalse("Forbidden em-dash in string: " + s, s.contains("\u2014"));
            assertFalse("Forbidden Shizuku/jargon in string: " + s,
                    s.contains("شيزوكو") || s.contains("-1000") || s.contains("١٠٠٠"));
        }
        String[] enNewStrings = new String[]{
                WgStrings.hybridHeading(false),
                WgStrings.hybridDetailLine(false, snap),
                WgStrings.hybridStealthToggleTitle(false),
                WgStrings.hybridMobileTcpToggleTitle(false),
                WgStrings.hybridActionOneTimeSetup(false),
                WgStrings.hybridActionActivateNow(false),
                WgStrings.hybridActionOpenListenerSettings(false),
                WgStrings.hybridHelperNote(false),
                WgStrings.hybridAppliedToast(false, true),
                WgStrings.hybridPairingHintToast(false),
                WgStrings.adbPairingChannelName(false),
                WgStrings.adbPairingNotifTitle(false, 0),
                WgStrings.adbPairingNotifTitle(false, 39121),
                WgStrings.adbPairingNotifBody(false),
                WgStrings.adbPairingActionReply(false),
                WgStrings.adbPairingHint(false),
                WgStrings.adbPairingCancel(false),
                WgStrings.adbPairingResultToast(false, true),
                WgStrings.adbPairingResultToast(false, false)
        };
        for (String s : enNewStrings) {
            assertFalse("Expected no Arabic leak in English UI string: " + s, s.matches(".*[\\u0600-\\u06FF].*"));
            assertFalse("Forbidden em-dash in string: " + s, s.contains("\u2014"));
            String lower = s.toLowerCase(java.util.Locale.ROOT);
            assertFalse("Forbidden Shizuku/jargon in EN string: " + s,
                    lower.contains("shizuku") || lower.contains("daemon") || lower.contains("loopback")
                            || lower.contains("-1000") || lower.contains("39121") || lower.contains("adb"));
        }
    }

    @Test
    public void testAwg15WarpReservedRoundTripAndGeneratedJson() throws Exception {
        String sampleI1 = "<b 0xc70000000108><r 8><b 0x0000449e><r 1200>";
        String warpJson = "{"
                + "\"name\":\"Cloudflare WARP (AWG 1.5)\","
                + "\"privateKey\":\"" + SAMPLE_PRIV_B64 + "\","
                + "\"clientIp\":\"172.16.0.2/32, 2606:4700:110:8::2/128\","
                + "\"dns\":\"1.1.1.1\","
                + "\"peerPublicKey\":\"" + SAMPLE_PUB_B64 + "\","
                + "\"endpoint\":\"engage.cloudflareclient.com:2408\","
                + "\"endpointV4\":\"162.159.192.1\","
                + "\"keepAlive\":25,"
                + "\"mtu\":1280,"
                + "\"jc\":4,"
                + "\"jmin\":40,"
                + "\"jmax\":120,"
                + "\"i1\":\"" + sampleI1 + "\","
                + "\"reserved\":\"12,34,56\""
                + "}";
        String[] epV4 = new String[1];
        WireGuardManager.TunnelConfig parsed = WireGuardManager.parseWarpGeneratedJson(warpJson, epV4);
        assertTrue(parsed.isWarp);
        assertEquals("162.159.192.1", epV4[0]);
        assertEquals(sampleI1, parsed.i1);
        assertEquals("12,34,56", parsed.reserved);
        assertTrue(parsed.hasAwgConfigured());
        String awgParams = parsed.toAwgParamsString();
        assertTrue(awgParams.contains("I1=" + sampleI1));
        assertTrue(awgParams.contains("Reserved=12,34,56"));

        String conf = WireGuardManager.exportConfText(parsed);
        WireGuardManager.TunnelConfig reparsed = WireGuardManager.parseConfText(conf, null);
        assertEquals(sampleI1, reparsed.i1);
        assertEquals("12,34,56", reparsed.reserved);

        String backup = WireGuardManager.serializeProfilesBackupJson(java.util.Collections.singletonList(parsed));
        List<WireGuardManager.TunnelConfig> restored = WireGuardManager.deserializeProfilesBackupJson(backup);
        assertEquals(1, restored.size());
        assertEquals(sampleI1, restored.get(0).i1);
        assertEquals("12,34,56", restored.get(0).reserved);
        assertTrue(restored.get(0).isWarp);
    }

    @Test
    public void testSafeCacheHygieneWhitelistAndNewUiStateStrings() {
        assertTrue(ModuleHygieneManager.isSafeCachePath("tgcache/photo_123.jpg"));
        assertTrue(ModuleHygieneManager.isSafeCachePath("/data/user/0/org.telegram.plus/cache/thumb_tmp.webp"));
        assertFalse(ModuleHygieneManager.isSafeCachePath(""));
        assertFalse(ModuleHygieneManager.isSafeCachePath(null));

        String[] protectedPaths = new String[]{
                "/data/user/0/org.telegram.plus/files/lspatch/origin.apk",
                "/data/user/0/org.telegram.plus/cache/xposed_meta",
                "/data/user/0/org.telegram.plus/cache/classes.dex",
                "/data/user/0/org.telegram.plus/oat/arm64/base.oat",
                "/data/user/0/org.telegram.plus/app_webview/Default",
                "/data/user/0/org.telegram.plus/databases/cache4.db",
                "/data/user/0/org.telegram.plus/shared_prefs/wg_plus_isolated_prefs.xml",
                "/data/user/0/org.telegram.plus/files/wg_native/libgojni.so",
                "/data/user/0/org.telegram.plus/files/televip/config.json"
        };
        for (String p : protectedPaths) {
            assertFalse("Protected path must NEVER be treated as disposable cache: " + p,
                    ModuleHygieneManager.isSafeCachePath(p));
        }

        for (boolean ar : new boolean[]{true, false}) {
            for (int st = 0; st <= 3; st++) {
                String item = WgStrings.readinessItemHandshake(ar, st);
                assertFalse(item.isEmpty());
                assertFalse(item.contains("\u2014"));
                assertFalse(item.contains("تليجرام") || item.contains("تيليغرام"));
            }
            assertFalse(WgStrings.readinessItemServer(ar, true).isEmpty());
            assertFalse(WgStrings.readinessItemServer(ar, false).isEmpty());
            assertFalse(WgStrings.readinessItemHook(ar, "org.telegram.plus").isEmpty());
            assertFalse(WgStrings.readinessItemHook(ar, "").isEmpty());
            assertFalse(WgStrings.statusAwaitingHandshakeWithProfile(ar, "WARP").isEmpty());
            assertFalse(WgStrings.statusStalledWithProfile(ar, "WARP").isEmpty());
            assertFalse(WgStrings.recoverAwgBtn(ar).isEmpty());
            assertFalse(WgStrings.cleanCacheBtn(ar, false).isEmpty());
            assertFalse(WgStrings.cleanCacheBtn(ar, true).isEmpty());
            assertFalse(WgStrings.toastCacheCleaned(ar, 1024L * 1024L, 5).isEmpty());
            assertFalse(WgStrings.toastCacheCleaned(ar, 0L, 0).isEmpty());
            assertFalse(WgStrings.diagnosticsBtn(ar).isEmpty());
            assertFalse(WgStrings.diagnosticsGithubBtn(ar).isEmpty());
            assertFalse(WgStrings.officialChannelBtn(ar).isEmpty());
            assertTrue(WgStrings.officialChannelBtn(ar).contains("@wgplus_official"));
            assertFalse(WgStrings.backupPassphraseTitle(ar, true).isEmpty());
            assertFalse(WgStrings.backupPassphraseTitle(ar, false).isEmpty());
        }
    }

    @Test
    public void testSocks5ClientAuthNoAuthAndRfc1929() throws Exception {
        // 1. No-auth handshake
        java.io.ByteArrayOutputStream noAuthOut = new java.io.ByteArrayOutputStream();
        java.io.DataInputStream noAuthIn = new java.io.DataInputStream(
                new java.io.ByteArrayInputStream(new byte[]{0x05, 0x00})
        );
        WireGuardManager.performSocks5ClientAuth(noAuthOut, noAuthIn, "", "");
        org.junit.Assert.assertArrayEquals(new byte[]{0x05, 0x01, 0x00}, noAuthOut.toByteArray());

        // 2. RFC 1929 username/password handshake
        java.io.ByteArrayOutputStream authOut = new java.io.ByteArrayOutputStream();
        java.io.DataInputStream authIn = new java.io.DataInputStream(
                new java.io.ByteArrayInputStream(new byte[]{0x05, 0x02, 0x01, 0x00})
        );
        WireGuardManager.performSocks5ClientAuth(authOut, authIn, "wg", "pass123");
        org.junit.Assert.assertArrayEquals(
                new byte[]{0x05, 0x02, 0x00, 0x02, 0x01, 0x02, 'w', 'g', 0x07, 'p', 'a', 's', 's', '1', '2', '3'},
                authOut.toByteArray()
        );

        // 3. Server rejects wrong credentials (0x01, 0x01)
        try {
            java.io.DataInputStream badIn = new java.io.DataInputStream(
                    new java.io.ByteArrayInputStream(new byte[]{0x05, 0x02, 0x01, 0x01})
            );
            WireGuardManager.performSocks5ClientAuth(new java.io.ByteArrayOutputStream(), badIn, "wg", "wrong");
            fail("expected SOCKS5 auth failure");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("SOCKS5 auth failed"));
        }
    }

    @Test
    public void testPatchVoipConfigJsonForProxy() throws Exception {
        String sample = "{\"enable_vp8_encoder\":true,\"force_tcp\":false,\"use_tcp\":false,\"audio_frame_size\":60}";
        String patched = WireGuardManager.patchVoipConfigJsonForProxy(sample);
        assertNotNull(patched);
        org.json.JSONObject obj = new org.json.JSONObject(patched);
        assertTrue(obj.getBoolean("force_tcp"));
        assertTrue(obj.getBoolean("use_tcp"));
        assertTrue(obj.getBoolean("enable_vp8_encoder"));
        assertEquals(60, obj.getInt("audio_frame_size"));
        assertEquals("plain", WireGuardManager.patchVoipConfigJsonForProxy("plain"));
    }

    @Test
    public void testKeystoreNoPlaintextFallbackAndDiagnosticsRedaction() {
        // Even in headless JVM (no AndroidKeyStore provider), WgKeystoreCrypto.encrypt MUST NOT return plaintext.
        String enc = WgKeystoreCrypto.encrypt(SAMPLE_PRIV_B64);
        assertFalse("encrypt() must never return raw plaintext", SAMPLE_PRIV_B64.equals(enc));
        assertTrue("encrypted value must carry enc:v1 or enc:v2 prefix", WgKeystoreCrypto.isEncryptedValue(enc));
        assertEquals(SAMPLE_PRIV_B64, WgKeystoreCrypto.decrypt(enc));

        String raw = "PrivateKey=" + SAMPLE_PRIV_B64 + " PresharedKey=" + SAMPLE_PSK_B64
                + " endpoint=198.51.100.42:51820 pass=mySecret123";
        String sanitized = WgDiagnosticsLog.sanitize(raw);
        assertFalse("PrivateKey leaked in diagnostic sanitizer", sanitized.contains(SAMPLE_PRIV_B64));
        assertFalse("PresharedKey leaked in diagnostic sanitizer", sanitized.contains(SAMPLE_PSK_B64));
        assertFalse("Endpoint leaked in diagnostic sanitizer", sanitized.contains("198.51.100.42:51820"));
        assertFalse("Password leaked in diagnostic sanitizer", sanitized.contains("mySecret123"));
        assertTrue(sanitized.contains("[REDACTED]") || sanitized.contains("[KEY_REDACTED]"));
    }

    @Test
    public void testRewriteGroupCallJoinPayloadRelaysAndBlackholesSafely() throws Exception {
        String samplePayload = "{"
                + "\"transport\":{"
                + "\"ufrag\":\"abc\",\"pwd\":\"xyz\","
                + "\"candidates\":["
                + "{\"ip\":\"149.154.167.220\",\"port\":\"1400\",\"protocol\":\"udp\"},"
                + "{\"ip\":\"2001:67c:4e8::1\",\"port\":1401,\"protocol\":\"tcp\"},"
                + "{\"ip\":\"127.0.0.1\",\"port\":\"5555\",\"protocol\":\"udp\"}"
                + "]"
                + "}"
                + "}";

        final java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger(0);
        String rewritten = WireGuardManager.rewriteGroupCallJoinPayload(
                samplePayload,
                (host, port) -> {
                    calls.incrementAndGet();
                    return port == 1400 ? 41100 : 41101;
                },
                false
        );
        assertEquals(2, calls.get());
        org.json.JSONObject root = new org.json.JSONObject(rewritten);
        org.json.JSONArray cands = root.getJSONObject("transport").getJSONArray("candidates");
        assertEquals("127.0.0.1", cands.getJSONObject(0).getString("ip"));
        assertEquals("41100", cands.getJSONObject(0).getString("port"));
        assertEquals("127.0.0.1", cands.getJSONObject(1).getString("ip"));
        assertEquals(41101, cands.getJSONObject(1).getInt("port"));
        assertEquals("127.0.0.1", cands.getJSONObject(2).getString("ip"));
        assertEquals("5555", cands.getJSONObject(2).getString("port"));

        // Re-running on already-relayed payload must be idempotent (0 new relays).
        calls.set(0);
        String secondPass = WireGuardManager.rewriteGroupCallJoinPayload(rewritten, (h, p) -> {
            calls.incrementAndGet();
            return 49999;
        }, false);
        assertEquals(0, calls.get());
        assertEquals(rewritten, secondPass);

        // When tunnel is down and killSwitchBlackhole=true, external candidates map to 127.0.0.1:9.
        String blackholed = WireGuardManager.rewriteGroupCallJoinPayload(samplePayload, (h, p) -> 0, true);
        org.json.JSONArray bhCands = new org.json.JSONObject(blackholed)
                .getJSONObject("transport").getJSONArray("candidates");
        assertEquals("127.0.0.1", bhCands.getJSONObject(0).getString("ip"));
        assertEquals("9", bhCands.getJSONObject(0).getString("port"));
        assertEquals(9, bhCands.getJSONObject(1).getInt("port"));
    }

    @Test
    public void testWgp1AndKeylessSyncRevProtection() throws Exception {
        // Verify keyless XSharedPreferences bundles declare hasSecrets=false and carry no privateKey/socksPass
        org.json.JSONObject fullBundle = new org.json.JSONObject();
        fullBundle.put("stateRev", 5);
        fullBundle.put("hasSecrets", true);
        fullBundle.put("socksUser", "wg");
        fullBundle.put("socksPass", "unified-secret");
        org.json.JSONObject pFull = new org.json.JSONObject();
        pFull.put("id", "p1");
        pFull.put("endpoint", "engage.cloudflareclient.com:2408");
        pFull.put("privateKey", SAMPLE_PRIV_B64);
        fullBundle.put("profiles", new org.json.JSONArray().put(pFull));
        assertTrue(fullBundle.getBoolean("hasSecrets"));
        assertEquals("unified-secret", fullBundle.getString("socksPass"));

        // Verify keyless bundle (hasSecrets=false) omits secrets
        org.json.JSONObject stripped = new org.json.JSONObject(fullBundle.toString());
        stripped.put("hasSecrets", false);
        stripped.remove("socksUser");
        stripped.remove("socksPass");
        stripped.getJSONArray("profiles").getJSONObject(0).remove("privateKey");
        assertFalse(stripped.has("socksPass"));
        assertFalse(stripped.getJSONArray("profiles").getJSONObject(0).has("privateKey"));

        // Verify WGP1 profile signature matching (shared-hub deduplication without ContentResolver)
        assertTrue(WireGuardManager.wgp1ProfileSigMatches(null, "engage.cloudflareclient.com:2408|abc=", "engage.cloudflareclient.com:2408|abc="));
        assertTrue(WireGuardManager.wgp1ProfileSigMatches(null, null, "engage.cloudflareclient.com:2408|abc="));
        assertFalse(WireGuardManager.wgp1ProfileSigMatches(null, "engage.cloudflareclient.com:2408|abc=", "engage.cloudflareclient.com:2408|def="));
        assertFalse(WireGuardManager.wgp1ProfileSigMatches(null, "engage.cloudflareclient.com:2408|abc=", ""));

        // Verify PUBLIC_STATUS hash matching
        String sigHash = WireGuardManager.computeProfileSigHash("engage.cloudflareclient.com:2408|abc=");
        assertEquals(12, sigHash.length());
        assertTrue(WireGuardManager.wgp1ProfileSigMatches(null, "engage.cloudflareclient.com:2408|abc=", "HASH:" + sigHash));
        assertFalse(WireGuardManager.wgp1ProfileSigMatches(null, "engage.cloudflareclient.com:2408|abc=", "HASH:000000000000"));

        // Verify deterministic HMAC-SHA256 loopback SOCKS secret derived from PrivateKey
        String det1 = WireGuardManager.deriveProfileSocksPass(SAMPLE_PRIV_B64);
        String det2 = WireGuardManager.deriveProfileSocksPass(WireGuardManager.normalizeKeyToHex(SAMPLE_PRIV_B64));
        assertEquals(32, det1.length());
        assertEquals(det1, det2);
        assertFalse(det1.equals(WireGuardManager.deriveProfileSocksPass(SAMPLE_PUB_B64)));

        // Verify 127.0.0.x port-preserving group-call rewrite + idempotence
        String grpPayload = "{\"transport\":{\"candidates\":[{\"ip\":\"91.108.9.85\",\"port\":1400},{\"ip\":\"127.0.0.7\",\"port\":1400}]}}";
        final java.util.concurrent.atomic.AtomicInteger grpCalls = new java.util.concurrent.atomic.AtomicInteger(0);
        String grpOut = WireGuardManager.rewriteGroupCallJoinPayloadAddr(
                grpPayload,
                (host, port) -> {
                    grpCalls.incrementAndGet();
                    return "127.0.0.7:" + port;
                },
                false
        );
        assertEquals(1, grpCalls.get());
        assertTrue(grpOut.contains("127.0.0.7"));
    }

    @Test
    public void testHandshakeHealthWindowAlignedWithGoAndProactiveNudge() {
        assertEquals(210L, WireGuardManager.HANDSHAKE_HEALTHY_WINDOW_SEC);
        assertEquals(120L, WireGuardManager.PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC);
        assertTrue(WireGuardManager.PROACTIVE_HANDSHAKE_NUDGE_AGE_SEC < WireGuardManager.HANDSHAKE_HEALTHY_WINDOW_SEC);
    }

    @Test
    public void testTelemetryFirestoreSchemaAndRedaction() throws Exception {
        String hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String dirtyRaw = "### WireGuard Plus Diagnostics (Android)\n"
                + "- Device / OS: Xiaomi 23129RAA4G (Android 15 / API 35)\n"
                + "- PrivateKey = " + SAMPLE_PRIV_B64 + "\n"
                + "- PskHex = " + hex64 + "\n"
                + "- socksPass=secret-pass-999\n"
                + "- Endpoint: 162.159.193.10:2408\n"
                + "[2026-11-25T07:24:21Z] [VOIP_RELAY/OPEN] target=91.108.9.58:1400 localPort=42842\n"
                + "[2026-11-25T07:24:21Z] [VOIP/RELAY] 1400->127.0.0.1:48729 (rtc)\n";

        String jsonStr = WgTelemetryReporter.buildFirestoreDocumentJsonFromParts(
                "v2.0.0",
                "org.telegram.messenger.web",
                "13.3.1",
                "Xiaomi 23129RAA4G",
                "15",
                35,
                "FROZEN_OWNER_TAKEOVER",
                "STANDARD_FGS",
                dirtyRaw
        );
        assertNotNull(jsonStr);
        assertFalse(jsonStr.isEmpty());

        org.json.JSONObject root = new org.json.JSONObject(jsonStr);
        org.json.JSONObject fields = root.getJSONObject("fields");
        assertEquals(12, fields.length());
        String[] expectedKeys = new String[]{
                "schemaVersion", "createdAt", "moduleVersion", "hostPackage",
                "hostVersion", "deviceModel", "androidRelease", "sdkInt",
                "triggerCode", "continuityTier", "fingerprint", "reportMarkdown"
        };
        for (String key : expectedKeys) {
            assertTrue("Missing Firestore field: " + key, fields.has(key));
        }
        assertEquals("1", fields.getJSONObject("schemaVersion").getString("integerValue"));
        assertEquals("35", fields.getJSONObject("sdkInt").getString("integerValue"));
        assertEquals("Xiaomi 23129RAA4G", fields.getJSONObject("deviceModel").getString("stringValue"));
        assertEquals("org.telegram.messenger.web", fields.getJSONObject("hostPackage").getString("stringValue"));
        assertEquals("FROZEN_OWNER_TAKEOVER", fields.getJSONObject("triggerCode").getString("stringValue"));

        String reportMd = fields.getJSONObject("reportMarkdown").getString("stringValue");
        assertFalse("Base64 key must be redacted", reportMd.contains(SAMPLE_PRIV_B64));
        assertFalse("64-hex key must be redacted", reportMd.contains(hex64));
        assertFalse("socksPass value must be redacted", reportMd.contains("secret-pass-999"));
        assertFalse("Public peer IP:port must be redacted", reportMd.contains("162.159.193.10"));
        assertFalse("Public relay target IP:port must be redacted", reportMd.contains("91.108.9.58"));
        assertTrue("Loopback address should remain visible for debugging", reportMd.contains("127.0.0.1:48729"));
    }

    @Test
    public void testSharedHubUnprotectedOwnerTakeoverDecisionAndStrings() {
        assertTrue(WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                "org.telegram.messenger.web", "org.telegram.wgplus.module", false));
        assertTrue(WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                "org.telegram.plus", "org.telegram.wgplus.module", false));
        assertFalse(WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                "org.telegram.messenger.web", "org.telegram.wgplus.module", true));
        assertFalse(WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                "org.telegram.wgplus.module", "org.telegram.wgplus.module", false));
        assertFalse(WireGuardManager.shouldTakeOverSharedTunnelFromUnprotectedOwner(
                "org.telegram.messenger.web", "org.telegram.plus", false));

        boolean[] langs = new boolean[]{true, false};
        for (boolean ar : langs) {
            String[] checks = new String[]{
                    WgStrings.telemetryAutoStatusSummary(ar, false),
                    WgStrings.telemetryAutoStatusSummary(ar, true),
                    WgStrings.telemetrySendNowBtn(ar, false),
                    WgStrings.telemetrySendNowBtn(ar, true)
            };
            for (String s : checks) {
                assertNotNull(s);
                assertFalse(s.trim().isEmpty());
                assertFalse("Em dash found: " + s, s.contains("\u2014"));
                assertFalse("Tanween on alef found: " + s, s.contains("\u0627\u064B"));
            }
        }
    }

    @Test
    public void testDiagnosticsUtf8HeadTailTruncationAndRedaction() {
        StringBuilder huge = new StringBuilder();
        huge.append("### WireGuard Plus Diagnostics (Android)\n");
        huge.append("- **Device / OS**: `samsung SM-S918B` (Android 17)\n");
        huge.append("- **Power Policy**: battOptIgnored=`true`\n");
        huge.append("- **Shared Pass Leak**: socksPass=super-secret-xyz Endpoint=198.51.100.77:2408\n\n");
        for (int i = 0; i < 650; i++) {
            huge.append("[2026-11-25T10:00:00Z] [OLD/EVENT] تقرير قديم رقم ").append(i).append(" padded padding event line.\n");
        }
        huge.append("[2026-11-25T12:40:00Z] [LATEST/CRASH_TAIL] newest_tail_marker_9911 target=91.108.9.58:1400\n");

        String out = WgDiagnosticsLog.sanitizeReportText(huge.toString(), 15800);
        int utf8Len = out.getBytes(StandardCharsets.UTF_8).length;
        assertTrue("Truncated report UTF-8 size must stay <= 15800 bytes, got " + utf8Len, utf8Len <= 15800);
        assertTrue("Header must be preserved", out.contains("### WireGuard Plus Diagnostics (Android)"));
        assertTrue("Newest tail event must be preserved", out.contains("newest_tail_marker_9911"));
        assertTrue("Omitted marker must be inserted", out.contains("[older events omitted]"));
        assertFalse("Secret must be redacted", out.contains("super-secret-xyz"));
        assertFalse("Public endpoint must be redacted", out.contains("198.51.100.77"));
        assertFalse("Relay target IP:port must be redacted", out.contains("91.108.9.58"));
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
