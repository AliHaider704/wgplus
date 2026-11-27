package org.telegram.wgplus.module;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Pure JVM tests exercising real {@link WgSyncAndCreds} shared-bundle serialization/import logic
 * (via in-memory SharedPreferences + ContextWrapper), adversarial {@link WgConfigCodec} newline/range
 * hardening, and IPv6/JSON/UTF-8 redaction in {@link WgDiagnosticsLog}.
 */
public class WgConfigAndRedactionEdgeTest {

    private static final String PRIV_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private static final String PUB_B64 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";

    private static final class InMemoryPrefs implements SharedPreferences {
        private final Map<String, Object> map = new ConcurrentHashMap<>();
        private final Set<OnSharedPreferenceChangeListener> listeners = Collections.synchronizedSet(new HashSet<>());

        @Override
        public Map<String, ?> getAll() {
            return new HashMap<>(map);
        }

        @Override
        public String getString(String key, String defValue) {
            Object v = map.get(key);
            return v instanceof String ? (String) v : defValue;
        }

        @SuppressWarnings("unchecked")
        @Override
        public Set<String> getStringSet(String key, Set<String> defValues) {
            Object v = map.get(key);
            return v instanceof Set ? (Set<String>) v : defValues;
        }

        @Override
        public int getInt(String key, int defValue) {
            Object v = map.get(key);
            return v instanceof Integer ? (Integer) v : defValue;
        }

        @Override
        public long getLong(String key, long defValue) {
            Object v = map.get(key);
            return v instanceof Long ? (Long) v : defValue;
        }

        @Override
        public float getFloat(String key, float defValue) {
            Object v = map.get(key);
            return v instanceof Float ? (Float) v : defValue;
        }

        @Override
        public boolean getBoolean(String key, boolean defValue) {
            Object v = map.get(key);
            return v instanceof Boolean ? (Boolean) v : defValue;
        }

        @Override
        public boolean contains(String key) {
            return map.containsKey(key);
        }

        @Override
        public Editor edit() {
            return new Editor() {
                private final Map<String, Object> staged = new HashMap<>();
                private final Set<String> removals = new HashSet<>();
                private boolean clearFirst = false;

                @Override
                public Editor putString(String key, String value) {
                    if (value == null) removals.add(key);
                    else staged.put(key, value);
                    return this;
                }

                @Override
                public Editor putStringSet(String key, Set<String> values) {
                    if (values == null) removals.add(key);
                    else staged.put(key, new HashSet<>(values));
                    return this;
                }

                @Override
                public Editor putInt(String key, int value) {
                    staged.put(key, value);
                    return this;
                }

                @Override
                public Editor putLong(String key, long value) {
                    staged.put(key, value);
                    return this;
                }

                @Override
                public Editor putFloat(String key, float value) {
                    staged.put(key, value);
                    return this;
                }

                @Override
                public Editor putBoolean(String key, boolean value) {
                    staged.put(key, value);
                    return this;
                }

                @Override
                public Editor remove(String key) {
                    removals.add(key);
                    staged.remove(key);
                    return this;
                }

                @Override
                public Editor clear() {
                    clearFirst = true;
                    staged.clear();
                    removals.clear();
                    return this;
                }

                @Override
                public boolean commit() {
                    if (clearFirst) map.clear();
                    for (String k : removals) map.remove(k);
                    map.putAll(staged);
                    return true;
                }

                @Override
                public void apply() {
                    commit();
                }
            };
        }

        @Override
        public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
            listeners.add(listener);
        }

        @Override
        public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
            listeners.remove(listener);
        }
    }

    private static Context newInMemoryModuleContext() {
        final Map<String, SharedPreferences> prefsByName = new ConcurrentHashMap<>();
        return new ContextWrapper(null) {
            @Override
            public Context getApplicationContext() {
                return this;
            }

            @Override
            public String getPackageName() {
                return "org.telegram.wgplus.module";
            }

            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                return prefsByName.computeIfAbsent(name, k -> new InMemoryPrefs());
            }
        };
    }

    @Test
    public void testRealSyncBundleExportImportAntiDowngradeAndRollingPassHistory() throws Exception {
        Context ctx = newInMemoryModuleContext();
        try {
            WireGuardManager.TunnelConfig cfg = new WireGuardManager.TunnelConfig();
            cfg.id = "p-main";
            cfg.name = "Main Node";
            cfg.privateKey = PRIV_B64;
            cfg.presharedKey = PRIV_B64;
            cfg.publicKey = PUB_B64;
            cfg.endpoint = "203.0.113.10:51820";
            cfg.address = "10.0.0.2/32";
            cfg.dns = "1.1.1.1";

            SharedPreferences sp = WireGuardManager.getPrefs(ctx);
            WireGuardManager.persistProfilesLocked(
                    sp,
                    Collections.singletonList(cfg),
                    cfg.id,
                    true,
                    true
            );
            sp.edit().putLong(WireGuardManager.KEY_SHARED_STATE_REV, 5L).apply();
            WgSyncAndCreds.syncDeterministicSocksCredentialsForProfile(ctx, cfg);

            // 1. Export without secrets must strip privateKey, presharedKey, socksUser, socksPass
            String noSecretsJson = WgSyncAndCreds.exportSharedSyncBundleJson(ctx, false);
            JSONObject noSecrets = new JSONObject(noSecretsJson);
            assertFalse(noSecrets.getBoolean("hasSecrets"));
            assertFalse(noSecrets.has("socksUser"));
            assertFalse(noSecrets.has("socksPass"));
            JSONObject p0 = noSecrets.getJSONArray("profiles").getJSONObject(0);
            assertFalse(p0.has("privateKey"));
            assertFalse(p0.has("presharedKey"));

            // 2. Importing keyless bundle into an already-keyed context with keepIncomingRev=true must NOT wipe secrets
            noSecrets.put("stateRev", 9L);
            long revAfterKeyless = WgSyncAndCreds.importSharedSyncBundleJson(ctx, noSecrets.toString(), true);
            assertEquals(5L, revAfterKeyless);
            assertEquals(PRIV_B64, WireGuardManager.loadConfig(ctx).privateKey);

            // 3. Export with secrets includes deterministic password and keys
            String fullJson = WgSyncAndCreds.exportSharedSyncBundleJson(ctx, true);
            JSONObject fullObj = new JSONObject(fullJson);
            assertTrue(fullObj.getBoolean("hasSecrets"));
            String expectedPass = WgSyncAndCreds.deriveProfileSocksPass(PRIV_B64);
            assertEquals(expectedPass, fullObj.getString("socksPass"));

            // 4. Stale lower revision must be rejected when keepIncomingRev=true
            fullObj.put("stateRev", 3L);
            fullObj.put("activeProfileId", "stale-id");
            assertEquals(5L, WgSyncAndCreds.importSharedSyncBundleJson(ctx, fullObj.toString(), true));

            // 5. Higher revision updates state on fresh target context cleanly
            Context freshCtx = newInMemoryModuleContext();
            fullObj.put("stateRev", 7L);
            assertEquals(7L, WgSyncAndCreds.importSharedSyncBundleJson(freshCtx, fullObj.toString(), true));
            assertEquals(expectedPass, WgSyncAndCreds.deriveProfileSocksPass(WireGuardManager.loadConfig(freshCtx).privateKey));

            // 6. Rolling SOCKS password history caps at 12 unique tokens
            for (int i = 0; i < 16; i++) {
                WgSyncAndCreds.recordAllowedSocksPass(ctx, "tok-" + i);
            }
            String csv = sp.getString(WireGuardManager.KEY_RECENT_SOCKS_PASSES_CSV, "");
            String[] items = csv.split(",");
            assertEquals(12, items.length);
            assertEquals("tok-15", items[0]);
        } finally {
            WireGuardManager.updateLocalSocksCreds("", "");
            WireGuardManager.clearSharedHubState();
        }
    }

    @Test
    public void testConfCodecStripsNewlineInjectionAndClampsBounds() throws Exception {
        JSONObject evilJson = new JSONObject();
        evilJson.put("id", "id-1\r\ninjected");
        evilJson.put("name", "Node\nEvil");
        evilJson.put("privateKey", PRIV_B64 + "\nAddress = 0.0.0.0/0");
        evilJson.put("presharedKey", PRIV_B64 + "\r\nEvil = 1");
        evilJson.put("publicKey", PUB_B64 + "\0extra");
        evilJson.put("endpoint", "198.51.100.2:51820\r\nAllowedIPs = 127.0.0.1/32");
        evilJson.put("h1", "111\nH2 = 222");
        evilJson.put("mtu", 99999);
        evilJson.put("keepAlive", -5);
        evilJson.put("jc", 99);
        evilJson.put("jmin", -10);
        evilJson.put("jmax", 5000);

        WireGuardManager.TunnelConfig cfg = WgConfigCodec.configFromJsonObject(evilJson, false);
        assertFalse(cfg.endpoint.contains("\n") || cfg.endpoint.contains("\r"));
        assertFalse(cfg.privateKey.contains("\n"));
        assertFalse(cfg.publicKey.contains("\0"));
        assertFalse(cfg.h1.contains("\n"));
        assertEquals(15, cfg.jc);
        assertEquals(0, cfg.jmin);
        assertEquals(1200, cfg.jmax);
        assertTrue(cfg.mtu <= 1420 && cfg.mtu >= 1200);

        String exported = WgConfigCodec.exportConfText(cfg);
        assertFalse("Exported .conf must not contain injected AllowedIPs override",
                exported.contains("AllowedIPs = 127.0.0.1/32"));
        assertFalse("Exported .conf must not contain injected H2 directive",
                exported.contains("H2 = 222"));

        // CRLF + inline '#' comment next to Base64 '=' padding must parse cleanly
        String crlfConf = "[Interface]\r\n"
                + "PrivateKey = " + PRIV_B64 + " # my private key\r\n"
                + "MTU = 500\r\n"
                + "[Peer]\r\n"
                + "PublicKey = " + PUB_B64 + "#inline comment\r\n"
                + "Endpoint = [2606:4700:4700::1111]:2408 # v6 ep\r\n"
                + "PersistentKeepalive = 9000\r\n";
        WireGuardManager.TunnelConfig parsed = WgConfigCodec.parseConfText(crlfConf, null);
        assertEquals(PRIV_B64, parsed.privateKey);
        assertEquals(PUB_B64, parsed.publicKey);
        assertEquals("[2606:4700:4700::1111]:2408", parsed.endpoint);
        assertTrue(parsed.mtu >= 1200);
        assertTrue(parsed.keepAlive <= 600);
    }

    @Test
    public void testDiagnosticsRedactsIpv6JsonSecretsAndPreservesUtf8Truncation() {
        String sample = "### WireGuard Plus Diagnostics (Android)\n"
                + "- Peer6: [2606:4700:4700::1111]:2408\n"
                + "- Loopback6: [::1]:48729\n"
                + "- JsonLeak: {\"privateKey\":\"secretKeyVal123\",\"socksPass\":\"myPass77\",\"token\":\"tokSecret\"}\n\n";
        StringBuilder body = new StringBuilder(sample);
        for (int i = 0; i < 450; i++) {
            body.append("سطر تشخيص عربي رقم ").append(i).append(" \uD83D\uDD12 اتصال آمن.\n");
        }
        body.append("[LATEST/TAIL] [2001:db8::99]:51820 end_marker_v6");

        String out = WgDiagnosticsLog.sanitizeReportText(body.toString(), 6000);
        byte[] outBytes = out.getBytes(StandardCharsets.UTF_8);
        assertTrue("UTF-8 output must respect byte cap, got " + outBytes.length, outBytes.length <= 6000);
        assertFalse("Public IPv6:port must be redacted", out.contains("2606:4700:4700::1111"));
        assertFalse("Tail IPv6:port must be redacted", out.contains("2001:db8::99"));
        assertTrue("Loopback [::1]:48729 may remain visible", out.contains("[::1]:48729"));
        assertFalse("JSON privateKey must be redacted", out.contains("secretKeyVal123"));
        assertFalse("JSON socksPass must be redacted", out.contains("myPass77"));
        assertFalse("JSON token must be redacted", out.contains("tokSecret"));
        assertTrue("Newest tail marker must survive truncation", out.contains("end_marker_v6"));
        assertFalse("UTF-8 truncation must never leave replacement U+FFFD chars", out.contains("\uFFFD"));
    }
}
