package org.telegram.wgplus.module;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Pure config/profile serialization, .conf parsing/exporting, WARP payload parsing,
 * and key format normalization extracted from WireGuardManager.
 */
final class WgConfigCodec {

    private WgConfigCodec() {
    }

    static String cleanSingleLine(String raw) {
        String s = WireGuardManager.safeTrim(raw);
        if (s.isEmpty()) {
            return "";
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                return s.substring(0, i).trim();
            }
        }
        return s;
    }

    static WireGuardManager.TunnelConfig configFromJsonObject(JSONObject obj, boolean decryptKeystore) {
        WireGuardManager.TunnelConfig cfg = new WireGuardManager.TunnelConfig();
        cfg.id = cleanSingleLine(obj.optString("id", UUID.randomUUID().toString()));
        if (cfg.id.isEmpty()) {
            cfg.id = UUID.randomUUID().toString();
        }
        cfg.name = cleanSingleLine(obj.optString("name", ""));
        String rawPriv = obj.optString("privateKey", "");
        String rawPsk = obj.optString("presharedKey", "");
        cfg.privateKey = cleanSingleLine(decryptKeystore ? WgKeystoreCrypto.decrypt(rawPriv) : rawPriv);
        cfg.presharedKey = cleanSingleLine(decryptKeystore ? WgKeystoreCrypto.decrypt(rawPsk) : rawPsk);
        cfg.address = cleanSingleLine(obj.optString("address", "10.0.0.2/32"));
        if (cfg.address.isEmpty()) cfg.address = "10.0.0.2/32";
        cfg.dns = cleanSingleLine(obj.optString("dns", "1.1.1.1"));
        if (cfg.dns.isEmpty()) cfg.dns = "1.1.1.1";
        cfg.publicKey = cleanSingleLine(obj.optString("publicKey", ""));
        cfg.endpoint = cleanSingleLine(obj.optString("endpoint", ""));
        cfg.keepAlive = WireGuardManager.clampKeepAlive(obj.optInt("keepAlive", 25));
        cfg.mtu = WireGuardManager.clampMtu(obj.optInt("mtu", 1280));
        cfg.jc = Math.max(0, Math.min(15, obj.optInt("jc", 0)));
        cfg.jmin = Math.max(0, Math.min(1200, obj.optInt("jmin", 0)));
        cfg.jmax = Math.max(0, Math.min(1200, obj.optInt("jmax", 0)));
        cfg.s1 = Math.max(0, Math.min(512, obj.optInt("s1", 0)));
        cfg.s2 = Math.max(0, Math.min(512, obj.optInt("s2", 0)));
        cfg.s3 = Math.max(0, Math.min(512, obj.optInt("s3", 0)));
        cfg.s4 = Math.max(0, Math.min(512, obj.optInt("s4", 0)));
        cfg.h1 = cleanSingleLine(obj.optString("h1", ""));
        cfg.h2 = cleanSingleLine(obj.optString("h2", ""));
        cfg.h3 = cleanSingleLine(obj.optString("h3", ""));
        cfg.h4 = cleanSingleLine(obj.optString("h4", ""));
        cfg.i1 = cleanSingleLine(obj.optString("i1", ""));
        cfg.i2 = cleanSingleLine(obj.optString("i2", ""));
        cfg.i3 = cleanSingleLine(obj.optString("i3", ""));
        cfg.i4 = cleanSingleLine(obj.optString("i4", ""));
        cfg.i5 = cleanSingleLine(obj.optString("i5", ""));
        cfg.reserved = cleanSingleLine(obj.optString("reserved", ""));
        cfg.isWarp = obj.optBoolean("isWarp", false);
        return cfg;
    }

    static JSONObject configToJsonObject(WireGuardManager.TunnelConfig cfg, boolean encryptKeystore) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("id", cfg.id);
        obj.put("name", WireGuardManager.safeTrim(cfg.name));
        String priv = WireGuardManager.safeTrim(cfg.privateKey);
        String psk = WireGuardManager.safeTrim(cfg.presharedKey);
        obj.put("privateKey", encryptKeystore ? WgKeystoreCrypto.encrypt(priv) : priv);
        obj.put("presharedKey", encryptKeystore ? WgKeystoreCrypto.encrypt(psk) : psk);
        obj.put("address", WireGuardManager.safeTrim(cfg.address).isEmpty() ? "10.0.0.2/32" : WireGuardManager.safeTrim(cfg.address));
        obj.put("dns", WireGuardManager.safeTrim(cfg.dns).isEmpty() ? "1.1.1.1" : WireGuardManager.safeTrim(cfg.dns));
        obj.put("publicKey", WireGuardManager.safeTrim(cfg.publicKey));
        obj.put("endpoint", WireGuardManager.safeTrim(cfg.endpoint));
        obj.put("keepAlive", WireGuardManager.clampKeepAlive(cfg.keepAlive));
        obj.put("mtu", WireGuardManager.clampMtu(cfg.mtu));
        obj.put("jc", Math.max(0, Math.min(15, cfg.jc)));
        obj.put("jmin", Math.max(0, Math.min(1200, cfg.jmin)));
        obj.put("jmax", Math.max(0, Math.min(1200, cfg.jmax)));
        obj.put("s1", Math.max(0, Math.min(512, cfg.s1)));
        obj.put("s2", Math.max(0, Math.min(512, cfg.s2)));
        obj.put("s3", Math.max(0, Math.min(512, cfg.s3)));
        obj.put("s4", Math.max(0, Math.min(512, cfg.s4)));
        obj.put("h1", WireGuardManager.safeTrim(cfg.h1));
        obj.put("h2", WireGuardManager.safeTrim(cfg.h2));
        obj.put("h3", WireGuardManager.safeTrim(cfg.h3));
        obj.put("h4", WireGuardManager.safeTrim(cfg.h4));
        obj.put("i1", WireGuardManager.safeTrim(cfg.i1));
        obj.put("i2", WireGuardManager.safeTrim(cfg.i2));
        obj.put("i3", WireGuardManager.safeTrim(cfg.i3));
        obj.put("i4", WireGuardManager.safeTrim(cfg.i4));
        obj.put("i5", WireGuardManager.safeTrim(cfg.i5));
        obj.put("reserved", WireGuardManager.safeTrim(cfg.reserved));
        obj.put("isWarp", cfg.isWarp);
        return obj;
    }

    static String serializeProfilesBackupJson(List<WireGuardManager.TunnelConfig> profiles) throws WgStrings.WgException {
        try {
            JSONObject root = new JSONObject();
            root.put("schema", WireGuardManager.BACKUP_SCHEMA);
            root.put("version", WgStrings.VERSION_LABEL);
            JSONArray arr = new JSONArray();
            if (profiles != null) {
                for (WireGuardManager.TunnelConfig cfg : profiles) {
                    if (cfg != null && cfg.hasPeerConfigured()) {
                        arr.put(configToJsonObject(cfg, false));
                    }
                }
            }
            if (arr.length() == 0 && profiles != null && !profiles.isEmpty()) {
                arr.put(configToJsonObject(profiles.get(0), false));
            }
            root.put("profiles", arr);
            return root.toString(2);
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID, t.getMessage(), t);
        }
    }

    static List<WireGuardManager.TunnelConfig> deserializeProfilesBackupJson(String rawJson) throws WgStrings.WgException {
        if (rawJson == null || rawJson.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
        }
        try {
            JSONObject root = new JSONObject(rawJson.trim());
            if (!WireGuardManager.BACKUP_SCHEMA.equals(root.optString("schema", ""))) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID);
            }
            JSONArray arr = root.optJSONArray("profiles");
            if (arr == null || arr.length() == 0) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID);
            }
            List<WireGuardManager.TunnelConfig> out = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject item = arr.optJSONObject(i);
                if (item != null) {
                    WireGuardManager.TunnelConfig cfg = configFromJsonObject(item, false);
                    cfg.id = UUID.randomUUID().toString();
                    out.add(cfg);
                }
            }
            if (out.isEmpty()) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID);
            }
            return out;
        } catch (WgStrings.WgException we) {
            throw we;
        } catch (Throwable t) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.BACKUP_INVALID, t.getMessage(), t);
        }
    }

    static boolean isEncryptedBackupEnvelope(String raw) {
        if (raw == null) {
            return false;
        }
        String t = raw.trim();
        if (!t.startsWith("{")) {
            return false;
        }
        try {
            JSONObject obj = new JSONObject(t);
            return WireGuardManager.BACKUP_SCHEMA.equals(obj.optString("format", ""));
        } catch (Throwable ignored) {
            return false;
        }
    }

    static String sanitizeSuggestedName(String raw) {
        String s = WireGuardManager.safeTrim(raw);
        if (s.isEmpty()) {
            return "";
        }
        int slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
        if (slash >= 0 && slash < s.length() - 1) {
            s = s.substring(slash + 1).trim();
        }
        String lower = s.toLowerCase(Locale.ROOT);
        String[] exts = new String[]{".conf", ".txt", ".png", ".jpg", ".jpeg", ".webp"};
        for (String ext : exts) {
            if (lower.endsWith(ext) && s.length() > ext.length()) {
                s = s.substring(0, s.length() - ext.length()).trim();
                break;
            }
        }
        if (s.length() > 32) {
            s = s.substring(0, 32).trim();
        }
        return s;
    }

    static String uniqueProfileName(String desired, List<WireGuardManager.TunnelConfig> existing, String excludeId) {
        String base = WireGuardManager.safeTrim(desired);
        if (base.isEmpty()) {
            base = "WireGuard";
        }
        if (!nameExists(base, existing, excludeId)) {
            return base;
        }
        for (int n = 2; n <= 99; n++) {
            String candidate = base + " (" + n + ")";
            if (!nameExists(candidate, existing, excludeId)) {
                return candidate;
            }
        }
        return base + " (" + UUID.randomUUID().toString().substring(0, 4) + ")";
    }

    private static boolean nameExists(String candidate, List<WireGuardManager.TunnelConfig> existing, String excludeId) {
        for (WireGuardManager.TunnelConfig item : existing) {
            if (excludeId != null && excludeId.equals(item.id)) {
                continue;
            }
            if (candidate.equalsIgnoreCase(WireGuardManager.safeTrim(item.name))) {
                return true;
            }
        }
        return false;
    }

    static String deriveProfileName(String endpoint, boolean isAr, int fallbackIndex) {
        String ep = WireGuardManager.safeTrim(endpoint);
        if (!ep.isEmpty()) {
            int colon = ep.lastIndexOf(':');
            String host = colon > 0 ? ep.substring(0, colon) : ep;
            if (host.length() > 24) {
                int dot = host.indexOf('.');
                if (dot > 0) {
                    host = host.substring(0, dot);
                }
            }
            if (!host.isEmpty()) {
                return host;
            }
        }
        return WgStrings.defaultProfileName(isAr, fallbackIndex);
    }

    static String normalizeKeyToHex(String inputKey) throws WgStrings.WgException {
        if (inputKey == null || inputKey.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_FORMAT);
        }
        String trimmed = inputKey.trim();
        if (trimmed.length() == 64 && trimmed.matches("^[0-9a-fA-F]{64}$")) {
            return trimmed.toLowerCase(Locale.ROOT);
        }
        byte[] decoded = null;
        try {
            decoded = android.util.Base64.decode(trimmed, android.util.Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_FORMAT, "", e);
        } catch (Throwable ignored) {
        }
        if (decoded == null) {
            try {
                decoded = java.util.Base64.getDecoder().decode(trimmed);
            } catch (IllegalArgumentException e) {
                throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_FORMAT, "", e);
            }
        }
        if (decoded == null || decoded.length != 32) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_KEY_LENGTH);
        }
        StringBuilder sb = new StringBuilder(64);
        for (byte b : decoded) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return sb.toString();
    }

    static WireGuardManager.TunnelConfig parseConfText(String confText, WireGuardManager.TunnelConfig base) throws WgStrings.WgException {
        if (confText == null || confText.trim().isEmpty()) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.EMPTY_CLIPBOARD);
        }
        WireGuardManager.TunnelConfig cfg = base != null ? base.copy() : new WireGuardManager.TunnelConfig();
        String section = "";
        boolean foundAny = false;

        String[] lines = confText.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length() - 1).trim().toLowerCase(Locale.ROOT);
                continue;
            }
            int eqIdx = line.indexOf('=');
            if (eqIdx <= 0) {
                continue;
            }
            String key = line.substring(0, eqIdx).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(eqIdx + 1).trim();
            int commentIdx = value.indexOf('#');
            if (commentIdx >= 0) {
                value = value.substring(0, commentIdx).trim();
            }

            switch (key) {
                case "privatekey":
                    cfg.privateKey = value;
                    foundAny = true;
                    break;
                case "presharedkey":
                    cfg.presharedKey = value;
                    foundAny = true;
                    break;
                case "address":
                    cfg.address = value;
                    foundAny = true;
                    break;
                case "dns":
                    cfg.dns = value;
                    foundAny = true;
                    break;
                case "mtu":
                    cfg.mtu = WireGuardManager.clampMtu(WireGuardManager.parseIntSafe(value, 1280));
                    foundAny = true;
                    break;
                case "jc":
                    cfg.jc = Math.max(0, Math.min(15, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "jmin":
                    cfg.jmin = Math.max(0, Math.min(1200, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "jmax":
                    cfg.jmax = Math.max(0, Math.min(1200, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s1":
                    cfg.s1 = Math.max(0, Math.min(512, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s2":
                    cfg.s2 = Math.max(0, Math.min(512, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s3":
                    cfg.s3 = Math.max(0, Math.min(512, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "s4":
                    cfg.s4 = Math.max(0, Math.min(512, WireGuardManager.parseIntSafe(value, 0)));
                    foundAny = true;
                    break;
                case "h1":
                    cfg.h1 = value;
                    foundAny = true;
                    break;
                case "h2":
                    cfg.h2 = value;
                    foundAny = true;
                    break;
                case "h3":
                    cfg.h3 = value;
                    foundAny = true;
                    break;
                case "h4":
                    cfg.h4 = value;
                    foundAny = true;
                    break;
                case "i1":
                    cfg.i1 = value;
                    foundAny = true;
                    break;
                case "i2":
                    cfg.i2 = value;
                    foundAny = true;
                    break;
                case "i3":
                    cfg.i3 = value;
                    foundAny = true;
                    break;
                case "i4":
                    cfg.i4 = value;
                    foundAny = true;
                    break;
                case "i5":
                    cfg.i5 = value;
                    foundAny = true;
                    break;
                case "reserved":
                    cfg.reserved = value;
                    foundAny = true;
                    break;
                case "publickey":
                    if (!"interface".equals(section)) {
                        cfg.publicKey = value;
                        foundAny = true;
                    }
                    break;
                case "endpoint":
                    cfg.endpoint = value;
                    foundAny = true;
                    break;
                case "persistentkeepalive":
                    cfg.keepAlive = WireGuardManager.clampKeepAlive(WireGuardManager.parseIntSafe(value, 25));
                    foundAny = true;
                    break;
                default:
                    break;
            }
        }

        if (!foundAny) {
            throw new WgStrings.WgException(WgStrings.ErrorCode.INVALID_CONF);
        }

        if (!WireGuardManager.safeTrim(cfg.endpoint).isEmpty()) {
            String currentName = WireGuardManager.safeTrim(cfg.name);
            if (currentName.isEmpty() || WgStrings.isDefaultProfileName(currentName)) {
                cfg.name = deriveProfileName(cfg.endpoint, false, 1);
            }
        }
        return cfg;
    }

    static String exportConfText(WireGuardManager.TunnelConfig cfg) {
        StringBuilder sb = new StringBuilder();
        String addr = cleanSingleLine(cfg.address);
        String dns = cleanSingleLine(cfg.dns);
        String h1 = cleanSingleLine(cfg.h1);
        String h2 = cleanSingleLine(cfg.h2);
        String h3 = cleanSingleLine(cfg.h3);
        String h4 = cleanSingleLine(cfg.h4);
        String i1 = cleanSingleLine(cfg.i1);
        String i2 = cleanSingleLine(cfg.i2);
        String i3 = cleanSingleLine(cfg.i3);
        String i4 = cleanSingleLine(cfg.i4);
        String i5 = cleanSingleLine(cfg.i5);
        String rsv = cleanSingleLine(cfg.reserved);
        String psk = cleanSingleLine(cfg.presharedKey);

        sb.append("[Interface]\n");
        sb.append("PrivateKey = ").append(cleanSingleLine(cfg.privateKey)).append('\n');
        sb.append("Address = ").append(addr.isEmpty() ? "10.0.0.2/32" : addr).append('\n');
        sb.append("DNS = ").append(dns.isEmpty() ? "1.1.1.1" : dns).append('\n');
        if (cfg.mtu > 0 && cfg.mtu != 1280) {
            sb.append("MTU = ").append(WireGuardManager.clampMtu(cfg.mtu)).append('\n');
        }
        if (cfg.jc > 0) {
            sb.append("Jc = ").append(cfg.jc).append('\n');
            if (cfg.jmin > 0) sb.append("Jmin = ").append(cfg.jmin).append('\n');
            if (cfg.jmax > 0) sb.append("Jmax = ").append(cfg.jmax).append('\n');
        }
        if (cfg.s1 > 0) sb.append("S1 = ").append(cfg.s1).append('\n');
        if (cfg.s2 > 0) sb.append("S2 = ").append(cfg.s2).append('\n');
        if (cfg.s3 > 0) sb.append("S3 = ").append(cfg.s3).append('\n');
        if (cfg.s4 > 0) sb.append("S4 = ").append(cfg.s4).append('\n');
        if (!h1.isEmpty()) sb.append("H1 = ").append(h1).append('\n');
        if (!h2.isEmpty()) sb.append("H2 = ").append(h2).append('\n');
        if (!h3.isEmpty()) sb.append("H3 = ").append(h3).append('\n');
        if (!h4.isEmpty()) sb.append("H4 = ").append(h4).append('\n');
        if (!i1.isEmpty()) sb.append("I1 = ").append(i1).append('\n');
        if (!i2.isEmpty()) sb.append("I2 = ").append(i2).append('\n');
        if (!i3.isEmpty()) sb.append("I3 = ").append(i3).append('\n');
        if (!i4.isEmpty()) sb.append("I4 = ").append(i4).append('\n');
        if (!i5.isEmpty()) sb.append("I5 = ").append(i5).append('\n');
        if (!rsv.isEmpty()) sb.append("Reserved = ").append(rsv).append('\n');

        sb.append("\n[Peer]\n");
        sb.append("PublicKey = ").append(cleanSingleLine(cfg.publicKey)).append('\n');
        if (!psk.isEmpty()) {
            sb.append("PresharedKey = ").append(psk).append('\n');
        }
        sb.append("Endpoint = ").append(cleanSingleLine(cfg.endpoint)).append('\n');
        sb.append("AllowedIPs = 0.0.0.0/0, ::/0\n");
        sb.append("PersistentKeepalive = ").append(WireGuardManager.clampKeepAlive(cfg.keepAlive)).append('\n');
        return sb.toString();
    }

    static WireGuardManager.TunnelConfig parseWarpGeneratedJson(String rawJson, String[] outEndpointV4) throws Exception {
        JSONObject obj = new JSONObject(rawJson);
        WireGuardManager.TunnelConfig cfg = new WireGuardManager.TunnelConfig();
        cfg.id = UUID.randomUUID().toString();
        cfg.name = WireGuardManager.safeTrim(obj.optString("name", "Cloudflare WARP (AWG 1.5)"));
        cfg.privateKey = WireGuardManager.safeTrim(obj.optString("privateKey", ""));
        cfg.address = WireGuardManager.safeTrim(obj.optString("clientIp", "172.16.0.2/32"));
        cfg.dns = WireGuardManager.safeTrim(obj.optString("dns", "1.1.1.1"));
        cfg.publicKey = WireGuardManager.safeTrim(obj.optString("peerPublicKey", ""));
        cfg.endpoint = WireGuardManager.safeTrim(obj.optString("endpoint", "engage.cloudflareclient.com:2408"));
        cfg.keepAlive = WireGuardManager.clampKeepAlive(obj.optInt("keepAlive", 25));
        cfg.mtu = WireGuardManager.clampMtu(obj.optInt("mtu", 1280));
        cfg.jc = Math.max(0, Math.min(15, obj.optInt("jc", 4)));
        cfg.jmin = Math.max(0, Math.min(1200, obj.optInt("jmin", 40)));
        cfg.jmax = Math.max(0, Math.min(1200, obj.optInt("jmax", 120)));
        cfg.i1 = WireGuardManager.safeTrim(obj.optString("i1", ""));
        cfg.reserved = WireGuardManager.safeTrim(obj.optString("reserved", ""));
        cfg.isWarp = true;
        cfg.enabled = true;
        cfg.routeCalls = true;
        if (!cfg.hasPeerConfigured()) {
            throw new IllegalStateException("Generated WARP payload incomplete");
        }
        if (outEndpointV4 != null && outEndpointV4.length > 0) {
            outEndpointV4[0] = WireGuardManager.safeTrim(obj.optString("endpointV4", ""));
        }
        return cfg;
    }
}
