package org.telegram.wgplus.module;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import android.sun.security.x509.CertAndKeyGen;
import android.sun.security.x509.X500Name;

/**
 * Generates, encrypts at rest via {@link WgKeystoreCrypto}, and loads the persistent
 * 2048-bit RSA key pair + self-signed X.509 certificate used by WireGuard Plus's built-in
 * Wireless ADB client. Also tracks pairing status and dynamic local TCP fallback port.
 */
public final class BuiltinAdbKeyManager {

    private static final String TAG = "WGPlusAdbKeys";
    private static final String PREFS_NAME = "wg_plus_builtin_adb_prefs";
    private static final String KEY_PRIVATE_PKCS8_ENC = "adb_priv_pkcs8_enc_v1";
    private static final String KEY_CERT_X509_B64 = "adb_cert_x509_b64_v1";
    private static final String KEY_PAIRED_ONCE = "adb_paired_once";
    private static final String KEY_DYNAMIC_TCP_PORT = "adb_dynamic_tcp_port";
    private static final String KEY_MOBILE_TCP_HEAL = "adb_mobile_tcp_heal";

    private static final int[] DYNAMIC_PORT_CANDIDATES = new int[]{5557, 5561, 5569, 5573, 5581, 5555};
    private static final int MIN_DYNAMIC_PORT = 5555;
    private static final int MAX_DYNAMIC_PORT = 5599;

    private static final Object LOCK = new Object();
    private static PrivateKey sCachedPrivateKey;
    private static Certificate sCachedCertificate;

    private BuiltinAdbKeyManager() {
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static boolean isPaired(Context context) {
        if (context == null) {
            return false;
        }
        SharedPreferences p = prefs(context);
        return p.getBoolean(KEY_PAIRED_ONCE, false)
                && !p.getString(KEY_PRIVATE_PKCS8_ENC, "").isEmpty()
                && !p.getString(KEY_CERT_X509_B64, "").isEmpty();
    }

    public static void markPaired(Context context, boolean paired) {
        if (context == null) {
            return;
        }
        prefs(context).edit().putBoolean(KEY_PAIRED_ONCE, paired).commit();
    }

    public static boolean isMobileTcpHealEnabled(Context context) {
        if (context == null) {
            return true;
        }
        return prefs(context).getBoolean(KEY_MOBILE_TCP_HEAL, true);
    }

    public static void setMobileTcpHealEnabled(Context context, boolean enabled) {
        if (context == null) {
            return;
        }
        prefs(context).edit().putBoolean(KEY_MOBILE_TCP_HEAL, enabled).apply();
    }

    public static int getDynamicTcpPort(Context context) {
        if (context == null) {
            return -1;
        }
        int saved = prefs(context).getInt(KEY_DYNAMIC_TCP_PORT, -1);
        return isValidDynamicPort(saved) ? saved : -1;
    }

    public static void setDynamicTcpPort(Context context, int port) {
        if (context == null || !isValidDynamicPort(port)) {
            return;
        }
        prefs(context).edit().putInt(KEY_DYNAMIC_TCP_PORT, port).commit();
    }

    public static boolean isValidDynamicPort(int port) {
        return port >= MIN_DYNAMIC_PORT && port <= MAX_DYNAMIC_PORT;
    }

    /**
     * Parses a user-entered pairing code. Supports either a plain 6-digit PIN ("123456")
     * or optional explicit "PIN:PORT" ("123456:37821") for manual port override.
     */
    public static String[] parsePairingInput(String raw) {
        if (raw == null) {
            return null;
        }
        String cleaned = raw.trim().replace(" ", "");
        if (cleaned.isEmpty()) {
            return null;
        }
        String pin = cleaned;
        String portStr = "";
        int sep = cleaned.indexOf(':');
        if (sep < 0) {
            sep = cleaned.indexOf('@');
        }
        if (sep > 0 && sep < cleaned.length() - 1) {
            pin = cleaned.substring(0, sep);
            portStr = cleaned.substring(sep + 1);
        }
        if (!isValidPairingCode(pin)) {
            return null;
        }
        if (!portStr.isEmpty()) {
            try {
                int port = Integer.parseInt(portStr);
                if (port <= 1024 || port > 65535) {
                    return null;
                }
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return new String[]{pin, portStr};
    }

    public static boolean isValidPairingCode(String code) {
        if (code == null || code.length() != 6) {
            return false;
        }
        for (int i = 0; i < 6; i++) {
            char c = code.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    public static int pickCandidateDynamicPort(Context context) {
        int saved = getDynamicTcpPort(context);
        if (isValidDynamicPort(saved) && !isLoopbackPortOpen(saved)) {
            return saved;
        }
        for (int candidate : DYNAMIC_PORT_CANDIDATES) {
            if (!isLoopbackPortOpen(candidate)) {
                setDynamicTcpPort(context, candidate);
                return candidate;
            }
        }
        setDynamicTcpPort(context, 5557);
        return 5557;
    }

    public static boolean isLoopbackPortOpen(int port) {
        if (port <= 0 || port > 65535) {
            return false;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 220);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static KeyIdentity getOrCreateIdentity(Context context) throws Exception {
        synchronized (LOCK) {
            if (sCachedPrivateKey != null && sCachedCertificate != null) {
                return new KeyIdentity(sCachedPrivateKey, sCachedCertificate);
            }
            SharedPreferences p = prefs(context);
            String encPriv = p.getString(KEY_PRIVATE_PKCS8_ENC, "");
            String certB64 = p.getString(KEY_CERT_X509_B64, "");
            if (!encPriv.isEmpty() && !certB64.isEmpty()) {
                try {
                    String privB64 = WgKeystoreCrypto.decrypt(encPriv);
                    if (!privB64.isEmpty()) {
                        PrivateKey priv = decodePrivateKeyBase64(privB64);
                        Certificate cert = decodeCertificateBase64(certB64);
                        sCachedPrivateKey = priv;
                        sCachedCertificate = cert;
                        return new KeyIdentity(priv, cert);
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "Stored ADB key load failed, regenerating: " + t.getMessage());
                }
            }

            CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA256withRSA");
            gen.generate(2048);
            PrivateKey priv = gen.getPrivateKey();
            long validitySeconds = 30L * 365L * 24L * 3600L;
            Certificate cert = gen.getSelfCertificate(
                    new X500Name("CN=WireGuardPlus"),
                    new Date(),
                    validitySeconds
            );

            String privB64 = encodePrivateKeyBase64(priv);
            String newCertB64 = encodeCertificateBase64(cert);
            p.edit()
                    .putString(KEY_PRIVATE_PKCS8_ENC, WgKeystoreCrypto.encrypt(privB64))
                    .putString(KEY_CERT_X509_B64, newCertB64)
                    .commit();
            sCachedPrivateKey = priv;
            sCachedCertificate = cert;
            return new KeyIdentity(priv, cert);
        }
    }

    static String encodePrivateKeyBase64(PrivateKey key) {
        return Base64.encodeToString(key.getEncoded(), Base64.NO_WRAP);
    }

    static PrivateKey decodePrivateKeyBase64(String b64) throws Exception {
        byte[] pkcs8 = Base64.decode(b64, Base64.NO_WRAP);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    static String encodeCertificateBase64(Certificate cert) throws Exception {
        return Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP);
    }

    static Certificate decodeCertificateBase64(String b64) throws Exception {
        byte[] der = Base64.decode(b64, Base64.NO_WRAP);
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    public static final class KeyIdentity {
        public final PrivateKey privateKey;
        public final Certificate certificate;

        public KeyIdentity(PrivateKey privateKey, Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
    }
}
