package org.telegram.wgplus.module;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Hardware-backed AndroidKeyStore AES-256-GCM wrapper for encrypting WireGuard PrivateKey
 * and PresharedKey values at rest in SharedPreferences. Transparently reads legacy plaintext
 * values from v1.1.0 and upgrades them on the next save.
 */
public final class WgKeystoreCrypto {
    private static final String TAG = "WGPlusKeystore";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "wg_plus_aes_gcm_v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String PREFIX = "enc:v1:";
    private static final int GCM_TAG_BITS = 128;

    private WgKeystoreCrypto() {
    }

    public static String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }
        if (plaintext.startsWith(PREFIX)) {
            return plaintext;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return plaintext;
        }
        try {
            SecretKey secretKey = getOrCreateSecretKey();
            if (secretKey == null) {
                return plaintext;
            }
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            String ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP);
            String ctB64 = Base64.encodeToString(cipherBytes, Base64.NO_WRAP);
            return PREFIX + ivB64 + ":" + ctB64;
        } catch (Throwable t) {
            Log.w(TAG, "Keystore encrypt fallback: " + t.getMessage());
            return plaintext;
        }
    }

    public static String decrypt(String stored) {
        if (stored == null || stored.isEmpty()) {
            return "";
        }
        if (!stored.startsWith(PREFIX)) {
            return stored;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return "";
        }
        try {
            String body = stored.substring(PREFIX.length());
            int sep = body.indexOf(':');
            if (sep <= 0 || sep >= body.length() - 1) {
                return "";
            }
            byte[] iv = Base64.decode(body.substring(0, sep), Base64.NO_WRAP);
            byte[] cipherBytes = Base64.decode(body.substring(sep + 1), Base64.NO_WRAP);

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
            if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                return "";
            }
            SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] plainBytes = cipher.doFinal(cipherBytes);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            Log.w(TAG, "Keystore decrypt failed: " + t.getMessage());
            return "";
        }
    }

    private static synchronized SecretKey getOrCreateSecretKey() throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return null;
        }
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            KeyStore.Entry existing = ks.getEntry(KEY_ALIAS, null);
            if (existing instanceof KeyStore.SecretKeyEntry) {
                return ((KeyStore.SecretKeyEntry) existing).getSecretKey();
            }
        }
        KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build();
        keyGen.init(spec);
        return keyGen.generateKey();
    }
}
