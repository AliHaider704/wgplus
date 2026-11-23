package org.telegram.wgplus.module;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hardware-backed AndroidKeyStore AES-256-GCM wrapper with an isolated 0600 file-backed
 * AES-256-GCM fallback (enc:v2:) so WireGuard PrivateKey/PresharedKey and ADB keys are
 * NEVER persisted as raw plaintext even if AndroidKeyStore fails on custom ROMs or API < 23.
 * Transparently reads legacy unprefixed values from v1.1.0 and upgrades them on next save.
 */
public final class WgKeystoreCrypto {
    private static final String TAG = "WGPlusKeystore";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "wg_plus_aes_gcm_v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String PREFIX_V1 = "enc:v1:";
    private static final String PREFIX_V2 = "enc:v2:";
    private static final String SW_KEY_FILENAME = "wg_plus_sw_aes_v2.key";
    private static final int GCM_TAG_BITS = 128;

    private static volatile File sNoBackupDir;
    private static volatile SecretKey sSoftwareFallbackKey;

    private WgKeystoreCrypto() {
    }

    public static void init(Context context) {
        if (context == null) {
            return;
        }
        try {
            Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
            File dir = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP
                    ? appCtx.getNoBackupFilesDir()
                    : appCtx.getFilesDir();
            if (dir != null) {
                sNoBackupDir = dir;
            }
        } catch (Throwable ignored) {
        }
    }

    public static boolean isEncryptedValue(String val) {
        return val != null && (val.startsWith(PREFIX_V1) || val.startsWith(PREFIX_V2));
    }

    public static String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }
        if (isEncryptedValue(plaintext)) {
            return plaintext;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            for (int attempt = 0; attempt < 2; attempt++) {
                try {
                    SecretKey secretKey = getOrCreateKeystoreKey();
                    if (secretKey != null) {
                        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                        byte[] iv = cipher.getIV();
                        byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
                        return PREFIX_V1
                                + b64Encode(iv)
                                + ":"
                                + b64Encode(cipherBytes);
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "Keystore encrypt attempt " + (attempt + 1) + " failed: " + t.getMessage());
                    if (attempt == 0) {
                        deleteBrokenKeystoreAlias();
                    }
                }
            }
        }
        // Hardware Keystore unavailable or API < 23: encrypt with 0600 file-backed AES-256-GCM (never plaintext!)
        try {
            SecretKey swKey = getOrCreateSoftwareKey();
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, swKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX_V2
                    + b64Encode(iv)
                    + ":"
                    + b64Encode(cipherBytes);
        } catch (Throwable t) {
            throw new IllegalStateException("Secret encryption unavailable", t);
        }
    }

    public static String decrypt(String stored) {
        if (stored == null || stored.isEmpty()) {
            return "";
        }
        if (stored.startsWith(PREFIX_V1)) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                return "";
            }
            try {
                return decryptWithKey(stored.substring(PREFIX_V1.length()), loadKeystoreKey());
            } catch (Throwable t) {
                Log.w(TAG, "Keystore v1 decrypt failed: " + t.getMessage());
                return "";
            }
        }
        if (stored.startsWith(PREFIX_V2)) {
            try {
                return decryptWithKey(stored.substring(PREFIX_V2.length()), getOrCreateSoftwareKey());
            } catch (Throwable t) {
                Log.w(TAG, "Software v2 decrypt failed: " + t.getMessage());
                return "";
            }
        }
        // Transparent legacy v1.1.0 plaintext read (re-encrypted on next save)
        return stored;
    }

    private static String decryptWithKey(String body, SecretKey secretKey) throws Exception {
        if (secretKey == null) {
            return "";
        }
        int sep = body.indexOf(':');
        if (sep <= 0 || sep >= body.length() - 1) {
            return "";
        }
        byte[] iv = b64Decode(body.substring(0, sep));
        byte[] cipherBytes = b64Decode(body.substring(sep + 1));
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    private static String b64Encode(byte[] data) {
        String encoded = Base64.encodeToString(data, Base64.NO_WRAP);
        if (encoded == null) {
            try {
                Class<?> b64 = Class.forName("java.util.Base64");
                Object enc = b64.getMethod("getEncoder").invoke(null);
                return (String) enc.getClass().getMethod("encodeToString", byte[].class).invoke(enc, data);
            } catch (Throwable ignored) {
            }
        }
        return encoded;
    }

    private static byte[] b64Decode(String s) {
        byte[] decoded = Base64.decode(s, Base64.NO_WRAP);
        if (decoded == null) {
            try {
                Class<?> b64 = Class.forName("java.util.Base64");
                Object dec = b64.getMethod("getDecoder").invoke(null);
                return (byte[]) dec.getClass().getMethod("decode", String.class).invoke(dec, s);
            } catch (Throwable ignored) {
            }
        }
        return decoded;
    }

    private static void deleteBrokenKeystoreAlias() {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS);
            }
        } catch (Throwable ignored) {
        }
    }

    private static synchronized SecretKey loadKeystoreKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        return null;
    }

    private static synchronized SecretKey getOrCreateKeystoreKey() throws Exception {
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

    private static synchronized SecretKey getOrCreateSoftwareKey() throws Exception {
        if (sSoftwareFallbackKey != null) {
            return sSoftwareFallbackKey;
        }
        File dir = sNoBackupDir;
        if (dir != null) {
            if (!dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            File keyFile = new File(dir, SW_KEY_FILENAME);
            if (keyFile.exists() && keyFile.length() == 32) {
                byte[] raw = new byte[32];
                try (FileInputStream fis = new FileInputStream(keyFile)) {
                    int off = 0;
                    while (off < 32) {
                        int r = fis.read(raw, off, 32 - off);
                        if (r <= 0) {
                            break;
                        }
                        off += r;
                    }
                    if (off == 32) {
                        sSoftwareFallbackKey = new SecretKeySpec(raw, "AES");
                        return sSoftwareFallbackKey;
                    }
                }
            }
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            try (FileOutputStream fos = new FileOutputStream(keyFile, false)) {
                fos.write(raw);
                fos.getFD().sync();
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                try {
                    android.system.Os.chmod(keyFile.getAbsolutePath(), 0600);
                } catch (Throwable ignored) {
                    //noinspection ResultOfMethodCallIgnored
                    keyFile.setReadable(false, false);
                    //noinspection ResultOfMethodCallIgnored
                    keyFile.setReadable(true, true);
                    //noinspection ResultOfMethodCallIgnored
                    keyFile.setWritable(false, false);
                    //noinspection ResultOfMethodCallIgnored
                    keyFile.setWritable(true, true);
                }
            }
            sSoftwareFallbackKey = new SecretKeySpec(raw, "AES");
            return sSoftwareFallbackKey;
        }
        // Unit-test or pre-init fallback: ephemeral 256-bit in-memory AES key (still never plaintext)
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        sSoftwareFallbackKey = new SecretKeySpec(raw, "AES");
        return sSoftwareFallbackKey;
    }
}
