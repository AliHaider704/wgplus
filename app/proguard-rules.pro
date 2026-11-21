# Keep module classes (XposedInit entry via assets/xposed_init, DaemonProcessHelper via app_process, ContentProvider, Activities, hooks)
-keep class org.telegram.wgplus.module.** { *; }

# Keep Go mobile JNI bridge classes & callbacks
-keep class go.** { *; }
-keep class wgbridge.** { *; }

# Keep Built-in Wireless ADB, SPAKE2 JNI, Sun X.509 cert generator, and Conscrypt TLS 1.3 JNI
-keep class io.github.muntashirakon.adb.** { *; }
-keep class android.sun.security.** { *; }
-keep class org.conscrypt.** { *; }

# Keep minimal BouncyCastle crypto classes used by libadb-android SPAKE2 HKDF; let R8 strip PQC and unused algorithms
-keep class org.bouncycastle.crypto.digests.SHA256Digest { *; }
-keep class org.bouncycastle.crypto.generators.HKDFBytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.HKDFParameters { *; }

# Let R8 tree-shake com.google.zxing.** down to QRCodeReader/QRCodeWriter directly used by WgQrCodec

-dontwarn de.robv.android.xposed.**
-dontwarn org.conscrypt.**
-dontwarn android.sun.security.**
-dontwarn io.github.muntashirakon.**
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
-dontwarn javax.annotation.**
-dontwarn java.lang.instrument.**
-dontwarn org.codehaus.**
