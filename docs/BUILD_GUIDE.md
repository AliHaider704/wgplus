# Build & Reproducibility Guide

This guide explains how to compile, test, patch, and sign **WireGuard Plus** from source on Windows (PowerShell) or Linux/macOS.

---

## 1. Prerequisites

| Tool | Recommended Version | Notes |
|------|---------------------|-------|
| **JDK** | OpenJDK 21 | Used for Gradle, `javac`, `jar`, and `javap` |
| **Android SDK** | Platform 35, Build-Tools `36.0.0` | `minSdk 21`, `targetSdk 34`, `compileSdk 35` |
| **Android NDK** | `r27c` (`27.2.12479018`) | Required by `gomobile` cgo cross-compilation |
| **Go** | `1.23+` (`1.26.x` verified) | With `golang.org/x/mobile/cmd/gomobile` installed |
| **Gradle** | `8.11.1` | Included via `./gradlew` / `gradlew.bat` |

---

## 2. Step 1: Test & Build the Native Go Bridge (`wgbridge.aar`)

> [!IMPORTANT]
> Always build `wgbridge.aar` using `scripts/build-wgbridge.ps1` rather than running `gomobile bind` alone. Standard `gomobile` emits an unguarded `System.loadLibrary("gojni")` inside `go.Seq.<clinit>`, which throws `UnsatisfiedLinkError` under LSPatch's `InMemoryDexClassLoader`. The build script automatically applies and bytecode-verifies the `UnsatisfiedLinkError` guard.

Run from the repository root in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-wgbridge.ps1 `
  -JavaHome "C:\Program Files\Android\openjdk\jdk-21.0.8" `
  -AndroidHome "C:\Program Files (x86)\Android\android-sdk" `
  -AndroidNdkHome "C:\Program Files (x86)\Android\AndroidNDK\android-ndk-r27c"
```

What this script executes:
1. Runs `go test -v ./...` inside `wgbridge-go` (verifying key parsing, MTU bounds, UAPI stats, and full SOCKS5 `UDP ASSOCIATE` VoIP packet relay).
2. Runs `gomobile bind -target="android/arm64,android/arm" -androidapi 21 -o app/libs/wgbridge.aar .`.
3. Patches `go/Seq.java` to tolerate prior `System.load(...)` preloading under LSPatch, recompiles `go/Seq.class`, repacks `app/libs/wgbridge.aar`, and verifies the exception handler table with `javap -c`.

---

## 3. Step 2: Build & Sign the Android Module APK

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\openjdk\jdk-21.0.8"
$env:ANDROID_HOME = "C:\Program Files (x86)\Android\android-sdk"
.\gradlew.bat clean assembleRelease
```

*(Note: If your network environment has broken IPv6 routes to `dl.google.com`, `-Djava.net.preferIPv4Stack=true` is already enabled in `gradle.properties`. Once dependencies are cached, you can append `--offline` for ~15-second offline builds.)*

Upon completion the APK is copied to `dist/WireGuardPlus-<version>.apk`.

### Signing

- With no `keystore.properties` in the repository root, the APK is signed with the Android debug key. That is fine for testing.
- For releases, copy `keystore.properties.example` to `keystore.properties`, point it at your own `.p12` keystore, and build again. The file and the keystore are git-ignored. Keep a backup of the keystore and use it for every release, because Android only updates an app when the signature matches.
- Gradle signs with the v1, v2 and v3 schemes.

---
## 4. Step 3: Verify Signatures & Bytecode Integrity

```powershell
& "C:\Program Files (x86)\Android\android-sdk\build-tools\36.0.0\apksigner.bat" verify --verbose .\dist\WireGuardPlus-<version>.apk
```

Expected output:
```text
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
```
