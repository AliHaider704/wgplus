# Build & Reproducibility Guide

This guide explains how to compile, test, package, and verify **WireGuard Plus** from source for both **Windows Desktop** (`desktop-win/`) and **Android** (`app/` + `wgbridge-go/`).

---

## Part 1: Building WireGuard Plus for Windows (`desktop-win/`)

### 1. Windows Prerequisites

| Tool | Recommended Version | Notes |
|------|---------------------|-------|
| **Go** | `1.26+` | `go.mod` specifies `1.26.10` |
| **Wails CLI** | `v2.17.1` | `go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1` |
| **Microsoft Edge WebView2** | Evergreen Runtime | Pre-installed on Windows 10/11 |
| **MSYS2 / MinGW GCC (Optional)** | `ucrt64` GCC | Required only when running Go tests with `-race` locally |

### 2. Test, Build & Package on Windows

Run from the repository root in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

Optional parameters:
- `-GoRoot "C:\path\to\go"` if portable Go is installed outside standard locations (`%LOCALAPPDATA%\Programs\Go`, `C:\Program Files\Go`).
- `-SkipTests` to skip running unit tests before `wails build`.

What `scripts/build-windows.ps1` executes:
1. Runs `go vet ./...`, all Go engine tests inside `wgbridge-go/` (with `-race` if GCC is present), and `GOOS=android GOARCH=arm64 go build ./...` to guarantee shared-engine mobile compatibility.
2. Runs `go vet ./...` and all package unit tests inside `desktop-win/` (`internal/clients`, `internal/config`, `internal/guard`, `internal/qr`, `internal/syswin`, `internal/vault`, `internal/warp`, `internal/watchdog`).
3. Builds `WireGuardPlus-Windows-x64.exe` via `wails build -clean -platform windows/amd64 -ldflags "-s -w"`.
4. Packages `dist/WireGuardPlus-Windows-x64-Portable.zip` containing `WireGuardPlus.exe`, `portable.flag`, and `PORTABLE_README.txt`.
5. Executes `WireGuardPlus-Windows-x64.exe --self-check`, verifying exit code `0` and `"ok": true`, then prints lowercase SHA-256 hashes for both release artifacts.

> **Reproducible CI & SLSA Provenance:** Every GitHub release tag also triggers [`.github/workflows/release-windows.yml`](../.github/workflows/release-windows.yml) on `windows-latest`, running `scripts/build-windows.ps1` and generating cryptographic build provenance attestations (`actions/attest-build-provenance@v2`).

---

## Part 2: Building the Android Module (`app/` + `wgbridge-go/`)

### 1. Android Prerequisites

| Tool | Recommended Version | Notes |
|------|---------------------|-------|
| **JDK** | OpenJDK 21 | Used for Gradle, `javac`, `jar`, and `javap` |
| **Android SDK** | Platform 35, Build-Tools `36.0.0` | `minSdk 21`, `targetSdk 34`, `compileSdk 35` |
| **Android NDK** | `r27c` (`27.2.12479018`) | Required by `gomobile` cgo cross-compilation |
| **Go** | `1.26+` | With `golang.org/x/mobile/cmd/gomobile` installed |
| **Gradle** | `8.11.1` | Included via `./gradlew` / `gradlew.bat` |

*(Do not create a `go.work` workspace file at the repository root; `desktop-win/go.mod` uses `replace wgbridge => ../wgbridge-go` specifically so `gomobile bind` continues to operate cleanly inside `wgbridge-go/`.)*

### 2. Test & Build the Native Go Bridge (`wgbridge.aar`)

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
1. Runs `go test -v ./...` inside `wgbridge-go` (verifying key parsing, MTU bounds, UAPI stats, AmneziaWG 1.0/1.5 obfuscation, DoH fallback, HTTP CONNECT, and full SOCKS5 `UDP ASSOCIATE` VoIP packet relay).
2. Runs `gomobile bind -target="android/arm64,android/arm" -androidapi 21 -o app/libs/wgbridge.aar .`.
3. Patches `go/Seq.java` to tolerate prior `System.load(...)` preloading under LSPatch, recompiles `go/Seq.class`, repacks `app/libs/wgbridge.aar`, and verifies the exception handler table with `javap -c`.

### 3. Build & Sign the Android Module APK

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\openjdk\jdk-21.0.8"
$env:ANDROID_HOME = "C:\Program Files (x86)\Android\android-sdk"
.\gradlew.bat testReleaseUnitTest assembleRelease
```

*(Note: If your network environment has broken IPv6 routes to `dl.google.com`, `-Djava.net.preferIPv4Stack=true` is already enabled in `gradle.properties`. Once dependencies are cached, you can append `--offline` for fast offline builds.)*

Upon completion the APK is copied to `dist/WireGuardPlus-<version>.apk`.

#### Signing
- With no `keystore.properties` in the repository root, the APK is signed with the Android debug key (fine for local testing).
- For releases, copy `keystore.properties.example` to `keystore.properties`, point it at your `.p12` keystore, and rebuild. Keep a backup of the release keystore because Android only allows in-place updates when the signing key matches.
- Gradle signs with v1, v2, and v3 APK signature schemes.

#### Verify APK Signature Integrity

```powershell
& "C:\Program Files (x86)\Android\android-sdk\build-tools\36.0.0\apksigner.bat" verify --verbose .\dist\WireGuardPlus-1.7.0.apk
```
