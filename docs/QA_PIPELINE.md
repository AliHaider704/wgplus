# Hybrid Multi-Device QA & Compatibility Testing Pipeline

WireGuard Plus (`wgplus`) validates Android and Windows builds across three complementary layers designed to catch OEM/API regressions early without requiring paid device farms.

## Architecture Overview

| Layer | Where It Runs | Cost | What It Verifies |
| --- | --- | --- | --- |
| **Tier 1: CI Build, ELF Audit & KVM Emulator Matrix** | GitHub Actions (`ubuntu-latest` + `windows-latest`) | Free | Go unit/race tests (`wgbridge-go`, `desktop-win`), Android unit tests + Release APKs, static ELF `e_machine` & Android 15+ 16 KB (`0x4000`) page-alignment checks (`scripts/audit-android-apk.py`), Arabic string lint, and headless KVM `x86_64` instrumentation tests on Android API `28, 31, 34, 35`. |
| **Tier 2: Firebase Test Lab Real OEM Matrix** | GitHub Actions -> Firebase Test Lab (Spark plan) | Free (up to 5 physical + 10 virtual runs/day) | `WgPlusSmokeInstrumentedTest` on real unrooted OEM phones (Google Pixel, Samsung, Xiaomi/Motorola), plus optional Robo launch verification on an LSPatch-patched host APK via `workflow_dispatch`. |
| **Tier 3: Local Hybrid Fleet Orchestrator** | Windows IDE (`scripts/qa-hybrid.ps1`) | Free | Static APK audit + Windows `--self-check` & `WireGuardPlusCalls` Wintun verification + parallel ADB checks across all plugged-in USB and Wi-Fi devices (Root & Non-Root detection, live `automation_status`, `handshakeHealthy`, crash/loop `logcat` scan). |

> **Important Xposed/LSPatch Boundary:** Cloud device farms (GitHub Actions emulators and Firebase Test Lab) run stock unrooted images. They reliably verify `libgojni.so` JNI loading, Go mux stability, ContentProvider IPC, companion UI rendering across OEMs/APIs, and LSPatch-embedded (`InMemoryDexClassLoader`) APK startup, while Magisk/LSPosed system hooks and OEM battery killers (Samsung OneUI / Xiaomi MIUI) remain verified via **Tier 3** on local physical devices.

---

## Tier 3: Running Local Hybrid QA from the IDE

```powershell
# Quick pre-push check across Windows + USB/Wireless ADB phones (skips reinstall)
.\scripts\qa-hybrid.ps1 -WirelessTargets "192.168.0.179:5555" -SkipBuild -SkipInstall

# Full install + verification across all connected devices
.\scripts\qa-hybrid.ps1 -WirelessTargets "192.168.0.179:5555" -SkipBuild
```

---

## Tier 2: One-Time Firebase Test Lab Spark Setup (5 Steps)

`.github/workflows/firebase-test-lab.yml` skips cleanly on `v*` tag pushes until secrets are added, so releases never fail without credentials. To enable real OEM cloud runs:

1. Open [Firebase Console](https://console.firebase.google.com/), create or select a project (Spark free plan is sufficient — up to **5 physical** and **10 virtual** device tests per day).
2. In [Google Cloud Console](https://console.cloud.google.com/), enable **Cloud Testing API** (`testing.googleapis.com`) and **Cloud Tool Results API** (`toolresults.googleapis.com`) for that project.
3. Under **IAM & Admin -> Service Accounts**, create a service account with the **Firebase Test Lab Admin** (`roles/cloudtestservice.testAdmin`) role (or **Editor** scoped to the test project) and download its JSON key.
4. In GitHub **Repository Settings -> Secrets and variables -> Actions**, add two secrets:
   - `GCP_PROJECT_ID`: Your Firebase / Google Cloud Project ID.
   - `FIREBASE_SERVICE_ACCOUNT_JSON`: Full contents of the downloaded JSON key file.
5. Run **Actions -> Firebase Test Lab (Real OEM Devices) -> Run workflow** anytime (or push a `v*` release tag). To test an LSPatch-patched Telegram host APK on real devices, paste its direct download URL into the `extra_host_apk_url` input.
