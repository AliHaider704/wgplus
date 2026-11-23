# Changelog

All notable changes to **WireGuard Plus** (`Windows Desktop` & `Android org.telegram.wgplus.module`) are documented in this file following the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## [1.9.0] - 2026-11-23

### Added
- **Dedicated Telegram VoIP Call Relays (Android & Windows)**:
  - **Android (`wgbridge-go/voip_relay.go`, `KeepaliveStatusProvider.java`, `XposedInit.java`)**: Added per-endpoint local `127.0.0.1` UDP/TCP VoIP relays (`StartVoipEndpointRelay`, 16-relay cap, 90s idle reaper) and targeted `Instance$Proxy` / endpoint rewriting for `tgcalls` so voice and video calls pass reliably without breaking connectivity.
  - **Windows (`wgbridge-go/voip_tun_windows.go`, `desktop-win/internal/voiptun/`)**: Embedded official signed Wintun (`v0.14.1`) and added `StartWindowsVoipTun` (`WireGuardPlusCalls`, `10.254.254.2/30`, MTU `1280`) routing strictly the 9 official Telegram VoIP IPv4 CIDRs with endpoint-loop exclusion, full-cone NAT, and exact RFC 1071/768 checksums while leaving normal PC traffic and Tailscale/VPN routes untouched.
- **In-App Diagnostics & Structured GitHub Issue Reporting (`wgbridge-go/diag.go`, `WgDiagnosticsLog.java`, `desktop-win/app.go`, `.github/ISSUE_TEMPLATE/bug_report.yml`)**: Added structured ring-buffer telemetry and a one-click diagnostic report copier formatted for GitHub bug reports.
- **Mandatory Official Channel Prompt (`WireGuardDialog.java`, `ModuleLauncherActivity.java`, `desktop-win/frontend/dist/app.js`)**: Restored the first-launch official channel invitation modal (`@wgplus_official`) across both Android and Windows.

### Fixed
- **Telegram Voice & Video Calls Hanging / Disconnecting**: Resolved post-answer call handshake stalls and drops on both Android (universal, ARM64, and ARMv7 across Telegram/Plus/AyuGram) and Windows Desktop (`AyuGram.exe`, Telegram Desktop).
- **Proxy Login Stalls & False Roaming Disconnects (`wgbridge-go/bridge.go`, `WireGuardManager.java`, `desktop-win/app.go`)**: Fixed hung loading states when signing into Telegram via the local proxy, prevented false tunnel teardowns on transient network-switch probes (`handleNetworkSwitch`), and improved Wi-Fi / Mobile Data continuity.
- **One UI Adaptive & Monochrome Launcher Icon (`app/src/main/res/drawable/ic_launcher_*.xml`, `mipmap-anydpi-v26/`)**: Migrated legacy PNG icon foreground/monochrome layers to crisp adaptive vector drawables so the launcher icon renders cleanly across Samsung One UI and Material You launchers.

### Security
- **Mandatory Android Local SOCKS5 Auth (`WireGuardManager.java`, `wgbridge-go/bridge.go`)**: Enforced RFC 1929 local authentication (`performSocks5ClientAuth`) on Android loopback SOCKS5 connections with `SOCKS_AUTH`/`SOCKS_REJECT` diagnostic auditing.
- **Android Keystore Fail-Closed Encryption (`WgKeystoreCrypto.java`)**: Eliminated plaintext storage fallback; keys now fall back strictly to a `0600` `noBackupFilesDir`-scoped AES-256-GCM key (`enc:v2:`) or fail closed.
- **ContentProvider Caller Signature Verification (`KeepaliveStatusProvider.java`)**: Added SHA-256 signing certificate digest checks alongside package checks for cross-process IPC callers.
- **Windows Loopback Process Guard Authenticode Validation (`desktop-win/internal/guard/process_guard_windows.go`)**: Added `WinVerifyTrust` Authenticode verification (`verifyAuthenticodeCached`) for basename-matched executables so spoofed binaries cannot bypass the strict loopback firewall.
- **Fail-Closed Android Kill Switch & Redacted Backups (`XposedInit.java`, `WireGuardManager.java`, `WireGuardDialog.java`)**: Enforced port `9` blackhole fallback when Kill Switch is armed and the tunnel is down; stripped raw private/preshared keys from `MODE_WORLD_READABLE` sync bundles; switched multi-profile clipboard exports to passphrase-encrypted `wgplus-backup-v1` bundles (`exportEncryptedBackupV1`) flagged `IS_SENSITIVE` on Android 13+.

## [1.8.0] - 2026-11-23

### Added
- **Full Nagram & Vector (LSPosed Fork) Compatibility (`XposedInit.java`, `WireGuardManager.java`, `ContinuityBridgeManager.java`, `AndroidManifest.xml`)**: Added `xyz.nextalone.nagram` to scope/queries/targets, `xposedsharedprefs`, and local mirror sync fallback for `targetSdk 36` clients without `<queries>`.
- **Multi-Client Shared Tunnel UI Sync (`WireGuardManager.java`, `KeepaliveStatusProvider.java`, `ModuleLauncherActivity.java`, `WireGuardDialog.java`)**: Companion app and secondary Telegram clients now display live **Connected** status and active port when another client owns the shared tunnel.
- **Adaptive & Monochrome App Icon (One UI / Material You)**: Replaced `<shape>` adaptive-icon background with `@color/ic_launcher_background`, added `<monochrome>` silhouette assets across all mipmap densities, and passed the launcher icon in `TaskDescription`.
- **Resilient Windows Auto-Updater (`desktop-win/updater.go`, `app.js`)**: Added local SOCKS5 tunnel transport, `github.com/.../releases/latest` redirect fallback, and automatic retry once the tunnel connects.

### Fixed
- **Nagram `NotificationsService` Crash**: Prevented synchronous `stopForeground()` inside `onStartCommand()` that triggered `RemoteServiceException: Context.startForegroundService() did not then call Service.startForeground()`.
- **Mobile UI & Arabic RTL Polish (`WireGuardDialog.java`, `WgStrings.java`)**: Hid the Disconnect button when disconnected, balanced Connect/Reconnect/Disconnect button sizing (`48dp`, single-line, equal `50/50` split in EN & AR), redesigned the Route & Calls verification table with clean RTL alignment and subtle dividers, and shortened verbose copy.
- **Windows Single-Click Server Switching (`desktop-win/app.go`, `app.js`)**: Added `SelectProfile()` for instant 1-click switching while disconnected, prevented 1-second telemetry polls from rebuilding `#profiles-list` mid-click, and fixed `ReferenceError: currentLang is not defined`.
- **Windows Kill Switch Guard on Switch Failure (`desktop-win/app.go`)**: Engaged `StartKillSwitchGuard()` if `Connect()` fails while Kill Switch is enabled.

## [1.7.9] - 2026-11-22

### Added
- **Minimal Version Footer (Windows & Android)**: Added a subtle `WireGuard Plus · v1.7.9` footer at the bottom of the Windows desktop UI, Android companion launcher (`ModuleLauncherActivity`), and in-Telegram settings dialog (`WireGuardDialog`).

### Fixed
- **Download & Upload Balance (`wgbridge-go/fast_netstack.go`, `bridge.go`)**: Tuned asymmetric RX/TX buffers (`rxMax=16MB` desktop / `8MB` mobile, `txMax=1MB`, `batchSize=32`, `CUBIC`) to restore full multi-hundred-Mbps download throughput (`149–265 Mbps` desktop, `145 Mbps` mobile) without outbound UDP burst loss.
- **Fast Initial Connect, Wakeup & Wi-Fi/LTE Roaming (`bridge.go`, `doh.go`, `WireGuardManager.java`)**:
  - Reduced DoH/fallback timeouts (`1200ms`/`1000ms`), accelerated initial handshake escalation (`250ms -> 450ms -> 800ms`), and sped up Phase 2 stall recovery (`3s` ticks -> `6s` hop).
  - Updated `EnsureTunnelAlive` to actively verify handshakes older than `15s` and `UpdatePeerEndpoint` to still hop/re-handshake on the active endpoint if DNS/DoH fails mid-handoff between Wi-Fi and Mobile Data.
- **Android Multi-Client Stability & Fork Compatibility (`WireGuardManager.java`, `XposedInit.java`, `KeepaliveBridgeListenerService.java`)**:
  - Integrated `isUsingSharedHub()` across `isTunnelRunning`, `getActivePort`, `enforceKillSwitchIfDisconnected`, `onAppForegroundChanged`, `runFailoverCheck`, and `handleRoamingEvent`.
  - Fixed `ForegroundServiceDidNotStartInTimeException`, `NoSuchMethodError` on `ConnectionsManager.setProxySettings` in AyuGram, and self-binding `KeepaliveBridgeListenerService` warnings.
- **Windows Official Channel Deep-Link (`desktop-win/frontend/dist/app.js`)**: Switched the channel invite link to `tg://resolve?domain=wgplus_official` so it opens Telegram Desktop directly instead of the browser.

## [1.7.8] - 2026-11-22

### Fixed
- **Upload Throughput Breakthrough (`wgbridge-go/fast_netstack.go`)**: Switched the userspace gVisor TCP congestion controller from `CUBIC` + `TCPRACKLossDetection` to `NewReno` (retaining `SACK` and `TCPDelayEnabled(false)`) and replaced silent outbound TUN packet drops in `WriteNotify` with `closeCh`-guarded backpressure, eliminating false loss-recovery `cwnd` collapses and restoring full upload speed across Windows and Android.
- **Tunnel Stability & Handshake Recovery (`wgbridge-go/bridge.go`)**: Updated `tunnelWatchdogLoop` so initial warmup and routine `>135s` rekeying use soft handshakes on the same UDP socket instead of wiping the WireGuard Noise session (`replace_peers=true`) mid-flight, preventing `2000-5000ms` TCP stalls.
- **Android Multi-Client Shared Tunnel Hub (`KeepaliveStatusProvider`, `WireGuardManager`)**: Added a shared local SOCKS5 hub across simultaneously running Telegram clients (`Telegram`, `Plus`, `AyuGram`, `Telegram Gold`, `Telegraph`, etc.) so all clients reuse one active WireGuard session with zero `PrivateKey` collisions.
- **Standalone Launcher Stability (`ModuleLauncherActivity`)**: Eliminated redundant full-screen `2.5s` `setContentView` rebuilds while connected.

## [1.7.3] - 2026-11-21

### Added
- **Multi-Client Simultaneous Support & Shared Config Sync (`KeepaliveStatusProvider`, `WireGuardManager`)**: Expanded Android module scope to **Telegram**, **Telegram Plus** (`v12.8.1.0+`), **Telegram Web**, **Telegram Beta**, **Telegram Gold**, **Telegraph**, **AyuGram**, and **Telegram X** (`TelegramXBridge`), syncing server profiles, active profile, Kill Switch, auto-connect, DoH, and call settings across all clients simultaneously.
- **Android Adaptive Launcher Icon**: Added crisp dark-slate & blue/emerald adaptive icon assets across `mipmap-*` densities.
- **Lightweight Non-Root Startup & Safe Cache Hygiene (`ModuleHygieneManager`, `NativeBridgeLoader`)**: Offloaded native library loading and auto-connect off the Telegram UI thread, plus safe temporary cache cleanup protecting LSPatch/Xposed, databases, prefs, and DEX/OAT caches.
- **Headless Automation APIs & Build Metadata**: Added `automation_status`, `automation_quick_warp`, `automation_import_conf`, `automation_clean_cache` and `dist/android-build-meta.json`.
- **Official Telegram Channel Invite**: Added a polite one-time notice and link to [`t.me/wgplus_official`](https://t.me/wgplus_official) after first successful connection on Android and Windows.

### Changed
- **73% Android APK Size Reduction**: Enabled R8 minification (`minifyEnabled true`), `shrinkResources true`, NDK `llvm-strip --strip-unneeded`, `gomobile -trimpath -ldflags="-s -w -buildid="`, BouncyCastle PQC table excludes, and ABI splits (`5.08 MB` arm64-v8a / `5.04 MB` armeabi-v7a / `11.26 MB` universal vs `18.82 MB` previously).
- **Bilingual MSA (`تيليجرام`) & Progressive UI Overhaul**: Refined zero-state onboarding, single primary CTA rule, 3-state handshake diagnostics with inline AWG 1.5/WARP recovery, and zero language leakage across Android & Windows.
- **8K Showcase Assets**: Regenerated `docs/assets/` showcase banners, Android/Windows screens, and `WireGuardPlus-Windows-Walkthrough.mp4` at 8K (`7680x4320`).

### Fixed
- **Eliminated Repeated Magisk Superuser Toasts (`PrivilegeBridge`, `ContinuityBridgeManager`)**: Consolidated root daemon bootstrap into a single per-boot `su -c` call (`bootstrapRootOncePerBoot`) with Binder IPC afterwards.

## [1.7.1] - 2026-11-20

### Fixed
- **Windows always-on after reboot/sleep**: Start with Windows, Auto-Connect when Telegram opens, and the new Auto-Connect When App Starts are now enabled by default (existing installs are migrated once, schema v2). The app now connects the active profile automatically at launch with retries while the network comes up, re-connects after sleep/resume, and re-syncs the HKCU Run entry on every start.

## [1.7.0] - 2026-11-20

### Added
- **Shared Free WARP (AWG 1.5) Core Provisioner (`wgbridge-go/warp.go`)**: Exported `GenerateWarpConfigJSON()` from the shared Go core (accessible to both Windows and Android via `gomobile`) generating X25519 WireGuard keys, registering anonymous Cloudflare WARP configs with AmneziaWG 1.5 QUIC mimicry (`Jc=4;Jmin=40;Jmax=120;I1=...`) + 3-byte `Reserved`, and registering IPv4 DoH fallback hints automatically.
- **1-Click Free WARP (AWG 1.5) on Windows (`desktop-win/`)**: Added `App.QuickConnectWarp(forceNew)` and a focal **1-Click Free WARP (AWG 1.5)** button that provisions or reuses a Free WARP profile, connects the tunnel, automatically pushes the authenticated `tg://socks` link to running/enabled Telegram Desktop clients (or copies to clipboard if none are detected), and runs live route + UDP call verification in one click.
- **1-Tap Free WARP (AWG 1.5) & Full AWG 1.5 on Android (`app/`)**: Rebuilt `wgbridge.aar` with AWG 1.5 + Cloudflare WARP `Reserved` handshake support, extended `TunnelConfig` and `.conf`/JSON serializers with `I1`-`I5` and `Reserved` fields, added an **AWG 1.5 QUIC** preset button, and added **1-Tap Free WARP (AWG 1.5)** actions in both `WireGuardDialog` and `ModuleLauncherActivity`.

## [1.6.1] - 2026-11-20

### Fixed
- **Free WARP (AWG 1.5) Handshake Compatibility (`wgbridge-go/awg_bind.go`)**: Fixed Cloudflare WARP 3-byte `Reserved` (`client_id`) header handling so `Reserved` octets `[1..3]` are stamped outside standard WireGuard `MAC1`/`MAC2` calculation (instead of recomputing `MAC1` and clearing `MAC2` as required only for AmneziaWG `H1`-`H4` custom headers), and validated inbound `MAC1` with zeroed `Reserved` bytes prior to stripping `[1..3]`. Previously, Cloudflare's `boringtun` edge silently dropped outbound handshake initiations and `awgBind` rejected inbound server responses.
- **WARP Fallback Hint (`desktop-win/internal/warp/warp_gen.go`)**: Registered Cloudflare's returned peer IPv4 address via `wgbridge.RegisterEndpointIpHint("engage.cloudflareclient.com", ...)` during anonymous WARP registration as an offline DoH fallback hint.

### Added
- **Cloudflare `boringtun` Interoperability Test (`wgbridge-go/bridge_desktop_test.go`)**: Added `TestWarpReservedCloudflareBoringtunInteroperability` plus strict `verifyMac1ZeroedReserved` wire checks in `TestAwg15CpsSignaturePacketsAndReservedBytes` verifying full AWG 1.5 `I1` + `Jc` + `Reserved` SOCKS5 TCP and UDP flow against an unmodified WireGuard server.

## [1.6.0] - 2026-11-19

### Added
- **WireGuard Plus for Windows Desktop (`desktop-win/`)**:
  - **Zero-Admin, Zero-Wintun Architecture (`asInvoker`)**: Runs completely in userspace with zero kernel drivers, zero UAC prompts, and zero routing conflicts with Tailscale, AdGuard, corporate VPNs, or gaming traffic.
  - **Multi-Client Detection & Dispatch (`internal/clients/`)**: Automatically detects installed and portable Windows Telegram clients (**Telegram Desktop**, **Telegram Desktop Portable**, **AyuGramDesktop Portable**, **64Gram**, **Forkgram**, **Unigram Microsoft Store**), tracks per-client TCP/UDP telemetry, supports **+ Add Portable `.exe`**, and dispatches authenticated `tg://socks` links in one click.
  - **Zero-Admin `iphlpapi` Loopback Process Firewall (`internal/guard/`)**: Verifies owning PIDs and executable image paths (`GetExtendedTcpTable` / `GetExtendedUdpTable` + `QueryFullProcessImageName`) before relaying traffic on `127.0.0.1`, blocking unauthorized local probes in `Strict` mode alongside per-install RFC 1929 SOCKS5 authentication and a fail-closed Kill Switch.
  - **DPAPI Vault, Portable Mode & Argon2id Backups (`internal/vault/`)**: Encrypts secrets via Windows `CryptProtectData`, keeps all vault/WebView2 state inside `./wgplus-data/` whenever `portable.flag` sits beside `WireGuardPlus.exe`, and supports passphrase-protected Argon2id + AES-256-GCM `.wgplus` exports for moving setups between PCs.
  - **1-Click Free WARP (`AWG 1.5`), QR Clipboard DIB Decoder & Auto-Failover**: Registers anonymous Cloudflare WARP profiles preconfigured with AmneziaWG 1.5 QUIC mimicry (`internal/warp/`), decodes standard and inverted QR screenshots straight from Win32 `CF_DIB` clipboard or files (`internal/qr/`), and fails over to the lowest-latency backup server when handshakes stall (`internal/watchdog/`).
  - **Sleep/Wake Continuity & Pure-Go Win32 Tray (`internal/syswin/`)**: Handles `WM_POWERBROADCAST` resume and `NotifyIpInterfaceChange` IP change recovery, pure-Go System Tray controls, and optional `HKCU` `--minimized` startup in full Dark/Light + English (LTR) / Arabic (RTL) WebView2 UI (`Wails v2`).
- **Upgraded Shared Go Engine (`wgbridge-go/`)**:
  - Added desktop netstack tuning (`SetDesktopMode`: `8192` queue / `128` batch / `16 MB` TX/RX windows, parallel cached tunnel DNS, dynamic `SetBlockIPv6`).
  - Added AmneziaWG 1.5 CPS signature packet support (`I1`-`I5` QUIC mimicry), Cloudflare WARP 3-byte `Reserved` header stamping with BLAKE2s `MAC1` recomputation (`awg_bind.go`), `SetCustomDoH`, optional local `HTTP CONNECT` proxy (`http_proxy.go`), build-tag-isolated `!android` guard hooks (`desktop_api.go`), 1-second live throughput & per-client telemetry (`telemetry.go`), and Telegram `DC1`/`DC2`/`DC4`/`DC5` + UDP call diagnostics (`diagnostics_calls.go`).
- **Windows Release CI & Build Provenance (`.github/workflows/release-windows.yml`, `scripts/build-windows.ps1`)**:
  - Builds & `--self-check` verifies `WireGuardPlus-Windows-x64.exe` and `WireGuardPlus-Windows-x64-Portable.zip` with SLSA build provenance (`actions/attest-build-provenance@v2`).
- **Dual-Platform Documentation & Media**:
  - Updated `README.md`, `README.ar.md`, `docs/*`, GitHub Pages (`docs/index.html`), Windows screenshots showcase, animated `windows-demo.gif`, and 720p `WireGuardPlus-Windows-Walkthrough.mp4`.

## [1.5.0] - 2026-11-16

### Added
- **Self-Contained Sovereign Silent Continuity (Zero External Helper Apps)**:
  - **`WgAdbConnectionManager`, `BuiltinAdbKeyManager` & `AdbPairingService`**: Built-in SPAKE2 + Conscrypt TLS 1.3 Wireless Debugging client (`libadb-android:3.1.1`) storing its RSA-2048 identity encrypted in `AndroidKeyStore` (`AES-256-GCM`), paired once via a 6-digit notification `RemoteInput` reply on Android 11+ with automatic silent `WRITE_SECURE_SETTINGS` Wi-Fi reconnection and dynamic local loopback TCP auto-heal (`adb_tcp_port`, e.g. `5561`) when switching to Mobile Data.
  - **`PrivilegeBridge` & `DaemonProcessHelper`**: Unified dual-mode continuity engine supporting Root (`uid=0`, `oom_score_adj = -800`, foreground cpuset), detached loopback-authenticated `wgplus_daemon`, and direct self-granted `SET_PROCESS_LIMIT` Binder `IActivityManager.setProcessImportant` (`adj=200` `force-imp`), applying `deviceidle`, Samsung MARs, `appops`, `netpolicy`, and `max_phantom_processes` exemptions silently.
  - **`BootContinuityReceiver` & Passive Wi-Fi Callback**: Automatically re-applies stealth protection on `LOCKED_BOOT_COMPLETED`, `BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`, and Wi-Fi availability changes with zero ongoing notifications.
  - **Plain Non-Technical Companion UI**: Simplified Arabic (`RTL`) and English (`LTR`) status strings in `ModuleLauncherActivity` and `WgStrings` with zero internal protocol or debugging jargon.

### Removed
- Complete removal of third-party Shizuku integration (`ShizukuBridge`, `ShizukuClientProvider`, `ShizukuProcessHelper`, `moe.shizuku.api.BinderContainer`, `<queries>` entries, and `moe.shizuku.manager.permission.API_V23`).

### Fixed
- **Notification Permission Sequencing**: Requests `POST_NOTIFICATIONS` before opening Wireless Debugging Developer Options on Android 13+, and strips `RemoteInput` before stopping/cancelling the pairing notification so `LIFETIME_EXTENDED_BY_DIRECT_REPLY` clears immediately upon submission.
- **Fast Daemon Bootstrap Race**: Registers the `wgplus_daemon` loopback endpoint with `KeepaliveStatusProvider` prior to running asynchronous OS exemptions (`wgplus-daemon-init`) and prevents unprivileged fallback shells from invoking `pm grant` under app UID.

## [1.4.0] - 2026-11-10

### Added
- **24/7 Silent Hybrid Continuity Engine (Zero Root, Zero Persistent Notification, Zero Samsung "1 Active App" Banner)**:
  - **`ShizukuBridge`, `ShizukuClientProvider`, `ShizukuProcessHelper` & `moe.shizuku.api.BinderContainer`**: Pure Android-SDK Shizuku v13 client receiving live `IShizukuService` binders via `sendBinder` and `REQUEST_BINDER`, applying `deviceidle` Doze + Samsung MARs whitelist, `netpolicy` unrestricted background allowance, `exempted` standby bucket, and `IActivityManager.setProcessImportant` (`adj=200` `force-imp` + `mKeepSEMPrcp` token) cleanly without third-party dependencies.
  - **`KeepaliveBridgeListenerService` (Zero-Capture Silent Boot Guard)**: Declared with empty `default_filter_types` and `disabled_filter_types="ongoing|conversations|alerting|silent"` so zero user notifications are ever read or processed, binding Telegram's `NotificationsService` (`BIND_AUTO_CREATE | BIND_IMPORTANT | BIND_INCLUDE_CAPABILITIES`) to hold `adj=200 / BFGS` silently across Deep Doze and device reboots even before Shizuku is restarted.
  - **`KeepaliveStatusProvider` & `ContinuityBridgeManager`**: Synchronous IPC bridge between hooked Telegram (`XposedInit` / `WireGuardManager`) and the companion app, automatically stripping ongoing FGS notification `49107` whenever Hybrid or Boot Guard protection is active, while transparently falling back to Foreground Service keepalive when neither is configured.
  - **Companion App Hybrid Card (`ModuleLauncherActivity`)**: Added live Hybrid tier telemetry, Stealth mode toggle, one-tap Shizuku authorization + OS exemption setup, and one-tap Boot Guard launcher in Arabic (`RTL`) and English (`LTR`).

## [1.3.0] - 2026-11-05

### Added
- **AmneziaWG Censorship & DPI Obfuscation (`awg_bind.go`)**:
  - Full userspace support for `Jc`, `Jmin`, `Jmax` random pre-handshake junk packets, `S1..S4` packet size padding, and `H1..H4` custom message type headers (single uint32 or `min-max` dynamic ranges) with Curve25519 public-key derivation and BLAKE2s-128 `MAC1` recalculation.
  - One-tap **Client junk preset** (`Jc=4, Jmin=50, Jmax=250`) in the collapsible DPI Obfuscation panel that works against standard WireGuard servers without server modifications.
- **One-Tap Multi-Profile Ping & Auto-Select Fastest (`ProbeEndpointHandshakeMs`)**:
  - Concurrent isolated cryptographic WireGuard/AmneziaWG handshakes measure real millisecond RTT across all saved profiles without interrupting an active tunnel, displaying live `ms` tags on each profile row and switching automatically to the fastest server.
- **Auto-Failover Health Watchdog**:
  - Optional `25s` health monitor detecting stale handshakes or tunnel drops and failing over automatically to the fastest reachable backup profile.
- **Strict Telegram Kill Switch (`StartKillSwitchGuard`)**:
  - Fail-closed loopback SOCKS5 guard port binding both `ConnectionsManager` (`tgnet`) and `VoIP` (`Instance.makeNativeInstance`) on cold start, manual disconnect, and unexpected drops so zero Telegram packets ever leak over direct ISP sockets.
- **Encrypted DNS-over-HTTPS (`DoH`, `RFC 8484`) Endpoint Resolver (`doh.go`)**:
  - Direct-IP TLS resolution (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`) for VPN `Endpoint` hostnames with ISP sinkhole/bogon (`0.0.0.0`, `127.0.0.0/8`) rejection and zero plaintext port-53 DNS leakage.
- **Auto-MTU Path Finder & Smart Idle Keepalive Battery Saver**:
  - One-tap path MTU discovery (`1420 -> 1392 -> 1360 -> 1320 -> 1280`) for `4G/5G` and PPPoE links, plus `ActivityLifecycleCallbacks` background detection pausing `persistent_keepalive_interval` to `0` after `90s` idle and restoring `25s` immediately on foreground resume.
- **Pure-Java Gallery QR Import/Export & Multi-Profile JSON Backup (`WgQrCodec.java`)**:
  - Import profiles from gallery QR screenshots (`0x5748`, supporting both light and dark-mode inverted QR images with zero `CAMERA` permission), display scannable high-contrast QR modals for any profile, and export/restore all profiles via `wgplus-backup-v1` JSON.

## [1.2.1] - 2026-11-05

### Fixed
- **Home Screen Launcher Icon Disappearing**:
  - Removed `de.robv.android.xposed.category.MODULE_SETTINGS` from `ModuleLauncherActivity` in `AndroidManifest.xml`, added standard `@android:drawable/sym_def_app_icon` resource declaration, and enforced `COMPONENT_ENABLED_STATE_ENABLED` at startup.
- **Multi-Profile Import Overwriting Existing Server**:
  - Added `WireGuardManager.importConfAsProfile` with synchronous `.commit()` persistence and hooked `org.telegram.ui.LaunchActivity.onActivityResult` directly on Telegram's DEX classloader.
- **Direct Tap-to-Switch & Inline Profile Deletion**:
  - Replaced horizontal chip strip with vertical Saved Profiles rows (`wg_connected_profile_id`) and inline `Edit` / `Delete` controls (`44dp` tap targets).

## [1.2.0] - 2026-11-05

### Added
- **Voice & Video Calls over WireGuard (`VoIP` / `tgcalls`)** via RFC 1928 `UDP ASSOCIATE` (`0x03`) + dual-layer `"mainconfig"` and `Instance.makeNativeInstance` hooks.
- **Multi-Profile Management, `.conf` File Import/Export, Keystore `AES-256-GCM` Encryption & Full ISO/IEEE/MADR Spec Suite**.

## [1.1.0] - 2026-11-05

### Added
- Zero-leak Arabic (`RTL`) and English (`LTR`) localization catalog (`WgStrings`) + WCAG AA Dark/Light theme tokens (`WgTheme`).

## [1.0.3] - 2026-11-05

### Added
- End-to-end tunnel verification (`verifyTunnel`) checking Exit IP, Country, TLS latency, and Telegram DC2 reachability.

## [1.0.2] - 2026-11-05

### Fixed
- Resolved `NoClassDefFoundError: wgbridge.Wgbridge` under LSPatch `InMemoryDexClassLoader` (`go.Seq` guard + Android 14+ `0500` DCL permissions) and unified PKCS12 release signing.

## [1.0.0] - 2026-11-04

### Added
- Initial userspace Go WireGuard (`wireguard-go` + `netstack`) to local TCP SOCKS5 bridge, Xposed `ProxyListActivity` integration, and `.conf` clipboard parser.
