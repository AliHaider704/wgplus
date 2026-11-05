# Changelog

All notable changes to **WireGuard Plus** (`org.telegram.wgplus.module`) are documented in this file following the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

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
