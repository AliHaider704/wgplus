# Security & Privacy Model

This document states the exact cryptographic, network-isolation, and storage boundaries of **WireGuard Plus** (`v1.9.0`) across **Windows Desktop** and **Android** based on verifiable implementation behavior.

---

## 1. Traffic Routing Boundaries (What Enters the Tunnel vs. What Does Not)

| Traffic Category | Routed Through WireGuard Tunnel? | Mechanism |
|------------------|----------------------------------|-----------|
| **Windows Telegram Clients (Chats, Media & Downloads)** | **Yes** | Telegram Desktop / Portable / AyuGram / 64Gram / Forkgram / Unigram -> `127.0.0.1:48729` (RFC 1929 SOCKS5 + `iphlpapi` & Authenticode Process Guard) -> `gVisor netstack` -> `wireguard-go`. |
| **Windows Voice & Video Calls** | **Yes** | Embedded `WireGuardPlusCalls` Wintun L3 adapter (`10.254.254.2/30`, MTU `1280`) routes strictly Telegram's 9 official VoIP IPv4 CIDRs (`91.108.4.0/22`, `91.108.8.0/21`, `91.108.12.0/22`, `91.108.16.0/22`, `91.108.20.0/22`, `91.108.56.0/22`, `149.154.160.0/20`, `91.105.192.0/23`, `185.76.151.0/24`) with endpoint-loop exclusion, alongside SOCKS5 `UDP ASSOCIATE 0x03`. Setting **Calls -> Peer-to-Peer: Nobody** inside desktop Telegram prevents direct P2P IP exposure. |
| **Android Messages, Chats, Channels & Media** | **Yes** | `ConnectionsManager.setProxySettings` + `native_setProxySettings` across accounts `0..3` -> authenticated RFC 1929 SOCKS5 on `127.0.0.1:<port>` (`SOCKS5 CONNECT 0x01`, or blackhole port `9` when Kill Switch is armed and disconnected) -> `gVisor netstack` -> `wireguard-go`. |
| **Android Voice & Video Calls (`1-on-1` & Group Calls)** | **Yes** (when *Route voice and video calls* is ON, default) | `"mainconfig"` `proxy_enabled_calls = true` + `Instance.makeNativeInstance` / `VoIPController.start` hooks inject authenticated `Instance$Proxy` and rewrite non-loopback VoIP endpoints through local `127.0.0.1` UDP/TCP relays (`StartVoipEndpointRelay` -> `gVisor netstack` -> `wireguard-go`). |
| **In-App DNS Resolution for Proxied Connections** | **Yes** | Domain targets sent over SOCKS5 (`ATYP = 0x03`) or HTTP CONNECT resolve inside `gVisor netstack` using your configured tunnel DNS server over the encrypted WireGuard link (with optional IPv6 AAAA suppression when `BlockIPv6` is active). |
| **Initial WireGuard Endpoint Hostname Lookup** | **Encrypted DoH** | `doh.go` resolves endpoint hostnames directly over HTTPS (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `9.9.9.9`, or your custom DoH resolver) using RFC 8484 wireformat queries, rejecting sinkhole/bogon IPs (`0.0.0.0`, `127.0.0.0/8`) without plaintext port-53 ISP leakage. |
| **External Browsers, Games & Other OS Apps** | **No** | Other Windows executables and external Android browsers remain untouched on your system route (or Tailscale / AdGuard / work VPN). `WireGuardPlusCalls` only routes Telegram's 9 call CIDRs, and non-Telegram Windows apps attempting to connect to the local proxy are blocked by `iphlpapi` + Authenticode checks in `Strict` mode. |

---

## 2. Outbound Network Transparency (Zero Telemetry)

WireGuard Plus includes **no analytics SDKs, ad networks, or crash uploaders**. The binaries initiate external network traffic **exclusively** for these explicit purposes:

| Purpose | Destination | Trigger |
|---------|-------------|---------|
| **1. Encrypted Tunnel Transport** | Your configured `.conf` peer UDP `Endpoint` (or Cloudflare WARP peer) | Tunnel Connect / active session / explicit **Ping All** |
| **2. Encrypted DoH Endpoint Resolution** | `1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `9.9.9.9` (`RFC 8484` HTTPS) or user-configured Custom DoH | Tunnel Connect when `Endpoint` is a hostname and DoH is enabled |
| **3. Route & VoIP Verification** | `one.one.one.one/cdn-cgi/trace`, `1.1.1.1:53` (UDP), and Telegram DCs `1/2/4/5` routed **inside** the active tunnel (plus `1.0.0.1:443` / `8.8.8.8:53` reachability checks) | User clicking **Verify Route & Calls** |
| **4. Optional Free WARP Registration** | `https://api.cloudflareclient.com/v0a2158/reg` (anonymous WireGuard keypair registration) | Windows user clicking **+ Free WARP (AWG 1.5)** |
| **5. App Update & Release Notes Check** | `https://api.github.com/repos/AliHaider704/wgplus/releases/latest` (and `tags/v...` / GitHub redirect fallback) | App launch / manual update check |

---

## 3. Windows Security & Isolation Model (`desktop-win/`)

- **Execution Manifest & Scoped VoIP Adapter:** `wails.exe.manifest` sets `requestedExecutionLevel level="asInvoker"`, extracting signed Wintun (`v0.14.1`) locally (`EnsureWintunDLLForApp`) only to bind the isolated `WireGuardPlusCalls` adapter for Telegram's 9 call CIDRs without altering the default OS gateway.
- **`iphlpapi` + Authenticode Loopback Process Firewall:** Before relaying any TCP stream on `127.0.0.1` (`SOCKS5` / `HTTP CONNECT`) or accepting a loopback UDP relay datagram (`UDP ASSOCIATE`), `internal/guard/process_guard_windows.go` queries `GetExtendedTcpTable` / `GetExtendedUdpTable` to identify the owning PID, inspects its full image path via `QueryFullProcessImageName` (`PROCESS_QUERY_LIMITED_INFORMATION`), and verifies Authenticode signatures (`WinVerifyTrust` / `verifyAuthenticodeCached`) for basename-matched executables so spoofed binaries cannot bypass `Strict` mode.
- **RFC 1929 Loopback Authentication:** Generates random per-install `SocksUser` / `SocksPass` credentials validated in constant time (`crypto/subtle.ConstantTimeCompare`) on both SOCKS5 and optional HTTP CONNECT listeners.
- **At-Rest Vault & Portable Export Cryptography:**
  - Server `PrivateKey`, `PresharedKey`, and `SocksPass` are encrypted at rest via Windows DPAPI (`windows.CryptProtectData` with application-scoped entropy `WireGuardPlus-Windows-DPAPI-v1` and `CRYPTPROTECT_UI_FORBIDDEN`).
  - Portable exports (`wgplus-backup-v1` `.wgplus` files) derive keys from user passphrases using **Argon2id** (`t=2, m=64 MiB, p=4`) and encrypt payloads with **AES-256-GCM**.
- **Portable Filesystem Boundary:** Placing `portable.flag` (or an existing `wgplus-data/` directory) next to `WireGuardPlus.exe` keeps `state.json` and the WebView2 runtime profile inside `./wgplus-data/`, leaving `%LOCALAPPDATA%` untouched.

---

## 4. Cryptographic Primitives & Android Storage Model

- **Tunnel Protocol:** Official `golang.zx2c4.com/wireguard` (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`), supporting Curve25519 key exchange, optional 256-bit `PresharedKey` post-quantum resistance, ChaCha20-Poly1305 authenticated encryption, and BLAKE2s hashing.
- **AmneziaWG 1.0 / 1.5 Obfuscation:** Derives the responder Curve25519 public key to recompute valid BLAKE2s-128 `MAC1` tags when remapping headers (`H1`-`H4`) or padding handshakes (`S1`/`S2`), while Cloudflare WARP 3-byte `Reserved` octets are stamped in `[1..3]` after standard WireGuard `MAC1`/`MAC2` calculation and stripped prior to inbound `MAC1` verification (`[1..3]` -> `0x00` bytes 1-3).
- **Android Credential Storage at Rest:** `PrivateKey`, `PresharedKey`, and the built-in Wireless ADB RSA-2048 private key (`BuiltinAdbKeyManager`) are encrypted prior to storage using a non-exportable 256-bit `AES/GCM/NoPadding` key (`enc:v1:`) inside `AndroidKeyStore` (`API 23+`), or a strict `0600` file-backed AES-256-GCM key (`enc:v2:`) inside `noBackupFilesDir` if Keystore is unavailable (plaintext fallback removed; throws `IllegalStateException` if encryption fails).
- **Android Loopback, IPC & Backup Isolation:** Loopback listeners bind strictly to `127.0.0.1`, enforce RFC 1929 local SOCKS5 authentication (`performSocks5ClientAuth`), drop non-loopback UDP frames, extract `libgojni.so` with `0500` permissions on Android 14+, verify SHA-256 caller signing certificates in `KeepaliveStatusProvider`, omit private/preshared keys from `MODE_WORLD_READABLE` sync mirrors (`publishWorldReadableSyncBundle`), encrypt exported multi-profile backups (`exportEncryptedBackupV1`) with `IS_SENSITIVE` clipboard flagging on Android 13+, enforce port `9` fail-closed Kill Switch fallback, and authenticate daemon commands with a 256-bit token (`MessageDigest.isEqual`).
- **Zero-Capture Boot Guard (Android):** `KeepaliveBridgeListenerService` is configured with empty `default_filter_types` and `disabled_filter_types="ongoing|conversations|alerting|silent"` plus no-op callbacks so zero notification content or metadata is ever read, stored, or transmitted.
