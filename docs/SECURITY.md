# Security & Privacy Model

This document states the exact cryptographic, network-isolation, and storage boundaries of **WireGuard Plus** (`v1.3.0`) based on verifiable implementation behavior.

---

## 1. Traffic Routing Boundaries (What Enters the Tunnel vs. What Does Not)

| Traffic Category | Routed Through WireGuard Tunnel? | Mechanism |
|------------------|----------------------------------|-----------|
| **Telegram Messages, Chats, Channels, Uploads & Downloads** | **Yes** | `ConnectionsManager.setProxySettings` + `native_setProxySettings` across accounts `0..3` -> `127.0.0.1:<port>` (`SOCKS5 CONNECT 0x01`) -> `gVisor netstack` -> `wireguard-go`. |
| **Telegram Voice & Video Calls (`1-on-1` & Group Calls)** | **Yes** (when *Route voice and video calls* is ON, default) | `"mainconfig"` `proxy_enabled_calls = true` + `Instance.makeNativeInstance` hook (`Instance$Proxy`) -> `127.0.0.1:<port>` (`SOCKS5 UDP ASSOCIATE 0x03` & `CONNECT 0x01`) -> `gVisor netstack` -> `wireguard-go`. Direct P2P UDP is suppressed. |
| **In-App DNS Resolution for Proxied Connections** | **Yes** | Domain targets sent over SOCKS5 (`ATYP = 0x03`) resolve inside `gVisor netstack` using your configured tunnel DNS server over the encrypted WireGuard link. |
| **Initial WireGuard Endpoint Hostname Lookup** | **Host Network** | Resolving the VPN server's own hostname (e.g., `ge-tbs.prod.surfshark.com`) must occur prior to establishing the WireGuard handshake. Use a direct IPv4:port endpoint if you wish to avoid initial DNS resolution on the local network. |
| **External Browser / Chrome Custom Tabs** | **No** | Opening an external `https://` web link launches Android's browser app in a separate OS process outside Telegram. Use a system-wide VPN when browsing external websites. |

---

## 2. Cryptographic Primitives

- **Tunnel Protocol**: Official `golang.zx2c4.com/wireguard` (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`), supporting Curve25519 key exchange, optional 256-bit `PresharedKey` post-quantum resistance, ChaCha20-Poly1305 authenticated encryption, and BLAKE2s hashing.
- **Credential Storage at Rest**: `PrivateKey` and `PresharedKey` strings are encrypted prior to storage in `wg_plus_isolated_prefs` using a hardware-backed 256-bit `AES/GCM/NoPadding` key (`wg_plus_aes_gcm_v1`) held inside Android's `AndroidKeyStore` (`API 23+`), with a fresh random 96-bit IV per encryption operation and a 128-bit authentication tag.
- **Visual Shoulder-Surfing Protection**: Private and preshared key fields are masked by default in the configuration UI.

---

## 3. Loopback & Process Isolation

- **Loopback-Only Binding**: Both the SOCKS5 TCP listener and per-call `UDP ASSOCIATE` sockets bind strictly to `127.0.0.1` (`IPv4 loopback`). Packet handlers explicitly drop any UDP packet whose source IP is not loopback (`!srcAddr.IP.IsLoopback()`), preventing LAN peers on shared Wi-Fi networks from reaching the local proxy.
- **Android 14+ Read-Only Native Binary**: `libgojni.so` is extracted atomically into Telegram's private internal `files/wg_native/` directory with `0500` (`r-x------`) permissions owned solely by the host app UID.
- **Minimal OS Permissions**: The module declares only `android.permission.INTERNET` (for standalone self-testing in `ModuleLauncherActivity`) and `android.permission.ACCESS_NETWORK_STATE` (for roaming detection). `android:allowBackup="false"` is enforced in `AndroidManifest.xml`.
