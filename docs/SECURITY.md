# Security & Privacy Model

This document states the exact cryptographic, network-isolation, and storage boundaries of **WireGuard Plus** (`v1.5.0`) based on verifiable implementation behavior.

---

## 1. Traffic Routing Boundaries (What Enters the Tunnel vs. What Does Not)

| Traffic Category | Routed Through WireGuard Tunnel? | Mechanism |
|------------------|----------------------------------|-----------|
| **Telegram Messages, Chats, Channels, Uploads & Downloads** | **Yes** | `ConnectionsManager.setProxySettings` + `native_setProxySettings` across accounts `0..3` -> `127.0.0.1:<port>` (`SOCKS5 CONNECT 0x01`) -> `gVisor netstack` -> `wireguard-go`. |
| **Telegram Voice & Video Calls (`1-on-1` & Group Calls)** | **Yes** (when *Route voice and video calls* is ON, default) | `"mainconfig"` `proxy_enabled_calls = true` + `Instance.makeNativeInstance` hook (`Instance$Proxy`) -> `127.0.0.1:<port>` (`SOCKS5 UDP ASSOCIATE 0x03` & `CONNECT 0x01`) -> `gVisor netstack` -> `wireguard-go`. Direct P2P UDP is suppressed. |
| **In-App DNS Resolution for Proxied Connections** | **Yes** | Domain targets sent over SOCKS5 (`ATYP = 0x03`) resolve inside `gVisor netstack` using your configured tunnel DNS server over the encrypted WireGuard link. |
| **Initial WireGuard Endpoint Hostname Lookup** | **Encrypted DoH** | `doh.go` resolves endpoint hostnames directly over HTTPS (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`) using RFC 8484 wireformat queries, rejecting sinkhole/bogon IPs (`0.0.0.0`, `127.0.0.0/8`) without plaintext port-53 ISP leakage. |
| **External Browser / Chrome Custom Tabs** | **No** | Opening an external `https://` web link launches Android's browser app in a separate OS process outside Telegram. Use a system-wide VPN when browsing external websites. |

---

## 2. Cryptographic Primitives

- **Tunnel Protocol**: Official `golang.zx2c4.com/wireguard` (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`), supporting Curve25519 key exchange, optional 256-bit `PresharedKey` post-quantum resistance, ChaCha20-Poly1305 authenticated encryption, and BLAKE2s hashing.
- **Credential Storage at Rest**: `PrivateKey`, `PresharedKey`, and the built-in Wireless ADB RSA-2048 private key (`BuiltinAdbKeyManager`) are encrypted prior to storage using a non-exportable 256-bit `AES/GCM/NoPadding` key (`wg_plus_aes_gcm_v1`) held inside Android's `AndroidKeyStore` (`API 23+`), with a fresh random 96-bit IV per encryption operation and a 128-bit authentication tag.
- **Visual Shoulder-Surfing Protection**: Private and preshared key fields are masked by default in the configuration UI.

---

## 3. Loopback & Process Isolation

- **Loopback-Only Binding**: The SOCKS5 TCP listener, per-call `UDP ASSOCIATE` sockets, and detached `wgplus_daemon` control socket all bind strictly to `127.0.0.1` (`IPv4 loopback`). Packet handlers explicitly drop any UDP packet whose source IP is not loopback (`!srcAddr.IP.IsLoopback()`), and `DaemonProcessHelper` authenticates every control command in constant time (`MessageDigest.isEqual`) against a 256-bit (`SecureRandom`) per-session hex token.
- **Android 14+ Read-Only Native Binary**: `libgojni.so` is extracted atomically into Telegram's private internal `files/wg_native/` directory with `0500` (`r-x------`) permissions owned solely by the host app UID.
- **Zero-Capture Boot Guard & Manifest Boundaries**: The core tunnel requires only `android.permission.INTERNET` and `android.permission.ACCESS_NETWORK_STATE`. Optional Sovereign Silent Continuity adds local Wireless Debugging pairing (`POST_NOTIFICATIONS` + `FOREGROUND_SERVICE_SPECIAL_USE`), `SET_PROCESS_LIMIT`, `WRITE_SECURE_SETTINGS`, `RECEIVE_BOOT_COMPLETED`, and `KeepaliveBridgeListenerService` (`BIND_NOTIFICATION_LISTENER_SERVICE`) configured with empty `android.service.notification.default_filter_types` and `disabled_filter_types="ongoing|conversations|alerting|silent"` plus no-op callbacks so zero notification content or metadata is ever read, stored, or transmitted. `android:allowBackup="false"` is enforced in `AndroidManifest.xml`.
