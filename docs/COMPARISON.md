# WireGuard Plus vs Proxies & System VPNs

If Telegram is blocked, throttled, or inspected by your ISP (common in **Iran, Iraq, Jordan**, and other networks using Deep Packet Inspection), there are several ways to restore access on both Windows PCs and Android phones. Each approach has real trade-offs.

This page explains honestly how **WireGuard Plus** compares to regular **Telegram MTProto/SOCKS5 proxies** and **system-wide or driver-based VPN apps** on both platforms, and when you should pick each one.

---

## Windows Desktop Comparison

| Capability | WireGuard Plus (Windows) | Official WireGuard Windows | WireSock / TunnlTo | AmneziaVPN Desktop | Telegram MTProto / SOCKS5 Proxy |
|------------|--------------------------|----------------------------|--------------------|--------------------|---------------------------------|
| **Requires Admin / UAC elevation** | **Optional** (`asInvoker` for chats/media; scoped `WireGuardPlusCalls` adapter for calls) | Yes (service + Wintun) | Yes (driver / service) | Yes (driver / service) | No |
| **Routes all system traffic via Wintun** | **No** (chats via SOCKS5; `WireGuardPlusCalls` scoped strictly to Telegram's 9 call CIDRs) | Yes (full/broad routes) | Yes (driver) | Yes (driver) | No |
| **Conflict with Tailscale, AdGuard, or work VPNs** | **Zero** (leaves non-Telegram routes untouched) | High (hijacks routes) | Moderate | High | Zero |
| **Portable USB / folder mode (zero AppData writes)** | **Yes** (`portable.flag` -> `./wgplus-data/`) | No | Limited | No | Inside client only |
| **Portable Telegram, AyuGram, 64Gram, Unigram** | **Yes** (auto-detect + `+ Add Portable .exe` + `Apply Proxy`) | System-wide only | App path rules | App split-tunnel | Manual per client |
| **AmneziaWG 1.5 (`I1`-`I5` QUIC mimicry) + Free WARP** | **Yes** (1-click generator + AWG 1.5) | No (standard WG only) | Limited | Yes | No |
| **`iphlpapi` + Authenticode Loopback Process Firewall** | **Yes** (blocks unauthorized/spoofed local probes) | N/A | N/A | N/A | None |
| **Voice & video calls inside tunnel** | **Yes** (isolated `WireGuardPlusCalls` Wintun L3 + SOCKS5 UDP; set P2P: Nobody in Telegram) | Yes | Yes | Yes | Breaks / IP leak |
| **Bilingual Dark & Light UI** | **Yes** (English LTR + Arabic RTL) | Light system look | Dark/Basic | Complex setup UI | Built into Telegram |

---

## Android Side-by-Side Comparison

| Capability | WireGuard Plus (Android) | System WireGuard / VPN App | Telegram MTProto / SOCKS5 Proxy | Modified Client Built-in Proxy |
|------------|--------------------------|----------------------------|--------------------------------|------------------------------|
| **Tunnels Telegram only (split by process)** | Yes | Only if app-exclusion works reliably | Yes (chats only) | Yes (chats only) |
| **Keeps Android VPN slot free (AdGuard / 2nd VPN)** | **Yes** | No (takes the single VPN slot) | Yes | Yes |
| **Requires Root** | **No** (works via LSPatch) | No | No | No |
| **Voice & video calls over encrypted tunnel** | **Yes** (UDP + TCP fallback, no P2P IP leak) | Yes | Unreliable / often blocked or falls back to P2P | Unreliable for UDP calls |
| **DPI obfuscation (AmneziaWG junk & padding)** | **Yes** (works even with standard WG peers) | Only in AmneziaWG-specific VPN clients | No | No |
| **Strict kill switch (zero direct IP leak)** | **Yes** (inside Telegram process) | System-wide kill switch | No | No |
| **Encrypted DNS-over-HTTPS (DoH) for server name** | **Yes** | Depends on client | No | No |
| **Works with your own private WireGuard `.conf`** | **Yes** (unlimited profiles + auto-failover) | Yes | No (needs separate proxy server) | Limited |
| **Channel spam / sponsored proxy ads** | **Never** | Never | Common on free MTProto proxies | Depends on proxy |
| **Affects local banking / domestic websites** | **Never** (only Telegram uses it) | Often breaks or slows local apps unless split-tunneled | Never | Never |

---

## Why Proxies and System VPNs Fall Short for Blocked Telegram

### 1. Why Telegram MTProto / SOCKS5 Proxies Break Under Strict Blocks
- **Voice & video calls often fail or leak your IP:** Standard MTProto proxies only handle Telegram MTProto traffic and do not carry full UDP `tgcalls` media reliably.
- **Public proxies get burned fast and inject ads:** Free proxies shared on channels are quickly blocked by ISPs, throttled, or force-subscribe users to promotional channels.
- **No modern WireGuard encryption or DPI evasion:** Plain SOCKS5/MTProto is trivial for modern ISP middleboxes to fingerprint and drop.

### 2. Why System-Wide VPN Apps Create Daily Friction
- **Takes Windows driver stack / Android's single VPN slot:** On Android, running a system VPN disables AdGuard, Intra, RethinkDNS, or work VPNs. On Windows, Wintun-based clients frequently conflict with Tailscale, WireGuard for Work, or corporate split-tunnels and require Administrator UAC rights.
- **Breaks local services and games:** Banking apps, gaming low-latency routes, university portals, and local stores either block foreign VPN IPs or add latency unless excluded carefully.
- **Constant toggling:** Tunneling every background process wastes battery on mobile and breaks local workflows on PC whenever you switch between Telegram and everything else.

### 3. How WireGuard Plus Solves Both
- Runs `wireguard-go` + `gVisor` netstack **strictly for Telegram** (`wgbridge-go` + `desktop-win/` on Windows; in-process on Android), leaving browsers, games, banking apps, and Tailscale on their normal connection.
- Keeps Android's single `VpnService` slot completely free and routes Android VoIP via local `127.0.0.1` UDP/TCP endpoint relays; on Windows, supports portable USB mode (`portable.flag`) while isolating calls cleanly via the `WireGuardPlusCalls` Wintun L3 adapter scoped strictly to Telegram's 9 IPv4 call CIDRs.
- Armored on Windows by `iphlpapi` loopback filtering + `WinVerifyTrust` Authenticode checks + RFC 1929 authentication, and on Android by mandatory local SOCKS5 auth, caller signing-certificate validation, and fail-closed Keystore/Kill Switch protection.
- Adds **AmneziaWG 1.0 / 1.5 DPI obfuscation** (`I1`-`I5` QUIC mimicry, junk bursts, padding, WARP `Reserved`) plus **DoH** endpoint resolution to survive networks that block standard WireGuard handshakes.

---

## When to Choose Something Else (Honest Trade-Offs)

WireGuard Plus is **not** the right tool for every scenario. Pick another tool if:

- **You need to unblock your browser, YouTube, Instagram, or the entire device:** WireGuard Plus intentionally tunnels **only Telegram**. Use a system-wide WireGuard or AmneziaWG client if you need device-wide tunneling.
- **On Windows, you cannot allow any Telegram client proxy or isolated VoIP adapter:** WireGuard Plus connects desktop Telegram chats via an authenticated `127.0.0.1` SOCKS5 URI and routes Telegram's 9 call IPv4 CIDRs through `WireGuardPlusCalls` (without touching non-Telegram routes). Remember to set **Calls -> Peer-to-Peer: Nobody** inside desktop Telegram once so Telegram never exposes your real IP via direct P2P.
- **On Android, you cannot install a patched Telegram APK (LSPatch) and do not have Root (LSPosed):** Because Android's non-VpnService path operates inside the Telegram process, it requires LSPatch (rootless) or LSPosed (root).
- **You only want a zero-setup 1-tap public proxy and never make Telegram calls:** A trusted MTProto proxy link requires no separate app if you only text and accept proxy limitations.

---

## Related Documentation

- [Main Overview & Quickstart](../README.md)
- [End-User Installation & Troubleshooting Guide](USER_GUIDE.md)
- [Architecture & Traffic Flow](ARCHITECTURE.md)
- [Security & Privacy Model](SECURITY.md)
