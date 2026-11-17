# WireGuard Plus vs Proxies & System VPNs

If Telegram is blocked, throttled, or inspected by your ISP (common in **Iran, Iraq, Jordan**, and other networks using Deep Packet Inspection), there are several ways to restore access. Each approach has real trade-offs.

This page explains honestly how **WireGuard Plus** compares to regular **Telegram MTProto/SOCKS5 proxies** and **system-wide VPN apps**, and when you should pick each one.

---

## Side-by-Side Comparison

| Capability | WireGuard Plus | System WireGuard / VPN App | Telegram MTProto / SOCKS5 Proxy | Modified Client Built-in Proxy |
|------------|----------------|----------------------------|--------------------------------|------------------------------|
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

## Why proxies and system VPNs fall short for blocked Telegram

### 1. Why Telegram MTProto / SOCKS5 proxies break under strict blocks
- **Voice & video calls often fail or leak your IP:** Standard MTProto proxies only handle Telegram MTProto traffic and do not carry full UDP `tgcalls` media reliably.
- **Public proxies get burned fast and inject ads:** Free proxies shared on channels are quickly blocked by ISPs, throttled, or force-subscribe users to promotional channels.
- **No modern WireGuard encryption or DPI evasion:** Plain SOCKS5/MTProto is trivial for modern ISP middleboxes to fingerprint and drop.

### 2. Why system-wide VPN apps create daily friction
- **Occupies Android's only VPN slot:** Running a system VPN disables AdGuard, Intra, RethinkDNS, or work VPNs.
- **Breaks local services:** Banking apps, local food delivery, university portals, and low-latency domestic sites either block foreign VPN IPs or slow down until you toggle the VPN off.
- **Battery & constant toggling:** Tunneling every background app drains battery and forces constant connect/disconnect cycles whenever you switch between Telegram and local apps.

### 3. How WireGuard Plus solves both
- Runs `wireguard-go` + `gVisor` netstack **strictly inside the Telegram process**, leaving the rest of your phone on your direct connection.
- Keeps Android's system VPN slot completely free.
- Hooks Telegram's call stack (`tgcalls`) so voice and video calls stay encrypted inside the tunnel without leaking your ISP IP over peer-to-peer UDP.
- Adds **AmneziaWG DPI obfuscation** (decoy junk bursts, padding, and custom headers) plus **DoH** endpoint resolution to survive networks that block standard WireGuard handshakes.

---

## When to choose something else (Honest Trade-Offs)

WireGuard Plus is **not** the right tool for every scenario. Pick another tool if:

- **You need to unblock your browser, YouTube, Instagram, or the whole phone:** WireGuard Plus intentionally tunnels **only Telegram**. Use a system-wide WireGuard or AmneziaWG client if you need device-wide tunneling.
- **You cannot install a patched Telegram APK (LSPatch) and do not have Root (LSPosed):** Because WireGuard Plus operates inside the Telegram process without Android's `VpnService`, it requires either LSPatch (rootless) or LSPosed (root).
- **You only want a zero-setup 1-tap public proxy and never make Telegram calls:** A trusted MTProto proxy link requires no patching if you only text and do not mind proxy limitations.

---

## Related Documentation

- [Main Overview & Quickstart](../README.md)
- [End-User Installation & Troubleshooting Guide](USER_GUIDE.md)
- [Architecture & Traffic Flow](ARCHITECTURE.md)
- [Security & Privacy Model](SECURITY.md)
