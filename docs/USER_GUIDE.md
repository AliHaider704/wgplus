# End-User Installation & Troubleshooting Guide

**WireGuard Plus** (`نفق وايرجارد بلس`) works on both **non-rooted** Android phones (via **LSPatch**) and **rooted** Android phones (via **LSPosed**).

---

## 1. Installation Methods

### Option A: Rootless Installation via LSPatch (Portable Mode - Recommended)
1. Install `WireGuardPlus-<version>.apk` on your phone (optional in Portable mode, required in Local mode; installing it also gives you access to the standalone test screen).
2. Open **LSPatch** -> **Manage** -> tap **+** -> select your **Telegram Plus** (`org.telegram.plus`) or **Telegram** (`org.telegram.messenger`) APK.
3. Select **Portable** patch mode.
4. Tap **Embed modules** and check **WireGuard Plus** (`نفق وايرجارد بلس`) alongside any other modules you use (such as **TeleVip**).
5. Tap **Start Patch**, then install the patched Telegram APK.

### Option B: Rooted Installation via LSPosed
1. Install `WireGuardPlus-<version>.apk`.
2. Open **LSPosed Manager** -> **Modules** -> **WireGuard Plus**.
3. Enable the module and check **Telegram Plus** (`org.telegram.plus`) and/or **Telegram** (`org.telegram.messenger`).
4. Force-stop and reopen Telegram.

---

## 2. Importing a WireGuard Configuration (`.conf`)

1. Open Telegram and go to **Settings -> Data and Storage -> Proxy Settings**.
2. Tap the **WireGuard** (`نفق وايرجارد`) button at the bottom corner (or long-press the top title bar of the Proxy screen).
3. In the **Saved profiles** (`الخوادم المحفوظة`) card:
   - Tap **File** (`ملف`) to choose a `.conf` file directly from your device downloads, **or**
   - Copy the contents of any WireGuard `.conf` file (e.g., Surfshark, Mullvad, ProtonVPN, Cloudflare WARP, or your own WireGuard VPS) and tap **Paste** (`لصق`).
4. Tap **Connect** (`اتصال`).

---

## 3. Voice & Video Calls over WireGuard

- **Route voice and video calls through tunnel** (`تمرير المكالمات الصوتية والمرئية عبر النفق`) is enabled by default.
- While enabled and connected:
  - Both call signaling (`MTProto`) and real-time voice/video media (`tgcalls` UDP/TCP) pass through your encrypted WireGuard server.
  - Direct peer-to-peer (`P2P`) UDP exposure is automatically disabled while the tunnel is active so your real ISP IP address is never revealed to the other party.
- When you tap **Disconnect**, WireGuard Plus cleanly restores your previous Telegram proxy state.

---

## 4. Verifying Your Tunnel Route

Tap **Verify route & calls** (`فحص المسار والمكالمات`) at any time while connected to run three live end-to-end checks through the WireGuard tunnel:
1. **Exit IP & Location**: Performs a real TLS handshake to `one.one.one.one` inside the tunnel and displays the exact public IP and country seen by external servers.
2. **Telegram DC**: Measures direct TCP reachability and latency to Telegram Datacenter 2 (`149.154.167.50:443`) through the tunnel.
3. **Voice & video calls**: Opens a live SOCKS5 `UDP ASSOCIATE` session and sends an encrypted UDP query through the WireGuard peer to confirm UDP media readiness.

---

## 5. Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| **Handshake timed out / Route check failed** | Expired VPN peer keys, or ISP blocking UDP port `51820` | Generate fresh WireGuard credentials or choose a peer endpoint running on an alternative UDP port (such as `443`, `53`, or `51820` on another region). |
| **Voice & video calls shows "TCP fallback only"** | Your VPN provider blocks outbound UDP port `53` inside the tunnel or restricts UDP forwarding | Calls will still connect over Telegram's TCP reflector fallback through the tunnel; switching to a standard full-UDP WireGuard peer enables low-latency UDP media. |
| **WireGuard button does not appear in Proxy Settings** | Module was not embedded during LSPatch patching | Re-patch Telegram in LSPatch Portable mode with `WireGuardPlus-<version>.apk` checked under **Embed modules**. |
