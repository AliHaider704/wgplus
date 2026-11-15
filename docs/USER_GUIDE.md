# End-User Installation & Troubleshooting Guide

**WireGuard Plus** (`نفق وايرجارد بلس`) works on both **non-rooted** Android phones (via **LSPatch**) and **rooted** Android phones (via **LSPosed**), with **no external helper apps required**.

---

## 1. Installation Methods

### Option A: Rootless Setup via LSPatch + One-Time Silent Continuity (Recommended)
1. Install `WireGuardPlus-<version>.apk` directly on your phone.
2. Install **LSPatch** ([JingMatrix fork](https://github.com/JingMatrix/LSPatch)), tap **Manage -> +**, and select your **Telegram Plus** (`org.telegram.plus`) or **Telegram** (`org.telegram.messenger`) APK (back up secret chats first if uninstalling original Telegram).
3. Choose **Portable** (tick **Embed modules -> WireGuard Plus**, plus any other modules you use such as **TeleVip**) **or Local** mode (enable **WireGuard Plus** in **LSPatch -> Modules** and select Telegram in its scope).
4. Tap **Start Patch** and install the patched Telegram APK.
5. Open **WireGuard Plus** (`نفق وايرجارد بلس`), tap **Activate protection & battery exemptions now**, and allow notifications when prompted. Developer Options -> **Wireless debugging** will open automatically (Android 11+).
6. Enable **Wireless debugging** (choose *Always allow on this network* if prompted), tap **Pair device with pairing code**, pull down the notification shade, enter the **6-digit code** into the WireGuard Plus notification reply field, and tap Send.
7. Done once: silent background protection stays active across **Wi-Fi**, **Mobile Data**, and **reboots** with zero ongoing notifications.

### Option B: Rooted Installation via LSPosed
1. Install `WireGuardPlus-<version>.apk`.
2. Open **LSPosed Manager** -> **Modules** -> **WireGuard Plus**.
3. Enable the module and check **Telegram Plus** (`org.telegram.plus`) and/or **Telegram** (`org.telegram.messenger`).
4. Force-stop and reopen Telegram.
5. Open **WireGuard Plus** and grant Root if prompted to activate maximum OS and kernel exemptions silently without notifications.

---

## 2. Importing a WireGuard Configuration (`.conf`)

1. Open Telegram and go to **Settings -> Data and Storage -> Proxy Settings**.
2. Tap the **WireGuard** (`نفق وايرجارد`) button at the bottom corner (or long-press the top title bar of the Proxy screen).
3. In the **Saved profiles** (`الخوادم المحفوظة`) card:
   - Tap **File** (`ملف`) to choose a `.conf` file directly from your device downloads, **or**
   - Tap **QR image** (`صورة QR`) to scan a QR code from your gallery without granting Camera permission, **or**
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
| **Handshake timed out / Route check failed** | Expired VPN peer keys, or ISP blocking UDP port `51820` | Generate fresh WireGuard credentials, enable the **Client junk preset** under DPI Obfuscation, or choose a peer endpoint on an alternative UDP port (such as `443` or `53`). |
| **Voice & video calls shows "TCP fallback only"** | Your VPN provider blocks outbound UDP port `53` inside the tunnel or restricts UDP forwarding | Calls still connect over Telegram's TCP reflector fallback through the tunnel; switching to a full-UDP WireGuard peer enables low-latency UDP media. |
| **WireGuard button does not appear in Proxy Settings** | Module was not embedded or scoped in LSPatch/LSPosed | Re-patch Telegram in LSPatch Portable mode with `WireGuardPlus-<version>.apk` checked under **Embed modules** (or enable Telegram in **Modules** scope). |
| **Persistent "Continuity Guard Active" notification still appears** | One-time silent continuity is not yet paired/activated, so safe foreground fallback is active | Open **WireGuard Plus**, ensure **Work silently in background without notification** is ON, tap **Activate protection & battery exemptions now**, and complete the one-time 6-digit Wireless Debugging pairing (or grant Root). |
| **Wireless Debugging option missing** | Developer Options are hidden | Open Android **Settings -> About phone -> Software information**, tap **Build number** 7 times, then tap **Activate protection & battery exemptions now** inside WireGuard Plus again. |
