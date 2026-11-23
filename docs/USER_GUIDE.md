# End-User Installation & Troubleshooting Guide

**WireGuard Plus** (`v1.9.0`) runs natively on **Windows 10/11 (x64)** (userspace proxy for Telegram chats/media plus an isolated `WireGuardPlusCalls` Wintun adapter scoped strictly to Telegram VoIP CIDRs) and on **Android 5.0+** (rootless via **LSPatch** or rooted via **LSPosed** / **Vector**).

---

## Part 1: Windows Desktop & Portable (`v1.9.0`)

### 1. Choosing Standard `.exe` vs Portable `.zip`

- **Single Executable (`WireGuardPlus-Windows-x64.exe`):** Stores your DPAPI-encrypted config vault and WebView2 state in `%LOCALAPPDATA%\WireGuardPlus\`.
- **Portable Edition (`WireGuardPlus-Windows-x64-Portable.zip`):** Contains `WireGuardPlus.exe` and an empty `portable.flag` file side by side. As long as `portable.flag` stays next to `WireGuardPlus.exe`, all settings, vault data, and WebView2 state remain strictly inside `./wgplus-data/` with zero `%LOCALAPPDATA%` writes.

> **Important when moving a Portable folder to a different PC:** Windows DPAPI keys are cryptographically bound to your current Windows user account. Before copying your portable folder to another computer, click **Export** -> **Encrypted Backup (`.wgplus`)** inside WireGuard Plus and set a passphrase, then import that `.wgplus` file on the new PC.

### 2. Adding Servers & Generating Free WARP (AWG 1.5)

1. Launch `WireGuardPlus.exe` (single executable; extracts embedded `wintun.dll` automatically when enabling `WireGuardPlusCalls` for Telegram voice/video calls).
2. Add a WireGuard or AmneziaWG server using any method:
   - **Import `.conf`** (or drag-and-drop a `.conf` / QR image anywhere onto the window).
   - **Import QR** from an image file or **Paste (`Ctrl+V`)** raw `.conf` text or a copied QR screenshot straight from your clipboard.
   - **+ Free WARP (AWG 1.5):** Registers a fresh anonymous Cloudflare WARP keypair with preconfigured AmneziaWG 1.5 QUIC mimicry (`I1`, `Jc`, `Jmin`, `Jmax`) and 3-byte `Reserved` header stamping in one click.
3. Click **Connect** (or double-click any saved server row, or use **Ping All** to measure handshake latency across all profiles first).

### 3. Connecting Telegram Desktop, Portable Editions & Third-Party Forks

WireGuard Plus automatically scans installed and running Telegram desktop clients, including:
- **Telegram Desktop** (installed or **Portable** with `tdata/`)
- **AyuGramDesktop** & **AyuGramDesktop Portable**
- **64Gram Desktop** & **64Gram Portable**
- **Forkgram**
- **Unigram** (Microsoft Store / MSIX)

To bind a client to your encrypted local SOCKS5 listener (`127.0.0.1:48729` with RFC 1929 authentication):
1. Check **Allow** next to your client under **Windows Telegram Clients** (controls which executables pass the `iphlpapi` Loopback Process Firewall).
2. Click **Apply Proxy**: WireGuard Plus automatically copies the authenticated `tg://socks?...` link and dispatches it via the client's CLI/protocol handler. Click **Enable** inside the Telegram confirmation popup that appears.
3. For USB/custom-folder portable clients that are currently closed, click **+ Add Portable `.exe`** once to browse to `Telegram.exe` or `AyuGram.exe`.

> **Call Privacy Checklist (Required once on Windows Desktop):** Inside your Telegram desktop client, open **Settings -> Privacy and Security -> Calls -> Peer-to-Peer** and set it to **Nobody**. WireGuard Plus automatically starts the isolated `WireGuardPlusCalls` L3 adapter (`10.254.254.2/30`) scoped strictly to Telegram's 9 official VoIP IPv4 CIDRs so `tgcalls` voice/video media passes cleanly through your tunnel while keeping browsers, games, and Tailscale on your normal gateway. Setting **Peer-to-Peer: Nobody** prevents direct P2P IP exposure.

### 4. Loopback Armor, System Tray & Autostart

- **Strict Loopback Kill Switch (ON by default):** Keeps `127.0.0.1:48729` bound and fails closed when disconnected so Telegram cannot fall back to direct connections.
- **Loopback Process Firewall (`iphlpapi` + Authenticode):** Inspects the owning PID and executable path of every incoming loopback socket and verifies Windows Authenticode signatures (`WinVerifyTrust`) for basename-matched executables, blocking unauthorized or spoofed processes in `Strict (Telegram Clients Only)` mode.
- **Sleep/Wake & Network Recovery:** Automatically listens for Windows `WM_POWERBROADCAST` resume events and `NotifyIpInterfaceChange` IP transitions to re-resolve endpoints and restore stale handshakes without tearing down healthy sessions.
- **Hide to Tray / Start with Windows:** Uses an optional pure-Go `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key (`--minimized`) that needs no Admin elevation.
- **Copy Diagnostics & GitHub Issues:** Click **Copy Diagnostics** in the app (on Windows or Android) to generate a sanitized diagnostic report ready to paste into the structured [GitHub Bug Report form](../.github/ISSUE_TEMPLATE/bug_report.yml).

### 5. Windows Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| **"Windows protected your PC" (SmartScreen)** | Unsigned independent open-source binary | Verify the file hash with `Get-FileHash .\WireGuardPlus-Windows-x64.exe -Algorithm SHA256` against [`SHA256SUMS.txt`](https://github.com/AliHaider704/wgplus/releases/latest/download/SHA256SUMS.txt), then click **More info -> Run anyway**, or build cleanly from source with `scripts/build-windows.ps1`. |
| **Portable Telegram / AyuGram not listed while closed** | Arbitrary folder outside `%APPDATA%` / Desktop / Downloads | Launch the portable `.exe` once while WireGuard Plus is open, or click **+ Add Portable `.exe`** to register its exact path permanently. |
| **Telegram rejects loopback connection in Strict mode** | An unrecognized fork name or unchecked client row | Ensure the client row has **Allow** checked under **Windows Telegram Clients**, or inspect blocked events under the **Loopback Firewall** log dropdown. |
| **Handshake hangs on restricted ISP** | ISP filtering standard WireGuard headers or DNS poisoning endpoint domain | Keep **Resolve Endpoint via Encrypted DoH** enabled, edit the profile -> **AmneziaWG DPI Stealth**, and select **AWG 1.5 QUIC Mimicry** or **Auto-Detect MTU**. |
| **Portable settings missing on a second PC** | DPAPI secrets are bound to the original Windows user account | Use **Export `.wgplus` Backup** with a passphrase on the original PC and import it on the second PC. |

---

## Part 2: Android (`LSPatch` / `LSPosed`)

**WireGuard Plus** (`نفق وايرجارد بلس`) works on both **non-rooted** Android phones (via **LSPatch**) and **rooted** Android phones (via **LSPosed**), with **no external helper apps required**.

### 1. Installation Methods

#### Option A: Rootless Setup via LSPatch + One-Time Silent Continuity (Recommended)
1. Install `WireGuardPlus-1.9.0-arm64-v8a.apk` (recommended for modern 64-bit phones), `WireGuardPlus-1.9.0-armeabi-v7a.apk`, or `WireGuardPlus-1.9.0.apk` directly on your phone.
2. Install **LSPatch** ([JingMatrix fork](https://github.com/JingMatrix/LSPatch)), tap **Manage -> +**, and select your **Telegram Plus** (`org.telegram.plus`) or **Telegram** (`org.telegram.messenger`) APK (back up secret chats first if replacing an existing install with a different signature).
3. Choose **Portable** (tick **Embed modules -> WireGuard Plus**, plus any other modules you use such as **TeleVip**) **or Local** mode (enable **WireGuard Plus** in **LSPatch -> Modules** and select Telegram in its scope).
4. Tap **Start Patch** and install the patched Telegram APK.
5. Open **WireGuard Plus** (`نفق وايرجارد بلس`), tap **Activate protection & battery exemptions now**, and allow notifications when prompted. Developer Options -> **Wireless debugging** will open automatically (Android 11+).
6. Enable **Wireless debugging** (choose *Always allow on this network* if prompted), tap **Pair device with pairing code**, pull down the notification shade, enter the **6-digit code** into the WireGuard Plus notification reply field, and tap Send.
7. Done once: silent background protection stays active across **Wi-Fi**, **Mobile Data**, and **reboots** with zero ongoing notifications.

#### Option B: Rooted Installation via LSPosed / Vector
1. Install `WireGuardPlus-1.9.0-arm64-v8a.apk` or `WireGuardPlus-1.9.0.apk`.
2. Open **LSPosed Manager** -> **Modules** -> **WireGuard Plus**.
3. Enable the module and check **Telegram Plus** (`org.telegram.plus`) and/or **Telegram** (`org.telegram.messenger`).
4. Force-stop and reopen Telegram.
5. Open **WireGuard Plus** and grant Root if prompted to activate maximum OS and kernel exemptions silently without notifications.

### 2. Importing a WireGuard Configuration (`.conf`) on Android

1. Open Telegram and go to **Settings -> Data and Storage -> Proxy Settings**.
2. Tap the **WireGuard** (`نفق وايرجارد`) button at the bottom corner (or long-press the top title bar of the Proxy screen).
3. In the **Saved profiles** (`الخوادم المحفوظة`) card:
   - Tap **File** (`ملف`) to choose a `.conf` file directly from your device downloads, **or**
   - Tap **QR image** (`صورة QR`) to scan a QR code from your gallery without granting Camera permission, **or**
   - Copy the contents of any WireGuard `.conf` file and tap **Paste** (`لصق`).
4. Tap **Connect** (`اتصال`).

### 3. Voice & Video Calls over WireGuard on Android

- **Route voice and video calls through tunnel** (`تمرير المكالمات الصوتية والمرئية عبر النفق`) is enabled by default.
- While enabled and connected:
  - Both call signaling (`MTProto`) and real-time voice/video media (`tgcalls` UDP/TCP) pass through your encrypted WireGuard server via dedicated local `127.0.0.1` per-endpoint relays (`voip_relay.go`).
  - Direct peer-to-peer (`P2P`) UDP exposure is automatically disabled while the tunnel is active so your real ISP IP address is never revealed to the other party.
- When you tap **Disconnect**, WireGuard Plus cleanly restores your previous Telegram proxy state.

### 4. Verifying Your Tunnel Route

Tap **Verify route & calls** (`فحص المسار والمكالمات`) at any time while connected (on Windows or Android) to run live end-to-end checks through the WireGuard tunnel:
1. **Exit IP & Location**: Performs a real TLS handshake to `one.one.one.one` inside the tunnel and displays the exact public IP and country seen by external servers.
2. **Telegram Datacenters**: Measures direct TCP reachability and latency to Telegram datacenters through the tunnel.
3. **Voice & video calls**: Opens a live SOCKS5 `UDP ASSOCIATE` session and sends an encrypted UDP query through the WireGuard peer to confirm UDP media readiness.

### 5. Android Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| **Handshake timed out / Route check failed** | Expired VPN peer keys, or ISP blocking UDP port `51820` | Generate fresh WireGuard credentials, enable the **Client junk preset** under DPI Obfuscation, or choose a peer endpoint on an alternative UDP port (such as `443` or `53`). |
| **Voice & video calls shows "TCP fallback only"** | Your VPN provider blocks outbound UDP port `53` inside the tunnel or restricts UDP forwarding | Calls still connect over Telegram's TCP reflector fallback through the tunnel; switching to a full-UDP WireGuard peer enables low-latency UDP media. |
| **WireGuard button does not appear in Proxy Settings** | Module was not embedded or scoped in LSPatch/LSPosed | Re-patch Telegram in LSPatch Portable mode with `WireGuardPlus-1.9.0.apk` (or `-arm64-v8a.apk`) checked under **Embed modules** (or enable Telegram in **Modules** scope). |
| **Persistent "Continuity Guard Active" notification still appears** | One-time silent continuity is not yet paired/activated, so safe foreground fallback is active | Open **WireGuard Plus**, ensure **Work silently in background without notification** is ON, tap **Activate protection & battery exemptions now**, and complete the one-time 6-digit Wireless Debugging pairing (or grant Root). |
| **Wireless Debugging option missing** | Developer Options are hidden | Open Android **Settings -> About phone -> Software information**, tap **Build number** 7 times, then tap **Activate protection & battery exemptions now** inside WireGuard Plus again. |
