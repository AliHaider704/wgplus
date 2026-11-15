# WireGuard Plus

[العربية](README.ar.md)

WireGuard Plus is an Android module that puts a WireGuard tunnel inside Telegram. Only Telegram's traffic goes through it, including voice and video calls. It does not use Android's VPN slot and does not require root, so you can keep another VPN or an ad blocker running at the same time.

It works with **Telegram Plus** (`org.telegram.plus`) and the official **Telegram** (`org.telegram.messenger`), and it is built to live next to other modules such as TeleVip without clashing with them.

> This is an unofficial community project. It is not affiliated with Telegram, WireGuard or Amnezia.

## What it does

- **Tunnel inside Telegram only.** WireGuard runs in userspace inside the Telegram process (wireguard-go and gVisor netstack). Chats, media and calls are routed through a local SOCKS5 proxy.
- **Voice and video calls.** The proxy supports UDP, and the module hooks Telegram's call code so media does not fall back to a direct connection.
- **AmneziaWG obfuscation.** Junk packets, packet padding and custom headers help against networks that block plain WireGuard. There is also a one tap client preset that works with ordinary WireGuard servers.
- **Kill switch.** While enabled, Telegram has nowhere to connect except the tunnel. If the tunnel drops, nothing leaks over your normal connection.
- **Encrypted DNS for the server name.** The endpoint hostname is looked up over DNS-over-HTTPS, so your ISP does not see or poison the lookup.
- **Ping and auto-failover.** Test all your servers at once, jump to the fastest, and optionally switch to a backup if the current one stops responding.
- **Auto MTU.** Finds a packet size that works on your mobile network.
- **24/7 Silent Sovereign Continuity (v1.5.0, Zero Helper Apps).** Built-in self-contained Wireless Debugging pairing (one-time 6-digit notification code on Android 11+, no third-party helper apps), detached background helper process, automatic Doze/Data-Saver/Samsung MARs exemptions, dynamic loopback TCP continuity on Mobile Data, automatic `uid=0` kernel boost on rooted phones, and a zero-capture Boot Guard (`KeepaliveBridgeListenerService`). Telegram stays alive across Wi-Fi, Mobile Data, Deep Doze, and device reboots with **zero persistent notification** and **zero Samsung "1 active app" banner**, falling back cleanly to standard foreground service protection if not configured.
- **Battery saver.** Pauses keepalives when Telegram has been in the background for a while.
- **Many profiles.** Import `.conf` files, paste from the clipboard, read a QR code from a screenshot in your gallery (no camera permission), show a QR code for sharing, and back up or restore everything as JSON.
- **Arabic and English**, right to left and left to right, dark and light themes.
- **Private keys and pairing credentials are encrypted** with the Android Keystore (`AES-256-GCM`). The core tunnel uses only `INTERNET` and `ACCESS_NETWORK_STATE`; optional silent background continuity uses one-time Wireless Debugging pairing, `SET_PROCESS_LIMIT`, `WRITE_SECURE_SETTINGS`, and zero-capture `BIND_NOTIFICATION_LISTENER_SERVICE`.

## What it does not do

- It does not tunnel other apps. Links opened in your browser are outside Telegram and are not protected.
- It is not a system VPN.

## Install from zero

You need an Android phone (Android 5.0 or newer; one-time silent Wireless Debugging activation requires Android 11 or newer) and a WireGuard config file (`.conf`) from a provider or your own server.

### A. Rootless setup via LSPatch + Silent Sovereign Continuity (Recommended)

No third-party privilege manager app is needed. Pick **Portable** mode (simplest, self-contained Telegram APK) or **Local** mode (easy future `WireGuardPlus` upgrades without re-patching Telegram):

1. Download and install the latest `WireGuardPlus-<version>.apk` from [Releases](https://github.com/AliHaider704/wgplus/releases). Allow installs from your browser or file manager if Android asks.
2. Install [JingMatrix LSPatch](https://github.com/JingMatrix/LSPatch) and open **Manage -> +**, then choose your **Telegram Plus** or **Telegram** APK (uninstall the original Telegram first if its signature differs; back up secret chats first, as cloud chats return on login).
3. Choose **Portable** mode (tick **Embed modules -> WireGuard Plus**, plus any other module such as **TeleVip**) **or Local** mode (then enable **WireGuard Plus** in **LSPatch -> Modules** and tick Telegram Plus / Telegram in its scope).
4. Tap **Start Patch** and install the patched Telegram APK, then log in to Telegram.
5. Open **WireGuard Plus** (`نفق وايرجارد بلس`), tap **Activate protection & battery exemptions now**, and allow the notification permission when prompted. Android **Developer Options -> Wireless Debugging** opens automatically.
6. In **Wireless Debugging**, enable the toggle (select *Always allow on this network* if shown), tap **Pair device with pairing code**, pull down the notification shade, type the **6-digit code** into the WireGuard Plus notification reply box, and send.
7. Done once: background continuity stays active across **Wi-Fi**, **Mobile Data**, and **reboots** with zero persistent notifications and zero external helper apps.

### B. Rooted phone, with LSPosed

1. Install `WireGuardPlus-<version>.apk` from [Releases](https://github.com/AliHaider704/wgplus/releases).
2. Open **LSPosed**, go to **Modules**, open **WireGuard Plus** and enable it.
3. Tick Telegram Plus and/or Telegram in its scope.
4. Force stop Telegram and open it again.
5. Open **WireGuard Plus** and grant root if prompted; maximum background priority (`oom_score_adj`, cgroup boost, Doze/background exemptions, and silent Boot Guard) activates automatically with zero notifications.

## First connection

1. In Telegram go to **Settings, Data and Storage, Proxy Settings**.
2. Tap the **WireGuard** button at the bottom corner. If you do not see it, long press the title bar of that screen.
3. Add a server in whichever way is easiest:
   - **Import .conf** to pick the file,
   - **QR image** to read a QR code from a screenshot,
   - **Paste** if you copied the config text.
4. Leave **Route voice and video calls through tunnel** on if you want calls protected.
5. Tap **Connect**. The module then runs a check and shows your exit IP and country, whether Telegram's servers are reachable, and whether UDP for calls works.

You can also open the WireGuard Plus app from your launcher. It shows the same information and is handy for testing a config before patching Telegram.

If something goes wrong, see the [user guide](docs/USER_GUIDE.md) for troubleshooting.

## Building from source

Short version, on Windows:

```powershell
# 1. Build the Go engine and run its tests (needs Go, Android NDK, gomobile)
powershell -ExecutionPolicy Bypass -File .\scripts\build-wgbridge.ps1

# 2. Build the APK and run unit tests (needs JDK 21 and the Android SDK)
.\gradlew.bat testReleaseUnitTest assembleRelease
```

The APK lands in `dist/`. Full prerequisites and details are in the [build guide](docs/BUILD_GUIDE.md).

Without a `keystore.properties` file the APK is signed with the Android debug key. To sign releases with your own key, copy `keystore.properties.example` and fill it in. Use the same key for every release, otherwise Android will refuse to update over the old install.

## Project layout

```
app/            Android module (Java): hooks, UI, profile storage, QR codec, built-in continuity
wgbridge-go/    Go engine: WireGuard, AmneziaWG, SOCKS5, DoH, kill switch
scripts/        Reproducible build of the native bridge
docs/           Architecture, build, user and security notes
```

## Documentation

- [User guide](docs/USER_GUIDE.md)
- [Build guide](docs/BUILD_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security and privacy model](docs/SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Reporting vulnerabilities](SECURITY.md)

## Credits

Built on [wireguard-go](https://git.zx2c4.com/wireguard-go), [gVisor](https://gvisor.dev), [gomobile](https://pkg.go.dev/golang.org/x/mobile), [ZXing](https://github.com/zxing/zxing), [libadb-android](https://github.com/MuntashirAkon/libadb-android), [Conscrypt](https://conscrypt.org/), and the packet obfuscation ideas from [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go). Each keeps its own license.

## License

[MIT](LICENSE)
