# WireGuard Plus

[العربية](README.ar.md)

WireGuard Plus is an Android module that puts a WireGuard tunnel inside Telegram. Only Telegram's traffic goes through it, including voice and video calls. It does not use Android's VPN slot and does not need root, so you can keep another VPN or an ad blocker running at the same time.

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
- **24/7 Silent Hybrid Continuity (v1.4.0).** Combines **Shizuku** (`uid=2000` process priority elevation + Doze/Data-Saver/OEM standby exemptions) with a zero-capture **Boot Guard** (`NotificationListenerService` with all notification categories filtered out) so Telegram stays alive in background and Deep Doze with **zero persistent notification** and **zero Samsung "1 active app" banner**. Falls back seamlessly to standard foreground service protection if Shizuku/Boot Guard are not set up.
- **Battery saver.** Pauses keepalives when Telegram has been in the background for a while.
- **Many profiles.** Import `.conf` files, paste from the clipboard, read a QR code from a screenshot in your gallery (no camera permission), show a QR code for sharing, and back up or restore everything as JSON.
- **Arabic and English**, right to left and left to right, dark and light themes.
- **Private keys are encrypted** with the Android Keystore. The core tunnel uses only `INTERNET` and `ACCESS_NETWORK_STATE`; optional Shizuku integration adds `moe.shizuku.manager.permission.API_V23` and zero-capture `BIND_NOTIFICATION_LISTENER_SERVICE`.

## What it does not do

- It does not tunnel other apps. Links opened in your browser are outside Telegram and are not protected.
- It is not a system VPN.

## Install from zero

You need an Android phone (Android 5.0 or newer) and a WireGuard config file (`.conf`) from a provider or your own server.

There are three setup options. Pick **A** (recommended modern setup) or **B** if your phone is not rooted.

### A. Modern No-Root Setup: LSPatch Local + Shizuku + Silent Hybrid (Recommended)

This mode makes future updates effortless (just install the new `WireGuardPlus` APK without re-patching Telegram) and eliminates the persistent keepalive notification and Samsung's `"1 active app"` panel entry.

1. Install **Shizuku** and start its service using Wireless Debugging (Android Settings -> Developer Options -> Wireless Debugging).
2. Download and install the latest `WireGuardPlus-<version>.apk` from [Releases](https://github.com/AliHaider704/wgplus/releases).
3. Install the [JingMatrix LSPatch](https://github.com/JingMatrix/LSPatch) manager and link it to Shizuku when prompted.
4. Patch your Telegram Plus / official Telegram APK in **Local** mode (uninstall original Telegram first if signature differs; back up secret chats).
5. Open **LSPatch -> Modules -> WireGuard Plus**, enable it, and check **Telegram Plus** and/or **Telegram** in its scope.
6. Open **WireGuard Plus** (`نفق وايرجارد بلس`), tap **Grant Shizuku & enable Hybrid**, and tap **Allow all the time**. This automatically applies OS Doze/OEM freezer/background-network exemptions and activates the silent **Boot Guard** (which even protects Telegram after a reboot before you re-start Shizuku).

### B. No Root without Shizuku: LSPatch Portable

LSPatch rebuilds the Telegram app with the module baked in. When Shizuku is absent, standard foreground service continuity protects your connection automatically.

1. Download the latest `WireGuardPlus-<version>.apk` from the [Releases](https://github.com/AliHaider704/wgplus/releases) page and install it. Allow installs from your browser or file manager if Android asks.
2. Get **LSPatch** (the manager app) from its GitHub releases and install it. The [JingMatrix fork](https://github.com/JingMatrix/LSPatch) is the one that is kept up to date.
3. Get the Telegram APK you want to patch: Telegram Plus or Telegram. If you already have it installed, you will need to uninstall it first, because the patched app has a different signature. Back up your chats first, cloud chats come back when you log in again but secret chats do not.
4. In LSPatch open **Manage**, tap **+**, and choose the Telegram APK.
5. Choose **Portable** mode.
6. Tap **Embed modules** and tick **WireGuard Plus**. Tick your other modules too (TeleVip for example).
7. Tap **Start Patch**, then install the patched APK it produces.
8. Open the patched Telegram and log in.

### C. Rooted phone, with LSPosed

1. Install `WireGuardPlus-<version>.apk`.
2. Open **LSPosed**, go to **Modules**, open **WireGuard Plus** and enable it.
3. Tick Telegram Plus and/or Telegram in its scope.
4. Force stop Telegram and open it again.

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

# 2. Build the APK (needs JDK 21 and the Android SDK)
.\gradlew.bat testReleaseUnitTest assembleRelease
```

The APK lands in `dist/`. Full prerequisites and details are in the [build guide](docs/BUILD_GUIDE.md).

Without a `keystore.properties` file the APK is signed with the Android debug key. To sign releases with your own key, copy `keystore.properties.example` and fill it in. Use the same key for every release, otherwise Android will refuse to update over the old install.

## Project layout

```
app/            Android module (Java): hooks, UI, profile storage, QR codec
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

Built on [wireguard-go](https://git.zx2c4.com/wireguard-go), [gVisor](https://gvisor.dev), [gomobile](https://pkg.go.dev/golang.org/x/mobile), [ZXing](https://github.com/zxing/zxing), and the packet obfuscation ideas from [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go). Each keeps its own license.

## License

[MIT](LICENSE)
