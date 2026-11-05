# Contributing

Thanks for helping out. Bug reports, fixes and translation corrections are all welcome.

## Before you start

- Open an issue first for anything bigger than a small fix, so we can agree on the approach.
- Build instructions are in [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md).

## Ground rules

- **No `XC_MethodReplacement`.** Every hook must be an `XC_MethodHook`, so the module keeps working next to TeleVip and other modules.
- **Rebuild the native bridge only with `scripts/build-wgbridge.ps1`.** Plain `gomobile bind` produces an AAR that crashes under LSPatch.
- **Arabic and English together.** Every user-facing string lives in `WgStrings.java` with both languages. Arabic screens must not show English words, and the other way round.
- **Keep the UI plain.** No icon sets, emoji or decorative badges. Text must keep at least 4.5:1 contrast in both themes (a unit test checks this).
- **Never commit secrets.** No private keys, `keystore.properties`, `.p12` files or real server configs.

## Checks to run

```powershell
cd wgbridge-go; go vet ./...; go test ./...
cd ..; .\gradlew.bat testReleaseUnitTest
```

If you changed the UI or hooks, also try it on a real device and say which Telegram and Android versions you used in the pull request.
