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

## Bounded tasks for new contributors

If you want to contribute, pick a self-contained area below and open an issue first to confirm scope:

1. **Hook compatibility across Telegram forks**
   - **Goal:** Verify and document Proxy Settings trigger and `tgcalls` hook behavior on additional Telegram clients (e.g., Nekogram, Forkgram, AyuGram).
   - **Acceptance criteria:** `XC_MethodHook` only (never `XC_MethodReplacement`), tested on real device, Telegram version + Android version reported.
2. **Additional UI localizations**
   - **Goal:** Add a new language (e.g., Persian / Russian / Turkish) alongside Arabic and English in `WgStrings.java` with full RTL/LTR coverage.
   - **Acceptance criteria:** Zero cross-language leakage, `testZeroLanguageLeakageZeroEmDashAndZeroBuzzwords` passes in `WgPlusFeatureSuiteTest`, and native text fits cleanly without clipping.
3. **Go engine unit tests (`wgbridge-go`)**
   - **Goal:** Expand edge-case tests for AmneziaWG parameter validation, SOCKS5 UDP relay timeouts, and DoH fallback handling.
   - **Acceptance criteria:** `go vet ./...` and `go test -v ./...` pass with zero flaky network dependencies where mockable.
4. **Documentation & troubleshooting examples**
   - **Goal:** Improve setup walkthroughs for specific regions/ISPs or LSPatch Portable vs Local upgrade flows in `docs/USER_GUIDE.md`.
   - **Acceptance criteria:** Accurate to current `v1.5.0` UI labels in both English and Arabic, no private configs or keys included.
