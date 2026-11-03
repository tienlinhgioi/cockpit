# Android port — build & test report

Only things that were actually executed are marked PASS. Everything else is listed under
"Not verified". Environment: Linux x86_64 sandbox, 4 cores, 15 GB RAM, no KVM, no Android
device or emulator. Upstream: jlcodes99/cockpit-tools @ `3edfff6`.

## 1. Automated checks that were run

| Check | Command | Result |
|---|---|---|
| TypeScript type check | `npx tsc --noEmit` | PASS |
| Upstream TS test suite | `npm test` | PASS — 1915/1915 (after fixing 1 failure I introduced, see §4) |
| Locale parity | `node scripts/check_locales.cjs` | PASS |
| Rust, Android target | `cargo check --target aarch64-linux-android -p cockpit-tools --lib` | PASS |
| Rust, Linux desktop (host) | `cargo check -p cockpit-tools --lib` | PASS |
| Management API unit + HTTP tests | `cargo test -p cockpit-tools --lib management_api` | PASS — 14/14 |
| Release APK build (ARM64) | `scripts/android-build.sh` | PASS (see §2) |
| APK integrity / signature | `unzip -t`, `apksigner verify` | PASS (v2 + v3, test key) |
| APK manifest / dex inspection | `aapt2 dump badging`, `grep` on dex | PASS after R8 fix (§4) |

### Management API tests (real axum server on loopback, real HTTP client, empty data dir)
Covers: 401 on missing/wrong token; Host/Origin rebinding rejected (403); MCP `initialize`,
`notifications/initialized` (202), `tools/list` (9 tools); every read tool returns without
leaking token field names or the API tokens; mutating tools denied for the read token; denied
for the control token without an in-app grant; `confirm` absent → preview only; strategy
`custom` denied; unknown tool/method errors; REST mirror (200 / 422); audit log contains no
tokens; token rotation invalidates the old token; disabling stops the listener. Pure-function
tests: email masking, credential redaction (Bearer, JWT, `sk-…`, `api_key=`, cookies, own
tokens), char-safe clipping, bearer parsing, control-gate logic, recommendation ranking,
auth lockout.
**These are tests of the code paths with an empty account store. They are not tests against
real Claude/Codex/Antigravity services.**

## 2. APK facts (from the built file)

* `cockpit-tools-android-arm64-test-signed.apk` — built 2026-11-03 01:27 UTC from branch head
  at that time; SHA-256 `8f0f6bdab991e0e157ac1544af1f8cf3cbe20984f62bec306f8910b7a8af2cfb`.
* Build recipe that finished: opt-level `s`, LTO off, 16 codegen units, `CARGO_BUILD_JOBS=2`,
  symbols stripped. Peak `rustc` memory observed: 11.8 GB.
* package `io.github.tienlinhgioi.cockpit`, version 1.3.78, minSdk 26, targetSdk 36,
  ABI `arm64-v8a` only. Size ≈ 91 MB (the Rust library alone is ≈ 86 MB; an earlier thin-LTO
  build was ≈ 85 MB but could not be reproduced within the sandbox memory limit).
* Signed with a throw-away **test** key (`CN=Cockpit Tools test signing`). Not for distribution.
* Manifest: `allowBackup=false`, network-security-config (cleartext only for localhost),
  data-extraction rules excluding everything, foreground service type `specialUse`.
  Permissions: INTERNET, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS
  plus RECEIVE_BOOT_COMPLETED and WAKE_LOCK, which the Tauri notification plugin adds (not
  used by Cockpit; not removed yet).

## 3. Not verified (could not be run here)

* **Any runtime behaviour on Android** — no device/emulator (no KVM). App launch, navigation,
  responsive layout on a real screen, WebView rendering, back-button/lifecycle handling,
  permission prompts, rotation, offline behaviour: **untested**.
* **JNI bridge at runtime** (Keystore encrypt/decrypt, foreground service start/stop,
  notification permission): compiled and name-preserved through R8 (checked in dex), but the
  calls themselves were never executed.
* **Real sign-in and real quota queries** for Claude, Codex, Antigravity, etc., account
  switching against live services, real gateway traffic to upstream providers: **untested**.
* Management API **on the phone** (it was tested on the Linux host only).
* Windows and macOS desktop builds: the desktop `cfg` changes are intended to be no-ops, but
  only Linux was compiled. CI desktop build jobs were skipped on the earlier failed run.
* Rust unit-test suite of the whole crate (only `management_api` tests were run).
* GitHub Actions `Android APK` workflow: all earlier runs failed at the setup step (§4);
  a fixed version was pushed and has not been confirmed green yet.
* Release signing with a real key; update-in-place across signing keys.
* Memory/CPU/battery measurements. APK size has not been optimised beyond `opt-level=s`,
  thin LTO and symbol stripping.

## 4. Problems found and fixed during verification

1. **R8 renamed JNI-called Kotlin methods** (`keystoreEncrypt`, `setServiceEnabled`, …) in the
   release build. The build succeeded but Keystore/service calls would have failed at runtime.
   Found by inspecting the dex; fixed with keep rules in `proguard-rules.pro`; re-checked.
2. **Broke an upstream test** (`SettingsPageView.test.ts`): my panel registered i18n resources
   at import time and the test's i18next stub lacks `addResourceBundle`. Now registered on
   mount with a guard. Full suite 1915/1915.
3. **CI**: `android-actions/setup-android@v3` crashed on the runner (Node 24); replaced by the
   runner's preinstalled SDK.
4. **Build memory**: `rustc` for this single ~450k-line crate peaks at 12-13 GB and was
   OOM-killed three times on a 15 GB machine (thin LTO/8 units; LTO off/4 units — so LTO is not
   the cause). The build only finished after limiting cargo's jobserver (`CARGO_BUILD_JOBS=2`)
   and using 16 codegen units. Any CI runner needs ≥ 16 GB RAM or the same settings (the
   script applies them by default).
5. **Sandbox only**: Maven Central rate-limited (HTTP 429) through the proxy; worked around
   with a local Gradle init script (not in the repo).

## 5. Known functional gaps (by design or not yet done)

See the compatibility table in `ANDROID.md`. In short: no launching/injecting other desktop
apps, no Claude Desktop Electron login, no Go/mihomo sidecars, no WebDAV sync on Android yet,
no second-window OAuth/preview windows, no auto-update/launch-at-login.
