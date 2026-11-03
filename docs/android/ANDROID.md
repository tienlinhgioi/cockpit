# Cockpit Tools for Android (ARM64)

Port of [jlcodes99/cockpit-tools](https://github.com/jlcodes99/cockpit-tools) @ `3edfff6` to
Android using Tauri 2. The same Rust core and React UI run on the phone; desktop-only pieces
are gated or replaced. Upstream license: CC-BY-NC-SA-4.0 (non-commercial, share-alike).

> Read `docs/android/TEST_REPORT.md` for what has and has **not** been verified.

## 1. Compatibility audit

| Class | Area | Evidence / notes |
|---|---|---|
| **Compatible** | Account storage, quota fetch/parse, OAuth token refresh, request logs/stats, import/export JSON | Pure Rust + `reqwest`/`rusqlite(bundled)`; compiles for `aarch64-linux-android` |
| **Compatible** | Native Rust API gateway (default engine), routing strategies, health, pricing | In-process `axum`/`hyper`; no external binary needed |
| **Compatible** | React UI, i18n, 2FA vault, clipboard, dialog, notification, opener, deep-link | Tauri plugins with Android support |
| **Needs change (done)** | HTTP/TLS | `native-tls`/OpenSSL removed on Android; `reqwest` uses rustls + bundled webpki roots |
| **Needs change (done)** | Data directory | `HOME`/`TMPDIR` pointed to app-private storage at startup (`android_platform::init_environment`) |
| **Needs change (done)** | Window management (`hide/minimize/set_size/...`) | Desktop-only Tauri APIs; no-op shims in `utils/android_window_compat.rs` |
| **Needs change (done)** | `cfg(target_os = "linux")` platform code | Android is treated as Linux-family (`any(linux, android)`); no behaviour change on desktop |
| **Replaced** | System tray / menu bar / floating card | Stub module `tray_android.rs`; UI side nav becomes a bottom bar |
| **Replaced** | Credential key at rest | AES-GCM key of `secure_account_storage` is wrapped by the Android Keystore (`ks1:` format) |
| **Replaced** | Trash/recycle bin | Direct delete of Cockpit-owned instance dirs only |
| **Replaced** | Always-on background | User-controlled foreground service (`GatewayService`, type `specialUse`) |
| **Not feasible / limited** | Launching, injecting into or switching *other desktop apps* (Antigravity IDE, Cursor, VS Code, Windsurf, Codex desktop, Claude Desktop …) | These apps are not on the phone; process discovery finds nothing. Account data, quota and gateway still work |
| **Not feasible** | Claude Desktop browser-session login (needs Electron helper) | Use Claude OAuth (system browser + paste code) or JSON/API-key import |
| **Not feasible** | Go `cockpit-cliproxy` sidecar, mihomo/sing-box proxy engine binaries | Desktop executables; native Rust gateway is used |
| **Not feasible** | Pelican native preview window, in-app second-window OAuth (Codex/ZCode/WorkBuddy webview login) | Single-activity app; Pelican *browser* preview and system-browser flows remain |
| **Not feasible** | Auto-updater, launch-at-login, single-instance plugin | Desktop-only; Android handles single task itself |
| **Known gap** | WebDAV backup sync | `reqwest_dav` is excluded on Android for now (TLS stack); local backup/export works |

## 2. What was added

* **Management API / MCP server** — `src-tauri/src/modules/management_api.rs`.
* **Android bridge** — `modules/android_platform.rs` (JNI) + `gen/android/.../CockpitBridge.kt`
  (Keystore) + `GatewayService.kt` (foreground service).
* **UI** — bottom navigation on small screens (`src/styles/mobile.css`), settings panel
  `MobileManagementPanel` (service toggle, management API, tokens, control grant, audit).
* **Build** — `scripts/android-build.sh`, `.github/workflows/android.yml`.

## 3. Install

1. Download `cockpit-tools-android-arm64*.apk` (CI artifact **Android APK** or `dist-android/`).
2. On the phone allow *Install unknown apps* for your browser/file manager.
3. Open the APK. Android 8.0+ (API 26+) on an ARM64 device; developed for Android 13+.
4. A file named `…-test-signed.apk` is signed with a throw-away key: fine for your own device,
   but a later build signed with another key cannot update it in place (uninstall first, which
   deletes app data). Use your own keystore (see CI secrets below) for stable updates.

Via adb: `adb install -r cockpit-tools-android-arm64.apk`.

## 4. Sign in to Claude (three different things)

| What | What it is | In Cockpit |
|---|---|---|
| **Claude Pro/Max subscription** | claude.ai plan; no API key included | OAuth login; Cockpit tracks the 5-hour/7-day quota windows |
| **Claude Code login** | The same subscription OAuth credentials used by the Claude Code CLI | Same OAuth flow |
| **Anthropic API billing** | Pay-per-token `sk-ant-…` keys from console.anthropic.com | "API key" account type; billed separately, **not** covered by Pro |

Claude Pro does **not** give a free API key. Do not expect subscription login to work as an API
key for other tools; check Anthropic's current terms before routing subscription credentials
through third-party software.

Steps: *Claude* page → add account → OAuth. Cockpit opens the system browser; after approving,
copy the code/callback URL shown by the page and paste it back into Cockpit. If a browser
cannot be opened, copy the URL manually. Importing Claude Code's local credentials from another
app (Termux) is not possible because Android sandboxes app data — use JSON import instead.

## 5. Gateway on Android

The Codex API Service (OpenAI-compatible) runs in-process. Enable it on the Codex page; it
listens on `127.0.0.1:<port>` by default. Other apps on the same phone (Termux, etc.) can call
`http://127.0.0.1:<port>/v1` with the gateway API key shown in the app. Exposing it to the LAN
is an explicit setting. Settings → *Android background service* starts a foreground service
(visible notification, Stop button). Android may still stop it (battery saver, OEM killers,
Android 15 limits); uptime is not guaranteed. Do not disable battery optimisation silently —
do it yourself in system settings if you need longer uptime.

## 6. Connect Claude Code to the Management API

Settings → *Management API / MCP* → **Enable** (off by default, listens on `127.0.0.1:17890`).
Two tokens: **read** (inspection) and **control** (may call mutating tools).

Where Claude Code runs:

* **Termux on the same phone** (Claude Code installed there):
  `claude mcp add --transport http cockpit http://127.0.0.1:17890/mcp --header "Authorization: Bearer <READ_TOKEN>"`
* **PC over USB**: `adb forward tcp:17890 tcp:17890`, then run the same command on the PC.
* **Claude.ai web / Claude mobile app**: *cannot* reach a phone-local MCP server (they only
  connect to remote HTTPS servers). Not supported; use Claude Code.

Tools: `get_accounts`, `get_quota`, `get_usage_statistics`, `get_gateway_status`,
`get_error_logs`, `get_account_health` (read) and `switch_account`, `configure_routing`,
`restart_gateway` (control).

Safety rules enforced in code:
* No tool returns OAuth tokens, API keys, cookies or passwords; free text is redacted; e-mails
  are masked unless you enable *Show full e-mail*.
* A mutating call needs **all three**: control token, an in-app *Grant* (15/60 min, auto-expires,
  revocable) and `confirm: true`. Without `confirm` it only returns a preview.
* `configure_routing` can only choose among `auto, random, quota_high_first, quota_low_first,
  plan_high_first, plan_low_first, expiry_soon_first`; it cannot change keys, ports, exposure
  or quotas. Nothing here circumvents provider quotas or limits.
* Failed-auth lockout, Host/Origin checks (DNS-rebinding), 256 KiB body limit, audit log.

REST mirror: `POST /api/v1/tools/<name>` with the same bearer token. `GET /healthz` needs no token.

## 7. Build from source

```bash
npm ci
scripts/android-build.sh            # release, ARM64 → dist-android/cockpit-tools-android-arm64*.apk
scripts/android-build.sh --debug
```
Needs JDK 21, Android SDK (platform 36, build-tools 36), NDK 27.2.12479018, Rust with target
`aarch64-linux-android`; see `scripts/android-env.sh` (override `ANDROID_HOME`/`NDK_HOME`).
CI: `.github/workflows/android.yml`. For a stable release signature add repository secrets
`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.
Never commit keystores.
