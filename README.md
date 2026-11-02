# Cockpit Tools — Android port (work in progress)

Android (ARM64) port of [jlcodes99/cockpit-tools](https://github.com/jlcodes99/cockpit-tools)
at upstream commit `3edfff6`, built with Tauri 2. Upstream license: CC-BY-NC-SA-4.0
(non-commercial, share-alike) — see upstream for the full terms.

**Status:** the Rust crate compiles for `aarch64-linux-android`; a release APK build is in
progress and **no APK has been produced or installed on a device yet**. Full documentation
(compatibility table, install, Claude Code connection, test report) is added when the build
is verified. The original upstream README is kept in `docs/upstream/README.zh-CN.md`.

Added in this port:
- `src-tauri/src/modules/management_api.rs` — token-protected localhost Management API / MCP
  server (9 tools; mutating tools need control token + in-app grant + `confirm`).
- `src-tauri/src/modules/android_platform.rs` + `gen/android` Kotlin — Android Keystore wrapping
  of the account-encryption key and API tokens; user-controlled foreground service.
- Android cfg gating of desktop-only code, mobile layout CSS, settings panel.
- `scripts/android-build.sh`, `.github/workflows/android.yml`.
