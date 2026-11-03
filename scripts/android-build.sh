#!/usr/bin/env bash
# Build, align, sign and verify the Android ARM64 APK.
#
#   scripts/android-build.sh [--debug]
#
# Environment (all optional):
#   ANDROID_KEYSTORE_FILE / ANDROID_KEYSTORE_PASSWORD / ANDROID_KEY_ALIAS / ANDROID_KEY_PASSWORD
#       Release signing key. Never commit these. If absent, an ephemeral throw-away key is
#       generated and the APK is named *-test-signed.apk (installable, but NOT for distribution
#       and it cannot be upgraded in place by a later build signed with another key).
#   OUT_DIR   output directory (default: dist-android)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/android-env.sh
source scripts/android-env.sh

MODE=release
[[ "${1:-}" == "--debug" ]] && MODE=debug
OUT_DIR="${OUT_DIR:-dist-android}"
BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
mkdir -p "$OUT_DIR"

if [[ "$MODE" == release ]]; then
  # Size/speed tuning for the phone build only; desktop release profiles are untouched.
  export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-s}"
  # LTO off + 4 codegen units: rustc peaks at ~12 GB with thin LTO / 8 units on this ~450k-line
  # crate and gets OOM-killed on 15 GB machines. Override via env if you have more RAM.
  export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-off}"
  export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-4}"
  export GRADLE_OPTS="${GRADLE_OPTS:--Xmx1g -Dorg.gradle.workers.max=2}"
  export CARGO_PROFILE_RELEASE_STRIP="${CARGO_PROFILE_RELEASE_STRIP:-true}"
  npx tauri android build --target aarch64 --apk --ci
else
  npx tauri android build --target aarch64 --apk --debug --ci
fi

APK_DIR=src-tauri/gen/android/app/build/outputs/apk
RAW="$(find "$APK_DIR" -name '*.apk' -path "*${MODE}*" | head -1)"
[[ -n "$RAW" ]] || { echo "No APK produced under $APK_DIR" >&2; exit 1; }
echo "Built: $RAW"

ALIGNED="$OUT_DIR/aligned.apk"
rm -f "$ALIGNED"
"$BT/zipalign" -p -f 4 "$RAW" "$ALIGNED"

SUFFIX=""
if [[ -n "${ANDROID_KEYSTORE_FILE:-}" ]]; then
  KS="$ANDROID_KEYSTORE_FILE"; KS_PASS="${ANDROID_KEYSTORE_PASSWORD:?}"; ALIAS="${ANDROID_KEY_ALIAS:?}"; KEY_PASS="${ANDROID_KEY_PASSWORD:-$KS_PASS}"
else
  SUFFIX="-test-signed"
  KS="$(mktemp -u).jks"; KS_PASS="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"; ALIAS=cockpit-test; KEY_PASS="$KS_PASS"
  keytool -genkeypair -keystore "$KS" -storepass "$KS_PASS" -keypass "$KEY_PASS" -alias "$ALIAS" \
    -keyalg RSA -keysize 3072 -validity 3650 -dname "CN=Cockpit Tools test signing" >/dev/null 2>&1
  trap 'rm -f "$KS"' EXIT
fi

FINAL="$OUT_DIR/cockpit-tools-android-arm64${SUFFIX}.apk"
rm -f "$FINAL"
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$KS_PASS" --ks-key-alias "$ALIAS" --key-pass "pass:$KEY_PASS" \
  --out "$FINAL" "$ALIGNED"
rm -f "$ALIGNED" "$FINAL.idsig"

"$BT/apksigner" verify --verbose --print-certs "$FINAL"
"$BT/aapt2" dump badging "$FINAL" | grep -E "^(package|sdkVersion|targetSdkVersion|native-code|uses-permission)" || true
ls -l "$FINAL"
sha256sum "$FINAL" | tee "$FINAL.sha256"
