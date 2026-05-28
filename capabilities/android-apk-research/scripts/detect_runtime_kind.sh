#!/usr/bin/env bash
# detect_runtime_kind.sh — classify an APK's app runtime in one second.
#
# Usage:
#   detect_runtime_kind.sh path/to.apk
#   detect_runtime_kind.sh --jsonl path/to.apk      # emit one JSONL record
#
# Output one of:
#   native               (Java/Kotlin only)
#   react_native_js      (RN with plain JS bundle)
#   react_native_hermes  (RN with Hermes bytecode bundle)
#   flutter_aot          (Flutter, libapp.so present)
#   capacitor            (Capacitor: assets/public/ webview content)
#   cordova              (Cordova: assets/www/ + cordova.js)
#   xamarin              (libmonodroid.so / Mono assemblies)
#   maui                 (.NET MAUI: libmono-component-* + Microsoft.Maui dlls)
#   unity                (libunity.so present)
#
# Drives:
#   - JADX heap setting (RN/Flutter still need native pass; xamarin/unity skip JADX)
#   - Step 7.5 (RN JS-bundle trace) and Step 7.6 (Flutter Dart-AOT trace) routing
#   - Pre-bundle hypothesis grading (force needs_route_map_validation for RN/Flutter)
#
# Bug class signal: presence of a non-native runtime predicts that Java-side
# routing is a thin relay and the real trust decision is in the bundle.
#
# Detection corner cases (corpus-3, 2026-05-19):
#   - Microsoft Teams ships per-feature Hermes bundles under
#     `assets/app_packages/<feature>/hermes.android.bundle` rather than the
#     canonical `assets/index.android.bundle`. The old probe missed these and
#     classified Teams as native; the corrected matcher widens the bundle glob
#     to any `*.bundle` / `*.jsbundle` under `assets/**`.
#   - Mint and similar RN apps ship a file-based unbundle: each module is its
#     own JS file under `assets/js-modules/*.js` plus an `UNBUNDLE` header
#     file. There is no single bundle file to probe magic on, so we infer
#     `react_native_js` from the directory + `libhermes-executor*.so`
#     presence (Hermes-engine link without a precompiled bundle means the
#     engine evals the JS modules at runtime). When `libhermes-executor*.so`
#     is present but no precompiled `.hbc`/`.bundle` is, output is
#     `react_native_js` (engine runs raw JS), not `react_native_hermes`.

set -u
# pipefail intentionally OFF: `grep -q` and `head -c` close pipes early, producing
# SIGPIPE (rc=141) in upstream processes. We rely on the last-stage rc only.

JSONL=0
if [ "${1-}" = "--jsonl" ]; then JSONL=1; shift; fi
APK=${1?usage: $0 [--jsonl] path/to.apk}
[ -r "$APK" ] || { echo "cannot read $APK" >&2; exit 1; }

# unzip -l is enough; we never need to extract.
LIST=$(unzip -l "$APK" 2>/dev/null) || { echo "not a zip: $APK" >&2; exit 1; }

KIND=native
HERMES=0

# React Native bundle detection — three shapes:
#   1) canonical: assets/index.android.bundle | assets/*.jsbundle
#   2) per-feature: assets/<anything>/<bundle>.bundle | hermes.android.bundle
#   3) file-based unbundle: assets/js-modules/*.js + assets/UNBUNDLE (Mint pattern)
BUNDLE_ENTRY=$(printf '%s\n' "$LIST" \
  | awk '{print $NF}' \
  | grep -E '^assets/(.*/)*(index[^/]*\.bundle|[^/]+\.jsbundle|hermes\.android\.bundle)$' \
  | head -1 || true)

# File-based unbundle (no single bundle entry but split JS modules present).
UNBUNDLE_DIR=$(printf '%s\n' "$LIST" \
  | awk '{print $NF}' \
  | grep -E '^assets/(js-modules|js_modules)/[^/]+\.js$' \
  | head -1 || true)

if [ -n "$BUNDLE_ENTRY" ]; then
  # Probe magic to distinguish Hermes from plain JS without extracting fully.
  # Hermes header magic is 0xc61fbc03 (facebook/hermes BCVersion.h).
  MAGIC=$( { unzip -p "$APK" "$BUNDLE_ENTRY" 2>/dev/null || true; } | head -c 4 | xxd -p)
  if [ "$MAGIC" = "c61fbc03" ]; then
    KIND=react_native_hermes; HERMES=1
  else
    KIND=react_native_js
  fi
elif [ -n "$UNBUNDLE_DIR" ]; then
  # File-based unbundle: raw JS modules. The presence of a Hermes engine .so
  # without a precompiled bundle still means JS is evaluated at runtime — keep
  # as react_native_js (not _hermes) so the operator knows there is no .hbc
  # to disasm; they need the raw JS path (Step 7.5b, not 7.5c).
  KIND=react_native_js
elif printf '%s\n' "$LIST" | awk '{print $NF}' | grep -qE '^assets/flutter_assets/.'; then
  KIND=flutter_aot
elif printf '%s\n' "$LIST" | awk '{print $NF}' | grep -qE '^lib/[^/]+/libapp\.so$'; then
  KIND=flutter_aot
elif printf '%s\n' "$LIST" | grep -qE 'lib/[^/]+/libunity\.so'; then
  KIND=unity
elif printf '%s\n' "$LIST" | grep -qE 'lib/[^/]+/libmonodroid\.so'; then
  # Distinguish Xamarin classic vs .NET MAUI
  if printf '%s\n' "$LIST" | grep -qiE 'assemblies/Microsoft\.Maui'; then
    KIND=maui
  else
    KIND=xamarin
  fi
elif printf '%s\n' "$LIST" | grep -q 'assets/public/index.html'; then
  KIND=capacitor
elif printf '%s\n' "$LIST" | grep -q 'assets/www/cordova.js'; then
  KIND=cordova
fi

if [ "$JSONL" = 1 ]; then
  printf '{"apk":"%s","runtime_kind":"%s","hermes":%s}\n' \
    "$APK" "$KIND" "$( [ $HERMES = 1 ] && echo true || echo false )"
else
  echo "$KIND"
fi
