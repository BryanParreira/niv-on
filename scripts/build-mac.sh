#!/usr/bin/env bash
# Local release build for macOS: universal binary, signed with Developer ID,
# notarized by Apple, stapled, plus signed updater artifacts.
# Needs: scripts/setup-release.sh run once (stores the notarization login).
set -euo pipefail
cd "$(dirname "$0")/.."

export APPLE_TEAM_ID="5PNLAR99PK"
export APPLE_SIGNING_IDENTITY="Developer ID Application: Bryan Bernardo Parreira (${APPLE_TEAM_ID})"
export APPLE_ID="$(security find-generic-password -s niv-on-notarize | awk -F'"' '/"acct"/ {print $4}')"
export APPLE_PASSWORD="$(security find-generic-password -s niv-on-notarize -w)"
export TAURI_SIGNING_PRIVATE_KEY="$(cat "$HOME/.tauri/niv-on.key")"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$(security find-generic-password -s niv-on-updater-key -a tauri-signer -w)"

npx tauri build --target universal-apple-darwin

BUNDLE="src-tauri/target/universal-apple-darwin/release/bundle"
APP="$(ls -d "$BUNDLE"/macos/*.app | head -1)"
DMG="$(ls "$BUNDLE"/dmg/*.dmg | head -1)"
echo
echo "== Verification =="
codesign --verify --deep --strict --verbose=2 "$APP"
spctl --assess --type execute --verbose=2 "$APP"
xcrun stapler validate "$APP"
# The DMG itself: sign + notarize + staple so Gatekeeper is happy when it's opened.
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --timestamp "$DMG"
xcrun notarytool submit "$DMG" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
xcrun stapler staple "$DMG"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
echo
echo "✓ Signed & notarized:"
echo "  $DMG"
ls "$BUNDLE"/macos/*.tar.gz* 2>/dev/null | sed 's/^/  updater: /'
