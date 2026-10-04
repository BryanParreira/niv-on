#!/usr/bin/env bash
# Replace the Apple app-specific password used for notarization, locally and in CI.
# 1. Revoke the old one at https://account.apple.com → Sign-In and Security → App-Specific Passwords
# 2. Create a new one there, then run this script and paste it when asked (input is hidden).
set -euo pipefail
TEAM_ID="5PNLAR99PK"
REPO="BryanParreira/niv-on"
APPLE_ID="$(security find-generic-password -s niv-on-notarize 2>/dev/null | awk -F'"' '/"acct"/ {print $4}')"
[[ -n "$APPLE_ID" ]] || read -rp "Apple ID email: " APPLE_ID
read -rsp "New app-specific password: " PW; echo
xcrun notarytool history --apple-id "$APPLE_ID" --password "$PW" --team-id "$TEAM_ID" >/dev/null
security add-generic-password -U -s "niv-on-notarize" -a "$APPLE_ID" -w "$PW"
printf '%s' "$PW" | gh secret set APPLE_PASSWORD --env release -R "$REPO"
unset PW
echo "✓ New password verified with Apple, saved to your keychain and to GitHub (environment: release)."
