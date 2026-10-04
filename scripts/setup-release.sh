#!/usr/bin/env bash
# One-time release setup for Niv.ON (run on the Mac that holds the Developer ID certificate).
#
#  1. Stores your Apple notarization credentials in the macOS keychain.
#  2. (optional, --github) Uploads every secret CI needs to GitHub Actions:
#     Apple certificate (.p12), notarization login, and the updater signing key.
#
# Usage:  scripts/setup-release.sh            # local notarization only
#         scripts/setup-release.sh --github   # also configure GitHub Actions secrets
set -euo pipefail

TEAM_ID="5PNLAR99PK"
IDENTITY="Developer ID Application: Bryan Bernardo Parreira (${TEAM_ID})"
REPO="BryanParreira/niv-on"
KEY_FILE="$HOME/.tauri/niv-on.key"

echo "== Apple notarization credentials =="
echo "Create an app-specific password at https://account.apple.com → Sign-In and Security → App-Specific Passwords."
read -rp "Apple ID email: " APPLE_ID
read -rsp "App-specific password (xxxx-xxxx-xxxx-xxxx): " APPLE_PASSWORD; echo
security add-generic-password -U -s "niv-on-notarize" -a "$APPLE_ID" -w "$APPLE_PASSWORD"
echo "Checking the credentials with Apple…"
xcrun notarytool history --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$TEAM_ID" >/dev/null
echo "✓ Notarization login works and is saved in your keychain (item: niv-on-notarize)."

if [[ "${1:-}" != "--github" ]]; then
  echo "Done. Build with: scripts/build-mac.sh"
  exit 0
fi

echo
echo "== GitHub Actions secrets for $REPO =="
P12_PASS="$(openssl rand -base64 24)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "Exporting your signing certificates (macOS will ask to allow keychain access)…"
echo "CI selects the Developer ID identity by name; nothing else is used."
security export -k login.keychain-db -t identities -f pkcs12 -P "$P12_PASS" -o "$TMP/all.p12"
UPDATER_PW="$(security find-generic-password -s niv-on-updater-key -a tauri-signer -w)"
gh secret set APPLE_CERTIFICATE           --env release -R "$REPO" < <(base64 -i "$TMP/all.p12")
gh secret set APPLE_CERTIFICATE_PASSWORD  --env release -R "$REPO" -b "$P12_PASS"
gh secret set APPLE_SIGNING_IDENTITY      --env release -R "$REPO" -b "$IDENTITY"
gh secret set APPLE_ID                    --env release -R "$REPO" -b "$APPLE_ID"
gh secret set APPLE_PASSWORD              --env release -R "$REPO" -b "$APPLE_PASSWORD"
gh secret set APPLE_TEAM_ID               --env release -R "$REPO" -b "$TEAM_ID"
gh secret set KEYCHAIN_PASSWORD           --env release -R "$REPO" -b "$(openssl rand -base64 24)"
gh secret set TAURI_SIGNING_PRIVATE_KEY   --env release -R "$REPO" < "$KEY_FILE"
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --env release -R "$REPO" -b "$UPDATER_PW"
echo "✓ GitHub secrets configured. Release with: scripts/release.sh <version>"
