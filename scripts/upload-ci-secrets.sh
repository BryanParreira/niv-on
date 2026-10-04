#!/usr/bin/env bash
# Copy signing material from this Mac's keychain into the protected `release`
# environment. Nothing is printed or written to the project. macOS will ask you
# to allow exporting the Developer ID certificate.
# APPLE_PASSWORD is set separately by scripts/rotate-apple-password.sh.
set -euo pipefail
R="${1:-BryanParreira/niv-on}"; E=release
TMP=$(mktemp -d); chmod 700 "$TMP"; trap 'rm -rf "$TMP"' EXIT
IDENTITY="Developer ID Application: Bryan Bernardo Parreira (5PNLAR99PK)"
OSSL="$(command -v /opt/homebrew/bin/openssl || command -v openssl)"
P12_PASS=$(openssl rand -base64 24)
# The keychain exports every identity; keep only the Developer ID certificate and
# its private key (matched by localKeyID) so CI signing is unambiguous.
security export -k login.keychain-db -t identities -f pkcs12 -P "$P12_PASS" -o "$TMP/all.p12" >/dev/null
"$OSSL" pkcs12 -legacy -in "$TMP/all.p12" -passin "pass:$P12_PASS" -nodes -out "$TMP/all.pem" 2>/dev/null
python3 - "$TMP/all.pem" "$TMP/devid.pem" "$IDENTITY" <<'PY'
import re, sys
src, dst, ident = sys.argv[1:4]
blocks = re.findall(r"Bag Attributes.*?-----END [A-Z ]+-----", open(src).read(), re.S)
kid = lambda b: (re.search(r"localKeyID: ([0-9A-F ]+)", b) or [None, None])[1]
certs = [b for b in blocks if "CERTIFICATE" in b and ident.split(":")[0] in b and "5PNLAR99PK" in b]
if len(certs) != 1:
    sys.exit(f"expected exactly one Developer ID certificate, found {len(certs)}")
keys = [b for b in blocks if "PRIVATE KEY" in b and kid(b) == kid(certs[0])]
if len(keys) != 1:
    sys.exit("matching private key not found")
open(dst, "w").write(certs[0] + "\n" + keys[0] + "\n")
PY
"$OSSL" pkcs12 -export -legacy -in "$TMP/devid.pem" -name "$IDENTITY" -passout "pass:$P12_PASS" -out "$TMP/c.p12"
count=$("$OSSL" pkcs12 -legacy -in "$TMP/c.p12" -passin "pass:$P12_PASS" -nokeys 2>/dev/null | grep -c "BEGIN CERTIFICATE")
subj=$("$OSSL" pkcs12 -legacy -in "$TMP/c.p12" -passin "pass:$P12_PASS" -nokeys 2>/dev/null | grep -m1 "^subject")
[[ "$count" == "1" && "$subj" == *"Developer ID Application"* ]] || { echo "bundle check failed"; exit 1; }
echo "bundle OK: 1 certificate ($subj)"
base64 -i "$TMP/c.p12" | gh secret set APPLE_CERTIFICATE --env $E -R "$R"
printf '%s' "$P12_PASS" | gh secret set APPLE_CERTIFICATE_PASSWORD --env $E -R "$R"
printf '%s' "$IDENTITY" | gh secret set APPLE_SIGNING_IDENTITY --env $E -R "$R"
printf '%s' "5PNLAR99PK" | gh secret set APPLE_TEAM_ID --env $E -R "$R"
security find-generic-password -s niv-on-notarize | awk -F'"' '/"acct"/ {printf "%s", $4}' | gh secret set APPLE_ID --env $E -R "$R"
openssl rand -base64 24 | tr -d '\n' | gh secret set KEYCHAIN_PASSWORD --env $E -R "$R"
gh secret set TAURI_SIGNING_PRIVATE_KEY --env $E -R "$R" < "$HOME/.tauri/niv-on.key"
security find-generic-password -s niv-on-updater-key -a tauri-signer -w | tr -d '\n' | gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --env $E -R "$R"
echo "✓ release secrets uploaded to $R (environment: $E)"
