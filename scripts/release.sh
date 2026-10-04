#!/usr/bin/env bash
# Bump the version everywhere, commit, tag and push. CI then builds, signs,
# notarizes and publishes the release + latest.json for the auto-updater.
# Usage: scripts/release.sh 0.2.0
set -euo pipefail
cd "$(dirname "$0")/.."
V="${1:?usage: scripts/release.sh <version, e.g. 0.2.0>}"
[[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like 1.2.3"; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "commit or stash your changes first"; exit 1; }

python3 - "$V" <<'PY'
import json, re, sys
v = sys.argv[1]
for path in ["package.json", "src-tauri/tauri.conf.json"]:
    d = json.load(open(path)); d["version"] = v
    json.dump(d, open(path, "w"), indent=2); open(path, "a").write("\n")
s = open("src-tauri/Cargo.toml").read()
s = re.sub(r'(?m)^version = "[^"]+"', f'version = "{v}"', s, count=1)
open("src-tauri/Cargo.toml", "w").write(s)
PY
(cd src-tauri && cargo update -p niv --precise "$V" >/dev/null 2>&1 || cargo check -q)
npm install --package-lock-only >/dev/null

git add package.json package-lock.json src-tauri/tauri.conf.json src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "Release v$V"
git tag "v$V"
git push origin HEAD "v$V"
echo "✓ Tagged v$V — follow the build at: https://github.com/BryanParreira/niv-on/actions"
