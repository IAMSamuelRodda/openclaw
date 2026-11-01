#!/bin/bash
set -euo pipefail

# Stages the pinned cloudflared used only for Cloudflare Access browser sign-in.
# The executable is wrapped in a fixed text envelope so AppImage tooling does not
# rewrite it; cloudflare_access.rs strips the envelope and checks the raw sha256.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT_DIR/scripts/lib/cloudflared-linux.json"
ARCH="${1:-}"
DESTINATION="${2:-}"
if [[ "$#" != 2 || ( "$ARCH" != arm64 && "$ARCH" != x86_64 ) || -z "$DESTINATION" || "$DESTINATION" == -* ]]; then
  echo "Usage: scripts/stage-cloudflared-linux.sh <arm64|x86_64> <resource-directory>" >&2
  exit 2
fi
read -r VERSION ASSET BINARY_SHA LICENSE_SHA < <(node - "$MANIFEST" "$ARCH" <<'JS'
const manifest = require(process.argv[2]);
const artifact = manifest.artifacts[process.argv[3]];
console.log(manifest.version, artifact.asset, artifact.sha256, manifest.licenseSha256);
JS
)
CACHE_DIR="$ROOT_DIR/apps/linux/src-tauri/target/cloudflared-cache/$VERSION"
mkdir -p "$CACHE_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/openclaw-cloudflared.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

verified_download() {
  local name="$1" expected="$2" url="$3" actual
  if [[ -f "$CACHE_DIR/$name" && ! -L "$CACHE_DIR/$name" ]]; then
    actual="$(sha256sum "$CACHE_DIR/$name" | awk '{print $1}')"
    [[ "$actual" != "$expected" ]] || return 0
  fi
  curl --fail --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 2 \
    --output "$WORK/$name" "$url"
  actual="$(sha256sum "$WORK/$name" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "ERROR: cloudflared $name sha256 mismatch" >&2
    return 1
  fi
  mv -f "$WORK/$name" "$CACHE_DIR/$name"
}

verified_download "$ASSET" "$BINARY_SHA" \
  "https://github.com/cloudflare/cloudflared/releases/download/$VERSION/$ASSET"
verified_download LICENSE "$LICENSE_SHA" \
  "https://raw.githubusercontent.com/cloudflare/cloudflared/$VERSION/LICENSE"
mkdir -p "$DESTINATION"
{ printf 'OPENCLAW-CLOUDFLARED-V1\n'; cat "$CACHE_DIR/$ASSET"; } > "$DESTINATION/cloudflared"
chmod 0644 "$DESTINATION/cloudflared"
node - "$MANIFEST" "$ARCH" "$DESTINATION/manifest.json" <<'JS'
const fs = require("node:fs");
const manifest = require(process.argv[2]);
const arch = process.argv[3];
fs.writeFileSync(process.argv[4], `${JSON.stringify({
  version: manifest.version, arch, sha256: manifest.artifacts[arch].sha256,
}, null, 2)}\n`);
JS
cp "$CACHE_DIR/LICENSE" "$DESTINATION/LICENSE"
echo "Staged cloudflared $VERSION ($ARCH)"
