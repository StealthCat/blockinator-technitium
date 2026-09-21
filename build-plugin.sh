#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TECHNITIUM_PATH="${1:-/opt/technitium/dns}"
PUBLISH_DIR="$HERE/bin/Release/publish"
DIST_DIR="$HERE/dist"
ZIP_FILE="$DIST_DIR/RemotePolicyBlockingApp.zip"

cd "$HERE"
rm -rf "$PUBLISH_DIR"

dotnet publish -c Release \
  -p:TechnitiumDnsServerPath="$TECHNITIUM_PATH" \
  -p:GenerateDependencyFile=true \
  -o "$PUBLISH_DIR"

DLL="$PUBLISH_DIR/RemotePolicyBlockingApp.dll"
DEPS="$PUBLISH_DIR/RemotePolicyBlockingApp.deps.json"
CONFIG="$PUBLISH_DIR/dnsApp.config"
README="$PUBLISH_DIR/README.md"

for f in "$DLL" "$DEPS" "$CONFIG" "$README"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: required plugin package file was not produced: $f" >&2
    exit 1
  fi
done

mkdir -p "$DIST_DIR"
rm -f "$ZIP_FILE"
(
  cd "$PUBLISH_DIR"
  zip -j "$ZIP_FILE" \
    RemotePolicyBlockingApp.dll \
    RemotePolicyBlockingApp.deps.json \
    dnsApp.config \
    README.md
)

if ! unzip -Z1 "$ZIP_FILE" | grep -qx 'RemotePolicyBlockingApp.deps.json'; then
  echo "ERROR: package validation failed: RemotePolicyBlockingApp.deps.json is absent." >&2
  exit 1
fi

echo "Created: $ZIP_FILE"
echo "Validated: RemotePolicyBlockingApp.deps.json is present at ZIP root."
