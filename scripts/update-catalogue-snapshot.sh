#!/usr/bin/env bash
# Refresh the signed catalogue snapshot embedded in list-service from the latest argus-lists release.
# The files stay signed by the release key; list-service verifies them at startup like a download.
#   scripts/update-catalogue-snapshot.sh [release-tag]     (default: latest; needs gh)
set -euo pipefail
dest="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crates/list-service/assets/catalogue"
tag="${1:-}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gh release download ${tag:+"$tag"} -R metril/argus-lists -D "$tmp" -p 'filters.json' -p 'filters.json.minisig' -p 'meta.json' -p 'meta.json.minisig'
mkdir -p "$dest"
cp "$tmp"/filters.json "$tmp"/filters.json.minisig "$tmp"/meta.json "$tmp"/meta.json.minisig "$dest"/
grep -o 'argus-lists v[0-9.]*' "$dest/filters.json.minisig" | head -1 || true
echo "snapshot updated in $dest; run: cargo nextest run -p list-service (verifies it) and commit"
