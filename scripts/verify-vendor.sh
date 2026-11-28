#!/usr/bin/env bash
# Verify that the vendored crates under vendor/ equal the pristine crates.io release plus the
# documented Argus patches, and nothing else.
#
#   scripts/verify-vendor.sh              verify all (needs network)
#   scripts/verify-vendor.sh --offline    skip the crates.io index cross-check
#   scripts/verify-vendor.sh --update     regenerate vendor/pristine/<crate>.diff after an intended patch change
#   scripts/verify-vendor.sh btls-sys     only the named crate(s)
#
# Per crate it (1) downloads <crate>-<ver>.crate from static.crates.io (or reuses the cargo cache
# when the hash matches), (2) checks its SHA-256 against vendor/pristine/crates.sha256 AND against
# the crates.io index checksum, (3) unpacks it and compares with vendor/<crate> using `diff -r`:
# no file may exist on only one side except the allowed ones below, no symlink, no changed exec bit,
# and the content differences of the common files must equal the committed vendor/pristine/<crate>.diff
# (the reviewed patch). Anything else fails and the offending paths are printed.
set -euo pipefail
cd "$(dirname "$0")/.."

offline=0 update=0 crates=()
for a in "$@"; do
  case "$a" in
    --offline) offline=1 ;;
    --update) update=1 ;;
    -*) echo "unknown option $a" >&2; exit 2 ;;
    *) crates+=("$a") ;;
  esac
done
PIN=vendor/pristine/crates.sha256
[ ${#crates[@]} -gt 0 ] || mapfile -t crates < <(grep -v '^#' "$PIN" | awk 'NF{print $1}')

# Paths allowed to exist only in the vendored tree (added by Argus).
extra_allowed() {
  case "$1" in
    btls-sys) echo "patches/argus-chrome-tls.patch" ;;
  esac
}
# Pristine paths (extended regex, anchored) allowed to be absent from the vendored tree.
missing_allowed() {
  case "$1" in
    # lockfile of the upstream workspace member, dropped on vendoring
    btls-sys) echo '^(Cargo\.lock|\.cargo_vcs_info\.json)$' ;;
    # only src/, Cargo.toml, LICENSE and README.md are kept (see vendor/README.md)
    *) echo '^(Cargo\.lock|\.cargo_vcs_info\.json|Cargo\.toml\.orig|(benches|examples|tests|\.github|\.cargo|fuzz)/.*|\.[^/]*|(rustfmt|clippy|deny|release-plz)\.toml|CHANGELOG\.md|[^/]*\.(yml|yaml))$' ;;
  esac
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "FAIL [$crate] $*" >&2; fail=1; }

index_path() {
  local n=$1 l=${#1}
  if [ "$l" -le 2 ]; then echo "$l/$n"; elif [ "$l" -eq 3 ]; then echo "3/${n:0:1}/$n"; else echo "${n:0:2}/${n:2:2}/$n"; fi
}

for crate in "${crates[@]}"; do
  read -r _ ver want < <(awk -v c="$crate" '$1==c' "$PIN")
  [ -n "${want:-}" ] || { bad "not pinned in $PIN"; continue; }
  f="$tmp/$crate-$ver.crate"
  got=""
  for c in "${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/"$crate-$ver.crate"; do
    [ -f "$c" ] && [ "$(sha256sum "$c" | cut -d' ' -f1)" = "$want" ] && { cp "$c" "$f"; got=cache; break; }
  done
  if [ -z "$got" ]; then
    curl -fsSL --retry 3 -o "$f" "https://static.crates.io/crates/$crate/$crate-$ver.crate" || { bad "download failed"; continue; }
  fi
  have=$(sha256sum "$f" | cut -d' ' -f1)
  [ "$have" = "$want" ] || { bad "crate sha256 $have != pinned $want"; continue; }
  if [ $offline = 0 ]; then
    idx=$(curl -fsSL --retry 3 "https://index.crates.io/$(index_path "$crate")" \
      | grep -F "\"vers\":\"$ver\"" | grep -o '"cksum":"[0-9a-f]*"' | head -1 | cut -d'"' -f4) || idx=""
    [ "$idx" = "$want" ] || { bad "crates.io index checksum '${idx:-unavailable}' != pinned $want"; continue; }
  fi
  P="$tmp/p-$crate"; mkdir "$P"
  tar -xzf "$f" -C "$P" --strip-components=1
  V="vendor/$crate"

  # symlinks anywhere in the vendored tree
  while IFS= read -r l; do bad "symlink: $l"; done < <(find "$V" -type l)
  # files on only one side
  (cd "$P" && find . -type f | sed 's|^\./||' | sort) > "$tmp/pl"
  (cd "$V" && find . -type f | sed 's|^\./||' | sort) > "$tmp/vl"
  allowed_extra=$(extra_allowed "$crate"); allowed_missing=$(missing_allowed "$crate")
  while IFS= read -r p; do
    grep -Eq "$allowed_missing" <<<"$p" || bad "missing from vendor (not allowed): $p"
  done < <(comm -23 "$tmp/pl" "$tmp/vl")
  while IFS= read -r p; do
    grep -Fxq "$p" <<<"$allowed_extra" || bad "extra in vendor (not allowed): $p"
  done < <(comm -13 "$tmp/pl" "$tmp/vl")
  # exec bit differences and content differences of the common files
  : > "$tmp/d"
  while IFS= read -r p; do
    if [ -x "$P/$p" ] && [ ! -x "$V/$p" ] || [ ! -x "$P/$p" ] && [ -x "$V/$p" ]; then bad "exec bit differs: $p"; fi
    cmp -s "$P/$p" "$V/$p" || diff -u --label "a/$p" --label "b/$p" "$P/$p" "$V/$p" >> "$tmp/d" || true
  done < <(comm -12 "$tmp/pl" "$tmp/vl")
  exp="vendor/pristine/$crate.diff"
  if [ $update = 1 ]; then cp "$tmp/d" "$exp"; echo "updated $exp"; continue; fi
  if ! diff -u "$exp" "$tmp/d" > "$tmp/dd"; then
    bad "content differs from the reviewed patch $exp; offending files:"
    grep '^+++ b/' "$tmp/dd" | sed 's/^+++ /  /' >&2 || true
    grep -h '^[-+]' "$tmp/dd" | grep -v '^\(---\|+++\)' | head -20 >&2
    # also list changed paths directly
    diff -rq "$P" "$V" 2>/dev/null | grep -v '^Only in' | sed 's/^/  /' >&2 || true
  fi
  [ $fail = 0 ] && echo "ok   $crate $ver (sha256 $have, $(wc -l < "$tmp/pl") pristine files, $(grep -c '^+++ ' "$tmp/d") patched)"
done
[ $fail = 0 ] && echo "vendor verification passed" || { echo "vendor verification FAILED" >&2; exit 1; }
