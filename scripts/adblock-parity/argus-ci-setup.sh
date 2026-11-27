#!/usr/bin/env bash
# Prepares a freshly started Argus container for the parity run: waits until it is healthy, creates the
# first admin, switches the filter lists to the uBOL-equivalent default set (uBlock filters, badware,
# privacy, quick-fixes, unbreak, EasyList, EasyPrivacy, Peter Lowe's, uBO's urlhaus-1) plus AdGuard Windows' defaults
# (AdGuard Base, Tracking Protection, URL Tracking, Mobile Ads), waits for the engine build and
# downloads the root CA.
#   argus-ci-setup.sh <web-ui-base-url> <ca-out-file>      e.g. http://127.0.0.1:3000 /tmp/argus-ca.crt
# LIST_SET_REGEX overrides which list names stay enabled (case-insensitive extended regex).
set -euo pipefail
base="${1:?web ui base url}"; ca_out="${2:?ca output file}"
api="$base/api/v1"
keep="${LIST_SET_REGEX:-^(ublock.*(filters|badware|privacy|quick|unbreak)|easylist|easyprivacy|peter lowe|adguard (base|tracking protection|url tracking|mobile ads))}"
jar="$(mktemp)"; trap 'rm -f "$jar"' EXIT

for i in $(seq 1 90); do curl -fsS "$api/health" >/dev/null 2>&1 && break; sleep 2; [ "$i" = 90 ] && { echo "argus never became healthy" >&2; exit 1; }; done

pw="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)Aa1!"
body="{\"username\":\"parity\",\"password\":\"$pw\",\"password_confirm\":\"$pw\"}"
curl -fsS -c "$jar" -H 'Content-Type: application/json' -d "$body" "$api/auth/register" >/dev/null \
  || curl -fsS -c "$jar" -H 'Content-Type: application/json' -d "$body" "$api/auth/login" >/dev/null
csrf="$(awk '$6=="csrf_token"{print $7}' "$jar")"
call() { curl -fsS -b "$jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' "$@"; }

lists="$(call "$api/lists?limit=500")"
echo "$lists" | jq -r '.items[] | "\(.enabled)\t\(.name)"' | sed 's/^/before: /'
echo "$lists" | jq -c '.items[]' | while read -r l; do
  id="$(jq -r .id <<<"$l")"; name="$(jq -r .name <<<"$l")"
  if echo "$name" | grep -Eiq "$keep"; then
    trusted=false; echo "$name" | grep -Eiq "^(ublock|adguard)" && trusted=true
    call -X PUT -d "{\"enabled\":true,\"trusted\":$trusted}" "$api/lists/$id" >/dev/null
  else
    call -X PUT -d '{"enabled":false}' "$api/lists/$id" >/dev/null
  fi
done
# uBO's default-on urlhaus-1 (Online Malicious URL Blocklist). Not in Argus's catalogue (checked
# crates/filter-engine/src/list.rs), so it is added as a custom list with uAssets' contentURL for that id.
urlhaus='{"id":"urlhaus-1","name":"Online Malicious URL Blocklist","url":"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt","enabled":true,"format":"abp","allowlist":false,"trusted":false}'
call -X POST -d "$urlhaus" "$api/lists" >/dev/null || call -X PUT -d '{"enabled":true}' "$api/lists/urlhaus-1" >/dev/null
call -X POST "$api/lists/refresh" >/dev/null || true

# Engine ready: a build has completed, none is running, scriptlets loaded.
for i in $(seq 1 180); do
  s="$(call "$api/engine/status")"
  [ "$(jq -r '.building' <<<"$s")" = false ] && [ "$(jq -r '.build_count' <<<"$s")" -ge 1 ] && [ "$(jq -r '.scriptlets_ready' <<<"$s")" = true ] && break
  sleep 2; [ "$i" = 180 ] && { echo "engine never became ready: $s" >&2; exit 1; }
done
call "$api/lists?limit=500" | jq -r '.items[] | select(.enabled) | "enabled: \(.name) (\(.rule_count) rules)"'
curl -fsS "$api/ca.crt" -o "$ca_out"
grep -q 'BEGIN CERTIFICATE' "$ca_out"
echo "argus ready; CA written to $ca_out"
