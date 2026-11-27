#!/usr/bin/env bash
# Local entry point for one parity shard.
#   scripts/adblock-parity/run.sh --blocker X --browser Y [--proxy host:port] [--ca root-ca.crt] [--sites a,b] [--out f.json]
# blocker: none | argus | ubol (chrome) | ubo (firefox) | adguard-ext | adguard-desktop (Windows runner, chrome)
# browser: chrome | firefox
# argus needs --proxy and --ca (the Argus root CA, e.g. `docker exec argus-proxy cat /app/certs/root-ca.crt`).
# Environment: CHROME_PATH (default /usr/bin/google-chrome if present, else Playwright's Chromium),
#              FIREFOX_BIN, ARGUS_PROXY, ARGUS_CA.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
case "${1:-}" in -h|--help|"") sed -n '2,9p' "${BASH_SOURCE[0]}"; exit 0;; esac
[ -d node_modules/playwright-core ] || npm ci --no-audit --no-fund
exec node run.mjs "$@"
