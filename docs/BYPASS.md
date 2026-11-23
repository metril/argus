# Bypass

Some sites should never be intercepted: banking, health, government, password managers, OS
updates and certificate-pinned apps. **Bypass** excludes hosts from TLS interception, in both
explicit (CONNECT) and transparent (SNI) mode.

Each entry is a pattern (an exact host, or `*.suffix` for subdomains only), a mode and a source.

| Mode | What the proxy does |
|---|---|
| `no_decrypt` | Tunnels without MITM. Host-level blocking rules still apply, and a `passthrough` event (host only) goes to the request log. |
| `full` | No MITM, no filtering, no log event; only the aggregate `bypassed_total` counter in `/stats/proxy`. Plain-HTTP requests to the host are forwarded unfiltered too. |

Sources, in precedence order: `custom` (and `migrated`) entries, then `sub:<id>` subscriptions,
then the first-party `argus:<category>` lists. For the same pattern at the same level the stricter
mode (`no_decrypt`) wins.

## First-party lists (nothing is bundled)

The curated categories (`banking_finance`, `payments`, `health`, `government`,
`password_managers`, `os_updates`, `pinned_apps`) are **not** part of the binary. They are
published as signed release assets of [metril/argus-lists](https://github.com/metril/argus-lists)
and the proxy subscribes to them by default (source `argus:<category>`, fetched from
`https://github.com/metril/argus-lists/releases/latest/download/<id>.txt`).

* **Verified before use.** Every file (and `meta.json`) must carry a valid minisign (Ed25519)
  signature for the public key compiled into the binary (`ARGUS_LISTS_PUBLIC_KEY`, currently a
  placeholder). `meta.json` also carries each list's SHA-256, so a validly signed but mismatched
  file is refused. `bypass.lists_public_key` and `bypass.lists_base_url` in the config override the
  key and location (testing, internal mirrors).
* **Cached, never downgraded.** The last good verified copy is kept in `argus-lists/` next to the
  settings (re-verified at every start). A release older than the installed one is never
  installed. Fetching starts when the server starts, retries with backoff until it succeeds and
  then checks every few hours; `POST /bypass/argus-lists/refresh` checks now.
* **Categories** are switches over those subscriptions: `GET /bypass/categories`, `PUT
  /bypass/categories/{id}` (`enabled`, `mode`), `GET /bypass/categories/{id}/hosts?q=`. Every
  category defaults to `no_decrypt` (as in AdGuard); any category, entry or subscription can be
  `full`. `GET /bypass/argus-lists` reports `{version, updated_at, last_checked, last_error,
  categories}`. Settings of the former embedded categories migrate into the subscriptions
  (switch and mode carry over; a mode still at the old `full` default becomes `no_decrypt`).

### Fail-safe

Until **every enabled** `argus:*` list has loaded at least once (from the network or the verified
cache), the proxy decrypts nothing: all HTTPS is tunnelled, hostname/SNI blocking still applies,
and the passthrough events carry `rule: failsafe`. When the lists load, decryption turns on live.
`GET /bypass/settings` and `/stats/proxy` show `failsafe {active, reason}`. The admin override
`decrypt_without_lists` (`PUT /bypass/settings`, default off, live, audited) decrypts anyway.

## Extended Validation certificates

With `ev_no_decrypt` on (the default; `GET`/`PUT /bypass/settings`, applied live) the proxy looks
at the upstream server's leaf certificate before decrypting and tunnels sites whose certificate
carries an EV policy (CA/B Forum 2.23.140.1.1 and the well-known CA-specific EV OIDs), with a
passthrough event whose `rule` is `ev`. The verdict is cached per host for 30 minutes, so only the
first connection pays for the extra handshake. Bypass entries take precedence.

## Custom entries and subscriptions

* **Custom entries** (`/bypass/entries`, cursor-paged with `counts.letters`) and **subscriptions**
  to external exclusion lists (`/bypass/subscriptions`; one host or `*.suffix` per line, `#`, `!`
  and `//` comments skipped, fetched with the filter lists' size limit and refresh schedule; a bare
  domain in a list also covers its subdomains) are kept in `bypass.json` next to the settings
  overlay (`/app/data` in the container).
* `GET /bypass/subscriptions/suggested` lists one-click subscriptions to AdGuard's
  [HttpsExclusions](https://github.com/AdguardTeam/HttpsExclusions) lists (banks, sensitive,
  issues, android, firefox, mac, windows); `POST /bypass/subscriptions` with
  `{"suggested_id": ...}` subscribes. They are fetched at runtime, never bundled.
* The old `proxy.tls_passthrough_hosts` setting is migrated into `migrated` entries
  (`no_decrypt`) the first time the proxy starts, and keeps working: changing the setting
  replaces those entries.

### Too-broad patterns

Single-label names and patterns that cover a whole public suffix (`com`, `*.com`, `co.uk`,
`*.co.uk`, per the Public Suffix List) are refused from every source: custom entries get a 400,
and list lines are skipped. The government namespaces (`*.gov`, `*.mil`, `*.gov.uk`, `*.nhs.uk`,
...) are allowed by a compiled-in list; the first-party lists' signed `meta.json` may add more
via `allowed_wildcards`, but only entries that are `*.` plus a public suffix of two or more labels
(or `*.gov` / `*.mil`) count, and only for first-party lists. Skipped lines are reported as
`skipped_lines` and `skipped_sample` (not as `last_error`, which is for real failures).

`GET /bypass/check?host=` says which source decides for a host. Everything applies live and every
change is audited. Scopes: `config:read` / `config:write`.
