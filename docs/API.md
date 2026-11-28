# API

Everything is under `/api/v1`. The machine-readable spec is served at
`/api/v1/openapi.json` (a committed snapshot lives in `docs/openapi.json`) and an interactive
reference at `/api/v1/docs`. The spec is generated from the same declarations that register the
routes, and tests fail if the snapshot, the route table or the scope declarations drift.

## Authentication

- **API token** (scripts, integrations): `Authorization: Bearer abk_<id>_<secret>`.
- **Session cookie** (the web UI): `POST /auth/login` sets `access_token` / `refresh_token`
  (httpOnly) and a readable `csrf_token` cookie. Unsafe methods (POST, PUT, PATCH, DELETE) must
  echo it in an `X-CSRF-Token` header; Bearer requests are exempt.

The first account is created with `POST /auth/register` and becomes the administrator;
registration then closes and administrators add accounts with `POST /users`.

### Creating a token

```
curl -X POST http://host:3000/api/v1/tokens \
  -H 'Content-Type: application/json' -H 'X-CSRF-Token: <csrf_token cookie>' \
  --cookie 'access_token=<jwt>' \
  -d '{"name":"ci","scopes":["lists:read","stats:read"],"expires_in_days":90}'
```

The response contains `secret` exactly once; only a digest is stored. A token can never hold a
scope its creator lacks, and its power shrinks if the creator is demoted or disabled. Revoking
(`DELETE /tokens/{id}`) takes effect on the next request. Optional `profiles` restricts a token to
the given profile ids (see "Profiles, devices and restricted tokens").

Expiry: `expires_in_days` (1 to 3650) or `expires_at` (RFC 3339, must be in the future), not both;
omit both for a token that never expires. Optional `purpose` (`extension`, `monitoring`, `script`,
`full`, `read_only`, `custom`; default `custom`) is a label for the UI and grants nothing. Profile ids
must exist. Token info carries `purpose`, `secret_hint` (token id and the last four characters,
never enough to rebuild the secret), `last_used_at`, `last_used_addr`, `updated_at` and, while an
old secret is still accepted, `prev_valid_until`.

### Editing and regenerating

`PATCH /tokens/{id}` (`tokens:self`; `PATCH /admin/tokens/{id}` with `tokens:admin`) changes
`name`, `scopes`, `profiles` (or `clear_profiles`), `purpose` and expiry (`expires_in_days`,
`expires_at` or `never_expires`; one of them). Absent fields stay. Scopes and profiles are checked
like on creation: the caller must hold every scope and cannot widen the profile restriction, so a
token can be narrowed but never widened beyond what the caller holds.

`POST /tokens/{id}/regenerate` `{grace_secs?}` (0 to 604800, default 0) issues a new secret for the
same token id and settings and returns it once. The old secret keeps working for `grace_secs`, then
stops. Revoking the token ends both secrets. Both calls are audited.

A token (not a session) calling these routes can act only on a token whose scopes, unknown scopes
and profile restriction are within its own (403 `token_outside_grant`), and cannot give a token a
lifetime beyond its own (403 `expiry_outside_grant`; `never_expires` is refused when the caller
expires). An expired token cannot be edited (409 `token_expired`); regenerate it with a new expiry
(`expires_in_days`, `expires_at` or `never_expires`, required for an expired token and optional on
a live one, where it replaces the expiry). A revoked token cannot be revived.

Compatibility: stored tokens that carry the new `bypass:site` scope are not readable by releases
before this one (an older release skips a record with an unknown scope, so the token disappears
from its list and can no longer be revoked there). From this release on, scope names the release
does not know are kept verbatim (`unknown_scopes` in the token info), grant nothing, and the token
still loads, lists and can be revoked.

### Browser extension sign-in

`POST /auth/extension-token` `{username, password, browser, replace_token_id?}` checks the
credentials like login (same rate limit, no session, no cookies) and returns
`{token, token_id, user}`: a never-expiring token named `Extension · {browser}` with exactly
`userscripts:bridge`, `rules:site`, `rules:ext`, `bypass:site`, `logs:read` and `stats:read`. 401 for wrong credentials, 403 `insufficient_role` when the
role lacks either scope. `replace_token_id` revokes that token if it is the caller's own (anyone
else's id is ignored). `DELETE /tokens/self` lets any API token revoke itself (400 for a cookie
session). Both routes accept extension origins (CORS); `GET /downloads/extension/chrome` adds an
`argus.json` with this server's address to the zip.

## Scopes

Every route declares the one scope it requires; routes without a declaration are denied. Roles are
bundles of scopes (table below), so a session's permissions are its role's scopes.

<!-- scopes:start -->
| Scope | Viewer | User | Admin | Description |
|---|---|---|---|---|
| `lists:read` | yes | yes | yes | View filter lists, their status and the update schedule. |
| `lists:write` | - | yes | yes | Add, edit, remove and refresh filter lists; change the update schedule. |
| `rules:read` | yes | yes | yes | Read custom rules; validate rules and test URLs against the engine (no changes). |
| `rules:write` | - | yes | yes | Replace the custom rules. |
| `rules:site` | - | yes | yes | Switch ad blocking off or on for a single site (a document exception in the custom rules); nothing else in the rules. |
| `rules:ext` | - | yes | yes | Add or remove one custom rule at a time through the browser extension (a single validated line); nothing else in the rules. |
| `bypass:site` | - | yes | yes | Stop Argus decrypting a single site (a no-decrypt bypass entry made through the browser extension); nothing else in the bypass lists. A profile-restricted token can only read it, unless it includes the default profile. |
| `engine:reload` | - | - | yes | Trigger a rebuild of the blocking engine. |
| `stats:read` | yes | yes | yes | Read blocking, proxy and engine statistics. |
| `logs:read` | - | yes | yes | Read the request log, live and recent (full browsing history of every client the token may see). |
| `stats:reset` | - | - | yes | Reset blocking statistics. |
| `config:read` | yes | yes | yes | Read the proxy configuration. |
| `config:write` | - | - | yes | Change or reload the proxy configuration. |
| `ca:read` | yes | yes | yes | Read CA certificate details (fingerprint, expiry, subject). |
| `ca:admin` | - | - | yes | Manage the CA certificate (reserved). |
| `scripts:read` | yes | yes | yes | View userscripts and their source. |
| `scripts:write` | - | yes | yes | Install, update, enable, disable and remove userscripts; view and clear their stored values. |
| `userscripts:bridge` | - | yes | yes | Connect the browser extension to userscripts: list and trigger a page's menu commands, and let approved scripts use this browser's logins. |
| `policy:read` | yes | yes | yes | View script policy rules, explanations, temporary permissions and blocked-source reports. |
| `policy:write` | - | yes | yes | Change script policy settings, rules and temporary permissions; import policy. |
| `profiles:read` | yes | yes | yes | List and view filtering profiles (lists and overlay rules) the token may access. |
| `profiles:write` | - | - | yes | Create, edit and delete filtering profiles. |
| `devices:read` | yes | yes | yes | List and view devices (profile, addresses, token state; never the token). |
| `devices:write` | - | - | yes | Create, edit and delete devices; issue and revoke device tokens. |
| `users:read` | - | - | yes | List and view user accounts. |
| `users:admin` | - | - | yes | Create, update, disable and delete user accounts. |
| `tokens:self` | - | yes | yes | Create, list and revoke your own API tokens. |
| `tokens:admin` | - | - | yes | List and revoke any user's API tokens. |
| `sessions:self` | yes | yes | yes | Log out, change your password, list and revoke your own sessions. |
| `sessions:admin` | - | - | yes | List and revoke any user's sessions. |
| `audit:read` | - | - | yes | Read the audit log. |
| `system:read` | yes | yes | yes | Read system status and metrics (JSON and Prometheus). |
<!-- scopes:end -->

## Errors

Every failure uses one envelope with a stable `code`:

```json
{ "error": { "code": "validation_failed", "message": "Request validation failed",
             "details": [ { "field": "username", "code": "length", "message": "..." } ] } }
```

Codes: `unauthorized` (401), `forbidden`, `insufficient_scope`, `scope_escalation`, `csrf_failed`
(403), `not_found` (404), `already_exists`, `last_admin`, `registration_closed` (409/403),
`validation_failed`, `invalid_body`, `invalid_query`, `bad_request`, `invalid_fetch_url`,
`fetch_destination_not_allowed` (400; a list URL that is not http(s) or points at a private,
loopback or link-local destination, see the README's fetch policy),
`precondition_failed` (412), `precondition_required` (428), `rate_limited` (429),
`internal_error` (500). Responses carry an `X-Request-Id` (a client-supplied one is echoed).

## Pagination

Every list endpoint takes `?page=1&limit=50` (limit 1..=200) and returns
`{ "items": [...], "total": n, "page": 1, "limit": 50, "has_more": false }`.
Prefer cursor paging: pass the response's `next_cursor` back as `?cursor=` (absent on the last
page). A cursor stays correct while rows are added or removed between requests; `page` is the
older offset form of the same list. Cursor-paged lists: users, sessions, tokens, profiles
(`q`), devices, site and source rules, bypass entries and category hosts, filter lists,
`/rules/ext` (`q`, `list`, `kind`), audit (`actor`, `action`, `q`, `since`, `outcome`;
newest first) and a userscript's storage (`q`, with `total`).

Details: `/rules/ext` cursors name the engine build; after a rebuild the old cursor gets `409`
`ext_rules_changed` and the client restarts from the first page. Audit `total` is exact for an
unfiltered query and otherwise a lower bound taken on the first page; pages fetched with a
cursor repeat that first-page value. An audit page may be short or empty yet still carry
`next_cursor` when the scan budget ran out; keep following it. Bypass hosts and userscript
storage accept `limit` up to 1000 (defaults 200 and 1000, so clients that send neither see
what they always did); other lists cap at 200.

## Concurrency control

`GET /config` and `GET /rules/custom` return an `ETag`; the matching `PUT` requires it in
`If-Match` (`428` if absent, `412` if stale).

## Rate limits and CORS

Limits are per client IP, per user session / API token, and stricter per IP for login, register
and refresh. `X-Forwarded-For` is honored only from `trusted_proxies`. CORS is same-origin only
unless `cors_origins` lists allowed origins. Session cookies get `Secure` per `webui.cookie_secure`
(`auto` by default: only when a trusted proxy reports `X-Forwarded-Proto: https`).

Failed logins are indistinguishable (same status, body and bcrypt work) whether the user is unknown,
disabled or the password is wrong.

## Lists, reports and the engine

- `POST /lists`, `PUT /lists/{id}`: besides `name`, `url`, `enabled`, accept `format` (`auto` by
  default; see the README's format table), `allowlist` and `trusted` (default false). A trusted
  list's `$replace`, `$urltransform`, `#%#`, snippet and unknown-scriptlet rules are active; for
  other lists they are dropped at build time. Changing `trusted` needs `lists:write` like every
  list edit and is recorded as its own audit entry (route `/api/v1/lists/{id}#trusted=<bool>`);
  it triggers a rebuild (trust is part of the engine cache key). Every list DTO carries `trusted`.
- `GET /engine/status`: besides the build state it reports `scriptlet_resources` (resources
  served) and `scriptlet_resources_dropped` (name and reason of each resource of the library that
  failed validation and is not served: syntax error, unresolved dependency). Scriptlets that
  `requiresTrust` (uBO's `trusted-*`) only run for rules of trusted lists.
- `GET /lists/{id}/report`, `GET /rules/custom/report`: `ListReport` of the last build (detected
  format, network/cosmetic/ext/skipped/deduped/rejected counts, first parse issues, header metadata,
  content SHA). `conversion_errors` (lines that are not rules) and `rejected` (rules the engine's
  compiler refused) are separate; `error_count` is their deprecated sum. Each `issues` entry has
  the source `line` (the `!#include` line for included rules), the `rule` text, the `reason` and
  the `stage` (`conversion` or `compile`). `ext_states` splits the extended rules by what the
  extended-rule index made of them (`ext_enforced`, `ext_unsupported`, `ext_invalid`,
  `ext_needs_trust` are the usual four). `redundant_count` (`deduped + compressed`) and
  `redundant` say a list adds nothing of its own. `attention` is set only by invalid rules
  (conversion errors, compiler rejections, malformed extended rules) reaching 1% of the list's
  rules, rounded up, at least one; unsupported, not-enforced and needs-trust rules are counted
  apart and never set it; the list feed's `attention` also covers a failed fetch and a stale or never fetched list.
- `GET /lists/{id}/lines?status=&q=&cursor=&limit=&profile=` (and `GET /rules/custom/lines`, which
  needs `rules:read` like `GET /rules/custom`): every source line of the list's cached text with
  the build's verdict: `comment`, `inactive` (false `!#if` branch),
  `network`, `cosmetic`, `extended` (with `kind`, `state`, `reason`), `duplicate` / `covered`
  (with the `list` that already provides it), `disabled` (a domain rule a `$badfilter` rule switches off; for engine rules the build keeps no
  per-rule record of `$badfilter`, so those show as `network`), `unsupported`, `invalid` (with
  `stage`). `profile` judges against that profile's engine and list set (its own rules for the
  custom route). `q` is at most 256 characters. Extended rules are judged per list. Line numbers
  are source lines; an `!#include`'s rules carry the include line. `status` is a comma-separated
  set (the names above, extended-rule states, or the groups `issues`, `applied`, `ignored`), `q` a
  case-insensitive substring of the rule. `counts` covers the whole list whatever the filter.
  A list that is disabled or changed since the last build is judged on its own (`in_build`
  false). The cursor names the build and the text; a stale one gets `409 lines_changed`.
- `GET /engine/build`: `BuildSummary` with the build state (`idle`, `fetching`, `compiling`,
  `failed` with the error; a failed build leaves the previous engine serving), last build duration
  and time, domain-set size and handed-off rule counts per kind. `ext_stats` reports what the
  extended-rule index did with them: per kind `parsed`, `active`, `dropped_untrusted`,
  `unsupported`, `parse_errors`, `badfiltered`; `dropped_untrusted_by_list`; the first parse
  `issues` and how many more were `issues_truncated`.
- `GET /lists/catalogue`, `POST /lists/catalogue/{id}`: browse the signed argus-lists catalogue
  and add an entry as an enabled list. It is the verified release, or the signed snapshot shipped
  with the binary until one has loaded; nothing is compiled in. The response is an object
  `{source, version, fetched_at, entries}`; each entry carries `description`, `homepage`,
  `region`, `noncommercial`, `licence_note`, `trusted`, `default_enabled` (recommended: installed
  once on a fresh install) and `installed`. Every list, including seeded ones, can be removed with
  `DELETE /lists/{id}` and is not added back.
- `GET /rules/ext?kind=`: paginated read-only listing of handed-off rules, each with its source
  `list` and `state`: `active`, `dropped_untrusted`, `unsupported` (with `reason`), `invalid`,
  `badfiltered`, `badfilter`, or `unknown` while a rebuild is being installed.
- `POST /rules/validate`: `{rules, format?, allowlist?, trusted?}` runs the same classifier as
  `/lists/{id}/lines`, standalone, so each line gets the verdict a build would give it
  (`!#if` branches, duplicates among the lines and trust included): `translated`, `accepted`,
  `handed_off` (with its `state`), `duplicate`, `skipped` or `rejected`. `trusted` defaults to
  false; pass `true` to judge the custom rules, which are built trusted.

## Per-site no-decrypt (browser extension)

`GET|PUT|DELETE /bypass/sites/{host}` back the extension's "Don't decrypt this site". Each needs
`bypass:site` or `config:write` (`config:read` alone is refused with 403 `insufficient_scope`). The
bypass list is global, so a profile-restricted token may only `GET`; `PUT` and `DELETE` give 403
`profile_restricted` unless its profiles include the default profile `0`. `bypass:site` opens
nothing else in the bypass list. At most 1000 extension entries exist: past that, `PUT` is `409`
`site_bypass_limit` (remove entries on the Bypass page).

- The host is normalised (lowercase, trailing dot dropped, IDNA to ASCII) and must be a registrable
  host name or an IP address: no scheme, port, path, wildcard or empty label, no single label or
  public suffix, no loopback, link-local, `localhost`, `.local`, `.internal` or `.arpa`, and not
  Argus's own host. Anything else is `400`.
- `GET` answers `{host, bypassed, mode, source, name, removable, ev_auto_tunnel}`. `source` is
  `extension`, `manual`, `category` (`name` is its title), `subscription` (its name), `failsafe`
  (the Argus lists have not loaded: HTTPS is tunnelled) or `none`. It is the lookup the proxy uses
  for that host. Extended Validation sites are tunnelled on top of this when `ev_auto_tunnel` is
  on; the certificate is only known at connection time.
- `PUT` adds a `no_decrypt` entry with source `extension` for exactly that host. A plain entry does
  not cover subdomains (`*.host` does, and is not made here). Idempotent; a host something else
  already bypasses gets no duplicate and the current state is returned.
- `DELETE` removes only that extension entry (200 with the state afterwards, also when there is
  none). If a manual entry, subscription or category is what bypasses the host: `409`
  `not_extension_entry`.
- Changes apply live like `/bypass/entries`; open connections are not dropped. They are audited
  (actor, token, host as target), and the entry's note names who added it.

## Recently blocked requests

`GET /stats/blocked/recent` reads the engine's bounded ring (newest first, paginated) and filters by
`client` (profile label), `host` (host or subdomains) and `list_id`. Entries carry the URL, source
host, request type, matched rule, list id (for domain-set hits) and client label. Requires
`stats:read`. URLs are stored without their query string and fragment unless
`adblock.recent_blocked_keep_query` is set. The ring size is `request_log_capacity` in
`GET /config` / `PUT /config` (100 to 500000, default 1000; about 1 KB per entry in each of the two
rings). A change applies at once, keeps the newest entries when it shrinks and does not disturb
live streams. `GET /system/metrics` also reports `storage`
(`deferred_dropped`, `deferred_failed`, `deferred_queued`) for the background database writer.

## Userscripts

Routes take `?profile=<id>` (default `0`). Writes are audited.

| Method and path | Scope | Purpose |
|---|---|---|
| `GET /userscripts`, `GET /userscripts/{id}`, `/source`, `/stats` | `scripts:read` | List, inspect, source, counters. |
| `POST /userscripts` | `scripts:write` | Install directly from `source` (no dependencies fetched, no `@connect *` approval). |
| `POST /userscripts/plan` | `scripts:write` | Body `{source}` or `{url}`: parse, fetch `@require`/`@resource` (integrity hashes verified, size capped, control-plane fetch policy) and return a plan summary with `plan_id` (grants, connect, matches, `broad_match`, `connect_all`, capability flags, warnings, dependencies, `already_installed`). Plans live 15 min in memory (max 32). |
| `POST /userscripts/plan/{plan_id}/confirm` | `scripts:write` | Body `{allow_connect_all?, browser_cookies?, enable?}` installs the plan (201). `allow_connect_all` only for scripts declaring `@connect *`; `browser_cookies` (use the browser's logins through the extension) only for scripts with a network or cookie grant. 404 unknown/expired plan, 409 already installed. |
| `POST /userscripts/{id}/check-update` | `scripts:write` | Body `{apply?}`. Fetches the update URL; result `up_to_date`, `updated` (only with `apply`, and only if the update does not widen `@match`/`@connect`/`@grant`) or `pending_approval` (stored on the script, returned with its diff). |
| `POST /userscripts/{id}/update/approve` | `scripts:write` | Apply the pending update (`{allow_connect_all?, browser_cookies?}`). |
| `POST /userscripts/{id}/approve` | `scripts:write` | Approve an imported script (`{allow_connect_all?, browser_cookies?}`); both flags only while it awaits approval (`409 not_pending_approval` otherwise). |
| `DELETE /userscripts/{id}/update` | `scripts:write` | Discard the pending update. |
| `GET /userscripts/{id}/storage` | `scripts:write` | Stored GM values: `used_bytes`, `quota_bytes`, per value name, size and 200-char preview. |
| `DELETE /userscripts/{id}/storage`, `/storage/{name}` | `scripts:write` | Clear all values or one. |
| `GET /userscripts/export?values=` | `scripts:read` | JSON bundle `argus-userscripts-v1` (sources, enabled, `@connect *` approval, fetched dependencies). `values=true` adds stored values, which may hold secrets, and needs `scripts:write`. JSON only (no zip). |
| `POST /userscripts/import` | `scripts:write` | Import a bundle (max 16 MiB), `on_conflict` `skip` (default) or `replace`; per-script results `{id,name,status,error?}`. |

Config (`[userscripts]`): `update_check_interval_hours` (0 = off, default) schedules checks of every
script with an update URL; `auto_apply_updates` (default false) applies found updates only when they
do not widen `@match`/`@connect`/`@grant`. Installing from a `.user.js` URL is `POST /userscripts/plan`
with `url`; there is no proxy interception.

## Extension bridge

Used by the browser extension (`docs/USERSCRIPT-PROTOCOL.md` section 8). `/ext/menu*` need a token
(not a cookie login) with `userscripts:bridge` and the header `X-Argus-Session: <sid>` of one of
that token's live channel sessions; the document must be bound to that session. A profile-restricted
token may use them: the binding already limits it to its profiles.

| Method and path | Scope | Purpose |
|---|---|---|
| `GET /ext/channel` | public at HTTP level | WebSocket; the first frame `{"t":"hello","token","v":1}` authenticates (token with `userscripts:bridge`). Only from an extension origin. 503 without a bridge. |
| `GET /ext/menu?mdoc=` | `userscripts:bridge` | Menu commands of a bound document, and host grants its scripts wait for. 403 `ext_session_required` / `ext_document_not_bound`, 404 unknown document. |
| `GET /ext/log?since=` | `logs:read` | The calling session's requests (blocks and allowed, full URL with query, type, first/third party, outcome `blocked`/`allowed`/`redirected`/`modified`/`aborted`, rule, list id and name, page host), oldest first, entries after `since`; `{next, entries}`. Needs `X-Argus-Session`; another session's requests are never returned. Newest 1000 kept per session. |
| `POST /ext/rules` | `rules:ext` | Body `{op:"add"\|"remove", rule}`: one network rule line (at most 2 KB) or one plain element-hiding rule `domain##selector` (at most 1 KB; registrable domains, no procedural/extended syntax, exceptions or scriptlets; a rule for all sites needs an id, class or attribute value in the selector); no comments, includes, preprocessor, scriptlet, `$replace`/`$csp` rules appended to or removed from the custom rules; audited, rebuilds the engine; `{rule_count, changed}`. Opens nothing else in the rules. |
| `GET /ext/rules?site=` | `rules:ext` | The custom rules that mention the site; `{site, rules}`. |
| `POST /ext/menu/trigger` | `userscripts:bridge` | Body `{mdoc,script,cmd}`: queue a synced command for the page; `{delivered}`. |

## Script policy and the in-page panel

Routes under `/api/v1/policy` (scopes `policy:read` / `policy:write`); see `docs/SCRIPT-POLICY.md`
for the model. Routes take `?profile=<id>` (default `0`) and writes are audited.

| Method and path | Scope | Purpose |
|---|---|---|
| `GET`, `PUT /policy/settings` | read / write | Master switch (off by default), global preset, default profile, strip mode, network hints. |
| `GET`, `POST /policy/site-rules`, `PUT`, `DELETE /policy/site-rules/{id}` | read / write | Per-site presets. |
| `GET`, `POST /policy/source-rules`, `PUT`, `DELETE /policy/source-rules/{id}` | read / write | Per-page source allow/deny rules (the matrix). |
| `GET`, `POST`, `DELETE /policy/temp`, `DELETE /policy/temp/{id}` | read / write | Temporary grants (TTL, until restart, optionally persisted). |
| `GET /policy/explain?url=`, `POST /policy/preview` | read | The CSP, HTML actions and hints for a URL; before/after for a proposed change. |
| `GET /policy/export`, `POST /policy/import` | read / write | JSON document; temporary grants are not exported. |
| `GET /policy/reports?site=` | read | Blocked sources per page for one-click allow, fed by the proxy's blocks and the browsers' violation reports of the policy the proxy added. |
| `GET`, `PUT /policy/panel` | read / write | In-page panel: `enabled` (per profile, off by default), `hotkey` (default `Alt+Shift+A`; modifiers plus one key, with Alt, Ctrl or Meta), `menu_button` (`off`, `on_demand` default, `always`: corner button for userscript menu commands, independent of `enabled`), `auth` (`pin` default, `session`, `none`), `pin` (4 to 64 characters; write-only, `pin_set` says whether one is set), `clear_pin`. Returns `reserved_host`. |
| `GET /rules/site-exceptions` | `rules:read` | Sites with ad blocking switched off. |
| `GET`, `PUT`, `DELETE /rules/site-exceptions/{site}` | `rules:site` or `rules:write` | Switch ad blocking off or on for a site (a host name, lowercase punycode). Stored as custom rules (`@@$domain=site` plus the sentinel `\|\|adblock.invalid^`), so they appear in `GET /rules/custom`. |

Deployment settings are in `[script_control]` (`panel_enabled`, `panel_host`, `dashboard_url`). The
panel's own endpoints (`/__adblock__/panel/state`, `/__adblock__/pv`, and the reserved host) are
proxy-internal and are not part of this API.

## Profiles, devices and restricted tokens

A profile is a named set of enabled filter lists plus overlay rules; profile `0` is the built-in
`default` profile (the global lists and custom rules), which cannot be renamed or deleted. A
device selects a profile by address or CIDR prefix, or by a device token. Ids are decimal strings.

| Method and path | Scope | Purpose |
|---|---|---|
| `GET`, `POST /profiles` | `profiles:read` / `profiles:write` | List / create (`name`, `description`, `lists`, `rules`). |
| `GET`, `PUT`, `DELETE /profiles/{profile_id}` | read / write | Get / update (omitted fields unchanged) / delete. Delete returns 409 while devices use the profile. |
| `GET`, `POST /devices` | `devices:read` / `devices:write` | List / create (`name`, `profile_id`, `ips`). |
| `GET`, `PUT`, `DELETE /devices/{device_id}` | read / write | Get / update name, profile or addresses / delete. |
| `POST /devices/{device_id}/token` | `devices:write` | Issue a token (replaces the current one). The response, `201 {"token": ...}` with `Cache-Control: no-store`, is the only place it ever appears. Use it as `http://device:<token>@<proxy-host>:<port>`. |
| `DELETE /devices/{device_id}/token` | `devices:write` | Revoke the token. |

Errors: 400 (malformed id, invalid name, list, address or rules, or the default profile), 403
(restricted token), 404, 409 (duplicate name or address, profile in use). Devices expose only
`has_token` and `token_hint` (last 4 characters); no response, audit entry or log carries a token
or its digest.

**The `profile` parameter.** Script policy (`/policy/*`), userscripts (`/userscripts/*`, including
storage) and `/rules/site-exceptions/*` operate on one profile, chosen with `?profile=<id>`
(default `0`). Site exceptions of a non-default profile edit that profile's overlay rules. A
malformed id is 400, an unknown one 404. A userscript plan can only be confirmed under the profile
it was planned for.

**Restricted tokens.** A token created with `profiles: [...]` can use only those profiles.
Enforcement is one extractor (`ProfileParam`) on every profile-scoped route: another profile, or
the default profile when `0` is not listed, is 403 `profile_forbidden`. Such a token lists only its
profiles and the devices assigned to them, cannot create profiles, and cannot create a device in
or move one to a profile it lacks. It may add an address or prefix to a device only when it lies
inside a range already assigned to a device of its own profiles, and never one that contains or lies
inside another profile's device range (403 `profile_restricted`); it cannot claim unassigned
addresses (which fall to `default`). Nested prefixes (a /32 inside another device's /24; the longest
match wins) are a deliberate feature of unrestricted tokens only; an identical address on two devices
is 409. A token minted by a restricted token inherits its restriction
when none is given and may only narrow it (wider is 403 `scope_escalation`). Global resources are
not profile-scoped, so for restricted tokens: every write is 403 `profile_restricted` (lists,
custom rules, config, engine, stats reset, users, CA, admin routes); reads of lists, config, stats,
system status and CA info are allowed, but `GET /stats/blocked/recent` returns only blocks of the
token's profiles (`client` is the profile id) and `GET /stats/filter` omits `top_blocked_domains`; `GET /rules/custom` needs access to profile `0`; users,
audit and admin reads are refused. Managing the token's own tokens and sessions stays allowed.
