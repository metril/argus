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
  content SHA).
- `GET /engine/build`: `BuildSummary` with the build state (`idle`, `fetching`, `compiling`,
  `failed` with the error; a failed build leaves the previous engine serving), last build duration
  and time, domain-set size and handed-off rule counts per kind. `ext_stats` reports what the
  extended-rule index did with them: per kind `parsed`, `active`, `dropped_untrusted`,
  `unsupported`, `parse_errors`, `badfiltered`; `dropped_untrusted_by_list`; the first parse
  `issues` and how many more were `issues_truncated`.
- `GET /lists/catalogue`, `POST /lists/catalogue/{id}`: browse the default-disabled catalogue and
  add an entry as a list. The catalogue is the signed argus-lists one once it has verified, else
  the built-in one. **Breaking change:** the response is now an object `{source, version,
  fetched_at, entries}` (`source` is `signed` or `builtin`), no longer a bare array; each entry
  also carries `description`, `homepage`, `region`, `noncommercial`, `licence_note` and `source`.
- `GET /rules/ext?kind=`: paginated read-only listing of handed-off rules, each with its source
  `list` and `state`: `active`, `dropped_untrusted`, `unsupported` (with `reason`), `invalid`,
  `badfiltered`, `badfilter`, or `unknown` while a rebuild is being installed.
- `POST /rules/validate`: `{rules, format?, allowlist?}` runs the real conversion pipeline and
  reports each line as `translated`, `accepted`, `handed_off`, `skipped` or `rejected`.

## Recently blocked requests

`GET /stats/blocked/recent` reads the engine's bounded ring (newest first, paginated) and filters by
`client` (profile label), `host` (host or subdomains) and `list_id`. Entries carry the URL, source
host, request type, matched rule, list id (for domain-set hits) and client label. Requires
`stats:read`. URLs are stored without their query string and fragment unless
`adblock.recent_blocked_keep_query` is set. `GET /system/metrics` also reports `storage`
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
| `PUT`, `DELETE /rules/site-exceptions/{site}` | `rules:write` | Switch ad blocking off or on for a site (a host name, lowercase punycode). Stored as custom rules (`@@$domain=site` plus the sentinel `\|\|adblock.invalid^`), so they appear in `GET /rules/custom`. |

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
