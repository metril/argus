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
the given profile ids (enforced once profile routes exist).

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
| `stats:reset` | - | - | yes | Reset blocking statistics. |
| `config:read` | yes | yes | yes | Read the proxy configuration. |
| `config:write` | - | - | yes | Change or reload the proxy configuration. |
| `ca:read` | yes | yes | yes | Read CA certificate details (fingerprint, expiry, subject). |
| `ca:admin` | - | - | yes | Manage the CA certificate (reserved). |
| `scripts:read` | yes | yes | yes | View userscripts and their source. |
| `scripts:write` | - | yes | yes | Install, update, enable, disable and remove userscripts. |
| `policy:read` | yes | yes | yes | Read the script policy (reserved). |
| `policy:write` | - | yes | yes | Change the script policy (reserved). |
| `profiles:read` | yes | yes | yes | Read filtering profiles (reserved). |
| `profiles:write` | - | - | yes | Change filtering profiles (reserved). |
| `devices:read` | yes | yes | yes | Read devices (reserved). |
| `devices:write` | - | - | yes | Change devices (reserved). |
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
  default; see the README's format table) and `allowlist`.
- `GET /lists/{id}/report`, `GET /rules/custom/report`: `ListReport` of the last build (detected
  format, network/cosmetic/ext/skipped/deduped/rejected counts, first parse issues, header metadata,
  content SHA).
- `GET /engine/build`: `BuildSummary` with the build state (`idle`, `fetching`, `compiling`,
  `failed` with the error; a failed build leaves the previous engine serving), last build duration
  and time, domain-set size and handed-off rule counts per kind.
- `GET /lists/catalogue`, `POST /lists/catalogue/{id}`: browse the default-disabled catalogue and
  add an entry as a list.
- `GET /rules/ext?kind=`: paginated read-only listing of rules that parsed but are not enforced yet.
- `POST /rules/validate`: `{rules, format?, allowlist?}` runs the real conversion pipeline and
  reports each line as `translated`, `accepted`, `handed_off`, `skipped` or `rejected`.

## Recently blocked requests

`GET /stats/blocked/recent` reads the engine's bounded ring (newest first, paginated) and filters by
`client` (profile label), `host` (host or subdomains) and `list_id`. Entries carry the URL, source
host, request type, matched rule, list id (for domain-set hits) and client label. Requires
`stats:read`. URLs are stored without their query string and fragment unless
`adblock.recent_blocked_keep_query` is set. `GET /system/metrics` also reports `storage`
(`deferred_dropped`, `deferred_failed`, `deferred_queued`) for the background database writer.
