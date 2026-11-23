# Running the web UI behind a reverse proxy

Argus can serve HTTPS itself (Settings > HTTPS, see the README). Use a reverse proxy instead when
you already run one, want a public certificate, or want to share one hostname between services.
Leave Argus's HTTPS **off** in that case: the proxy talks plain HTTP to Argus on a trusted network.

Two settings tell Argus to believe the proxy:

- **Trusted proxies** (`[webui] trusted_proxies`, the proxy's IP address, for example
  `["127.0.0.1"]`). Only these peers may set `X-Forwarded-For` (real client IP, used for rate
  limits, the audit log and the request log) and `X-Forwarded-Proto`. Anyone else's headers are
  ignored.
- **`cookie_secure = "auto"`** (the default). Session cookies get the `Secure` flag when the request
  came over HTTPS, which Argus knows from `X-Forwarded-Proto: https` sent by a trusted proxy. Use
  `"always"` if every access is HTTPS, never if you need plain HTTP too.

The proxy must forward the `Host` header unchanged and send `X-Forwarded-Proto` (and
`X-Forwarded-For`). The live log stream uses Server-Sent Events, so response buffering must be off
for `/api/v1/`.

## Caddy

```caddyfile
argus.example.com {
    reverse_proxy 127.0.0.1:3000 {
        flush_interval -1
    }
}
```

Caddy sets `X-Forwarded-For`, `X-Forwarded-Proto` and `Host` itself. Add `127.0.0.1` to the trusted
proxies.

## nginx

```nginx
server {
    listen 443 ssl http2;
    server_name argus.example.com;
    ssl_certificate     /etc/ssl/argus.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/argus.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        $connection_upgrade;
        proxy_buffering off;      # live log stream (SSE)
        proxy_read_timeout 1h;
    }
}

map $http_upgrade $connection_upgrade { default upgrade; '' close; }
```

If the proxy runs in another container or host, list that address under `trusted_proxies` and bind
Argus's web UI to an interface only the proxy can reach.

## Checking it

1. Open `https://argus.example.com/`, log in, and confirm in the browser dev tools that the
   `access_token` cookie has the `Secure` flag.
2. The Audit and Sessions pages should show your real client IP, not the proxy's. If they show the
   proxy's address, its IP is missing from `trusted_proxies`.
