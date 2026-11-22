# Transparent gateway mode

Run the proxy on a Linux router/gateway so LAN clients are filtered with **no proxy settings**.
The OS redirects TCP 80/443 to a second listener; the proxy recovers each connection's original
destination from the kernel (`SO_ORIGINAL_DST` for IPv4, `IP6T_SO_ORIGINAL_DST` for IPv6) and runs
the same filtering pipeline as explicit-proxy mode. Explicit mode keeps working on `proxy.port`.

Clients must still **trust the proxy CA** (see [CA-INSTALLATION.md](CA-INSTALLATION.md)); without
it HTTPS pages fail with certificate errors. Linux only (other platforms report transparent mode
as unsupported at startup).

## Configuration

```toml
[proxy]
host = "::"                      # dual-stack: accepts redirected IPv4 and IPv6
port = 8080                      # explicit proxy (unchanged)
transparent_port = 3129          # enables the transparent listener; omit to disable
tls_passthrough_hosts = [        # never intercepted, in BOTH modes
    "bank.example.com",          # exact
    "*.pinned-app.example",      # subdomains only (not the apex)
]
```

`host = "0.0.0.0"` (the default) is IPv4 only.

## How a redirected connection is handled

| Traffic | Behaviour |
|---|---|
| TLS with SNI, host not on the passthrough list | Intercepted; certificate minted for the SNI name; upstream dialled by **hostname** (normal DNS) on the original destination's port |
| TLS without SNI (e.g. a client dialling an IP) | Raw tunnel to the original destination address, no interception |
| TLS to a passthrough host | Raw tunnel (hostname dialled), client sees the origin's real certificate |
| Not TLS on port 443 (including plain HTTP) | Raw tunnel to the original destination |
| Plain HTTP (other ports, e.g. 80) | Served and filtered; target host from each request's `Host` header, falling back to the original destination IP |
| Anything else | Raw tunnel to the original destination |

* **Loop guard:** a connection whose original destination is the proxy itself (its listening
  ports on a loopback/local address, or the accepted socket's own address) is refused, as is one
  whose original destination cannot be read (e.g. a client that connected to the transparent port
  directly). Resolving a *hostname* to the proxy is not checked.
* **QUIC / HTTP/3:** the proxy cannot intercept QUIC. It strips `Alt-Svc` from responses so
  browsers are not told about HTTP/3, and you should reject UDP/443 (below) so clients that already
  know an h3 endpoint fall back to TCP.
* Encrypted Client Hello (ECH) hides the real SNI; such connections are not handled specially
  (untested).

## nftables example

Untested as a whole; adapt interface names. `LAN` is the client-facing interface.

```nft
define LAN  = "eth1"
define PORT = 3129

table inet adblocker {
    chain redirect {
        type nat hook prerouting priority dstnat; policy accept;
        iifname $LAN tcp dport { 80, 443 } redirect to :$PORT
    }
    chain quic {
        type filter hook forward priority filter; policy accept;
        iifname $LAN udp dport 443 reject
    }
}
```

* `prerouting` only sees traffic arriving from the LAN, so the proxy's own upstream connections
  (locally generated, `output` hook) are not redirected and cannot loop.
* To also filter the gateway's **own** traffic, add an `output` chain hooked at `dstnat`
  (`type nat hook output priority -100`) and exclude the proxy's own connections, otherwise its
  upstream dials are redirected back to itself:
  `meta skuid != "adblocker" tcp dport { 80, 443 } redirect to :$PORT` (or match a
  `meta mark` set by the proxy's service/cgroup). Redirecting from the `output` hook with
  `redirect to :PORT` is exactly what the opt-in kernel test exercises, for IPv4 and IPv6.
* IPv6: the `inet` table above covers both families, but the proxy must listen on `::` and
  `net.ipv6.conf.all.forwarding` must be on. Clients with global IPv6 addresses bypass an IPv4-only
  setup, so redirect (or block) IPv6 as well.

## Host requirements

* `sysctl -w net.ipv4.ip_forward=1` (and `net.ipv6.conf.all.forwarding=1` for IPv6) on a router.
* Loading nftables rules needs root / `CAP_NET_ADMIN`. The proxy itself binds an unprivileged port;
  reading the original destination is a plain `getsockopt` and is not expected to need a
  capability (not verified unprivileged).
* **Docker:** use `network_mode: host`. In a bridge network the container only sees addresses
  rewritten by Docker's own NAT, so the original destination is lost and connections are refused
  (not tested). Published ports (`3129`) are only useful for explicit-style testing.

## Verifying

* `cargo nextest run -p e2e` runs every scenario through both entry modes with an injected
  original-destination source.
* `ADBLOCKER_KERNEL_TEST=1 cargo nextest run -p proxy-core --test kernel_original_dst` creates a
  throwaway network namespace (`unshare -rn`, or `unshare -n` as root), loads an nftables
  `REDIRECT` there and checks the real `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` results. It
  skips with a message when the tools or privileges are missing and never touches host rules.
