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

`LAN` is the client-facing interface; adapt it. `1000` is the UID the proxy runs as (the
container's `argus` user; check with `id argus` or `docker top`).

```nft
define LAN  = "eth1"
define PORT = 3129

table inet argus {
    # Traffic from LAN clients, before routing. One rule per family (the proxy listens on "::",
    # so both land on the same dual-stack socket).
    chain nat_prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname != $LAN return
        # Loop guard: traffic addressed to the gateway itself (including the proxy's own ports
        # and the web UI) is never redirected.
        fib daddr type local return
        meta nfproto ipv4 tcp dport { 80, 443 } redirect to :$PORT
        meta nfproto ipv6 tcp dport { 80, 443 } redirect to :$PORT
    }

    # Optional: also filter the gateway's own traffic. Without the UID exclusion the proxy's
    # upstream connections would be redirected back into itself.
    chain nat_output {
        type nat hook output priority dstnat; policy accept;
        meta skuid 1000 return
        fib daddr type local return
        tcp dport { 80, 443 } redirect to :$PORT
    }

    # The proxy cannot intercept QUIC; make clients fall back to TCP.
    chain block_quic {
        type filter hook forward priority filter; policy accept;
        iifname $LAN udp dport 443 reject
    }
}
```

Apply with `nft -f argus.nft` (as root); remove with `nft delete table inet argus`.

* `redirect` is a keyword in nft: do not use it as a chain name.
* The `nat_prerouting` chain only sees traffic arriving from the LAN, so the proxy's own upstream
  connections (locally generated, `output` hook) cannot loop. If you drop the `nat_output` chain
  the UID exclusion is not needed.
* The loop guard in the proxy itself (see above) is a second line of defence, not a substitute
  for the exclusions: a looped connection is refused, not served.
* IPv6: the proxy must listen on `::` and `net.ipv6.conf.all.forwarding` must be on. Clients
  with global IPv6 addresses bypass an IPv4-only setup, so redirect (or block) IPv6 as well.

**How this was validated.** The ruleset above was loaded with `nft -f` inside a throwaway
network namespace (`unshare -rn`, with a dummy `eth1`) and read back with `nft list ruleset`, so
the syntax and the kernel's acceptance of every rule are checked. It has **not** been run on a real
gateway with live client traffic. The original-destination lookup itself is covered by the
opt-in kernel test described under Verifying.

## Host requirements

* `sysctl -w net.ipv4.ip_forward=1` (and `net.ipv6.conf.all.forwarding=1` for IPv6) on a router.
* Loading nftables rules needs root / `CAP_NET_ADMIN`. The proxy itself binds an unprivileged port;
  reading the original destination is a plain `getsockopt` and is not expected to need a
  capability (not verified unprivileged).
* **Docker:** use `network_mode: host` (the shipped `compose.yaml` does). In a bridge network the
  container only sees addresses rewritten by Docker's own NAT, so the original destination is
  lost and connections are refused (not tested). `cap_drop: ALL` is kept: the redirect runs on the
  gateway's firewall, not in the container. With host networking the explicit proxy, the
  transparent listener and the web UI bind directly on the host (`8080`, `3129`, `3000`); there is
  no `ports:` mapping.

## Changing ports and listeners

Everything above can be changed from the web UI (Proxy page) or `PUT /api/v1/config` without
restarting: the proxy host, explicit port, transparent port (`0` turns it off), TLS passthrough
hosts, allowed clients, allowed destinations and the web UI's own host and port. New sockets are
bound first; if a bind fails the old listener stays up and the call returns `409 bind_failed`
with the reason. Connections already accepted keep running on the old socket; the web UI's old
address keeps answering for 30 seconds so the page can redirect.

UI changes are saved to a settings overlay, not to the shipped `config/default.toml`, which is
read-only in the container. The overlay lives at `CONFIG_OVERLAY_PATH` (the image sets
`/app/data/settings.toml`, on the data volume; elsewhere it defaults to `<adblock.data_dir>/settings.toml`).
It holds only the keys that differ from the base file, `transparent_port = 0` means off, and
`POST /api/v1/config/reload` re-reads both files. Delete the overlay to return to the shipped
defaults.

## Verifying

* `cargo nextest run -p e2e` runs every scenario through both entry modes with an injected
  original-destination source.
* `ARGUS_KERNEL_TEST=1 cargo nextest run -p proxy-core --test kernel_original_dst` creates a
  throwaway network namespace (`unshare -rn`, or `unshare -n` as root), loads an nftables
  `REDIRECT` there and checks the real `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` results. It
  skips with a message when the tools or privileges are missing and never touches host rules.
