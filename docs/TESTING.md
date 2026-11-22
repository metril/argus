# Testing

All suites run under `cargo nextest` (parallel across all cores). Every test owns its ports,
temp dirs and CA, so nothing needs serialising.

## Unit and integration tests

    cargo nextest run --workspace --all-features --exclude e2e --exclude e2e-browser

CI shards this with `--partition count:N/4` over a prebuilt nextest archive.

## End-to-end (in-process proxy, real TLS origin, reqwest client)

    cargo nextest run -p e2e

`crates/e2e` provides `TestOrigin`, `TestProxy`, `TestClient` and the `e2e_test!` macro, which
instantiates a scenario for both entry modes (explicit proxy and transparent).

## Kernel (real `SO_ORIGINAL_DST` behind an nftables REDIRECT)

Needs unprivileged user namespaces and `nft`/`ip`; skipped unless enabled:

    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # Ubuntu 24.04+
    ADBLOCKER_KERNEL_TEST=1 cargo nextest run -p proxy-core --test kernel_original_dst --no-capture

## Browser (headless Chromium over CDP through the proxy)

    cargo nextest run -p e2e-browser --no-capture

* Browser discovery: `ADBLOCKER_BROWSER=/path/to/chrome`, else `chromium`/`google-chrome` on
  `PATH`, else Playwright's cache (`~/.cache/ms-playwright`). With none found tests print
  `SKIPPED` and pass; `ADBLOCKER_REQUIRE_BROWSER=1` (set in CI) turns that into a failure.
* One browser, throwaway profile, proxy and origin per test. The proxy CA is trusted through
  `--ignore-certificate-errors-spki-list` (CA key plus the proxy-issued leaf of every test
  hostname), never a blanket ignore; the baseline test also checks the served chain via CDP.
* Every session records console errors, uncaught exceptions, `securitypolicyviolation` events
  and security log entries; `Session::assert_clean()` fails a test on any that involve our
  injected resources.
* Scriptlets use a tiny local `set-constant` by default; `Resources::Bundled` loads the repo's
  uBO snapshot from `crates/filter-engine/resources/` at runtime.
* `KNOWN_FAILING` in `crates/e2e-browser/src/lib.rs` lists scenarios that expose real proxy bugs
  (currently empty).
  They still run and print their failure but do not fail the suite. Remove an entry when its
  bug is fixed (the runner says when an entry starts passing). Rules in these scenarios see
  non-default ports in every URL, so write host rules as `||host^` (a path rule such as
  `||host/p` matches only default-port URLs, as in uBO).
* Debug a run with `ADBLOCKER_BROWSER_NETLOG=/path/net.json` (Chromium net-log of the session).

## Lint

    cargo fmt --all --check
    cargo clippy --workspace --all-features --all-targets -- -D warnings

## Load test (latency, reload under load)

    cargo run --release -p e2e --bin loadgen -- --help
    cargo run --release -p e2e --bin loadgen -- --model open --rate 3000 --duration 10 --repeat 3

Direct versus proxied latency (h1/h2), open or closed loop, optional list reload scenario, JSON
with `--json`. Run it on a quiet machine, never alongside the test suite. See `docs/perf/README.md`
for the exact baseline commands; a fast smoke test (`crates/e2e/tests/loadgen_smoke.rs`) runs in
the normal suite.
