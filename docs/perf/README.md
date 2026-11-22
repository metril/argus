# Performance baselines

`loadgen` (`crates/e2e/src/bin/loadgen.rs`, library in `crates/e2e/src/loadgen.rs`) measures request
latency direct (client to origin) and through the MITM proxy (client, CONNECT, interception, origin)
over HTTP/1.1 and HTTP/2. Output is one JSON object with `--json`.

## Reproduce `baseline-2026-11-22.json`

Quiet machine, nothing else running (not alongside the test suite):

    cargo build --release -p e2e --bin loadgen
    # steady state: open loop 3000 req/s, 10 s measured after 3 s warm-up, 3 runs
    cargo run --release -p e2e --bin loadgen -- --model open --rate 3000 --duration 10 \
        --warmup 3 --repeat 3 --json > steady.json
    # list reload: 100k-rule list rebuilt and swapped in every 5 s under the same load
    cargo run --release -p e2e --bin loadgen -- --scenario reload --model open --rate 3000 \
        --duration 32 --warmup 3 --reload-interval 5 --json > reload.json

The file holds `{"steady": <steady.json>, "reload": <reload.json>}`.

## How it measures

* Three runtimes: load generator, origin and in-process proxy, each pinned to whole physical cores
  (SMT siblings together; `--no-pin` disables). On the 4-core/8-thread reference machine:
  loadgen cpus 0,4; origin 1,5; proxy 2,3,6,7.
* Open loop: requests are dispatched on a fixed schedule from a dedicated thread; latency runs
  from the scheduled time, so stalls are charged (no coordinated omission). Closed loop
  (`--model closed --conns N`) is back to back; h2 uses N concurrent streams per host.
* Warm-up (excluded) touches every host and class so certificates exist and pools are full.
* Mix (`--mix small=60,medium=10,blocked=20,html=10`): 1 KiB, 64 KiB, blocked by the proxy, HTML
  rewritten by a cosmetic rule. Responses are validated (status, size, `x-adblock: blocked`, the
  injected style); any mismatch, transport error, 429/503 or dropped request fails the run.
  Direct sends every class to the origin, so the per-class `blocked` delta compares the proxy's
  local answer to an origin response.
* List: generated 50k rules by default (`--rules`), or `--lists a.txt,b.txt`.
* External proxy: `--proxy-addr host:port --ca proxy-ca.crt --origin-ca-dir dir --host-suffix localhost`.
  The proxy must trust `dir/origin-ca.crt` (written on first run, reused later), allow loopback
  destinations and resolve `*.localhost`. Explicit mode only; no reload scenario.
* Exit status is non-zero if any request failed, was rejected or dropped.

## Connection admission

New connections are admitted by a lock-free limiter (default 10,000/s, burst 100 ms of tokens;
`performance.connection_rate_limit`, 0 = unlimited). `performance.max_connections = 0` derives the
cap from the soft `RLIMIT_NOFILE`; the API and UI report the effective value. Admission no longer
reads the process memory from `/proc` per connection (it refreshes at most once per check interval).

* Unit: `load_manager::tests::default_limit_admits_10k_per_second_and_enforces_above`.
* Real TCP (ignored by default; needs a release build and a quiet machine):
  `cargo nextest run --release -p e2e --test admission_e2e --run-ignored all`. 10,000 new
  connections/s for 3 s: 30000 accepted, 0 rejected. 20,000/s offered: about 30,400 accepted
  (10k/s plus the burst) and the rest rejected.
* Micro-benchmark: `cargo bench -p proxy-core --bench proxy_bench -- admission`: 12.5 us before
  the `/proc` fix, 0.70 us after, per admit+release per thread with 8 threads contending.

## A/B method used for changes

`loadgen` binaries of the two commits, run interleaved (base, new, base, new, ...) at open loop
3000 req/s, 10 s measured, 3 s warm-up; report medians with the min..max range. The h2 p99.9
tail (about 10 ms vs about 1 ms direct) is present before and after and shows up whenever the mix
contains the `html` class (rewritten pages), not for `small`, `medium` or `blocked` alone.
