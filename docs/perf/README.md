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
    # list reload: 100k-rule list rebuilt and swapped in every 5 s under the same load; each
    # reload stores the list as custom rules and runs the real list service's `reload_now`, so
    # parse, compile and install run on its dedicated build pool (`--build-threads N` sizes it)
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
* Seeding an external proxy: the workload needs the rules `loadgen --print-list --rules 50000
  --host-suffix localhost` prints (a blocked host and a cosmetic rule per host, plus the generated
  list). Load them as the custom rules through the API (`localhost:13000` below is the Web UI
  port; the proxy also needs `proxy.allowed_destinations = ["127.0.0.0/8"]` and
  `proxy.extra_upstream_ca_paths = ["<dir>/origin-ca.crt"]`):

      curl -s -c jar -H 'content-type: application/json' http://localhost:13000/api/v1/auth/register \
          -d '{"username":"admin_user","password":"...","password_confirm":"..."}'   # first user = admin
      CSRF=$(grep csrf_token jar | awk '{print $NF}')
      ETAG=$(curl -s -D - -o /dev/null -b jar http://localhost:13000/api/v1/rules/custom | grep -i '^etag' | cut -d' ' -f2 | tr -d '\r')
      loadgen --print-list --rules 50000 --host-suffix localhost \
          | python3 -c 'import json,sys; print(json.dumps({"rules": sys.stdin.read()}))' > rules.json
      curl -s -b jar -H "x-csrf-token: $CSRF" -H "if-match: $ETAG" -X PUT \
          -H 'content-type: application/json' --data-binary @rules.json \
          http://localhost:13000/api/v1/rules/custom
      curl -s http://localhost:13000/api/v1/ca.crt > proxy-ca.crt

  Then `loadgen --proxy-addr 127.0.0.1:8080 --ca proxy-ca.crt --origin-ca-dir dir --host-suffix
  localhost ...`. Pin the proxy yourself (`taskset`); the loadgen runtimes pin only themselves.
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

## Results 2026-11-22 (`results-2026-11-22.json`)

`master` (phase 5) vs `p6-performance`, binaries interleaved, 5 rounds, open loop 3000 req/s, 10 s
measured, 3 s warm-up, 50k generated rules. Medians with min..max. The host was **not quiet** (about
35% CPU of other projects' niced processes, load average 3-6, spikes above 10): single runs show
50-350 ms stalls even on the direct path, which is where the wide ranges come from.

| Measurement | Target | master | p6-performance | |
|---|---|---|---|---|
| Added p99, h1 (proxy - direct, ms) | < 2 | 0.76 (0.41..73) | 0.35 (-77..58) | met at the median |
| Added p99, h2 (ms) | < 2 | 0.55 (0.46..0.86) | 0.59 (0.40..3.6) | met |
| Proxy p99.9, h1 / h2 (ms) | | 13.2 (3.8..130) / 4.0 (2.5..10.2) | 3.0 (1.6..111) / 11.6 (1.9..25) | noise-dominated |
| Reload, around p99 / steady p99, h1 | <= 1.2 | 1.51 (1.12..1.85) | 0.92 (0.04..2.16); second run 0.62 | met at the median |
| Reload, around p99 / steady p99, h2 | <= 1.2 | 1.41 (1.18..1.94) | 1.61 (0.91..1.80); second run 1.11 (0.98..1.86) | not met reliably |
| Reload, around-window max, h1 / h2 (ms) | < 10 | 6.7 / 6.3 | 5.9 (3.2..17) / 8.4 (3.9..25) | median met, range not |
| Engine check, real lists (EasyList + EasyPrivacy) | < 5 us | | blocked 3.4-3.8 us, allowed miss 5.0, long URL 5.9, third-party script 6.1 | not met for allowed requests |
| Admission, 8 threads (bench) | | | 0.71 us per admit+release | |
| Admission e2e (release, ignored tests) | | | 2 passed | |
| `profiles_bench` resolve / per request | ~20 / ~27 ns | | 21.0 / 28.3 ns | no regression |

Reload build time (100k rules, through the list service's build pool) is about 230 ms on both
commits. A sweep of `--build-threads 1/2/4` (h2, 4 rounds) gave ratios 0.92 / 0.81 / 1.19 and the
same build time, but a later interleaved repeat of the default (2 vs 4 threads on the loadgen's
4 pinned CPUs) did not reproduce the difference, so the default stays at half the cores.

Engine check, per stage on the real lists (criterion, ns): URL parse 330, request construction
(two parses) 1160-1420, adblock-rust `check_network_request` 2130 (blocked) to 3670-4650 (allowed
misses, scales with URL token count), full `SharedEngine::check` 3.4-6.1 us. The matcher is 60-75%
of an allowed check. A bypass of the URL parse for canonical URLs (own host parse, public-suffix
lookup) measured no gain (the suffix lookup costs about what the parse did) and was dropped.

HTML responses over h2: the engine side of a rewritten response (document check, `site_off`,
`csp_for`, `cosmetic_for`) is 1.0-1.6 us at 100, 50k and 500k rules (flat). Closed-loop throughput
with `--mix html=100` is the same at 100 and 500k rules (12.3k req/s). Open-loop p99.9 is bimodal
(2-5 ms or 40-50 ms per run) at every list size, and the same stalls appear on the direct path
(2 of 8 direct runs showed 58 ms and 350 ms p99.9), so the earlier list-size dependence was host
noise, not per-response work.

Allocator (real `adblocker` binary behind `loadgen --proxy-addr`, proxy pinned to 4 logical CPUs,
5 interleaved rounds, 50k rules): mimalloc raised closed-loop throughput 8% (h1 4931 -> 5329 req/s,
h2 4753 -> 5164) and lowered closed-loop p99 slightly, but peak RSS grew 557 (533..565) -> 693
(629..708) MiB (+24%) and open-loop p99 was dominated by host stalls in both variants. Not worth
the memory: it stays out.

## A/B method used for changes

`loadgen` binaries of the two commits, run interleaved (base, new, base, new, ...) at open loop
3000 req/s, 10 s measured, 3 s warm-up; report medians with the min..max range.
The h2 p99.9 tail seen in single runs (about 10 ms vs about 1 ms direct) is host noise, not list size
(see Results 2026-11-22).
