# Performance baselines

`loadgen` (`crates/e2e/src/bin/loadgen.rs`, library in `crates/e2e/src/loadgen.rs`) measures request
latency direct (client to origin) and through the MITM proxy (client, CONNECT, interception, origin)
over HTTP/1.1 and HTTP/2. Output is one JSON object with `--json`.

## Method: paired runs

Added latency is measured with `--paired`: direct and proxy are driven in the **same run**. On every
scheduled tick the same request (same class and host) goes out on both paths, in alternating order,
timed from the same scheduled instant, so both see the same host load and the same stalls. The
quoted number is the per-percentile delta (proxy minus direct) inside the run. Subtracting the p99
of two separate runs (the earlier method, still available without `--paired`) mixes in whatever
the host did between them and is not used for conclusions. `--paired` needs `--model open`; the
rate is per path (so the host carries twice that load) and `--max-inflight` is per path.

Quiet machine, nothing else running (not alongside the test suite):

    cargo build --release -p e2e --bin loadgen
    # steady state: open loop 3000 req/s per path, 10 s measured after 3 s warm-up, 5 rounds
    cargo run --release -p e2e --bin loadgen -- --paired --model open --rate 3000 --duration 10 \
        --warmup 3 --repeat 5 --json > steady.json
    # list reload: 100k-rule list rebuilt and swapped in every 5 s under the same load; each
    # reload stores the list as custom rules and runs the real list service's `reload_now`, so
    # parse, compile and install run on its dedicated build pool (`--build-threads N` sizes it)
    cargo run --release -p e2e --bin loadgen -- --scenario reload --paired --model open \
        --rate 3000 --duration 32 --warmup 3 --reload-interval 5 --repeat 5 --json > reload.json

The in-process proxy runs with the shipped admission settings (`connection_rate_limit` 10000/s,
`max_connections` derived from the descriptor limit), so the real admission path is part of what
is measured; `--connection-rate-limit N` raises or removes the limit (0 = unlimited).
A request still outstanding when the 35 s drain gives up is counted as an error (the run fails);
it is never dropped silently.

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

## Results 2026-11-22 (`results-2026-11-22.json`, key `paired_rerun`)

Paired method, 10 rounds (two batches of 5), open loop 3000 req/s per path, 10 s measured (32 s for
reload), 3 s warm-up, 50k generated rules, shipped admission settings. Medians with min..max.
"Quiet rounds" are those where the **direct** path's own p99 stayed under 2 ms and nothing was
dropped; in the other rounds the direct path itself showed 100-250 ms stalls, i.e. the host, not
the proxy. Every request in every round succeeded (0 errors, 0 rejected); 3 steady and 4 reload
rounds (all h1) dropped requests during such stalls and are flagged failed by loadgen.

**The host was not quiet**: unrelated background workloads (about 1% CPU
each, 8-12% nice, 23-28% system), load average 2.1-9.3 during the
runs; `uptime` and the top CPU consumers before and after every batch are in the JSON. Nothing
was stopped or paused.

| Measurement | Target | All rounds | Quiet rounds | Verdict |
|---|---|---|---|---|
| Added p99, h1 (ms) | < 2 | 23.7 (0.34..54.9) | 0.44 (0.34..0.45), 3 of 10 rounds | met when the host is quiet; **cannot be decided on this machine** (7 of 10 rounds contain 100+ ms host stalls on the direct path) |
| Added p99, h2 (ms) | < 2 | 0.59 (0.42..3.8) | 0.49 (0.42..1.26), 6 of 10 | met at the median; one round (3.8, direct p99 11 ms) missed by noise |
| Added p50 / p90, h1 (ms) | | 0.18 / 0.30 | | stable across all rounds (0.16..0.19 / 0.27..0.32) |
| Added p50 / p90, h2 (ms) | | 0.18 / 0.28 | | stable across all rounds |
| Proxy p99.9, h1 / h2 (ms) | | 216 (3.9..409) / 24 (2.0..43) | 7.0 / 16 | noise-dominated; quiet-round values are 3-8x the direct path's |
| Reload, around p99 / steady p99, h1 | <= 1.2 | 0.06 (0.01..1.73) | 1.09 (0.08..1.73), 5 of 10 | **not met reliably**; steady p99 in noisy rounds is host stalls, so the ratio is meaningless there |
| Reload, around p99 / steady p99, h2 | <= 1.2 | 0.99 (0.83..1.21) | 1.00 (0.83..1.21), 9 of 10 | met at the median, top of range just above |
| Reload, around-window max, h1 (ms) | < 10 | 6.6 (2.9..15.2) | 6.5 (2.9..10.1) | median met; range not |
| Reload, around-window max, h2 (ms) | < 10 | 11.2 (3.2..17.1) | 10.8 (3.2..16.5) | **missed** (median above 10) |
| Reload, added p99 during the scenario, h1 / h2 (ms) | < 2 | 1.37 (0.43..3.7) / 0.55 (0.46..0.89) | 0.49 / 0.55 | h2 met; h1 met when quiet |
| Reload build, 100k rules (ms) | | 223 (212..232) h1 / 227 (222..238) h2 | | |
| Engine check, real lists (EasyList + EasyPrivacy) | < 5 us | blocked 3.5-3.8 us; allowed miss 5.2, long URL 6.0, third-party script 6.1 | | **missed** for allowed requests (5.0-6.1 us against 5 us); 60-75% of it is inside adblock-rust's matcher, which this project does not control |
| Overlay profile, check path (criterion) | | allowed 2.60 -> 1.82 us, base-blocked 3.75 -> 2.02, document 5.49 -> 4.81 | | one adblock request per check instead of two or three |
| Admission, 8 threads (bench) | | 0.71 us per admit+release | | carried over from the earlier run, not re-measured |
| Admission e2e (release, ignored tests) | | 2 passed | | carried over, not re-run |
| `profiles_bench` resolve / per request | ~20 / ~27 ns | 21.0 / 28.3 ns | | carried over, not re-measured |

Summary. **Met**: added p99 on h2; added p99 on h1 whenever the host is quiet; reload ratio on h2
at the median. **Missed**: reload around-window max on h2 (< 10 ms); engine check on allowed
requests (5.0-6.1 us vs 5 us). **Not decidable here**: added p99 h1 in the presence of the other
project's load (the direct path alone shows 100+ ms p99 in 7 of 10 rounds), reload ratio on h1,
p99.9 on both. They need a quiet machine; rerun the commands above there.

The earlier unpaired table (master vs p6-performance, separate direct and proxy runs) is kept in the
JSON under `steady`/`reload` but superseded: its "added p99" subtracted p99 values from different
runs.

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
