# Reload and engine check notes (2026-11-22)

Real lists: EasyList + EasyPrivacy, 135,869 rules (88,514 in the domain set), downloaded from
easylist.to and kept outside the repo. Bench:

    ADBLOCK_BENCH_LISTS=/path/easylist.txt:/path/easyprivacy.txt \
        cargo bench -p filter-engine --bench check -- check_real

Cold build (`build_set` + engine load): about 95-215 ms + 7-15 ms, blob 3.1 MiB, RSS delta
8-15 MiB. A rebuild is cheap enough that a per-list parse cache was not added; an unchanged
input set is already skipped by the engine key.

`SharedEngine::check` on the real lists (criterion, mean): blocked host 5.5-10 us, blocked path
3.7-7 us, allowed miss 5.3-10 us, allowed long URL 7.7-19 us, third-party script 6.8 us. The
host was at load average 15-30 on 8 cores, so run-to-run spread (2x) exceeds any gain from the
single engine load or the memoized source-page parse in `matcher::make_request`; no speed-up
is claimed. Request construction (two URL parses) was ~2.7 us of the ~5 us.

Reload under load (`loadgen --scenario reload`, 3 runs before/after): invalid. With load
average 25-30 the steady p99 was 50-270 ms with dropped requests in both builds, so the
acceptance criteria could not be evaluated. Re-run on a quiet machine.

Design changes: retired engines, aux data and swapped-out domain sets/IP filters are freed on
a reaper thread (`filter_engine::reaper`); list builds run on a dedicated low-priority pool
(`ListServiceConfig::build_threads`, config `adblock.build_threads`, 0 = cores/2). `loadgen`
reloads through the list service (custom rules plus `reload_now`), so that pool is what it
measures. Quiet-ish machine numbers and the per-stage engine check breakdown are in
`README.md` (Results 2026-11-22).
