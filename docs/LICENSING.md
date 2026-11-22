# Licensing notes

The workspace is `MIT OR Apache-2.0`.

## uBlock Origin scriptlet snapshot (GPL-3.0)

`crates/filter-engine/resources/ubo-resources.json` is converted from uBlock Origin's scriptlet
library, which is **GPL-3.0-or-later**. Distributing a binary that embeds it makes that binary
subject to the GPL, which conflicts with the workspace licence. The project owner has not decided
how to handle this, so the snapshot is opt-in:

- Cargo feature `bundled-ubo-resources` (crates `filter-engine` and `list-service`), **off by
  default**, and not part of `proxy-core`'s `full` feature. Without it nothing GPL is compiled in
  (the JSON file stays in the source tree but is never `include_str!`-ed).
- Enable it deliberately: `cargo build -p proxy-core --features list-service/bundled-ubo-resources`
  (or add the feature to the crate you build).

### Default build behaviour

- Scriptlets (`+js(...)`) need a resource library. It is fetched at runtime from
  `scriptlet_resources_url` and cached as `<data_dir>/resources.json`; the cache is the offline
  fallback after the first successful fetch. Until then, scriptlet rules inject nothing.
- `$redirect` resources still work offline: the built-ins (`noop.js`, `noop.css`, `noop.html`,
  `noop.txt`, `noop.json`, `noop-vmap1.0.xml`, `1x1.gif`, `1x1.png`, `noop-0.1s.mp3`) are original:
  text bodies are trivial and the binary files are assembled in code from the GIF, PNG/zlib and
  MPEG specifications. Only the resource names follow uBO conventions so existing rules resolve.
- Fetching the library at runtime does not embed GPL code in the binary; whether using it
  at runtime has licence implications for your deployment is for the owner to decide.

### Reverting

Remove the feature and the JSON file (and `bundled.rs`'s `cfg` branch) to drop the snapshot
entirely, or enable the feature to restore the previous behaviour.
