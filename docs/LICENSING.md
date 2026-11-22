# Licensing notes

The workspace is `MIT OR Apache-2.0`.

## uBlock Origin resource library (GPL-3.0)

The default build embeds the uBlock Origin resource library (GPL-3.0-or-later):
`crates/filter-engine/resources/ubo-resources.json`, converted from uBlock Origin's scriptlet
library. Provenance (upstream commit, date, how to regenerate) is in
`crates/filter-engine/resources/SOURCE.txt`.

To build without it, disable default features:

- `cargo build --release --no-default-features --features websockets` (add `userscripts` and
  `webui` as needed; `full` includes the library), or
- depend on `filter-engine` / `list-service` with `default-features = false`.

Without the library nothing GPL is compiled in; the file stays in the source tree but is never
`include_str!`-ed.

### Runtime behaviour

- Scriptlets (`+js(...)`) need a resource library. The order is: the freshest successfully fetched
  copy (from `scriptlet_resources_url`), else the on-disk cache `<data_dir>/resources.json`, else
  the embedded copy. Every library, whatever its origin, is validated before it is served (see
  `GET /engine/status`).
- `$redirect` resources work offline: the built-ins (`noop.js`, `noop.css`, `noop.html`,
  `noop.txt`, `noop.json`, `noop-vmap1.0.xml`, `1x1.gif`, `1x1.png`, `noop-0.1s.mp3`) are original:
  text bodies are trivial and the binary files are assembled in code from the GIF, PNG/zlib and
  MPEG specifications. Only the resource names follow uBO conventions so existing rules resolve.
