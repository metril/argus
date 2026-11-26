# uBlock Origin procedural filterer (vendored)

Argus's in-page procedural cosmetic engine (`crates/proxy-core/assets/procedural.js`) is built on
uBlock Origin's content-script procedural filterer.

| | |
|---|---|
| Upstream | <https://github.com/gorhill/uBlock>, `src/js/contentscript-extra.js` |
| Commit | `5934db2a0437a50182c4a8f3da2e0941cf806253` (2026-11-21), the same commit as the bundled scriptlet library (`crates/filter-engine/resources/SOURCE.txt`) |
| Licence | GPL-3.0-or-later (see `docs/LICENSING.md`) |
| sha256 of the pristine file | `8457cd7c87cf618b478c9fcf3e9716e120f3a469a530a22c951bc6f7c79e3d73` |

Note: that commit is younger than the 14-day pin rule; it is kept so the engine and the scriptlets
stay one uBO release. Bump both together (regenerate the resources, replace this file, re-run the
JS tests) to move.

## Files

- `contentscript-extra.js` here: the pristine upstream file, for diffing on updates. Not shipped.
- `crates/proxy-core/assets/procedural.js`: the shipped engine. Lines up to `PSelectorRoot` are the
  upstream `PSelector*` classes (all operators and their semantics) with these edits only:
  wrapped in the factory `argusProceduralEngine(window, opts)` (no `vAPI`, window passed in),
  `triggerDOMChange` calls `opts.onChange`. Everything after is Argus code:
  - a compiler from selector text and from adblock-rust's `procedural_actions` operator arrays to
    uBO's compiled form (`{selector, tasks, action}`), including nested `:has()`/`:not()`/`:if-not()`
    arguments and CSS after an operator (uBO's `spath`);
  - a driver replacing uBO's `ProceduralFilterer` (which needs `vAPI.domFilterer`/`domWatcher`):
    uBO's commit/budget logic and action code, plus a throttled scheduler (one pass per >=100 ms,
    frame-aligned, cost-adaptive) on a childList+subtree observer.
- `crates/proxy-core/js-tests/`: jsdom tests (`npm test`), run by the `js-engine` CI job.

## Operators and actions

All upstream operators: `:has()`/`:if()`, `:not()`/`:if-not()`, `:has-text()`, `:matches-attr()`,
`:matches-css()`, `-before`, `-after`, `:matches-media()`, `:matches-path()`, `:matches-prop()`,
`:min-text-length()`, `:others()`, `:shadow()`, `:spath()`, `:upward()` (number or selector),
`:watch-attr()`, `:xpath()`; actions `:remove()`, `:style()`, `:remove-attr()`, `:remove-class()`.

## AdGuard syntax (`#?#`, `#$?#`) translated to uBO operators

`:contains()`/`:-abp-contains()` -> `:has-text()`; `:-abp-has()` -> `:has()`; `:nth-ancestor(n)` ->
`:upward(n)`; `:matches-property()` -> `:matches-prop()`; `:-abp-properties()`/`:properties()` ->
`:matches-css()` (glob `*` allowed); `:if()`/`:if-not()`; `:xpath()`, `:upward()`, `:matches-attr()`,
`:matches-css*()`; `#$?#sel { remove: true }` -> `:remove()`; `#$?#sel { css }` -> `:style(css)`.

Not translated (no uBO equivalent): `:is()`/`:where()` containing a procedural operator; multi-
declaration `:-abp-properties()`; `:contains()` with a regexp using unbalanced parentheses.
Rules that adblock-rust rejects outright (uBO-only operators it does not parse) never reach the
engine.
