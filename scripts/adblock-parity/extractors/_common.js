// Shared by every extractor; prepended (as text) to each extractor body by sites.mjs.
// Browser-side. Waits on real completion conditions (poll + overall deadline), never a fixed sleep.
const waitFor = (fn, timeoutMs, what) => new Promise((resolve, reject) => {
  const t0 = Date.now();
  const tick = () => {
    let v = null;
    try { v = fn(); } catch (_) { /* not ready */ }
    if (v) return resolve(v);
    if (Date.now() - t0 > timeoutMs) return reject(new Error('timeout waiting for ' + what));
    setTimeout(tick, 150);
  };
  tick();
});
// Same, but the condition must hold continuously for `stableMs` (results that trickle in).
const waitStable = (fn, timeoutMs, stableMs, what) => new Promise((resolve, reject) => {
  const t0 = Date.now();
  let since = 0;
  const tick = () => {
    let ok = false;
    try { ok = !!fn(); } catch (_) { /* not ready */ }
    const now = Date.now();
    if (ok) { since = since || now; if (now - since >= stableMs) return resolve(true); } else since = 0;
    if (now - t0 > timeoutMs) return reject(new Error('timeout waiting for ' + what));
    setTimeout(tick, 150);
  };
  tick();
});
const txt = (e) => (e ? e.textContent.replace(/\s+/g, ' ').trim() : '');
// Builds the common result schema from [{category,name,pass}].
const build = (tests, meta) => {
  const categories = {};
  let passed = 0;
  for (const t of tests) {
    const c = (categories[t.category] ||= { passed: 0, total: 0, percent: 0 });
    c.total++;
    if (t.pass) { c.passed++; passed++; }
  }
  for (const c of Object.values(categories)) c.percent = c.total ? +(100 * c.passed / c.total).toFixed(2) : 0;
  const total = tests.length;
  return { score: { passed, total, percent: total ? +(100 * passed / total).toFixed(2) : 0 }, categories, tests, meta: meta || {} };
};
