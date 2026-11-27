// A test passes only if it passed in every pass; records per-test pass vectors. Same rule for every blocker.
export function combinePasses(runs) {
  const keyOf = (t) => t.category + '\u0000' + t.name;
  const tests = runs[0].tests.map((t) => {
    const passes = runs.map((r) => !!r.tests.find((x) => keyOf(x) === keyOf(t))?.pass);
    return { ...t, pass: passes.every(Boolean), passes };
  });
  const categories = {};
  for (const t of tests) { const c = (categories[t.category] ||= { passed: 0, total: 0, percent: 0 }); c.total++; if (t.pass) c.passed++; }
  for (const c of Object.values(categories)) c.percent = c.total ? +(100 * c.passed / c.total).toFixed(2) : 0;
  const passed = tests.filter((t) => t.pass).length;
  return { ...runs[runs.length - 1], tests, categories, score: { passed, total: tests.length, percent: tests.length ? +(100 * passed / tests.length).toFixed(2) : 0 } };
}
