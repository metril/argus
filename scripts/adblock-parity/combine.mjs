// A test passes only if it passed in every pass; records per-test pass vectors. Same rule for every blocker.
// A test whose probe rejected only slowly (>= PARITY_NET_MS, see net.mjs) in some pass and never quickly in any
// pass is `network`: unmeasurable, kept in `tests` (with durations) but excluded from the score.
import { rescore, testKey } from './net.mjs';
export function combinePasses(runs) {
  const tests = runs[0].tests.map((t) => {
    const per = runs.map((r) => r.tests.find((x) => testKey(x) === testKey(t)));
    const passes = per.map((x) => !!x?.pass);
    const nets = per.map((x) => x?.net).filter(Boolean);
    const network = nets.some((n) => n.tag === 'network') && !nets.some((n) => n.tag === 'fast');
    const { net, ...rest } = t;
    return { ...rest, pass: network ? false : passes.every(Boolean), passes, ...(network ? { network: true, netMs: nets.flatMap((n) => n.ms) } : {}) };
  });
  const { categories, score } = rescore(tests);
  return { ...runs[runs.length - 1], tests, categories, score };
}
