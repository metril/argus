// Network-failure tagging. A blocker's cancel/abort rejects within a few ms; a runner network failure or timeout
// takes far longer. An init script records every fetch/XHR/script/img outcome + duration per URL; after
// extraction, tests whose host maps to recorded requests that ALL rejected slowly (>= PARITY_NET_MS) are tagged
// `network` (unmeasurable), identically for every blocker. Tests the probe cannot map are untouched.
export const NET_MS = +(process.env.PARITY_NET_MS || 1500);

// Function declaration source (BiDi preload) / wrapped as an IIFE (Playwright addInitScript).
export const NET_RECORDER_FN = `() => {
  if (window.__argusNet) return;
  const rec = (window.__argusNet = []);
  const now = () => performance.now();
  const add = (url, kind, t0, outcome) => { try { rec.push({ url: String(url), kind, outcome, ms: Math.round(now() - t0) }); } catch (_) {} };
  const f = window.fetch;
  if (f) window.fetch = function (input, init) {
    const t0 = now(), url = (input && input.url) || input;
    return f.apply(this, arguments).then((r) => { add(url, 'fetch', t0, 'resolved'); return r; }, (e) => { add(url, 'fetch', t0, 'rejected'); throw e; });
  };
  const open = XMLHttpRequest.prototype.open, send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, url) { this.__nu = url; return open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    const t0 = now(), url = this.__nu;
    this.addEventListener('loadend', () => add(url, 'xhr', t0, this.status === 0 ? 'error' : 'resolved'));
    return send.apply(this, arguments);
  };
  const seen = new WeakSet();
  const watch = (el) => {
    if (seen.has(el) || !(el.tagName === 'SCRIPT' || el.tagName === 'IMG' || el.tagName === 'IFRAME') || !(el.src || el.getAttribute('src'))) return;
    seen.add(el);
    const t0 = now(), kind = el.tagName.toLowerCase();
    el.addEventListener('load', () => add(el.src, kind, t0, 'resolved'));
    el.addEventListener('error', () => add(el.src, kind, t0, 'error'));
  };
  const scan = (n) => { if (n.nodeType !== 1) return; watch(n); n.querySelectorAll && n.querySelectorAll('script[src],img[src],iframe[src]').forEach(watch); };
  new MutationObserver((ms) => ms.forEach((m) => { m.addedNodes.forEach(scan); if (m.type === 'attributes') watch(m.target); })).observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['src'] });
}`;
export const netInitScript = `(${NET_RECORDER_FN})()`;

const hostOf = (u) => { try { return new URL(u, 'http://x/').hostname.toLowerCase(); } catch { return ''; } };
const HOST_RE = /[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+/gi;

// Tags result.tests in place: t.net = { ms:[rejection durations], tag:'network'|'fast' } when mappable and rejected.
export function tagNetwork(result, records, thresholdMs = NET_MS) {
  if (!result || !Array.isArray(result.tests) || !Array.isArray(records)) return result;
  for (const t of result.tests) {
    const hosts = [...new Set((t.name.match(HOST_RE) || []).map((h) => h.toLowerCase()))];
    if (!hosts.length) continue;
    const mine = records.filter((r) => { const h = hostOf(r.url); return h && hosts.some((x) => h === x || h.endsWith('.' + x)); });
    const rej = mine.filter((r) => r.outcome !== 'resolved');
    if (!rej.length) continue;
    const ms = rej.map((r) => r.ms);
    t.net = { ms, tag: ms.every((m) => m >= thresholdMs) ? 'network' : 'fast' };
  }
  return result;
}

// Recompute score/categories from tests, skipping tests flagged `network` or whose key is in `skip`.
export const testKey = (t) => t.category + '\u0000' + t.name;
export function rescore(tests, skip) {
  const categories = {};
  let passed = 0, total = 0;
  for (const t of tests) {
    if (t.network || skip?.has(testKey(t))) continue;
    const c = (categories[t.category] ||= { passed: 0, total: 0, percent: 0 });
    c.total++; total++;
    if (t.pass) { c.passed++; passed++; }
  }
  for (const c of Object.values(categories)) c.percent = c.total ? +(100 * c.passed / c.total).toFixed(2) : 0;
  return { categories, score: { passed, total, percent: total ? +(100 * passed / total).toFixed(2) : 0 } };
}
