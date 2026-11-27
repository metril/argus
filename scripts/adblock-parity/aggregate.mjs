#!/usr/bin/env node
// Merges shard JSON files into a markdown report + merged.json and fails if Argus scores below any baseline
// in any category.   node aggregate.mjs <dir-with-shard-json> [--out report.md] [--merged merged.json] [--tolerance 0]
// Comparison pairs (same browser; the desktop app only runs Chrome): argus/chrome vs ubol, adguard-ext,
// adguard-desktop (chrome); argus/firefox vs ubo, adguard-ext (firefox). `--tolerance` is in percentage points.
// `argus-strict` (Argus with the opt-in Strict profile) is its own informational column; it never
// takes part in the verdict, which stays on default `argus`.
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const dir = argv.find((a) => !a.startsWith('--') && argv[argv.indexOf(a) - 1]?.startsWith('--') !== true) || '.';
const opt = (k, d) => (argv.includes('--' + k) ? argv[argv.indexOf('--' + k) + 1] : d);
const tol = +(opt('tolerance', process.env.PARITY_TOLERANCE ?? 0));

const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.json') && !e.name.startsWith('merged') ? [path.join(d, e.name)] : []));
const all = walk(dir).map((f) => JSON.parse(fs.readFileSync(f, 'utf8'))).filter((s) => s.blocker && s.results);
const key = (s) => `${s.blocker}/${s.browser}${s.platform === 'win32' ? ' (win)' : ''}`;
// Baselines that could not be set up (e.g. AdGuard for Windows trial needs an account) are reported, never compared.
const unavailable = all.filter((s) => s.unavailable);
const shards = all.filter((s) => !s.unavailable);
const order = ['none', 'argus', 'argus-strict', 'ubol', 'ubo', 'adguard-ext', 'adguard-desktop'];
shards.sort((a, b) => order.indexOf(a.blocker) - order.indexOf(b.blocker) || a.browser.localeCompare(b.browser));
const siteIds = [...new Set(shards.flatMap((s) => s.results.map((r) => r.site)))];
const get = (s, site) => s.results.find((r) => r.site === site);
const pct = (r) => (r && r.ok ? `${r.score.percent.toFixed(1)}%` : r ? 'ERR' : '-');

let md = '# Adblock parity\n\n';
md += `Tolerance: ${tol} percentage points. Shards: ${shards.map(key).map((k) => '`' + k + '`').join(', ') || 'none'}\n\n`;
md += '## Total score (blocked / total)\n\n| Site | ' + shards.map(key).join(' | ') + ' |\n|---|' + shards.map(() => '---').join('|') + '|\n';
for (const site of siteIds) md += `| ${site} | ${shards.map((s) => pct(get(s, site))).join(' | ')} |\n`;

for (const site of siteIds) {
  const cats = [...new Set(shards.flatMap((s) => Object.keys(get(s, site)?.categories || {})))];
  if (!cats.length) continue;
  md += `\n### ${site}\n\n| Category | ${shards.map(key).join(' | ')} |\n|---|${shards.map(() => '---').join('|')}|\n`;
  for (const c of cats) md += `| ${c} | ${shards.map((s) => { const x = get(s, site)?.categories?.[c]; return x ? `${x.percent.toFixed(0)}% (${x.passed}/${x.total})` : '-'; }).join(' | ')} |\n`;
}

const failures = unavailable.filter((s) => s.blocker === 'argus').map((s) => `${key(s)} unavailable: ${s.unavailable}`);
const pairs = { chrome: ['ubol', 'adguard-ext', 'adguard-desktop'], firefox: ['ubo', 'adguard-ext'] };
for (const browser of ['chrome', 'firefox']) {
  const argus = shards.find((s) => s.blocker === 'argus' && s.browser === browser);
  if (!argus) {
    if (shards.some((s) => pairs[browser].includes(s.blocker) && s.browser === browser)) failures.push(`argus/${browser} shard is missing (it failed before producing results)`);
    continue;
  }
  for (const base of shards.filter((s) => pairs[browser].includes(s.blocker) && (s.blocker === 'adguard-desktop' ? browser === 'chrome' : s.platform !== 'win32' && s.browser === browser))) {
    for (const site of siteIds) {
      const a = get(argus, site), b = get(base, site);
      if (!b || !b.ok) continue; // a broken baseline cannot be compared against
      if (!a || !a.ok) { failures.push(`${site}: argus/${browser} produced no result (${a?.error || 'missing'}) vs ${key(base)}`); continue; }
      if (a.score.percent + tol < b.score.percent) failures.push(`${site} TOTAL: argus/${browser} ${a.score.percent}% < ${key(base)} ${b.score.percent}%`);
      for (const [c, bc] of Object.entries(b.categories)) {
        const ac = a.categories[c];
        if (!ac) { if (bc.passed > 0) failures.push(`${site} / ${c}: argus/${browser} has no such category; ${key(base)} ${bc.percent}%`); continue; }
        if (ac.percent + tol < bc.percent) failures.push(`${site} / ${c}: argus/${browser} ${ac.percent}% (${ac.passed}/${ac.total}) < ${key(base)} ${bc.percent}% (${bc.passed}/${bc.total})`);
      }
    }
  }
}
// Tests that passed in some passes but not all (noisy: timeouts/network failures); already scored as failed.
const unstable = shards.flatMap((s) => s.results.flatMap((r) => (r.tests || []).filter((t) => t.passes && t.passes.some(Boolean) && !t.passes.every(Boolean)).map((t) => `${key(s)} ${r.site} / ${t.category} / ${t.name}: ${t.passes.map((p) => (p ? 'P' : 'F')).join('')}`)));
const broken = shards.flatMap((s) => s.results.filter((r) => !r.ok).map((r) => `${key(s)} ${r.site}: ${r.error}`));
if (unavailable.length) md += `\n## Baselines unavailable (excluded)\n\n${unavailable.map((s) => `- \`${key(s)}\`: baseline unavailable: ${s.unavailable}`).join('\n')}\n`;
if (shards.some((s) => s.blocker === 'argus-strict')) md += '\n_`argus-strict` is informational and does not affect the verdict._\n';
md += '\n## Verdict\n\n' + (failures.length ? `**FAIL**: Argus is below a baseline in ${failures.length} place(s):\n\n${failures.map((f) => '- ' + f).join('\n')}\n` : '**PASS**: Argus matches or beats every baseline in every category.\n');
if (unstable.length) md += `\n## Unstable tests (passed in some passes, counted as failed)\n\n${unstable.map((f) => '- ' + f).join('\n')}\n`;
if (broken.length) md += `\nExtraction errors (not scored):\n\n${broken.map((f) => '- ' + f).join('\n')}\n`;

fs.writeFileSync(opt('out', path.join(dir, 'report.md')), md);
fs.writeFileSync(opt('merged', path.join(dir, 'merged.json')), JSON.stringify({ tolerance: tol, shards, failures }, null, 2));
console.log(md);
process.exit(failures.length ? 1 : 0);
