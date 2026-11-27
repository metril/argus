#!/usr/bin/env node
// One shard: one blocker x one browser, all test sites -> one JSON file.
//   node run.mjs --blocker none|argus|ubol|ubo|adguard-ext|adguard-desktop --browser chrome|firefox
//                [--proxy host:port] [--ca path/to/ca.crt] [--sites turtlecute,toolz] [--out file.json]
//                [--chrome-path /usr/bin/google-chrome] [--ready-timeout 120]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { ensureExtension } from './fetch-extensions.mjs';
import { SITES, extractorSource } from './sites.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? [...a, [v.slice(2), all[i + 1]?.startsWith('--') || all[i + 1] === undefined ? 'true' : all[i + 1]]] : a), []));
const blocker = args.blocker || 'none';
const browser = args.browser || 'chrome';
const proxy = args.proxy || process.env.ARGUS_PROXY;
const caPath = args.ca || process.env.ARGUS_CA;
const chromePath = args['chrome-path'] ?? process.env.CHROME_PATH ?? (fs.existsSync('/usr/bin/google-chrome') ? '/usr/bin/google-chrome' : '');
const readyTimeoutMs = +(args['ready-timeout'] || 120) * 1000;
const sites = args.sites ? SITES.filter((s) => args.sites.split(',').includes(s.id)) : SITES;
const out = args.out || path.join(here, 'results', `${blocker}-${browser}.json`);
const EXT = new Set(['ubol', 'ubo', 'adguard-ext']);
const log = (...a) => console.error(`[${blocker}/${browser}]`, ...a);
const writeDoc = (d) => { fs.mkdirSync(path.dirname(out), { recursive: true }); fs.writeFileSync(out, JSON.stringify(d, null, 2)); log('wrote', out); };
// A baseline that could not be set up is reported, not failed: the aggregator excludes it.
const unavailableDoc = (reason) => ({ blocker, browser, platform: process.platform, unavailable: reason, results: [], finished: new Date().toISOString() });
if (args.unavailable) { writeDoc(unavailableDoc(args.unavailable)); process.exit(0); }

if (blocker === 'argus' && (!proxy || !caPath)) throw new Error('argus needs --proxy host:port and --ca <root CA pem>');
if (!['chrome', 'firefox'].includes(browser)) throw new Error('--browser chrome|firefox');

// Canary: an ad host every blocker in the matrix blocks. Resolves true once a no-cors fetch from a normal
// http origin is rejected, i.e. the blocker's engine is loaded and filtering. Polled, not slept.
const notFiltering = `blocker not filtering: canary ad host still reachable after ${readyTimeoutMs / 1000}s (never scored)`;
// Pure `||host^` tracker hosts (no $redirect stub), so a filtering blocker aborts them. A majority must reject.
// Argus only: a response carrying `x-adblock: blocked|redirected` (headers readable via a cors fetch) also counts
// as blocked. Extension baselines stay strict (reject only).
const canaryFor = (isArgus) => `(async () => {
  const urls = ['https://adservice.google.com/ddm/fls/z', 'https://ads.pubmatic.com/AdServer/js/showad.js', 'https://www.googleadservices.com/pagead/conversion.js'];
  const one = async (u) => {
    const q = u + (u.includes('?') ? '&' : '?') + 'c=' + Date.now();
    try { await fetch(q, { mode: 'no-cors', cache: 'no-store' }); } catch (e) { return true; }
    ${isArgus ? "try { const r = await fetch(q, { mode: 'cors', cache: 'no-store' }); return /^(blocked|redirected)$/.test(r.headers.get('x-adblock') || ''); } catch (e) { return true; }" : 'return false;'}
  };
  const n = (await Promise.all(urls.map(one))).filter(Boolean).length;
  return n * 2 > urls.length;
})()`;
const CANARY = canaryFor(blocker === 'argus');

function nssImport(dbDir, ca) {
  if (spawnSync('certutil', ['-V']).error) return false;
  fs.mkdirSync(dbDir, { recursive: true });
  const db = 'sql:' + dbDir;
  if (!fs.existsSync(path.join(dbDir, 'cert9.db'))) spawnSync('certutil', ['-N', '-d', db, '--empty-password']);
  const r = spawnSync('certutil', ['-A', '-d', db, '-t', 'C,,', '-n', 'argus-ca', '-i', ca]);
  if (r.status !== 0) throw new Error('certutil import failed: ' + r.stderr);
  return true;
}

async function pollReady(evalFn) {
  if (blocker === 'none') return true;
  const t0 = Date.now();
  while (Date.now() - t0 < readyTimeoutMs) {
    if (await evalFn()) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

// ---------- Chrome (playwright-core) ----------
async function runChrome() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'parity-chrome-'));
  const home = path.join(tmp, 'home'); // isolated HOME so the Argus CA lands in a throwaway NSS db
  fs.mkdirSync(home);
  const a = ['--no-sandbox', '--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-search-engine-choice-screen', '--disable-features=DisableLoadExtensionCommandLineSwitch'];
  let extVersion = null;
  if (EXT.has(blocker)) {
    const e = await ensureExtension(blocker, 'chrome');
    extVersion = e.version;
    a.push(`--disable-extensions-except=${e.path}`, `--load-extension=${e.path}`);
  }
  if (blocker === 'argus') {
    a.push(`--proxy-server=http://${proxy}`);
    if (!nssImport(path.join(home, '.pki', 'nssdb'), caPath)) throw new Error('certutil (libnss3-tools) is required to trust the Argus CA');
  }
  const ctx = await chromium.launchPersistentContext(path.join(tmp, 'profile'), {
    ...(chromePath ? { executablePath: chromePath } : {}),
    headless: false,
    args: a,
    ignoreDefaultArgs: ['--disable-extensions', '--headless'],
    env: { ...process.env, HOME: home },
    viewport: { width: 1366, height: 900 },
  });
  const ua = await (async () => { const p = ctx.pages()[0] || (await ctx.newPage()); return p.evaluate(() => navigator.userAgent); })();
  const canaryPage = ctx.pages()[0] || (await ctx.newPage());
  await canaryPage.goto('http://example.com/', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => {});
  const ready = await pollReady(() => canaryPage.evaluate(CANARY).catch(() => false));
  for (const p of ctx.pages()) if (p !== canaryPage) await p.close().catch(() => {});
  if (!ready) {
    await ctx.close();
    fs.rmSync(tmp, { recursive: true, force: true });
    return { unavailable: notFiltering };
  }
  const results = [];
  for (const s of sites) {
    results.push(await measure(s, async () => {
      const p = await ctx.newPage();
      try {
        await p.goto(s.url, { waitUntil: 'domcontentloaded', timeout: 60000 });
        return await p.evaluate(extractorSource(s));
      } finally { await p.close().catch(() => {}); }
    }));
  }
  await ctx.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  return { ua, ready, extVersion, results };
}

// ---------- Firefox (selenium-webdriver + geckodriver) ----------
async function runFirefox() {
  const { Builder } = await import('selenium-webdriver');
  const firefox = (await import('selenium-webdriver/firefox.js')).default;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'parity-ff-'));
  const profile = path.join(tmp, 'profile');
  fs.mkdirSync(profile);
  const opts = new firefox.Options();
  opts.addArguments('-headless', '-profile', profile);
  if (process.env.FIREFOX_BIN) opts.setBinary(process.env.FIREFOX_BIN);
  if (blocker === 'argus') {
    if (!nssImport(profile, caPath)) throw new Error('certutil (libnss3-tools) is required to trust the Argus CA in the Firefox profile');
    const [h, p] = [proxy.split(':')[0], +proxy.split(':')[1]];
    for (const [k, v] of Object.entries({ 'network.proxy.type': 1, 'network.proxy.http': h, 'network.proxy.http_port': p, 'network.proxy.ssl': h, 'network.proxy.ssl_port': p, 'network.proxy.no_proxies_on': '' })) opts.setPreference(k, v);
  }
  for (const [k, v] of Object.entries({ 'datareporting.policy.dataSubmissionEnabled': false, 'browser.shell.checkDefaultBrowser': false, 'app.update.auto': false, 'extensions.autoDisableScopes': 0 })) opts.setPreference(k, v);
  const driver = await new Builder().forBrowser('firefox').setFirefoxOptions(opts).build();
  try {
    await driver.manage().setTimeouts({ script: 420000, pageLoad: 90000 });
    let extVersion = null;
    if (EXT.has(blocker)) {
      const e = await ensureExtension(blocker, 'firefox');
      extVersion = e.version;
      await driver.installAddon(e.path, false);
    }
    const ua = await driver.executeScript('return navigator.userAgent');
    const home = (await driver.getAllWindowHandles())[0];
    await driver.get('http://example.com/');
    const ready = await pollReady(() => driver.executeAsyncScript(`const cb = arguments[arguments.length - 1]; ${CANARY}.then(cb, () => cb(false));`).catch(() => false));
    // Close welcome/first-run tabs the extensions open.
    if (!ready) return { unavailable: notFiltering };
    for (const h of await driver.getAllWindowHandles()) if (h !== home) { await driver.switchTo().window(h); await driver.close(); }
    await driver.switchTo().window(home);
    const results = [];
    for (const s of sites) {
      results.push(await measure(s, async () => {
        await driver.get(s.url);
        const r = await driver.executeAsyncScript(`const cb = arguments[arguments.length - 1]; ${extractorSource(s)}.then(cb, (e) => cb({ __error: String(e) }));`);
        if (r?.__error) throw new Error(r.__error);
        return r;
      }));
    }
    return { ua, ready, extVersion, results };
  } finally {
    await driver.quit().catch(() => {});
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function measure(site, fn) {
  const t0 = Date.now();
  let lastErr;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const r = await fn();
      log(site.id, `${r.score.passed}/${r.score.total} (${r.score.percent}%) in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
      return { site: site.id, url: site.url, ok: true, ...r, seconds: Math.round((Date.now() - t0) / 1000) };
    } catch (e) { lastErr = e; log(site.id, 'attempt', attempt, 'failed:', e.message.split('\n')[0]); }
  }
  return { site: site.id, url: site.url, ok: false, error: lastErr.message.split('\n')[0], score: { passed: 0, total: 0, percent: 0 }, categories: {}, tests: [], meta: {} };
}

const started = new Date().toISOString();
const r = await (browser === 'chrome' ? runChrome() : runFirefox());
if (r.unavailable) { log('baseline unavailable:', r.unavailable); writeDoc(unavailableDoc(r.unavailable)); process.exit(0); }
writeDoc({ blocker, browser, platform: process.platform, proxy: blocker === 'argus' ? proxy : null, extensionVersion: r.extVersion, userAgent: r.ua, canaryBlocked: r.ready, started, finished: new Date().toISOString(), results: r.results });
