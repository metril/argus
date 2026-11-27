#!/usr/bin/env node
// One shard: one blocker x one browser, all test sites -> one JSON file.
//   node run.mjs --blocker none|argus|ubol|ubo|adguard-ext|adguard-desktop --browser chrome|firefox
//                [--proxy host:port] [--ca path/to/ca.crt] [--sites turtlecute,toolz] [--out file.json]
//                [--chrome-path /usr/bin/google-chrome] [--ready-timeout 120] [--settle 15]
import fs from 'node:fs';
import { combinePasses } from './combine.mjs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { ensureExtension } from './fetch-extensions.mjs';
import { SITES, extractorSource } from './sites.mjs';
import { netInitScript, NET_RECORDER_FN, tagNetwork } from './net.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? [...a, [v.slice(2), all[i + 1]?.startsWith('--') || all[i + 1] === undefined ? 'true' : all[i + 1]]] : a), []));
const blocker = args.blocker || 'none';
const isArgus = blocker === 'argus' || blocker === 'argus-strict';
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

if (isArgus && (!proxy || !caPath)) throw new Error('argus needs --proxy host:port and --ca <root CA pem>');
if (!['chrome', 'firefox'].includes(browser)) throw new Error('--browser chrome|firefox');

// Canary: an ad host every blocker in the matrix blocks. Two probes from a normal http origin, both polled:
//  - fetch(no-cors) must reject with a TypeError within FAST_MS (a timeout/abort is an ERROR, not "blocked");
//  - a <script src> of the same host must fire onerror within FAST_MS (onload = reached, timeout = error).
// Ready = both blocked on 2 consecutive polls. Verdicts: 'blocked' | 'reached' | 'error'.
const FAST_MS = 3000;
const notFiltering = `blocker not filtering: canary ad host still reachable after ${readyTimeoutMs / 1000}s (never scored)`;
// Three pure `||host^` ad hosts, probed in parallel; a majority (2 of 3) must be blocked. No single host is
// blocked by every blocker (uBO stubs googlesyndication via $redirect, AdGuard may not list adservice/googleadservices).
// Per host two probes: fetch(no-cors) must reject with a TypeError within FAST_MS (timeout/abort = 'error'),
// and a <script src> must fire onerror within FAST_MS (onload = 'reached'). Both must be blocked.
// (Check e.name, not instanceof: under Firefox/Marionette the TypeError comes from another realm.)
// Argus only: a cors fetch whose response carries `x-adblock: blocked|redirected` also counts as a blocked
// fetch, and a script that loads (Argus may serve a redirect stub) is tolerated. Extensions stay strict.
const canaryFor = (isArgus, scriptOnly = false) => `(async () => {
  const FAST = ${FAST_MS}, ARGUS = ${isArgus}, SCRIPT_ONLY = ${scriptOnly};
  const urls = ['https://ads.pubmatic.com/AdServer/js/showad.js', 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js', 'https://adservice.google.com/ddm/fls/z'];
  const one = async (u) => {
    const q = (k) => u + (u.includes('?') ? '&' : '?') + k + '=' + Date.now();
    const f = (async () => {
      const c = new AbortController(); const t = setTimeout(() => c.abort(), 8000); const t0 = Date.now();
      try { await fetch(q('c'), { mode: 'no-cors', cache: 'no-store', signal: c.signal }); }
      catch (e) { return e && e.name === 'TypeError' && Date.now() - t0 <= FAST ? 'blocked' : 'error'; } finally { clearTimeout(t); }
      if (!ARGUS) return 'reached';
      try { const r = await fetch(q('m'), { mode: 'cors', cache: 'no-store' }); return /^(blocked|redirected)$/.test(r.headers.get('x-adblock') || '') ? 'blocked' : 'reached'; }
      catch (e) { return e && e.name === 'TypeError' ? 'blocked' : 'error'; }
    })();
    const sc = new Promise((res) => { const t0 = Date.now(); const el = document.createElement('script');
      const done = (v) => { clearTimeout(to); el.remove(); res(v); };
      const to = setTimeout(() => done('error'), 8000);
      el.onerror = () => done(Date.now() - t0 <= FAST ? 'blocked' : 'error'); el.onload = () => done('reached');
      el.src = q('s'); document.head.appendChild(el); });
    const [fv, sv] = await Promise.all([f, sc]);
    return { host: new URL(u).host, fetch: fv, script: sv, blocked: (SCRIPT_ONLY ? sv === 'blocked' : fv === 'blocked') && (sv === 'blocked' || (ARGUS && sv === 'reached')) };
  };
  const hosts = await Promise.all(urls.map(one));
  return { ok: hosts.filter((h) => h.blocked).length * 2 > urls.length, hosts };
})()`;
// AdGuard's Firefox extension (MV2) filters <script> loads on these hosts but, in CI, let no-cors fetches through
// (pubmatic blocked; googlesyndication/adservice fetch 'reached' for the full 120s). Its engine is up when the
// script probe is blocked, so judge readiness on the script probe there; per-site scoring is unaffected.
const CANARY = canaryFor(isArgus, blocker === 'adguard-ext' && browser === 'firefox');
// Control request: must keep working on every site run, else the run is discarded and retried once. It is a
// same-origin fetch of the test page's own URL: no list can scope a rule to "third-party requests from this
// site" onto it (AdGuard Base ships `*$3p,domain=adblock.turtlecute.org|paileactivist.github.io`, which blocks any
// third-party control host such as example.com), and blocking the page's own document would break the test.
const CONTROL = `(async () => { const c = new AbortController(); const t = setTimeout(() => c.abort(), 10000);
  try { await fetch(location.href, { cache: 'no-store', signal: c.signal }); return true; } catch (e) { return false; } finally { clearTimeout(t); } })()`;
const SETTLE_MS = +(args['settle'] ?? 15) * 1000; // after the canary passes, let the engine finish loading
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let lastCanary = null;

function nssImport(dbDir, ca) {
  if (spawnSync('certutil', ['-V']).error) return false;
  fs.mkdirSync(dbDir, { recursive: true });
  const db = 'sql:' + dbDir;
  if (!fs.existsSync(path.join(dbDir, 'cert9.db'))) spawnSync('certutil', ['-N', '-d', db, '--empty-password']);
  const r = spawnSync('certutil', ['-A', '-d', db, '-t', 'C,,', '-n', 'argus-ca', '-i', ca]);
  if (r.status !== 0) throw new Error('certutil import failed: ' + r.stderr);
  return true;
}

async function pollReady(evalFn, beforeEach) {
  if (blocker === 'none') return true;
  const t0 = Date.now();
  let streak = 0;
  while (Date.now() - t0 < readyTimeoutMs) {
    if (beforeEach) await beforeEach().catch(() => {});
    lastCanary = await evalFn();
    streak = lastCanary?.ok ? streak + 1 : 0;
    if (streak >= 2) { log('canary blocked', JSON.stringify(lastCanary), '- settling', SETTLE_MS / 1000, 's'); await sleep(SETTLE_MS); return true; }
    await sleep(1000);
  }
  log('canary last state:', JSON.stringify(lastCanary));
  return false;
}

// Chrome MV3 extension state: service worker -> enabled DNR rulesets + storage keys (logged on failure,
// and polled so the canary only counts once static rulesets are enabled).
async function chromeExtState(ctx) {
  const out = [];
  for (const w of ctx.serviceWorkers()) {
    if (!w.url().startsWith('chrome-extension://')) continue;
    const st = await w.evaluate(async () => ({
      rulesets: await chrome.declarativeNetRequest.getEnabledRulesets().catch((e) => 'err:' + e),
      storageKeys: await chrome.storage.local.get(null).then((o) => Object.keys(o).slice(0, 40)).catch(() => null),
    })).catch((e) => ({ error: String(e).split('\n')[0] }));
    out.push({ sw: w.url(), ...st });
  }
  return out;
}
async function chromeFailureDump(ctx) {
  log('extension state:', JSON.stringify(await chromeExtState(ctx)));
  for (const p of ctx.pages()) log('page', p.url(), '|', await p.evaluate(() => document.body?.innerText.replace(/\s+/g, ' ').slice(0, 300)).catch(() => ''));
}
// Opening the extension's options page wakes its MV3 service worker (and triggers first-run init).
async function keepAlive(ctx) {
  const w = ctx.serviceWorkers().find((x) => x.url().startsWith('chrome-extension://'));
  if (!w) return;
  const origin = new URL(w.url()).origin;
  if (ctx.pages().some((p) => p.url().startsWith(origin))) return;
  const p = await ctx.newPage();
  await p.goto(origin + '/pages/options.html', { timeout: 15000 }).catch(() => {});
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
  if (isArgus) {
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
  const rulesetsUp = async () => { const st = await chromeExtState(ctx); return !EXT.has(blocker) || st.length === 0 || st.some((x) => Array.isArray(x.rulesets) && x.rulesets.length); };
  const ready = await pollReady(
    async () => ((await rulesetsUp().catch(() => true)) ? canaryPage.evaluate(CANARY).catch(() => null) : null),
    async () => { if (blocker === 'adguard-ext') await keepAlive(ctx); },
  );
  if (!ready && EXT.has(blocker)) await chromeFailureDump(ctx);
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
        await p.addInitScript(netInitScript);
        await p.goto(s.url, { waitUntil: 'domcontentloaded', timeout: 60000 });
        const r = await p.evaluate(extractorSource(s));
        tagNetwork(r, await p.evaluate(() => window.__argusNet || []).catch(() => []));
        r.control = await p.evaluate(CONTROL).catch(() => false);
        return r;
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
  const getScriptManager = (await import('selenium-webdriver/bidi/scriptManager.js')).default;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'parity-ff-'));
  const profile = path.join(tmp, 'profile');
  fs.mkdirSync(profile);
  const opts = new firefox.Options();
  opts.addArguments('-headless', '-profile', profile);
  opts.enableBidi();
  if (process.env.FIREFOX_BIN) opts.setBinary(process.env.FIREFOX_BIN);
  if (isArgus) {
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
    const ready = await pollReady(() => driver.executeAsyncScript(`const cb = arguments[arguments.length - 1]; ${CANARY}.then(cb, () => cb(null));`).catch(() => null));
    if (!ready && EXT.has(blocker)) {
      // Log what the extension left open (welcome/onboarding tabs) to diagnose first-run blockers.
      for (const h of await driver.getAllWindowHandles()) {
        await driver.switchTo().window(h);
        log('tab', await driver.getCurrentUrl().catch(() => '?'), '|', await driver.executeScript("return (document.body && document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 300)").catch(() => ''));
      }
    }
    // Close welcome/first-run tabs the extensions open.
    if (!ready) return { unavailable: notFiltering };
    for (const h of await driver.getAllWindowHandles()) if (h !== home) { await driver.switchTo().window(h); await driver.close(); }
    await driver.switchTo().window(home);
    // Firefox/selenium has no addInitScript: a BiDi preload script runs the recorder before page scripts.
    try { await (await getScriptManager([], driver)).addPreloadScript(NET_RECORDER_FN); } catch (e) { log('net recorder unavailable:', e.message.split('\n')[0]); }
    const results = [];
    for (const s of sites) {
      if (blocker === 'ubo' && s.fetchProbe) {
        // uBO on Firefox answers blocked no-cors fetches locally (opaque response in ~8ms, while script loads of the
        // same host fail), so a page that scores by "fetch rejected" reads uBO as blocking nothing. Not measurable.
        results.push({ site: s.id, url: s.url, ok: false, error: 'not measurable: uBO/Firefox resolves blocked no-cors fetches as opaque responses', score: { passed: 0, total: 0, percent: 0 }, categories: {}, tests: [], meta: {} });
        continue;
      }
      results.push(await measure(s, async () => {
        await driver.get(s.url);
        const r = await driver.executeAsyncScript(`const cb = arguments[arguments.length - 1]; ${extractorSource(s)}.then(cb, (e) => cb({ __error: String(e) }));`);
        if (r?.__error) throw new Error(r.__error);
        tagNetwork(r, await driver.executeScript('return window.__argusNet || []').catch(() => []));
        r.control = await driver.executeAsyncScript(`const cb = arguments[arguments.length - 1]; ${CONTROL}.then(cb, () => cb(false));`).catch(() => false);
        return r;
      }));
    }
    return { ua, ready, extVersion, results };
  } finally {
    await driver.quit().catch(() => {});
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// Each site runs PARITY_PASSES times (default 2). A run is valid only if the unblocked control host was
// reachable; a failed or invalid run is discarded and retried once. A test counts as passed only if it passed in
// EVERY valid scored pass (the leading warm-up pass absorbs lazy compile/caches and is not scored) (symmetric for all blockers), de-noising timeouts/network failures that read as "blocked".
// Per-test pass vectors are recorded in `tests[].passes`; firstPercent is the first valid pass's score.
const PASSES = Math.max(1, +(process.env.PARITY_PASSES || 2)); // scored passes; one extra unscored warm-up pass runs first
async function measure(site, fn) {
  const t0 = Date.now();
  let lastErr = new Error('no result');
  const runs = [];
  let warm = null;
  for (let pass = 0; pass <= PASSES; pass++) {
    let got = null;
    for (let attempt = 1; attempt <= 2 && !got; attempt++) {
      try {
        const r = await fn();
        if (!r.control) { lastErr = new Error('control (same-origin fetch of the test page) failed'); log(site.id, `pass ${pass} attempt ${attempt} discarded:`, lastErr.message); continue; }
        got = r;
      } catch (e) { lastErr = e; log(site.id, `pass ${pass} attempt ${attempt} failed:`, e.message.split('\n')[0]); }
    }
    if (got) { log(site.id, `pass ${pass === 0 ? "warm-up (unscored)" : pass}: ${got.score.passed}/${got.score.total} (${got.score.percent}%)`); if (pass === 0) warm = got; else runs.push(got); }
  }
  if (runs.length) { const { control, ...r } = combinePasses(runs); return { site: site.id, url: site.url, ok: true, ...r, controlOk: true, passes: runs.length, firstPercent: warm?.score.percent, seconds: Math.round((Date.now() - t0) / 1000) }; }
  return { site: site.id, url: site.url, ok: false, error: lastErr.message.split('\n')[0], score: { passed: 0, total: 0, percent: 0 }, categories: {}, tests: [], meta: {} };
}

const started = new Date().toISOString();
const r = await (browser === 'chrome' ? runChrome() : runFirefox());
if (r.unavailable) { log('baseline unavailable:', r.unavailable); writeDoc(unavailableDoc(r.unavailable)); process.exit(0); }
writeDoc({ blocker, browser, platform: process.platform, proxy: isArgus ? proxy : null, extensionVersion: r.extVersion, userAgent: r.ua, canaryBlocked: !!r.ready, canary: lastCanary, started, finished: new Date().toISOString(), results: r.results });
