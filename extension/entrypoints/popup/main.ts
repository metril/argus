import { cachedLookup, getSettings, hostOf, type Interception } from '../../lib/api';
import type { MenuData } from '../../lib/bridge-types';
import { renderMenu } from '../../lib/menu';

const app = document.getElementById('app')!;

function el(tag: string, text?: string, cls?: string) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const status = (text: string, cls: string) => app.append(el('div', text, `s ${cls}`));

function openOptions(label = 'Open settings') {
  const a = el('a', label);
  a.setAttribute('href', '#');
  a.addEventListener('click', (ev) => { ev.preventDefault(); void browser.runtime.openOptionsPage(); });
  app.append(a);
}

const menuBox = document.createElement('div');
menuBox.id = 'menu';
document.body.append(menuBox);

async function userscripts(tab: { id?: number; url?: string } | undefined) {
  if (tab?.id === undefined || !/^https?:/.test(tab.url ?? '')) return;
  let mdoc: string | null = null;
  try {
    const r = await browser.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: () => {
        const e = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
        const s = e && e.serverTiming && Array.from(e.serverTiming).find((x) => x.name === 'argus');
        return s ? s.description : null;
      },
    });
    mdoc = (r?.[0]?.result as string | null | undefined) ?? null;
  } catch { return; }
  if (!mdoc) return;
  menuBox.append(el('h2', 'Userscripts'));
  const body = el('div');
  menuBox.append(body);
  const note = (t: string, c: string) => { body.textContent = ''; body.append(el('div', t, `s ${c}`)); };
  const s = await getSettings();
  let sid: string | undefined; // held in memory only
  try {
    const st = (await browser.runtime.sendMessage({ type: 'bridge-status' })) as { connected?: boolean; sid?: string } | undefined;
    sid = st?.connected ? st.sid : undefined;
  } catch { /* ignore */ }
  if (!s.argusUrl || !sid) { note('The extension is not connected to Argus.', 'warn'); return; }
  const headers = { Authorization: `Bearer ${s.token}`, 'X-Argus-Session': sid };
  let data: MenuData;
  try {
    const res = await fetch(`${s.argusUrl}/api/v1/ext/menu?mdoc=${encodeURIComponent(mdoc)}`, { headers });
    if (res.status === 403 || res.status === 409) { note('This page was not opened through the connected extension.', 'warn'); return; }
    if (!res.ok) { note(`Userscript menu unavailable (HTTP ${res.status}).`, 'warn'); return; }
    data = (await res.json()) as MenuData;
  } catch { note('Cannot reach Argus.', 'warn'); return; }

  const pending = [];
  for (const g of data.grants ?? []) {
    let all = false;
    try { all = await browser.permissions.contains({ origins: g.patterns }); } catch { /* treat as missing */ }
    if (!all) pending.push(g);
  }
  renderMenu(body, { commands: data.commands ?? [], grants: pending }, {
    async trigger(c) {
      try {
        const res = await fetch(`${s.argusUrl}/api/v1/ext/menu/trigger`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mdoc, script: c.script, cmd: c.cmd }),
        });
        if (!res.ok) return false;
        return ((await res.json()) as { delivered?: boolean }).delivered === true;
      } catch { return false; }
    },
    grant(g) { return browser.permissions.request({ origins: g.patterns }); },
    close: () => window.close(),
  });
}

(async () => {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const host = hostOf(tab?.url);
  app.textContent = '';
  void userscripts(tab);
  if (!host) { status('Not a web page.', 'mut'); return; }
  app.append(el('h2', host));
  const s = await getSettings();
  const r = await cachedLookup(host);

  if (r.kind === 'unconfigured') { status('Argus is not configured.', 'warn'); openOptions('Configure'); return; }
  if (r.kind === 'auth') { status(`Authentication failed (HTTP ${r.status}). Check the token and its logs:read scope.`, 'warn'); openOptions(); return; }
  if (r.kind === 'error') { status(`Cannot reach Argus: ${r.message}`, 'warn'); openOptions(); return; }
  if (r.kind === 'unseen') { status('Not seen by Argus: this site is not filtered.', 'mut'); }
  if (r.kind === 'ok') {
    const c = r.cert;
    if (c.verdict === 'invalid') status(`Invalid upstream certificate: ${c.reason === 'distrusted' ? 'issuer no longer trusted for it' : (c.reason ?? 'other')}${c.detail ? ` (${c.detail})` : ''}`, 'bad');
    else status(`Upstream certificate valid${c.ev ? ' (EV)' : ''}`, 'ok');
    const dl = el('dl');
    const row = (k: string, v: string) => dl.append(el('dt', k), el('dd', v));
    row('Subject', c.subject); row('Issuer', c.issuer);
    row('Valid from', c.not_before); row('Valid to', c.not_after);
    row('Fingerprint', c.fp);
    if (c.sans.length) row('SANs', c.sans.join(', '));
    app.append(dl);
  }

  if (tab?.id !== undefined) {
    try {
      const i = (await browser.runtime.sendMessage({ type: 'interception', tabId: tab.id })) as Interception | undefined;
      if (i === 'intercepted') status('Intercepted by Argus', 'ok');
      else if (i === 'direct') status('Direct (not intercepted)', 'mut');
    } catch { /* Chrome: unavailable */ }
  }

  const a = el('a', 'Open Argus web UI');
  a.setAttribute('href', `${s.argusUrl}/`);
  a.setAttribute('target', '_blank');
  app.append(a);
})();
