import { cachedLookup, getSettings, hostOf, type Interception } from '../../lib/api';

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

(async () => {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const host = hostOf(tab?.url);
  app.textContent = '';
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
    if (c.verdict === 'invalid') status(`Invalid upstream certificate: ${c.reason ?? 'other'}${c.detail ? ` (${c.detail})` : ''}`, 'bad');
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
