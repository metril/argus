import { useEffect, useState } from 'preact/hooks';
import { makeCookie, siteOf } from '../../lib/cookiejar/model';
import type { RuleSet } from '../../lib/cookiejar/rules';
import { errText, useClient } from './client';
import { Confirm, Sw, targetValue, toast } from './kit';
import { cookieFromIdentity, parseIdentity } from './model';

const DELAYS: [number, string][] = [[0.5, '30 seconds'], [1, '1 minute'], [10, '10 minutes'], [60, '1 hour']];

/** A site as the rules store it: the host, no scheme, path or leading dot. */
function cleanSite(v: string): string {
  const t = v.trim().toLowerCase();
  if (!t) return '';
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(t) ? t : `https://${t}`).hostname.replace(/^\./, ''); } catch { return ''; }
}

export function RulesTab({ site }: { site: string }) {
  const client = useClient();
  const [rules, setRules] = useState<RuleSet | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => { void client.call({ op: 'rules.get' }).then(setRules, (e) => setErr(errText(e))); }, [client]);

  const apply = async (patch: Partial<RuleSet>, undoTo?: RuleSet, said?: string) => {
    try {
      const next = await client.call({ op: 'rules.set', rules: patch });
      setRules(next); setErr('');
      if (said) toast(said, undoTo ? () => void client.call({ op: 'rules.set', rules: undoTo }).then(setRules, () => {}) : undefined);
    } catch (e) { setErr(errText(e)); }
  };
  if (!rules) return <div class="cm-body"><div class="muted center" role="status">{err || 'Loading rules…'}</div></div>;
  const delayOpts = DELAYS.some(([m]) => m === rules.autoDelete.delayMinutes) ? DELAYS : [...DELAYS, [rules.autoDelete.delayMinutes, `${rules.autoDelete.delayMinutes} minutes`] as [number, string]].sort((a, b) => a[0] - b[0]);

  return (
    <div class="cm-body">
      {err && <div class="banner err" role="alert"><span class="bt">{err}</span></div>}
      <div class="rgrid">
        <div class="card rows full">
          <div class="srow center">
            <Sw on={rules.autoDelete.enabled} label="Auto-delete" onChange={(v) => void apply({ autoDelete: { enabled: v, delayMinutes: rules.autoDelete.delayMinutes } })} />
            <span>
              Delete cookies for sites not on the keep list{' '}
              <select class="select inl" aria-label="Wait" value={String(rules.autoDelete.delayMinutes)} onChange={(e) => void apply({ autoDelete: { enabled: rules.autoDelete.enabled, delayMinutes: Number(targetValue(e)) } })}>
                {delayOpts.map(([m, l]) => <option key={m} value={String(m)}>{l}</option>)}
              </select>{' '}
              after the last tab closes
            </span>
          </div>
        </div>
        <SiteList title="Keep list" note="Cookies for these sites are never auto-deleted." ph="example.com" aria="Site to keep" items={rules.keep} def={site}
          onAdd={(v) => apply({ keep: [...rules.keep, v] }, rules, `Added ${v} to the keep list`)} onRemove={(v) => apply({ keep: rules.keep.filter((x) => x !== v) }, rules, `Removed ${v}`)} />
        <SiteList title="Greylist" note="Cookies for these sites are kept until the browser restarts." ph="example.com" aria="Site to greylist" items={rules.grey} def={site}
          onAdd={(v) => apply({ grey: [...rules.grey, v] }, rules, `Added ${v} to the greylist`)} onRemove={(v) => apply({ grey: rules.grey.filter((x) => x !== v) }, rules, `Removed ${v}`)} />
        <Protected rules={rules} site={site} onChange={setRules} />
      </div>
    </div>
  );
}

function SiteList({ title, note, ph, aria, items, def, onAdd, onRemove }: {
  title: string; note: string; ph: string; aria: string; items: string[]; def: string; onAdd: (v: string) => Promise<void>; onRemove: (v: string) => Promise<void>;
}) {
  const [v, setV] = useState('');
  const add = async () => { const s = cleanSite(v) || (v.trim() ? '' : ''); if (!s) return; await onAdd(s); setV(''); };
  void def;
  return (
    <div class="card" data-testid={`rules-${title.toLowerCase().replace(/ /g, '-')}`}>
      <h3>{title}</h3>
      <p class="muted">{note}</p>
      <div class="attach">
        <input class="input" placeholder={ph} aria-label={aria} value={v} onInput={(e) => setV(targetValue(e))} onKeyDown={(e) => { if (e.key === 'Enter') void add(); }} />
        <button type="button" class="btn" onClick={() => void add()}>Add</button>
      </div>
      <Items items={items.map((x) => ({ id: x, text: x }))} onRemove={(id) => void onRemove(id)} />
    </div>
  );
}

function Items({ items, onRemove }: { items: { id: string; text: string }[]; onRemove: (id: string) => void }) {
  return (
    <div class="lst">
      {items.length ? items.map((it) => (
        <div class="li" key={it.id}>
          <span class="mono t" title={it.text}>{it.text}</span>
          <Confirm label="Remove" sm left aria={`Remove ${it.text}`} onConfirm={() => onRemove(it.id)} />
        </div>
      )) : <span class="muted">Nothing here yet.</span>}
    </div>
  );
}

function Protected({ rules, site, onChange }: { rules: RuleSet; site: string; onChange: (r: RuleSet) => void }) {
  const client = useClient();
  const [name, setName] = useState('');
  const [dom, setDom] = useState('');
  const [msg, setMsg] = useState('');
  const add = async () => {
    const n = name.trim();
    const host = cleanSite(dom) || site;
    if (!n || !host) { setMsg('Give a cookie name and a domain.'); return; }
    setMsg('');
    try {
      const live = (await client.call({ op: 'list', site: host })).filter((c) => c.name === n && (c.domain.replace(/^\./, '').toLowerCase() === host || siteOf(c.domain) === siteOf(host)));
      let cookies = live;
      if (!cookies.length) {
        const stores = await client.call({ op: 'stores' });
        cookies = [makeCookie({ name: n, domain: host, storeId: stores.find((s) => s.kind === 'default')?.id ?? stores[0]?.id ?? '' })];
      }
      onChange(await client.call({ op: 'rules.protect', cookies, protect: true }));
      setName(''); setDom('');
    } catch (e) { setMsg(errText(e)); }
  };
  const remove = async (key: string) => {
    const c = cookieFromIdentity(key);
    if (!c) return;
    try {
      const before = rules;
      onChange(await client.call({ op: 'rules.protect', cookies: [c], protect: false }));
      toast(`Removed ${c.name}`, () => void client.call({ op: 'rules.set', rules: before }).then(onChange, () => {}));
    } catch (e) { setMsg(errText(e)); }
  };
  const items = rules.protected.flatMap((k) => { const p = parseIdentity(k); return p ? [{ id: k, text: `${p.name} · ${p.host}` }] : []; });
  return (
    <div class="card full" data-testid="rules-protected">
      <h3>Protected cookies</h3>
      <p class="muted">These cookies are never deleted by auto-delete or bulk delete.</p>
      <div class="attach">
        <input class="input" placeholder="Cookie name" aria-label="Cookie name" value={name} onInput={(e) => setName(targetValue(e))} />
        <input class="input" placeholder="Domain" aria-label="Domain" value={dom} onInput={(e) => setDom(targetValue(e))} onKeyDown={(e) => { if (e.key === 'Enter') void add(); }} />
        <button type="button" class="btn" onClick={() => void add()}>Add</button>
      </div>
      {msg && <div class="hint err-h" role="alert">{msg}</div>}
      <Items items={items} onRemove={(id) => void remove(id)} />
    </div>
  );
}
