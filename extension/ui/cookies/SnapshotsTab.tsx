import { Fragment } from 'preact';
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { whenText } from '../../lib/cookiejar/provenance';
import type { CookieDiff, SnapshotMeta } from '../../lib/cookiejar/snapshots';
import { Icon } from '../icons';
import { errText, useClient } from './client';
import { Confirm, Pill, targetValue, toast } from './kit';
import { useMedia } from './Table';

const when = (at: number) => whenText(at).replace(/:\d\d$/, '');
const LIVE = 'live';

export function SnapshotsTab({ site }: { site: string }) {
  const client = useClient();
  const [snaps, setSnaps] = useState<SnapshotMeta[]>([]);
  const [name, setName] = useState('');
  const [count, setCount] = useState<number | null>(null);
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [diff, setDiff] = useState<CookieDiff | null>(null);
  const [err, setErr] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [live, setLive] = useState(0);
  const [warn, setWarn] = useState<{ id: string; text: string } | null>(null);
  const narrow = useMedia('(max-width:640px)');
  // The live jar changes under a comparison with it.
  useEffect(() => { let t: ReturnType<typeof setTimeout> | undefined; const off = client.onActivity(() => { clearTimeout(t); t = setTimeout(() => setLive((n) => n + 1), 300); }); return () => { clearTimeout(t); off(); }; }, [client]);

  const load = useCallback(async () => {
    try { setSnaps((await client.call({ op: 'snapshot.list' })).slice().sort((x, y) => y.createdAt - x.createdAt)); setErr(''); } catch (e) { setErr(errText(e)); }
    setLoaded(true);
  }, [client]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => client.onResync(() => { void load(); setLive((n) => n + 1); }), [client, load]);
  useEffect(() => { void client.call({ op: 'list', ...(site ? { site } : {}) }).then((l) => setCount(l.length), () => setCount(null)); }, [client, site]);

  // Defaults for Compare once there are snapshots.
  useEffect(() => {
    if (!snaps.length) { setA(''); setB(''); return; }
    setA((cur) => (snaps.some((s) => s.id === cur) ? cur : snaps[0]!.id));
    setB((cur) => (cur === LIVE || snaps.some((s) => s.id === cur) ? cur : snaps[1]?.id ?? LIVE));
  }, [snaps]);

  const seq = useRef(0);
  useEffect(() => {
    if (!a || !b || a === b) { setDiff(null); return; }
    const my = ++seq.current;
    client.call({ op: 'snapshot.diff', id: a, ...(b === LIVE ? {} : { other: b }) }).then((d) => { if (my === seq.current) setDiff(d); }, (e) => { if (my === seq.current) { setDiff(null); setErr(errText(e)); } });
  }, [client, a, b, snaps, live]);

  const save = async () => {
    try {
      const label = name.trim() || `${site || 'All sites'} · ${new Date().toTimeString().slice(0, 5)}`;
      await client.call({ op: 'snapshot.save', name: label, ...(site ? { site } : { cookies: await client.call({ op: 'list' }) }) });
      setName(''); toast('Snapshot saved'); await load();
    } catch (e) { toast(errText(e)); }
  };
  // What a restore will do, said while its button is armed.
  const explain = async (s: SnapshotMeta) => {
    setWarn({ id: s.id, text: 'Checking what restoring will change…' });
    const say = (text: string) => setWarn((w) => (w && w.id === s.id ? { id: s.id, text } : w));
    try {
      const d = await client.call({ op: 'snapshot.diff', id: s.id });
      say(`Restoring "${s.name}" sets ${s.count} cookie${s.count === 1 ? '' : 's'}, replaces ${d.changed.length} and removes ${d.added.length} that are not in it.`);
    } catch { say(`Restoring "${s.name}" sets ${s.count} cookies and may replace or remove others.`); }
  };
  const restore = async (s: SnapshotMeta) => {
    try {
      const r = await client.call({ op: 'snapshot.restore', id: s.id });
      toast(`Restored ${r.set} cookie${r.set === 1 ? '' : 's'}${r.removed ? `, removed ${r.removed}` : ''}${r.skippedProtected ? `, kept ${r.skippedProtected} protected` : ''}. The cookie table now shows them.`);
    } catch (e) { toast(errText(e)); }
  };
  const del = async (s: SnapshotMeta) => {
    try { await client.call({ op: 'snapshot.delete', id: s.id }); toast(`Deleted ${s.name}`); await load(); } catch (e) { toast(errText(e)); }
  };
  const nameOf = (id: string) => (id === LIVE ? 'Live cookies' : snaps.find((s) => s.id === id)?.name ?? id);

  return (
    <>
      <div class="banner info"><Icon n="lock" size={16} /><span class="bt">Stored encrypted in this browser. Snapshots never leave it.</span></div>
      <div class="toolbar">
        <div class="attach srch">
          <input class="input" placeholder="Snapshot name" aria-label="Snapshot name" value={name} onInput={(e) => setName(targetValue(e))} onKeyDown={(e) => { if (e.key === 'Enter') void save(); }} />
          <button type="button" class="btn pri" onClick={() => void save()}>Save current</button>
        </div>
        <span class="dim">{count === null ? '' : `Saves the ${count} cookie${count === 1 ? '' : 's'} for ${site || 'all sites'}`}</span>
      </div>
      {err && <div class="banner err" role="alert"><Icon n="warn" size={16} /><span class="bt">{err}</span></div>}
      <div class="cm-body">
        <div class="tw">
          <table class="t sn" data-testid="snapshot-list" aria-label="Snapshots">
            <thead><tr><th>Snapshot</th><th>Saved</th><th class="r">Cookies</th><th class="acth">Actions</th></tr></thead>
            <tbody>
              {snaps.map((s) => (
                <Fragment key={s.id}>
                <tr class={warn?.id === s.id ? 'armed-row' : ''}>
                  <td class="n"><b>{s.name}</b></td>
                  <td class="muted sv">{when(s.createdAt)}</td>
                  <td class="r num ct">{s.count}</td>
                  <td class="act"><div class="aw">
                    <Confirm label="Restore" sm neutral aria={`Restore ${s.name}`} onArm={() => void explain(s)} onDisarm={() => setWarn(null)} onConfirm={() => void restore(s)} />
                    <Confirm label="Delete" sm left aria={`Delete ${s.name}`} onConfirm={() => void del(s)} />
                  </div>{narrow && warn?.id === s.id && <div class="rwarn" role="status">{warn.text}</div>}</td>
                </tr>
                {!narrow && warn?.id === s.id && <tr class="warnrow"><td colSpan={4}><div class="rwarn" role="status">{warn.text}</div></td></tr>}
                </Fragment>
              ))}
              {loaded && snaps.length === 0 && <tr><td colSpan={4} class="empty muted">No snapshots yet. Save one before you change cookies, and compare or restore it later.</td></tr>}
            </tbody>
          </table>
        </div>
        {snaps.length > 0 && (
          <>
            <div class="sec-t">Compare</div>
            <div class="toolbar">
              <select class="select" aria-label="First snapshot" value={a} onChange={(e) => setA(targetValue(e))}>{snaps.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
              <span class="dim">vs</span>
              <select class="select" aria-label="Second snapshot or live cookies" value={b} onChange={(e) => setB(targetValue(e))}>
                {snaps.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                <option value={LIVE}>Live cookies</option>
              </select>
            </div>
            <div class="tw">
              <table class="t" data-testid="snapshot-diff" aria-label="Differences">
                <thead><tr><th>Change</th><th>Name</th><th>Domain</th><th>Detail</th></tr></thead>
                <tbody>
                  {a === b ? <tr><td colSpan={4} class="empty muted">Pick two different snapshots.</td></tr>
                    : !diff ? <tr><td colSpan={4} class="empty muted">Comparing…</td></tr>
                    : diff.added.length + diff.removed.length + diff.changed.length === 0 ? <tr><td colSpan={4} class="empty muted">No differences.</td></tr>
                    : <>
                      {diff.added.map((c, i) => <tr key={`a${i}`}><td><Pill kind="ok">Added</Pill></td><td class="mono">{c.name}</td><td class="mono">{c.domain}</td><td class="mono muted">only in {nameOf(b)}</td></tr>)}
                      {diff.removed.map((c, i) => <tr key={`r${i}`}><td><Pill kind="err">Removed</Pill></td><td class="mono">{c.name}</td><td class="mono">{c.domain}</td><td class="mono muted">only in {nameOf(a)}</td></tr>)}
                      {diff.changed.map((x, i) => <tr key={`c${i}`}><td><Pill kind="warn">Changed</Pill></td><td class="mono">{x.after.name}</td><td class="mono">{x.after.domain}</td><td class="mono muted">{x.fields.map((f) => (f === 'value' ? 'value differs' : f)).join(', ')}</td></tr>)}
                    </>}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </>
  );
}
