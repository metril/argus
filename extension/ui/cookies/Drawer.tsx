import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { BulkResult, StoreInfo } from '../../lib/cookiejar/api';
import type { Cookie } from '../../lib/cookiejar/model';
import { HISTORY_NOTE, NOT_SEEN_HINT, OFF_LINE, whenText, type Provenance } from '../../lib/cookiejar/provenance';
import type { Issue } from '../../lib/cookiejar/validate';
import { postExtRule } from '../../lib/api';
import { Icon } from '../icons';
import { settings } from '../store';
import { errText, useClient } from './client';
import { blankDraft, fromCookie, toCookie, type Draft } from './data';
import { Confirm, Field, Modal, Pill, SwRow, targetValue, toast } from './kit';
import { SAME_SITE_LABELS, storeLabel, type Row } from './model';

export function Drawer({ row, stores, defaultStore, site, prov, onClose, onChanged }: {
  row?: Row; stores: StoreInfo[]; defaultStore: string; site: string; prov: Provenance | undefined; onClose: () => void; onChanged: () => void;
}) {
  const client = useClient();
  const base = row?.c;
  const isNew = !row;
  const ro = !!row?.stripped;
  const [d, setD] = useState<Draft>(() => (base ? fromCookie(base) : blankDraft(site, defaultStore)));
  const [issues, setIssues] = useState<Issue[] | null>(null);
  const [fail, setFail] = useState('');
  const [busy, setBusy] = useState(false);
  const set = (p: Partial<Draft>) => setD((x) => ({ ...x, ...p }));
  const next = useMemo(() => toCookie(d, base), [d, base]);
  // Escape closes at once; with unsaved edits it arms Cancel ("Discard changes?") instead.
  const first = useRef(JSON.stringify(d));
  const dirty = !ro && JSON.stringify(d) !== first.current;
  const [discard, setDiscard] = useState(false);
  const cancelBtn = useRef<HTMLButtonElement>(null);
  const armDiscard = () => { setDiscard(true); cancelBtn.current?.focus(); };
  useEffect(() => { if (!discard) return; const t = setTimeout(() => setDiscard(false), 4000); return () => clearTimeout(t); }, [discard]);
  const cancel = () => { if (dirty && !discard) armDiscard(); else onClose(); };

  // The library's own rules, asked for as the user types.
  const seq = useRef(0);
  useEffect(() => {
    if (ro) return;
    const my = ++seq.current;
    const t = setTimeout(() => {
      client.call({ op: 'validate', cookie: next }).then((r) => { if (my === seq.current) setIssues(r); }, () => { if (my === seq.current) setIssues([]); });
    }, 120);
    return () => clearTimeout(t);
  }, [next, ro, client]);

  const bad = !ro && (issues === null || issues.length > 0 || !d.name.trim());
  const done = (msg: string) => { toast(msg); onChanged(); onClose(); };
  const save = async () => {
    setBusy(true); setFail('');
    try {
      if (isNew) await client.call({ op: 'create', cookie: next });
      else await client.call({ op: 'edit', old: base!, next });
      done(isNew ? 'Cookie added' : 'Cookie saved');
    } catch (e) { setFail(errText(e)); setBusy(false); }
  };
  const duplicate = async () => {
    setBusy(true); setFail('');
    try { await client.call({ op: 'create', cookie: toCookie({ ...d, name: `${d.name}-copy` }, base ? { ...base, partitionKey: base.partitionKey } as Cookie : undefined) }); done('Cookie duplicated'); }
    catch (e) { setFail(errText(e)); setBusy(false); }
  };
  const remove = async () => {
    setBusy(true);
    try {
      const res = await client.call({ op: 'remove', cookies: [base!] });
      onChanged(); onClose();
      toast('Cookie deleted', res.done.length ? () => { void client.call({ op: 'create', cookie: base! }).then(onChanged, () => {}); } : undefined);
    } catch (e) { setFail(errText(e)); setBusy(false); }
  };

  const badges = (<>{base?.partitionKey && <Pill kind="acc">Partitioned</Pill>}{ro && <Pill kind="err">Stripped by rule</Pill>}</>);
  const footer = ro ? null : (
    <div class="mf">
      {!isNew && <Confirm label="Delete" onConfirm={() => void remove()} disabled={busy} testid="drawer-delete" />}
      {!isNew && <button type="button" class="btn cfh" disabled={busy || bad} onClick={() => void duplicate()}>Duplicate</button>}
      <button ref={cancelBtn} type="button" class={`btn cfh${discard ? ' dng on' : ''}`} onClick={cancel} onBlur={() => setDiscard(false)}>{discard ? 'Discard changes?' : 'Cancel'}</button>
      <button type="button" class="btn pri cfh" id="dsave" disabled={busy || bad} onClick={() => void save()}>Save</button>
    </div>
  );
  const dis = ro;
  return (
    <Modal drawer onEscape={cancel} title={isNew ? 'Add cookie' : d.name || base?.name || ''} onClose={onClose} badges={badges} footer={footer} testid="cookie-drawer">
      <div class="mb" id="detf">
        {ro && <div class="banner info"><Icon n="info" size={16} /><span class="bt">This cookie never reached the browser, so it cannot be edited. It is shown from provenance only.</span></div>}
        <Field label="Name" id="dn"><input class="input mono" id="dn" value={d.name} disabled={dis} spellcheck={false} onInput={(e) => set({ name: targetValue(e) })} /></Field>
        <Field label="Value" id="dv"><textarea class="input mono" id="dv" rows={2} value={d.value} disabled={dis} spellcheck={false} onInput={(e) => set({ value: targetValue(e) })} /></Field>
        <div class="two">
          <Field label="Domain" id="dd"><input class="input mono" id="dd" value={d.domain} disabled={dis} onInput={(e) => set({ domain: targetValue(e) })} /></Field>
          <Field label="Path" id="dp"><input class="input mono" id="dp" value={d.path} disabled={dis} onInput={(e) => set({ path: targetValue(e) })} /></Field>
        </div>
        <SwRow on={d.hostOnly} label="Host only (no Domain attribute)" disabled={dis} id="dho" onChange={(v) => set({ hostOnly: v })} />
        <SwRow on={d.session} label="Session cookie" disabled={dis} id="dsess" onChange={(v) => set({ session: v })} />
        <Field label="Expires" id="dexp" hidden={d.session}><input class="input" type="date" id="dexp" value={d.expires} disabled={dis} onInput={(e) => set({ expires: targetValue(e) })} /></Field>
        <div class="two">
          <Field label="SameSite" id="dss">
            <select class="select" id="dss" value={d.sameSite} disabled={dis} onChange={(e) => set({ sameSite: targetValue(e) as Draft['sameSite'] })}>
              {SAME_SITE_LABELS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
            </select>
          </Field>
          <Field label="Store" id="dstore">
            <select class="select" id="dstore" value={d.storeId} disabled={dis || !isNew} onChange={(e) => set({ storeId: targetValue(e) })}>
              {stores.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </Field>
        </div>
        <div class="flags">
          <SwRow on={d.secure} label="Secure" disabled={dis} id="dsec" onChange={(v) => set({ secure: v })} />
          <SwRow on={d.httpOnly} label="HttpOnly" disabled={dis} id="dhttp" onChange={(v) => set({ httpOnly: v })} />
          <SwRow on={d.partitioned} label="Partitioned (CHIPS)" disabled={dis} id="dpart" onChange={(v) => set({ partitioned: v })} />
        </div>
        <Field label="Top-level site (partition)" id="dps" hidden={!d.partitioned}><input class="input mono" id="dps" value={d.topSite} disabled={dis} placeholder="https://example.com" onInput={(e) => set({ topSite: targetValue(e) })} /></Field>
        {!ro && (
          <div class="vmsg" id="vmsg" aria-live="polite">
            {issues && issues.length > 0 && issues.map((i) => <div key={i.field + i.reason} class="bad-m"><Icon n="warn" size={14} /><span>{i.reason}</span></div>)}
            {issues && issues.length === 0 && d.name.trim() && <div class="okm"><Icon n="check" size={14} /><span>Looks valid.</span></div>}
            {!d.name.trim() && issues && issues.length === 0 && <div class="bad-m"><Icon n="warn" size={14} /><span>The cookie needs a name.</span></div>}
            {fail && <div class="bad-m"><Icon n="warn" size={14} /><span>{fail}</span></div>}
          </div>
        )}
        {!isNew && !ro && stores.length > 1 && <Transfer cookie={base!} stores={stores} onDone={() => { onChanged(); onClose(); }} />}
        {!isNew && (
          <>
            <div class="sec-t">Where it came from</div>
            <div id="prov"><Where row={row!} prov={prov} /></div>
          </>
        )}
      </div>
    </Modal>
  );
}

/** Copy or move to another store; a cookie that already exists there is asked about. */
function Transfer({ cookie, stores, onDone }: { cookie: Cookie; stores: StoreInfo[]; onDone: () => void }) {
  const client = useClient();
  const others = stores.filter((s) => s.id !== cookie.storeId);
  const [to, setTo] = useState(others[0]?.id ?? '');
  const [ask, setAsk] = useState<{ move: boolean } | null>(null);
  const [msg, setMsg] = useState('');
  const run = async (move: boolean, conflict: 'ask' | 'overwrite' | 'skip') => {
    setMsg('');
    try {
      const r: BulkResult = await client.call({ op: 'copy', cookies: [cookie], toStoreId: to, move, conflict });
      if (r.conflicts?.length) { setAsk({ move }); return; }
      setAsk(null);
      if (r.failed.length) { setMsg(r.failed[0]!.error); return; }
      if (r.skipped.length && !r.done.length) { setMsg(move ? 'Left as it is.' : 'Skipped: the other store keeps its own.'); return; }
      toast(`${move ? 'Moved' : 'Copied'} to ${storeLabel(stores, to)}`);
      onDone();
    } catch (e) { setMsg(errText(e)); }
  };
  if (!others.length) return null;
  return (
    <>
      <div class="sec-t">Copy or move to another store</div>
      <div class="rw">
        <select class="select grow" aria-label="Target store" value={to} onChange={(e) => { setTo(targetValue(e)); setAsk(null); }}>
          {others.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <button type="button" class="btn" onClick={() => void run(false, 'ask')}>Copy</button>
        <button type="button" class="btn" onClick={() => void run(true, 'ask')}>Move</button>
      </div>
      {ask && (
        <div class="banner warn" role="alert">
          <Icon n="warn" size={16} />
          <span class="bt">{storeLabel(stores, to)} already has this cookie. Overwrite it or skip?</span>
          <span class="ba">
            <button type="button" class="btn" onClick={() => void run(ask.move, 'overwrite')}>Overwrite</button>
            <button type="button" class="btn" onClick={() => void run(ask.move, 'skip')}>Skip</button>
          </span>
        </div>
      )}
      {msg && <div class="hint" role="status">{msg}</div>}
    </>
  );
}

function Where({ row, prov }: { row: Row; prov: Provenance | undefined }) {
  if (!prov) return <p class="muted">Checking…</p>;
  if (!prov.enabled) return <p class="muted">{OFF_LINE}</p>;
  const info = row.info;
  const rec = info?.record;
  if (!info?.seen || !rec) {
    return (
      <>
        <p><b>Not seen in transit.</b></p>
        <p class="muted">{NOT_SEEN_HINT}.</p>
        <p class="hint">{HISTORY_NOTE}</p>
      </>
    );
  }
  const s = settings.value;
  const link = rec.listId && s ? `${s.argusUrl}/filters/${encodeURIComponent(rec.listId)}${rec.line ? `#L${rec.line}` : ''}` : '';
  return (
    <>
      <dl class="kv">
        <dt>When</dt><dd>{whenText(rec.at)}</dd>
        <dt>Set by</dt><dd><span class="mono">{rec.host}{rec.path}</span></dd>
        <dt>As sent vs stored</dt>
        <dd>{info.diffs.length ? info.diffs.map((x) => <div key={x.label}>{x.label}: {x.sent} → {x.stored}</div>) : 'Stored exactly as the server sent it.'}</dd>
        {rec.rule && (
          <>
            <dt>{info.effect === 'stripped' ? 'Stripped by' : 'Changed by'}</dt>
            <dd><code>{rec.rule}</code><br /><span class="dim">{rec.listName ?? rec.listId ?? 'Your rules'}{link ? <> · <a href={link} target="_blank" rel="noreferrer">{rec.line ? `line ${rec.line}` : 'open list'}</a></> : rec.line ? ` · line ${rec.line}` : ''}</span></dd>
          </>
        )}
      </dl>
      {!row.stripped && <BlockRule cookie={row.c} />}
      <p class="hint">{HISTORY_NOTE}</p>
    </>
  );
}

/** "Block this cookie": the generated `$cookie` rule, to copy or to add to My rules. */
function BlockRule({ cookie }: { cookie: Cookie }) {
  const client = useClient();
  const [line, setLine] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const show = async () => {
    try { setLine(await client.call({ op: 'rule.line', cookie, options: { action: 'remove', scope: 'host' } })); } catch (e) { setMsg(errText(e)); }
  };
  const add = async () => {
    const s = settings.value;
    if (!s) { setMsg('Sign in from the extension popup to add rules.'); return; }
    setBusy(true); setMsg('');
    const r = await postExtRule(s, 'add', line);
    setBusy(false);
    if (r.ok) { setMsg(r.value.changed ? `Added to My rules. ${r.value.rule_count} custom rules. Reload the page to apply.` : 'No change: the rule was already there.'); toast('Added to My rules in Argus'); }
    else if (r.scope) setMsg('Sign in again from the popup to allow creating rules.');
    else setMsg(r.status === 400 ? `Argus rejected this rule: ${r.message ?? 'it is not an accepted rule.'}` : 'Could not save. Try again.');
  };
  return (
    <>
      <div class="rw"><button type="button" class="btn" id="blockck" onClick={() => void show()}>Block this cookie</button></div>
      <div id="blk">
        {line && (
          <>
            <div class="ruleb mono" data-testid="rule-line">{line}</div>
            <div class="rw">
              <button type="button" class="btn" onClick={() => void navigator.clipboard?.writeText(line).then(() => toast('Rule copied'), () => toast('Could not copy'))}>Copy</button>
              <button type="button" class="btn" disabled={busy} onClick={() => void add()}>Add to My rules</button>
            </div>
          </>
        )}
        {msg && <div class="hint" role="status">{msg}</div>}
      </div>
    </>
  );
}
