import { useEffect, useRef, useState } from 'preact/hooks';
import type { StoreInfo } from '../../lib/cookiejar/api';
import { CODECS } from '../../lib/cookiejar/codecs';
import { isEncrypted } from '../../lib/cookiejar/crypto';
import type { ImportMode, ImportPlan, RowStatus } from '../../lib/cookiejar/detect';
import { ClientError, errText, useClient } from './client';
import { readFileText } from './files';
import { Field, Modal, Pill, Segmented, targetValue, toast } from './kit';

const SHOWN = 300;
const RESULT: Record<RowStatus, { kind: 'ok' | 'warn' | 'err'; l: string }> = {
  import: { kind: 'ok', l: 'Will import' }, replace: { kind: 'warn', l: 'Will replace existing' }, rejected: { kind: 'err', l: 'Rejected' },
};

export function ImportDialog({ stores, defaultStore, site, onClose, onDone }: { stores: StoreInfo[]; defaultStore: string; site: string; onClose: () => void; onDone: () => void }) {
  const client = useClient();
  const [text, setText] = useState('');
  const [mode, setMode] = useState<ImportMode>('merge');
  const [store, setStore] = useState(defaultStore || stores[0]?.id || '');
  const [pass, setPass] = useState('');
  const [planned, setPlanned] = useState<{ key: string; plan: ImportPlan } | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const encrypted = isEncrypted(text);
  // The dry run belongs to exactly these inputs; Import waits until the plan on screen is the one for what is in the box.
  const inputKey = JSON.stringify([text, store, mode, encrypted ? pass : '']);
  const plan = planned && planned.key === inputKey ? planned.plan : null;
  const need = encrypted && !pass;

  useEffect(() => { if (!store && (defaultStore || stores[0])) setStore(defaultStore || stores[0]!.id); }, [defaultStore, stores]);

  // A dry run for every change of the text, the passphrase, the mode or the store.
  const seq = useRef(0);
  useEffect(() => {
    const my = ++seq.current;
    if (!text.trim() || !store || need) { setPlanned(null); setErr(''); return; }
    const t = setTimeout(() => {
      client.call({ op: 'import', text, storeId: store, mode, dryRun: true, ...(site ? { host: site } : {}), ...(encrypted ? { passphrase: pass } : {}) }).then(
        (r) => { if (my === seq.current) { setPlanned({ key: inputKey, plan: r.plan }); setErr(''); } },
        (e) => { if (my === seq.current) { setPlanned(null); setErr(e instanceof ClientError && e.code === 'wrong-passphrase' ? 'That passphrase does not open this export.' : errText(e)); } },
      );
    }, 220);
    return () => clearTimeout(t);
  }, [text, store, mode, pass, need, encrypted, site, client]);

  const ok = plan ? plan.counts.import + plan.counts.replace : 0;
  const go = async () => {
    setBusy(true);
    try {
      const r = await client.call({ op: 'import', text, storeId: store, mode, ...(site ? { host: site } : {}), ...(encrypted ? { passphrase: pass } : {}) });
      const res = r.result;
      const bits = [res ? `Imported ${res.created + res.replaced} cookie${res.created + res.replaced === 1 ? '' : 's'}` : 'Imported'];
      if (res?.removed) bits.push(`removed ${res.removed}`);
      if (res?.failed.length) bits.push(`${res.failed.length} failed`);
      if (res?.skippedProtected) bits.push(`kept ${res.skippedProtected} protected`);
      toast(bits.join(', '));
      onDone(); onClose();
    } catch (e) { setErr(errText(e)); setBusy(false); }
  };
  const choose = async (e: Event) => {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (f) setText(await readFileText(f));
    (e.target as HTMLInputElement).value = '';
  };
  return (
    <Modal title="Import cookies" onClose={onClose} testid="import-dialog" footer={
      <div class="mf">
        <button type="button" class="btn" onClick={onClose}>Cancel</button>
        <button type="button" class="btn pri" id="imgo" disabled={!ok || busy || need} onClick={() => void go()}>{ok ? `Import ${ok}` : 'Import'}</button>
      </div>
    }>
      <div class="mb">
        <div class="rw"><b>Paste</b><span class="dim">or</span>
          <button type="button" class="btn" onClick={() => file.current?.click()}>Choose file…</button>
          <input ref={file} type="file" class="vh" tabIndex={-1} aria-label="Cookie file" accept=".txt,.json,.csv,.sh,text/plain,application/json" onChange={(e) => void choose(e)} />
        </div>
        <textarea class="input mono" id="imt" rows={6} spellcheck={false} aria-label="Cookies to import" placeholder="Netscape cookies.txt, JSON, a Cookie header, CSV or an encrypted Argus export" value={text} onInput={(e) => setText(targetValue(e))} />
        {encrypted && (
          <Field label="Passphrase" id="imp">
            <input class={`input${err.includes('passphrase') ? ' bad' : ''}`} type="password" id="imp" autocomplete="off" placeholder="Passphrase of this export" value={pass} onInput={(e) => setPass(targetValue(e))} />
          </Field>
        )}
        <div class="muted" id="imdet" role="status">
          {!text.trim() ? 'Paste cookies or choose a file.' : need ? 'This export is encrypted. Enter its passphrase.' : plan ? <>Detected: <b>{CODECS[plan.format].label}</b> · {plan.rows.length} cookie{plan.rows.length === 1 ? '' : 's'}</> : err ? '' : 'Reading…'}
        </div>
        {err && <div class="hint err-h" role="alert">{err}</div>}
        {plan && plan.warnings.map((w) => <div key={w} class="hint warnh">{w}</div>)}
        {plan && (
          <div class="tw" id="imtbl">
            <table class="t" style="min-width:520px">
              <thead><tr><th>Name</th><th>Domain</th><th>Result</th></tr></thead>
              <tbody>
                {plan.rows.slice(0, SHOWN).map((r) => (
                  <tr key={r.row}>
                    <td class="mono">{r.cookie?.name ?? `Row ${r.row}`}</td>
                    <td class="mono">{r.cookie?.domain ?? ''}</td>
                    <td><Pill kind={RESULT[r.status].kind}>{RESULT[r.status].l}</Pill> {(r.reason || r.note) && <span class="muted">{r.reason ?? r.note}</span>}</td>
                  </tr>
                ))}
                {plan.rows.length > SHOWN && <tr><td colSpan={3} class="muted">and {plan.rows.length - SHOWN} more rows</td></tr>}
              </tbody>
            </table>
          </div>
        )}
        {stores.length > 1 && (
          <Field label="Import into" id="imstore">
            <select class="select" id="imstore" value={store} onChange={(e) => setStore(targetValue(e))}>{stores.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}</select>
          </Field>
        )}
        <Segmented<ImportMode> label="Import mode" cls="wide" value={mode} onChange={setMode} options={[{ v: 'merge', l: 'Merge with existing' }, { v: 'replace', l: 'Replace cookies for these sites' }]} />
      </div>
    </Modal>
  );
}
