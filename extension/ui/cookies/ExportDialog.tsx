import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { CODECS, FORMAT_IDS, snippet, SNIPPETS, type FormatId, type SnippetId } from '../../lib/cookiejar/codecs';
import { hostOfCookie, type Cookie } from '../../lib/cookiejar/model';
import { Icon } from '../icons';
import { errText, useClient } from './client';
import { copyText, saveText } from './files';
import { Field, Modal, SwRow, targetValue, toast } from './kit';
import { inSite } from './model';

type Scope = 'sel' | 'site' | 'all';
const PREVIEW_MAX = 200_000;

/** One format choice: a codec (`fmt:netscape`) or a command snippet (`sn:curl`). */
const FORMAT_OPTIONS: { v: string; l: string }[] = [
  ...FORMAT_IDS.map((id) => ({ v: `fmt:${id}`, l: CODECS[id].label })),
  ...SNIPPETS.map((s) => ({ v: `sn:${s.id}`, l: `${s.label} command` })),
];

export function ExportDialog({ selected, site, onClose }: { selected: Cookie[]; site: string; onClose: () => void }) {
  const client = useClient();
  const [fmt, setFmt] = useState('fmt:netscape');
  const [scope, setScope] = useState<Scope>(selected.length ? 'sel' : site ? 'site' : 'all');
  const [rows, setRows] = useState<Cookie[]>(selected);
  const [loading, setLoading] = useState(false);
  const [enc, setEnc] = useState(false);
  const [pass, setPass] = useState('');
  const [sealed, setSealed] = useState<{ key: string; text: string } | null>(null);
  const [err, setErr] = useState('');
  const isSnippet = fmt.startsWith('sn:');

  useEffect(() => {
    if (scope === 'sel') { setRows(selected); return; }
    let alive = true;
    setLoading(true);
    client.call({ op: 'list' }).then((r) => { if (alive) { setRows(scope === 'site' && site ? r.filter((c) => inSite(c, site)) : r); setLoading(false); } }, (e) => { if (alive) { setErr(errText(e)); setLoading(false); } });
    return () => { alive = false; };
  }, [scope, site, client]);

  const url = useMemo(() => `https://${site || (rows[0] ? hostOfCookie(rows[0]) : 'example.com')}/`, [site, rows]);
  const plain = useMemo(() => {
    if (!rows.length) return '';
    const [kind, id] = fmt.split(':') as ['fmt' | 'sn', string];
    return kind === 'sn' ? snippet(id as SnippetId, rows, { url }) : CODECS[id as FormatId].export(rows);
  }, [rows, fmt, url]);
  const ext = useMemo(() => {
    const [kind, id] = fmt.split(':') as ['fmt' | 'sn', string];
    return kind === 'sn' ? 'sh' : CODECS[id as FormatId].extension;
  }, [fmt]);

  // The encrypted text is made for exactly these inputs, shown as such and written as such.
  const sealKey = `${fmt}|${scope}|${rows.length}|${pass}|${plain.length}`;
  const wantSeal = enc && !isSnippet && !!pass && rows.length > 0;
  const live = useRef(sealKey);
  live.current = sealKey;
  const seal = async (): Promise<string> => {
    const key = sealKey;
    const r = await client.call({ op: 'export', cookies: rows, format: fmt.split(':')[1] as FormatId, passphrase: pass });
    if (live.current === key) setSealed({ key, text: r.text });
    return r.text;
  };
  useEffect(() => {
    if (!wantSeal) { setSealed(null); return; }
    const t = setTimeout(() => { seal().catch((e) => setErr(errText(e))); }, 450);
    return () => clearTimeout(t);
  }, [sealKey, wantSeal]);

  const need = enc && !isSnippet && !pass;
  const empty = rows.length === 0;
  const shown = wantSeal ? (sealed?.key === sealKey ? sealed.text : 'Encrypting…') : empty ? '(no cookies in this scope)' : plain;
  const clipped = shown.length > PREVIEW_MAX ? `${shown.slice(0, PREVIEW_MAX)}\n… (preview cut here; the file has everything)` : shown;
  const final = async (): Promise<string> => (wantSeal ? (sealed?.key === sealKey ? sealed.text : await seal()) : plain);
  const name = `argus-cookies.${wantSeal ? 'enc.json' : ext}`;
  const disabled = empty || need || loading;
  const doCopy = async () => {
    try { await copyText(await final()); toast('Copied'); } catch (e) { toast(`Could not copy: ${errText(e)}`); }
  };
  const doSave = async () => {
    try { saveText(name, await final(), wantSeal ? 'application/json' : 'text/plain'); toast(`Saved ${name}`); } catch (e) { toast(`Could not save: ${errText(e)}`); }
  };
  return (
    <Modal title="Export cookies" onClose={onClose} testid="export-dialog" footer={
      <div class="mf">
        <button type="button" class="btn" onClick={onClose}>Close</button>
        <button type="button" class="btn" disabled={disabled} onClick={() => void doSave()}>Save</button>
        <button type="button" class="btn pri" disabled={disabled} onClick={() => void doCopy()}>Copy</button>
      </div>
    }>
      <div class="mb">
        <div class="two">
          <Field label="Format" id="exf">
            <select class="select" id="exf" value={fmt} onChange={(e) => setFmt(targetValue(e))}>
              {FORMAT_OPTIONS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
            </select>
          </Field>
          <Field label="Scope" id="exs">
            <select class="select" id="exs" value={scope} onChange={(e) => setScope(targetValue(e) as Scope)}>
              <option value="sel" disabled={!selected.length}>Selected ({selected.length})</option>
              <option value="site" disabled={!site}>This site</option>
              <option value="all">All sites</option>
            </select>
          </Field>
        </div>
        <SwRow on={enc && !isSnippet} label="Encrypt with a passphrase" disabled={isSnippet} onChange={setEnc} id="exe" />
        {enc && !isSnippet && (
          <div>
            <input class={`input${need ? ' bad' : ''}`} type="password" id="exp" placeholder="Passphrase" aria-label="Passphrase" autocomplete="off" value={pass} onInput={(e) => setPass(targetValue(e))} />
            {need && <div class="hint err-h">Enter a passphrase to encrypt.</div>}
          </div>
        )}
        {isSnippet && <div class="hint">Commands cannot be encrypted. Anyone who sees one can use the cookie values in it.</div>}
        <div class="banner warn"><Icon n="warn" size={16} /><span class="bt">This file is equivalent to being logged in. Anyone who has it can use your sessions.</span></div>
        <div class="rw"><span class="sec-t">Preview</span><span class="dim" id="excnt">{rows.length} cookie{rows.length === 1 ? '' : 's'}</span></div>
        <pre class="pv" id="exprev" tabIndex={0} aria-label="Export preview" data-testid="export-preview">{clipped}</pre>
        {err && <div class="hint err-h" role="alert">{err}</div>}
      </div>
    </Modal>
  );
}
