import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { StoreInfo } from '../../lib/cookiejar/api';
import { identityKey, makeCookie, type Cookie, type SameSite } from '../../lib/cookiejar/model';
import { fetchProvenance, joinProvenance, type Provenance, type ProvenanceRecord } from '../../lib/cookiejar/provenance';
import { settings } from '../store';
import { errText, useClient, type ListedCookie } from './client';
import { dateInput, rowOf, strippedRow, type Row } from './model';

// -- the draft of one cookie in the drawer -----------------------------------------------------------
export interface Draft {
  name: string; value: string; domain: string; path: string;
  hostOnly: boolean; session: boolean; expires: string;
  sameSite: SameSite; storeId: string;
  secure: boolean; httpOnly: boolean; partitioned: boolean; topSite: string;
}

export function blankDraft(site: string, storeId: string): Draft {
  return { name: '', value: '', domain: site, path: '/', hostOnly: true, session: true, expires: dateInput(Date.now() / 1000 + 30 * 86400), sameSite: 'lax', storeId, secure: true, httpOnly: false, partitioned: false, topSite: '' };
}

export function fromCookie(c: Cookie): Draft {
  return {
    name: c.name, value: c.value, domain: c.domain, path: c.path, hostOnly: c.hostOnly, session: c.session,
    expires: dateInput(c.expirationDate ?? Date.now() / 1000 + 30 * 86400), sameSite: c.sameSite, storeId: c.storeId,
    secure: c.secure, httpOnly: c.httpOnly, partitioned: !!c.partitionKey, topSite: c.partitionKey?.topLevelSite ?? '',
  };
}

const withScheme = (s: string) => (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);

/** The cookie a draft describes. An expiry the user did not touch keeps its exact time. */
export function toCookie(d: Draft, base?: Cookie): Cookie {
  const bare = d.domain.trim().replace(/^\./, '');
  const o: Partial<Cookie> & { name: string; domain: string } = {
    name: d.name, value: d.value, domain: d.hostOnly ? bare : '.' + bare, hostOnly: d.hostOnly, path: d.path.trim() || '/',
    secure: d.secure, httpOnly: d.httpOnly, sameSite: d.sameSite, storeId: d.storeId, session: d.session,
    firstPartyDomain: base?.firstPartyDomain ?? '',
  };
  if (!d.session) {
    const keep = base && !base.session && base.expirationDate !== undefined && dateInput(base.expirationDate) === d.expires;
    o.expirationDate = keep ? base!.expirationDate! : Math.floor(new Date(`${d.expires || dateInput(Date.now() / 1000 + 30 * 86400)}T23:59:59`).getTime() / 1000);
  }
  if (d.partitioned && d.topSite.trim()) {
    const top = withScheme(d.topSite.trim());
    o.partitionKey = base?.partitionKey && base.partitionKey.topLevelSite === top ? base.partitionKey : { topLevelSite: top };
  }
  return makeCookie(o);
}

// -- throttling ------------------------------------------------------------------------------------
export interface Throttle { call(): void; cancel(): void }

/** Runs `fn` a `wait` after the last call, but never later than `maxWait` after the first call of a burst. */
export function throttle(fn: () => void, wait: number, maxWait: number): Throttle {
  let t: ReturnType<typeof setTimeout> | undefined;
  let first = 0;
  return {
    call() {
      const now = Date.now();
      if (!t) first = now;
      clearTimeout(t);
      t = setTimeout(() => { t = undefined; fn(); }, Math.max(0, Math.min(wait, first + maxWait - now)));
    },
    cancel() { clearTimeout(t); t = undefined; },
  };
}

export const RELOAD_WAIT_MS = 350;
export const RELOAD_MAX_WAIT_MS = 2000;

// -- listing --------------------------------------------------------------------------------------
export interface CookieData {
  cookies: ListedCookie[];
  stores: StoreInfo[];
  loading: boolean;
  error: string;
  /** Re-reads the cookies (and the store list when `stores`). */
  reload: (stores?: boolean) => Promise<void>;
}

/**
 * Every cookie of the browser, kept fresh while it changes them; the scope is applied by the caller.
 * Removals are applied from the activity entry itself; other changes trigger a throttled re-read
 * (at most about 2 s late, paused while the page is hidden). The store list is read on start and on resync.
 */
export function useCookieData(): CookieData {
  const client = useClient();
  const [cookies, setCookies] = useState<ListedCookie[]>([]);
  const [stores, setStores] = useState<StoreInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const gen = useRef(0);
  const dirty = useRef(false);

  const reload = useCallback(async (withStores = false) => {
    const my = ++gen.current;
    dirty.current = false;
    try {
      const [list, st] = await Promise.all([client.call({ op: 'list' }), withStores ? client.call({ op: 'stores' }) : Promise.resolve(undefined)]);
      if (my !== gen.current) return;
      setCookies(list);
      if (st) setStores(st);
      setError('');
    } catch (e) {
      if (my === gen.current) setError(errText(e));
    } finally {
      if (my === gen.current) setLoading(false);
    }
  }, [client]);

  useEffect(() => { setLoading(true); void reload(true); }, [reload]);
  useEffect(() => {
    const th = throttle(() => { if (document.hidden) dirty.current = true; else void reload(); }, RELOAD_WAIT_MS, RELOAD_MAX_WAIT_MS);
    const off = client.onActivity((e) => {
      if (e.kind === 'removed' || e.kind === 'expired' || e.kind === 'evicted') {
        setCookies((cur) => { const i = cur.findIndex((c) => identityKey(c) === e.key); return i < 0 ? cur : [...cur.slice(0, i), ...cur.slice(i + 1)]; });
        // A read that started before this removal must not bring the cookie back: drop its reply, then read again.
        gen.current++;
        th.call();
        return;
      }
      th.call();
    });
    const offSync = client.onResync(() => { th.cancel(); void reload(true); });
    const vis = () => { if (!document.hidden && dirty.current) void reload(); };
    document.addEventListener('visibilitychange', vis);
    return () => { th.cancel(); off(); offSync(); document.removeEventListener('visibilitychange', vis); };
  }, [client, reload]);
  return { cookies, stores, loading, error, reload };
}

// -- provenance -----------------------------------------------------------------------------------
const MAX_RECORDS = 5000;
const recKey = (r: ProvenanceRecord) => `${r.at}|${r.name}|${r.host}|${r.path}|${r.effect ?? ''}`;

/**
 * The proxy's records for this browser session; `{ enabled: false }` while capture is off or the proxy is older.
 * The first read takes the whole ring, later ones only what is newer than the last record.
 */
export function useProvenance(host: string): Provenance | undefined {
  const client = useClient();
  const [p, setP] = useState<Provenance>();
  const s = settings.value;
  const token = s?.token;
  const url = s?.argusUrl;
  const last = useRef(0);
  const have = useRef<Map<string, ProvenanceRecord>>(new Map());
  const gen = useRef(0);
  const load = useCallback(async (fresh: boolean) => {
    if (!s || !s.argusUrl || !s.token) { setP({ enabled: false, reason: 'unavailable' }); return; }
    const my = ++gen.current;
    if (fresh) { last.current = 0; have.current = new Map(); }
    let sid = '';
    try {
      const st = (await (globalThis as any).browser.runtime.sendMessage({ type: 'bridge-status' })) as { sid?: string } | undefined;
      sid = st?.sid ?? '';
    } catch { /* background not ready */ }
    const r = await fetchProvenance(s, sid, { since: Math.max(0, last.current - 1), ...(host ? { host } : {}) });
    if (my !== gen.current) return;
    if (!r.enabled) { last.current = 0; have.current = new Map(); setP(r); return; }
    for (const rec of r.records) { have.current.set(recKey(rec), rec); if (rec.at > last.current) last.current = rec.at; }
    if (have.current.size > MAX_RECORDS) {
      const keep = [...have.current.entries()].sort((a, b) => b[1].at - a[1].at).slice(0, MAX_RECORDS);
      have.current = new Map(keep);
    }
    setP({ enabled: true, records: [...have.current.values()] });
  }, [url, token, host]);
  useEffect(() => { void load(true); }, [load]);
  useEffect(() => {
    const th = throttle(() => { if (!document.hidden) void load(false); }, 1200, 4000);
    const off = client.onActivity((e) => { if (e.kind === 'set' || e.kind === 'changed') th.call(); });
    const offSync = client.onResync(() => { th.cancel(); void load(false); });
    return () => { th.cancel(); off(); offSync(); };
  }, [client, load]);
  return p;
}

/** Browser cookies and stripped ones as table rows, with provenance joined in when it is on. */
export function useRows(cookies: ListedCookie[], prov: Provenance | undefined): Row[] {
  return useMemo(() => {
    if (prov?.enabled) {
      const j = joinProvenance(cookies, prov.records);
      return [...cookies.map((c) => rowOf(c, j.info.get(identityKey(c)))), ...j.stripped.map(strippedRow)];
    }
    return cookies.map((c) => rowOf(c));
  }, [cookies, prov]);
}
