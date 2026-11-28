import type { CookieJar } from './api';
import { CODECS, type FormatId, type ParseContext } from './codecs';
import { stripBom } from './codecs/types';
import { identityKey, siteOfCookie, type Cookie } from './model';
import { firstProblem } from './validate';

/** Chrome keeps about 180 cookies per registrable domain, Firefox about 150 per host. */
export const DEFAULT_DOMAIN_LIMIT = 180;

/** Guesses the format of pasted text; null when it looks like none of them. */
export function detectFormat(input: string): FormatId | null {
  const text = stripBom(input).trim();
  if (!text) return null;
  if (text.startsWith('{') || text.startsWith('[')) {
    let v: unknown;
    try { v = JSON.parse(text); } catch { return null; }
    if (v && !Array.isArray(v) && typeof v === 'object' && 'origins' in v) return 'playwright';
    const items: unknown[] = Array.isArray(v) ? v : Array.isArray((v as { cookies?: unknown })?.cookies) ? (v as { cookies: unknown[] }).cookies : [];
    const o = items.find((x) => x && typeof x === 'object') as Record<string, unknown> | undefined;
    if (!o) return null;
    if ('hostOnly' in o || 'expirationDate' in o || 'storeId' in o) return 'json';
    if ('expires' in o || 'size' in o || 'sourceScheme' in o) return Array.isArray(v) ? 'puppeteer' : 'playwright';
    return Array.isArray(v) ? 'json' : 'playwright';
  }
  const lines = text.split(/\r?\n/);
  if (/^#\s*netscape http cookie file/i.test(lines[0] ?? '') || lines.some((l) => l.startsWith('#HttpOnly_'))) return 'netscape';
  const data = lines.filter((l) => l.trim() && !(l.startsWith('#') && !l.startsWith('#HttpOnly_')));
  const tabbed = (l: string) => { const f = l.replace(/^#HttpOnly_/, '').split('\t'); return f.length >= 6 && /^(TRUE|FALSE)$/i.test(f[1] ?? '') && /^(TRUE|FALSE)$/i.test(f[3] ?? ''); };
  if (data.length && data.every(tabbed)) return 'netscape';
  const first = (data[0] ?? '').split(',').map((h) => h.trim().toLowerCase().replace(/^"|"$/g, ''));
  if (first.includes('name') && first.some((h) => ['domain', 'host', 'host_key'].includes(h)) && first.length > 2) return 'csv';
  if (/^(set-)?cookie\s*:/i.test(text)) return 'header';
  if (/^[^=;\s,]+=[^\n]*$/.test(text.split(/\r?\n/)[0] ?? '') && !text.includes('\t')) return 'header';
  return null;
}

export type RowStatus = 'import' | 'replace' | 'rejected';

export interface PlanRow {
  row: number;
  status: RowStatus;
  /** Present unless the row could not be read at all. */
  cookie?: Cookie;
  /** The cookie it would replace (`replace` only). */
  existing?: Cookie;
  /** Why it is rejected: one sentence. */
  reason?: string;
  /** Something the import changes without rejecting the row. */
  note?: string;
}

export type ImportMode = 'merge' | 'replace';

export interface ImportPlan {
  format: FormatId;
  storeId: string;
  mode: ImportMode;
  rows: PlanRow[];
  counts: Record<RowStatus, number>;
  warnings: string[];
  /** The live cookies of the target store the plan was made against. */
  existing: Cookie[];
}

export interface PlanContext extends ParseContext {
  /** The store the cookies go into. */
  storeId: string;
  /** The live cookies (any store; only the target store matters). */
  existing: Cookie[];
  mode?: ImportMode;
  /** Force a format instead of detecting it. */
  format?: FormatId;
  limitPerDomain?: number;
  /** Whether this browser has first-party isolation; when false the field is dropped from imported cookies. */
  firstPartyDomain?: boolean;
}

/** A dry run: what importing this text would do, row by row, without touching the jar. */
export function planImport(text: string, ctx: PlanContext): ImportPlan {
  const mode = ctx.mode ?? 'merge';
  const format = ctx.format ?? detectFormat(text);
  const empty = (reason: string): ImportPlan => ({ format: format ?? 'json', storeId: ctx.storeId, mode, rows: [{ row: 1, status: 'rejected', reason }], counts: { import: 0, replace: 0, rejected: 1 }, warnings: [], existing: [] });
  if (!format) return empty('This text is not a cookie format Argus recognises.');
  const parsed = CODECS[format].parse(text, ctx);
  if (parsed.length === 0) return empty('There are no cookies in this text.');

  const existing = ctx.existing.filter((c) => c.storeId === ctx.storeId);
  const live = new Map(existing.map((c) => [identityKey(c), c]));
  const rows: PlanRow[] = [];
  const lastRow = new Map<string, number>();
  for (const p of parsed) {
    if (!p.cookie) { rows.push({ row: p.row, status: 'rejected', reason: p.error ?? 'This row could not be read.' }); continue; }
    const cookie: Cookie = { ...p.cookie, storeId: ctx.storeId };
    let note: string | undefined;
    if (ctx.firstPartyDomain === false && cookie.firstPartyDomain) {
      cookie.firstPartyDomain = '';
      note = 'First-party isolation data was dropped because this browser does not support it.';
    }
    const bad = firstProblem(cookie, ctx.now !== undefined ? { now: ctx.now } : {});
    if (bad) { rows.push({ row: p.row, status: 'rejected', cookie, reason: bad.reason }); continue; }
    const key = identityKey(cookie);
    const prev = lastRow.get(key);
    if (prev !== undefined) { const r = rows[prev]!; r.status = 'rejected'; r.reason = `A later row (${p.row}) sets the same cookie.`; delete r.existing; }
    lastRow.set(key, rows.length);
    const old = live.get(key);
    rows.push({ row: p.row, status: old ? 'replace' : 'import', cookie, ...(old ? { existing: old } : {}), ...(note ? { note } : {}) });
  }

  const counts: Record<RowStatus, number> = { import: 0, replace: 0, rejected: 0 };
  for (const r of rows) counts[r.status]++;
  return { format, storeId: ctx.storeId, mode, rows, counts, warnings: limitWarnings(rows, existing, mode, ctx.limitPerDomain ?? DEFAULT_DOMAIN_LIMIT), existing };
}

function limitWarnings(rows: PlanRow[], existing: Cookie[], mode: ImportMode, limit: number): string[] {
  const imported = new Map<string, Set<string>>();
  for (const r of rows) {
    if (r.status === 'rejected' || !r.cookie) continue;
    const site = siteOfCookie(r.cookie);
    (imported.get(site) ?? imported.set(site, new Set()).get(site)!).add(identityKey(r.cookie));
  }
  const out: string[] = [];
  for (const [site, keys] of imported) {
    const kept = mode === 'replace' ? 0 : existing.filter((c) => siteOfCookie(c) === site && !keys.has(identityKey(c))).length;
    const total = kept + keys.size;
    if (total > limit) out.push(`${site} would hold ${total} cookies, but browsers keep about ${limit} per domain and drop the oldest.`);
  }
  return out;
}

export interface ApplyResult {
  created: number;
  replaced: number;
  removed: number;
  failed: { row: number; reason: string }[];
  skippedProtected: number;
}

/**
 * Carries out a plan. `merge` adds and overwrites; `replace` also removes the target store's other
 * cookies for the imported sites (protected cookies stay). The new cookies go in before any removal.
 */
export async function applyPlan(jar: CookieJar, plan: ImportPlan, o: { mode?: ImportMode; isProtected?: (c: Cookie) => boolean } = {}): Promise<ApplyResult> {
  const mode = o.mode ?? plan.mode;
  const res: ApplyResult = { created: 0, replaced: 0, removed: 0, failed: [], skippedProtected: 0 };
  const keys = new Set<string>();
  for (const r of plan.rows) {
    if (r.status === 'rejected' || !r.cookie) continue;
    try {
      await jar.create(r.cookie);
      keys.add(identityKey(r.cookie));
      if (r.status === 'replace') res.replaced++; else res.created++;
    } catch (e) {
      res.failed.push({ row: r.row, reason: (e as Error).message });
    }
  }
  if (mode === 'replace') {
    const sites = new Set(plan.rows.filter((r) => r.cookie && keys.has(identityKey(r.cookie))).map((r) => siteOfCookie(r.cookie!)));
    const stale = plan.existing.filter((c) => sites.has(siteOfCookie(c)) && !keys.has(identityKey(c)));
    const out = await jar.removeMany(stale, o.isProtected ? { isProtected: o.isProtected } : {});
    res.removed = out.done.length;
    res.skippedProtected = out.skipped.length;
    for (const f of out.failed) res.failed.push({ row: 0, reason: `Could not remove ${f.cookie.name}: ${f.error}` });
  }
  return res;
}
