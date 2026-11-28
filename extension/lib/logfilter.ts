import type { LogEntry } from './api';

export type Party = 'all' | 'first' | 'third';
export type StatusKey = 'blocked' | 'allowed' | 'modified' | 'user';
export type TypeKey = 'document' | 'script' | 'css' | 'xhr' | 'image' | 'media' | 'font' | 'websocket' | 'other';

export const STATUS_KEYS: StatusKey[] = ['blocked', 'allowed', 'modified', 'user'];
export const STATUS_LABELS: Record<StatusKey, string> = { blocked: 'Blocked', allowed: 'Allowed', modified: 'Redirected / modified', user: 'User rules' };
export const TYPE_KEYS: TypeKey[] = ['document', 'script', 'css', 'xhr', 'image', 'media', 'font', 'websocket', 'other'];
export const TYPE_LABELS: Record<TypeKey, string> = {
  document: 'Document', script: 'Script', css: 'CSS', xhr: 'XHR / fetch', image: 'Image', media: 'Media', font: 'Font', websocket: 'WebSocket', other: 'Other',
};

export interface Filters { search: string; party: Party; status: ReadonlySet<StatusKey>; types: ReadonlySet<TypeKey> }
export const noFilters = (): Filters => ({ search: '', party: 'all', status: new Set(), types: new Set() });

export function typeKey(t: string): TypeKey {
  switch (t) {
    case 'document': case 'subdocument': case 'sub_frame': case 'main_frame': return 'document';
    case 'script': return 'script';
    case 'stylesheet': case 'css': return 'css';
    case 'xhr': case 'fetch': case 'xmlhttprequest': return 'xhr';
    case 'image': case 'imageset': return 'image';
    case 'media': return 'media';
    case 'font': return 'font';
    case 'websocket': return 'websocket';
    default: return 'other';
  }
}

/** The status chips an entry belongs to (a user-rule hit is both its outcome and `user`). */
export function statusKeys(e: Pick<LogEntry, 'outcome' | 'user_rule'>): StatusKey[] {
  const k: StatusKey[] = [];
  if (e.outcome === 'blocked' || e.outcome === 'aborted') k.push('blocked');
  else if (e.outcome === 'allowed') k.push('allowed');
  else k.push('modified');
  if (e.user_rule) k.push('user');
  return k;
}

/** Empty chip sets filter nothing; within a chip group any selected chip matches. */
export function matches(e: LogEntry, f: Filters): boolean {
  if (f.party === 'first' && e.third_party !== false) return false;
  if (f.party === 'third' && e.third_party !== true) return false;
  if (f.status.size > 0 && !statusKeys(e).some((k) => f.status.has(k))) return false;
  if (f.types.size > 0 && !f.types.has(typeKey(e.type))) return false;
  const q = f.search.trim().toLowerCase();
  if (q && ![e.url, e.rule ?? '', e.list_name ?? e.list_id ?? '', e.type, e.method].some((x) => x.toLowerCase().includes(q))) return false;
  return true;
}

export const applyFilters = <T extends LogEntry>(rows: T[], f: Filters): T[] => rows.filter((r) => matches(r, f));

export const statusLabel = (e: Pick<LogEntry, 'outcome'>) => (e.outcome === 'aborted' ? 'blocked' : e.outcome);

/** Plain-text export, one tab-separated line per row. */
export function exportText(rows: LogEntry[]): string {
  return rows.map((r) => [r.time, statusLabel(r), r.method, r.url, r.type, r.rule ?? '', r.list_name ?? r.list_id ?? ''].join('\t')).join('\n');
}
