import type { Cookie } from '../model';
import { fromLoose } from './loose';
import { stripBom, type Codec, type ParsedRow } from './types';

export const CSV_COLUMNS = ['name', 'value', 'domain', 'hostOnly', 'path', 'secure', 'httpOnly', 'sameSite', 'session', 'expirationDate', 'storeId', 'partitionKey', 'hasCrossSiteAncestor', 'firstPartyDomain'] as const;

/** Spreadsheets run cells starting with these as formulas; export prefixes `'`, import removes it. */
const NEEDS_GUARD = /^'*[=+\-@\t\r]/;
const HAS_GUARD = /^'(?='*[=+\-@\t\r])/;
const guard = (s: string): string => (NEEDS_GUARD.test(s) ? "'" + s : s);
const unguard = (s: string): string => s.replace(HAS_GUARD, '');

const quote = (s: string) => (/[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s);

/** RFC 4180 records: quoted fields, doubled quotes, newlines inside quotes, CRLF or LF. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], field = '', q = false, any = false;
  const end = () => { row.push(field); field = ''; any = false; };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (q) {
      if (ch === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += ch;
    } else if (ch === '"' && field === '') { q = true; any = true; }
    else if (ch === ',') end();
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      if (any || field !== '' || row.length) { end(); rows.push(row); row = []; }
    } else { field += ch; any = true; }
  }
  if (any || field !== '' || row.length) { end(); rows.push(row); }
  return rows;
}

const ALIAS: Record<string, string> = {
  host: 'domain', hostkey: 'domain', domain: 'domain', expires: 'expirationDate', expiry: 'expirationDate', expirationdate: 'expirationDate',
  httponly: 'httpOnly', ishttponly: 'httpOnly', issecure: 'secure', samesite: 'sameSite', hostonly: 'hostOnly', storeid: 'storeId', partitionkey: 'partitionKey',
  hascrosssiteancestor: 'hasCrossSiteAncestor', firstpartydomain: 'firstPartyDomain',
};

export const csv: Codec = {
  id: 'csv',
  label: 'CSV',
  extension: 'csv',
  mime: 'text/csv',
  export(cs: Cookie[]) {
    const cell = (c: Cookie): string[] => [
      c.name, c.value, c.domain, String(c.hostOnly), c.path, String(c.secure), String(c.httpOnly), c.sameSite, String(c.session),
      c.session || c.expirationDate === undefined ? '' : String(c.expirationDate), c.storeId, c.partitionKey?.topLevelSite ?? '',
      c.partitionKey?.hasCrossSiteAncestor === undefined ? '' : String(c.partitionKey.hasCrossSiteAncestor), c.firstPartyDomain,
    ];
    return [CSV_COLUMNS.join(','), ...cs.map((c) => cell(c).map((x) => quote(guard(x))).join(','))].join('\r\n') + '\r\n';
  },
  parse(text): ParsedRow[] {
    const rows = parseCsv(stripBom(text));
    const head = rows.shift();
    if (!head) return [];
    const cols = head.map((h) => { const k = h.trim().toLowerCase().replace(/[_\s-]/g, ''); return ALIAS[k] ?? k; });
    if (!cols.includes('name') || !cols.includes('domain')) return [{ row: 1, error: 'The first line must name the columns, including name and domain.' }];
    return rows.map((r, i) => {
      const o: Record<string, unknown> = {};
      cols.forEach((k, j) => { const v = unguard(r[j] ?? ''); if (v !== '' || k === 'value') o[k] = v; });
      const ancestor = o.hasCrossSiteAncestor;
      if (typeof o.partitionKey === 'string' && o.partitionKey) {
        o.partitionKey = { topLevelSite: o.partitionKey, ...(ancestor === 'true' || ancestor === 'false' ? { hasCrossSiteAncestor: ancestor === 'true' } : {}) };
      }
      const exp = o.expirationDate;
      if (typeof exp === 'string' && exp === '') delete o.expirationDate;
      return fromLoose(o, i + 2);
    });
  },
};
