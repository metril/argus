import { makeCookie, normalizeSameSite } from '../model';
import { stripBom, type Codec, type ParseContext, type ParsedRow } from './types';

const NO_HOST = 'A Cookie header has no domain, so choose the site it belongs to first.';
const ATTR = /(^|;)\s*(path|domain|expires|max-age|samesite)\s*=|(^|;)\s*(secure|httponly|partitioned)\s*(;|$)/i;

function pair(s: string): [string, string] | undefined {
  const i = s.indexOf('=');
  if (i <= 0) return undefined;
  return [s.slice(0, i).trim(), s.slice(i + 1).trim()];
}

function setCookieLine(line: string, row: number, ctx: ParseContext): ParsedRow {
  const [first, ...attrs] = line.split(';');
  const nv = pair(first ?? '');
  if (!nv) return { row, error: 'This Set-Cookie line has no name=value.' };
  let domain = ctx.host ?? '';
  let hostOnly = true;
  let path = '/', secure = false, httpOnly = false, partitioned = false;
  let sameSite = 'unspecified';
  let exp: number | undefined;
  for (const a of attrs) {
    const [k0, ...rest] = a.split('=');
    const k = (k0 ?? '').trim().toLowerCase();
    const v = rest.join('=').trim();
    if (k === 'domain' && v) { domain = v.replace(/^\./, ''); hostOnly = false; }
    else if (k === 'path' && v.startsWith('/')) path = v;
    else if (k === 'secure') secure = true;
    else if (k === 'httponly') httpOnly = true;
    else if (k === 'partitioned') partitioned = true;
    else if (k === 'samesite') sameSite = v;
    else if (k === 'max-age' && /^-?\d+$/.test(v)) exp = (ctx.now ?? Date.now()) / 1000 + Number(v);
    else if (k === 'expires' && exp === undefined) { const t = Date.parse(v); if (!Number.isNaN(t)) exp = t / 1000; }
  }
  if (!domain) return { row, error: NO_HOST };
  const host = (ctx.host ?? domain).replace(/^\./, '');
  return {
    row,
    cookie: makeCookie({
      name: nv[0], value: nv[1], domain: hostOnly ? domain : '.' + domain, hostOnly, path, secure, httpOnly, sameSite: normalizeSameSite(sameSite),
      session: exp === undefined, ...(exp !== undefined ? { expirationDate: exp } : {}),
      ...(partitioned ? { partitionKey: { topLevelSite: `https://${host}` } } : {}),
    }),
  };
}

/** `Cookie:` request header (`a=1; b=2`) and `Set-Cookie:` response lines. */
export const header: Codec = {
  id: 'header',
  label: 'Cookie header',
  extension: 'txt',
  mime: 'text/plain',
  export: (cs) => cs.map((c) => `${c.name}=${c.value}`).join('; '),
  parse(text, ctx = {}) {
    const out: ParsedRow[] = [];
    let row = 0;
    for (const raw of stripBom(text).split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      const set = /^set-cookie\s*:\s*/i.exec(line);
      if (set) { out.push(setCookieLine(line.slice(set[0].length), ++row, ctx)); continue; }
      const body = line.replace(/^cookie\s*:\s*/i, '');
      if (!/^cookie\s*:/i.test(line) && ATTR.test(body) && /^[^=;\s]+=/.test(body)) { out.push(setCookieLine(body, ++row, ctx)); continue; }
      for (const part of body.split(';')) {
        if (!part.trim()) continue;
        row++;
        const nv = pair(part);
        if (!nv) { out.push({ row, error: `"${part.trim().slice(0, 40)}" is not name=value.` }); continue; }
        if (!ctx.host) { out.push({ row, error: NO_HOST }); continue; }
        out.push({ row, cookie: makeCookie({ name: nv[0], value: nv[1], domain: ctx.host.replace(/^\./, ''), hostOnly: true }) });
      }
    }
    return out;
  },
};
