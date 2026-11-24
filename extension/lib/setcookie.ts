/** A parsed `Set-Cookie` header, ready for `cookies.set` (see RFC 6265 section 5.2). */
export interface ParsedCookie {
  name: string; value: string; domain?: string; path?: string; secure: boolean; httpOnly: boolean;
  sameSite?: 'no_restriction' | 'lax' | 'strict'; expires?: number; delete: boolean;
}

/** `now` is in seconds. Max-Age wins over Expires; a past expiry means delete. */
export function parseSetCookie(line: string, now = Date.now() / 1000): ParsedCookie | null {
  const parts = line.split(';');
  const first = parts.shift() ?? '';
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  const c: ParsedCookie = { name: first.slice(0, eq).trim(), value: first.slice(eq + 1).trim(), secure: false, httpOnly: false, delete: false };
  if (!c.name) return null;
  let maxAge: number | undefined;
  let expires: number | undefined;
  for (const raw of parts) {
    const i = raw.indexOf('=');
    const k = (i < 0 ? raw : raw.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? '' : raw.slice(i + 1).trim();
    if (k === 'domain' && v) c.domain = v.replace(/^\./, '').toLowerCase();
    else if (k === 'path' && v.startsWith('/')) c.path = v;
    else if (k === 'secure') c.secure = true;
    else if (k === 'httponly') c.httpOnly = true;
    else if (k === 'samesite') {
      const s = v.toLowerCase();
      c.sameSite = s === 'none' ? 'no_restriction' : s === 'strict' ? 'strict' : 'lax';
    } else if (k === 'max-age' && /^-?\d+$/.test(v)) maxAge = Number(v);
    else if (k === 'expires') { const t = Date.parse(v); if (!Number.isNaN(t)) expires = t / 1000; }
  }
  if (maxAge !== undefined) {
    if (maxAge <= 0) c.delete = true; else c.expires = now + maxAge;
  } else if (expires !== undefined) {
    if (expires <= now) c.delete = true; else c.expires = expires;
  }
  return c;
}

/** Apply `Set-Cookie` lines to cookie store `storeId` (and only it). */
export async function storeSetCookies(br: any, url: string, storeId: string, lines: string[]): Promise<void> {
  for (const line of lines) {
    const c = parseSetCookie(line);
    if (!c) continue;
    try {
      if (c.delete) {
        await br.cookies.remove({ url, name: c.name, storeId });
        continue;
      }
      const d: Record<string, unknown> = { url, name: c.name, value: c.value, secure: c.secure, httpOnly: c.httpOnly, storeId };
      if (c.domain) d.domain = c.domain;
      if (c.path) d.path = c.path;
      if (c.sameSite) d.sameSite = c.sameSite;
      if (c.expires !== undefined) d.expirationDate = c.expires;
      await br.cookies.set(d);
    } catch { /* a cookie the browser refuses is dropped, as it would be */ }
  }
}
