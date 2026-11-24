import type { ConnectSpec } from './bridge-types';

export function normHost(h: string): string {
  h = h.toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  return h;
}

/** Local re-check of the proxy's @connect decision; the extension may only narrow it. */
export function connectAllows(c: ConnectSpec, hostIn: string): boolean {
  const host = normHost(hostIn);
  const page = normHost(c.page);
  if (!host) return false;
  if (host === page || c.all) return true;
  const labels = host.split('.');
  for (const raw of c.list) {
    const e = normHost(raw.trim());
    if (!e || e === '*') continue;
    if (e === 'self') { if (host === page) return true; continue; }
    if (e === 'localhost') { if (host === 'localhost') return true; continue; }
    if (e.endsWith('.*')) {
      const i = labels.indexOf(e.slice(0, -2));
      if (i >= 0 && i < labels.length - 1) return true;
      continue;
    }
    const d = e.startsWith('*.') ? e.slice(2) : e;
    if (host === d || host.endsWith('.' + d)) return true;
  }
  return false;
}

/** Loopback, private, link-local and unspecified targets (and local names): never relayed. */
export function isLocalTarget(hostIn: string): boolean {
  const h = normHost(hostIn);
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (h.includes(':')) {
    if (h === '::' || h === '::1') return true;
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
    if (m) return isLocalTarget(m[1]!);
    const first = parseInt(h.split(':')[0] || '0', 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
  }
  return false;
}

/** Parses an http(s) URL; returns the normalised host or null. */
export function httpHost(url: string): { host: string; scheme: string } | null {
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return { host: normHost(u.hostname), scheme: u.protocol.slice(0, -1) };
  } catch { return null; }
}
