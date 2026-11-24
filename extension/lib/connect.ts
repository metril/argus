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

/** Parses an http(s) URL; returns the normalised host or null. */
export function httpHost(url: string): { host: string; scheme: string } | null {
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return { host: normHost(u.hostname), scheme: u.protocol.slice(0, -1) };
  } catch { return null; }
}
