import type { CertInfo, ErrorKind, Lookup } from './api';
import { hostOf } from './api';

export type Site =
  | { kind: 'loading' }
  | { kind: 'none'; reason: 'browser' | 'insecure' }
  | { kind: 'unseen' }
  | { kind: 'unknown' }
  | { kind: 'cert'; cert: CertInfo };

export type Resolved =
  | { view: 'signin'; reason?: 'expired' }
  | { view: 'main'; site: Site; banner?: { error: ErrorKind; refused?: boolean } };

export interface StateInput {
  configured: boolean;
  tabUrl?: string;
  /** Undefined while the lookup is still running. */
  lookup?: Lookup;
}

/** Which popup view to show, from what is known so far. Pure. */
export function resolveState(i: StateInput): Resolved {
  if (!i.configured) return { view: 'signin' };
  if (!hostOf(i.tabUrl)) return { view: 'main', site: { kind: 'none', reason: /^http:/.test(i.tabUrl ?? '') ? 'insecure' : 'browser' } };
  const l = i.lookup;
  if (!l) return { view: 'main', site: { kind: 'loading' } };
  switch (l.kind) {
    case 'unconfigured': return { view: 'signin' };
    case 'unseen': return { view: 'main', site: { kind: 'unseen' } };
    case 'ok': return { view: 'main', site: { kind: 'cert', cert: l.cert } };
    case 'error':
      if (l.error === 'sessionExpired') return { view: 'signin', reason: 'expired' };
      return { view: 'main', site: { kind: 'unknown' }, banner: { error: l.error, ...(l.refused ? { refused: true } : {}) } };
  }
}

export interface BannerCopy { title: string; body?: string; action?: 'retry' | 'allow' | 'switch' }

/** One title, at most a short line, one action. Never a raw HTTP code. */
export function bannerCopy(error: ErrorKind, host: string, refused = false): BannerCopy {
  switch (error) {
    case 'badCredentials': return { title: 'Wrong username or password' };
    case 'forbidden': return { title: 'No extension access', body: 'Ask an admin.', action: 'switch' };
    case 'unreachable': return { title: `Can't reach ${host}`, body: refused ? 'Proxy refused it.' : 'Check the address.', action: 'retry' };
    case 'noHostPermission': return { title: 'Permission needed', body: `Allow access to ${host}.`, action: 'allow' };
    case 'sessionExpired': return { title: 'Signed out', body: 'Sign in again.' };
    case 'rateLimited': return { title: 'Too many tries', body: 'Wait a minute.' };
  }
}

export function daysUntil(iso: string, now = Date.now()): number {
  return Math.floor((Date.parse(iso) - now) / 86_400_000);
}

export function issuerName(issuer: string): string {
  return /(?:^|,\s*)CN=([^,]+)/.exec(issuer)?.[1]?.trim() ?? issuer;
}

export function invalidReason(c: CertInfo): string {
  if (c.reason === 'distrusted') return 'Untrusted issuer.';
  const r = String(c.reason ?? '').replace(/_/g, ' ');
  return r ? `${r[0]!.toUpperCase()}${r.slice(1)}.` : 'Invalid certificate.';
}
