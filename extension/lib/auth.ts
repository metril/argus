import { errorForResponse, getSettings, networkError, type ErrorKind, type Settings } from './api';

export type SignInResult = { ok: true; settings: Settings } | { ok: false; error: ErrorKind; refused?: boolean };

/** `argus.lan:8443` -> `https://argus.lan:8443`; null when it is not a usable address. */
export function normalizeUrl(v: string): string | null {
  let t = v.trim().replace(/\/+$/, '');
  if (!t) return null;
  if (!/^https?:\/\//i.test(t)) t = `https://${t}`;
  try { return new URL(t).origin; } catch { return null; }
}

export const browserName = (): 'Chrome' | 'Firefox' => (/Firefox\//.test(navigator.userAgent) ? 'Firefox' : 'Chrome');

/** Trades the password for an extension token; the password is never stored. */
export async function signIn(rawUrl: string, username: string, password: string): Promise<SignInResult> {
  const argusUrl = normalizeUrl(rawUrl);
  if (!argusUrl) return { ok: false, error: 'unreachable' };
  const old = await getSettings();
  try {
    const res = await fetch(`${argusUrl}/api/v1/auth/extension-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username, password, browser: browserName(),
        ...(old.tokenId && old.argusUrl === argusUrl ? { replace_token_id: old.tokenId } : {}),
      }),
    });
    if (res.status === 401) return { ok: false, error: 'badCredentials' };
    const e = errorForResponse(res);
    if (e) return { ok: false, ...e };
    const j = (await res.json()) as { token: string; token_id: string; user?: { username?: string } };
    const settings: Settings = { argusUrl, token: j.token, tokenId: j.token_id, user: j.user?.username ?? username, since: new Date().toISOString() };
    await browser.storage.local.set({ ...settings });
    return { ok: true, settings };
  } catch {
    return { ok: false, ...(await networkError(argusUrl)) };
  }
}

/** Stores a hand-made API token after `check` accepts it. */
export async function useToken(rawUrl: string, token: string, check: (s: Settings) => Promise<ErrorKind | null>): Promise<{ ok: true } | { ok: false; error: ErrorKind }> {
  const argusUrl = normalizeUrl(rawUrl);
  if (!argusUrl || !token.trim()) return { ok: false, error: 'unreachable' };
  const s: Settings = { argusUrl, token: token.trim() };
  const err = await check(s);
  if (err) return { ok: false, error: err };
  await browser.storage.local.set({ argusUrl, token: s.token });
  await browser.storage.local.remove(['tokenId', 'user', 'since']);
  return { ok: true };
}

const TOKEN_KEYS = ['token', 'tokenId', 'user', 'since'];

async function revoke(argusUrl?: string, token?: string) {
  if (!argusUrl || !token) return;
  try { await fetch(`${argusUrl}/api/v1/tokens/self`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(3000) }); } catch { /* offline: still signed out locally */ }
}

/**
 * Background side of sign-out: the token goes first (so nothing can reconnect with it), then the
 * channel stops and the proxy clears, then the captured token is revoked (best effort, bounded).
 */
export async function signOutInBackground(d: { bridge: { stop(): Promise<void> }; proxy: { release(): Promise<void> } }): Promise<void> {
  const s = await getSettings();
  await browser.storage.local.remove(TOKEN_KEYS);
  try { await d.bridge.stop(); await d.proxy.release(); } catch { /* ignore */ }
  await revoke(s.argusUrl, s.token);
}

/** UI side: the background does it (it outlives the popup); if it cannot be reached, do it here. */
export async function signOut(waitMs = 1500): Promise<void> {
  const s = await getSettings();
  let done = false;
  try {
    done = !!(await Promise.race([browser.runtime.sendMessage({ type: 'sign-out' }), new Promise((r) => setTimeout(() => r(false), waitMs))]));
  } catch { /* worker gone */ }
  if (!done) {
    await browser.storage.local.remove(TOKEN_KEYS);
    await revoke(s.argusUrl, s.token);
  }
}

/** `argus.json` in a downloaded Chrome zip carries this server's address. */
export async function bundledUrl(): Promise<string> {
  try {
    const r = await fetch((browser.runtime as any).getURL('/argus.json'));
    if (!r.ok) return '';
    const j = (await r.json()) as { argusUrl?: unknown };
    return typeof j.argusUrl === 'string' ? j.argusUrl : '';
  } catch { return ''; }
}
