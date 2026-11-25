const KEY = 'granted';

/** Patterns too broad to count as a per-host grant (never reported to Argus). */
export function isBroad(o: string): boolean {
  if (o === '<all_urls>') return true;
  const m = /^(\*|https?):\/\/([^/]*)\/(.*)$/.exec(o);
  if (!m) return true;
  const host = m[2];
  return host === '*' || host === '' || host === '*.*' || m[3] !== '*';
}

/** Remember patterns the user granted through the popup (Firefox lists only `<all_urls>`). */
export async function recordGrant(browser: any, patterns: string[]): Promise<void> {
  try {
    const cur = ((await browser.storage.local.get(KEY))?.[KEY] ?? []) as string[];
    const next = [...new Set([...cur, ...patterns.filter((p) => !isBroad(p))])].slice(-2000);
    await browser.storage.local.set({ [KEY]: next });
  } catch { /* ignore */ }
}

/** Recorded per-host grants: the only consent for script logins (browser permissions are broad). */
export async function reportedOrigins(browser: any): Promise<string[]> {
  return listGrants(browser);
}

/** Chrome match-pattern semantics for a recorded grant: scheme, host (`*.x` = subdomains only), optional port. */
export function patternMatches(pattern: string, scheme: string, host: string, port = ''): boolean {
  const m = /^(\*|https?):\/\/([^/]*)\/(.*)$/.exec(pattern);
  if (!m || (m[1] !== '*' && m[1] !== scheme)) return false;
  const pm = /^(.*?)(?::(\d+))?$/.exec(m[2]!.toLowerCase())!;
  const ph = pm[1]!;
  if (pm[2] && pm[2] !== port) return false;
  const h = host.toLowerCase();
  if (ph === '*') return true;
  if (ph.startsWith('*.')) return h.endsWith(ph.slice(1)) && h.length > ph.length - 1;
  return ph === h;
}

export async function isGranted(browser: any, scheme: string, host: string, port = ''): Promise<boolean> {
  return (await listGrants(browser)).some((p) => patternMatches(p, scheme, host, port));
}

export async function allGranted(browser: any, patterns: string[]): Promise<boolean> {
  const cur = await listGrants(browser);
  return patterns.every((p) => cur.includes(p));
}

/** Recorded script-login grants, for the options page. */
export async function listGrants(browser: any): Promise<string[]> {
  try { return (((await browser.storage.local.get(KEY))?.[KEY] ?? []) as string[]).filter((o) => !isBroad(o)); } catch { return []; }
}

/** Forgets a grant. */
export async function revokeGrant(browser: any, pattern: string): Promise<void> {
  try {
    const cur = ((await browser.storage.local.get(KEY))?.[KEY] ?? []) as string[];
    await browser.storage.local.set({ [KEY]: cur.filter((p) => p !== pattern) });
  } catch { /* ignore */ }
}
