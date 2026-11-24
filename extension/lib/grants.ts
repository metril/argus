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

/** Per-host origins to report: the browser's narrow grants plus the recorded ones it still holds. */
export async function reportedOrigins(browser: any): Promise<string[]> {
  const p = await browser.permissions.getAll();
  const out = new Set<string>(((p?.origins ?? []) as string[]).filter((o) => /^(https?|\*):\/\//.test(o) && !isBroad(o)));
  try {
    const rec = ((await browser.storage.local.get(KEY))?.[KEY] ?? []) as string[];
    for (const o of rec) {
      if (!isBroad(o) && (await browser.permissions.contains({ origins: [o] }))) out.add(o);
    }
  } catch { /* ignore */ }
  return [...out];
}
