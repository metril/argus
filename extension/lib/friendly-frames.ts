/**
 * about:blank, srcdoc and blob: frames are never fetched through Argus, so the proxy cannot
 * inject into them. Its boot script (in the parent page) can reach them through `contentWindow`
 * / `contentDocument`, but a frame created from markup and never touched by script slips past.
 * While the extension is connected, a document-start content script (all frames, matched by the
 * parent's origin) hands each such frame to the parent's boot script, which injects the same
 * bundle the page got.
 */

export const FRAMES_SCRIPT_ID = 'argus-friendly-frames';
/** Where WXT emits `entrypoints/friendly-frames.content.ts`. */
export const FRAMES_SCRIPT_FILE = 'content-scripts/friendly-frames.js';

const FRIENDLY = /^(about:(blank|srcdoc)|blob:)/i;

/**
 * Runs inside a frame (page world): ask the nearest ancestor that carries Argus's runtime
 * (`__argusRuntime.frame`, set by the boot script) to inject into this window. Returns whether
 * an ancestor took it. A no-op for ordinary documents and for cross-origin parents.
 */
export function attachFriendlyFrame(win: any = globalThis): boolean {
  try {
    if (!FRIENDLY.test(String(win.location.href))) return false;
    let p = win;
    for (let i = 0; i < 8; i++) {
      const up = p.parent;
      if (!up || up === p) return false;
      p = up;
      const rt = p.__argusRuntime;
      if (rt && typeof rt.frame === 'function') {
        rt.frame(win);
        return true;
      }
    }
  } catch { /* cross-origin parent or detached frame */ }
  return false;
}

/** The content script body: now, and again once the document exists if it did not yet. */
export function runInFrame(win: any = globalThis): void {
  if (win.document?.documentElement) {
    attachFriendlyFrame(win);
    return;
  }
  win.document?.addEventListener?.('readystatechange', () => { attachFriendlyFrame(win); }, { once: true });
}

/** Registers the content script while the bridge is connected, removes it otherwise. */
export class FriendlyFrames {
  private registered: boolean | null = null;
  private chain: Promise<void> = Promise.resolve();

  constructor(private browser: any) {}

  sync(connected: boolean): Promise<void> {
    this.chain = this.chain.then(() => this.apply(connected)).catch(() => { /* retried on the next change */ });
    return this.chain;
  }

  private async apply(connected: boolean): Promise<void> {
    const s = this.browser?.scripting;
    if (!s?.registerContentScripts || !s.unregisterContentScripts) return;
    if (this.registered === connected) return;
    const existing: { id: string }[] = (await s.getRegisteredContentScripts?.({ ids: [FRAMES_SCRIPT_ID] })) ?? [];
    const has = existing.some((x) => x.id === FRAMES_SCRIPT_ID);
    if (connected && !has) {
      await s.registerContentScripts([{
        id: FRAMES_SCRIPT_ID,
        js: [FRAMES_SCRIPT_FILE],
        matches: ['<all_urls>'],
        allFrames: true,
        matchOriginAsFallback: true,
        runAt: 'document_start',
        world: 'MAIN',
        persistAcrossSessions: true,
      }]);
    } else if (!connected && has) {
      await s.unregisterContentScripts({ ids: [FRAMES_SCRIPT_ID] });
    }
    this.registered = connected;
  }
}
