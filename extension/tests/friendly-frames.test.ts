import { describe, expect, it, vi } from 'vitest';
import { Bridge } from '../lib/bridge';
import { attachFriendlyFrame, FriendlyFrames, FRAMES_SCRIPT_FILE, FRAMES_SCRIPT_ID, runInFrame } from '../lib/friendly-frames';

const win = (href: string, parent?: any, extra: object = {}) => {
  const w: any = { location: { href }, document: { documentElement: {} }, ...extra };
  w.parent = parent ?? w;
  return w;
};

describe('attachFriendlyFrame', () => {
  it('hands about:blank, srcdoc and blob frames to the nearest ancestor runtime', () => {
    for (const href of ['about:blank', 'about:srcdoc', 'blob:https://a.test/1-2']) {
      const frame = vi.fn();
      const top = win('https://a.test/', undefined, { __argusRuntime: { frame } });
      const child = win(href, top);
      expect(attachFriendlyFrame(child)).toBe(true);
      expect(frame).toHaveBeenCalledWith(child);
    }
  });

  it('walks past a frame that has no runtime of its own', () => {
    const frame = vi.fn();
    const top = win('https://a.test/', undefined, { __argusRuntime: { frame } });
    const mid = win('about:blank', top);
    const leaf = win('about:blank', mid);
    expect(attachFriendlyFrame(leaf)).toBe(true);
    expect(frame).toHaveBeenCalledWith(leaf);
  });

  it('ignores ordinary documents, top windows and parents without a runtime', () => {
    const frame = vi.fn();
    const top = win('https://a.test/', undefined, { __argusRuntime: { frame } });
    expect(attachFriendlyFrame(win('https://a.test/x', top))).toBe(false);
    expect(attachFriendlyFrame(win('about:blank'))).toBe(false);
    expect(attachFriendlyFrame(win('about:blank', win('https://b.test/')))).toBe(false);
    expect(frame).not.toHaveBeenCalled();
  });

  it('survives a cross-origin parent', () => {
    const top: any = { get __argusRuntime() { throw new Error('SecurityError'); } };
    top.parent = top;
    expect(attachFriendlyFrame(win('about:blank', top))).toBe(false);
  });

  it('waits for the document when it does not exist yet', () => {
    const frame = vi.fn();
    const top = win('https://a.test/', undefined, { __argusRuntime: { frame } });
    let later: (() => void) | undefined;
    const child = win('about:srcdoc', top, {
      document: { addEventListener: (_: string, f: () => void) => { later = f; } },
    });
    runInFrame(child);
    expect(frame).not.toHaveBeenCalled();
    child.document.documentElement = {};
    later!();
    expect(frame).toHaveBeenCalledWith(child);
  });
});

function fakeScripting(initial: string[] = []) {
  const ids = new Set(initial);
  return {
    ids,
    registerContentScripts: vi.fn(async (l: any[]) => { l.forEach((x) => ids.add(x.id)); }),
    unregisterContentScripts: vi.fn(async ({ ids: i }: { ids: string[] }) => { i.forEach((x) => ids.delete(x)); }),
    getRegisteredContentScripts: vi.fn(async ({ ids: i }: { ids: string[] }) => i.filter((x) => ids.has(x)).map((id) => ({ id }))),
  };
}

describe('FriendlyFrames', () => {
  it('registers a document-start, all-frames, origin-fallback script in the page world once', async () => {
    const scripting = fakeScripting();
    const f = new FriendlyFrames({ scripting });
    await f.sync(true);
    await f.sync(true);
    expect(scripting.registerContentScripts).toHaveBeenCalledTimes(1);
    const [spec] = scripting.registerContentScripts.mock.calls[0]![0];
    expect(spec).toMatchObject({
      id: FRAMES_SCRIPT_ID, js: [FRAMES_SCRIPT_FILE], allFrames: true, matchOriginAsFallback: true,
      runAt: 'document_start', world: 'MAIN', matches: ['<all_urls>'],
    });
  });

  it('removes it when disconnected, and adopts one a previous worker left', async () => {
    const scripting = fakeScripting([FRAMES_SCRIPT_ID]);
    const f = new FriendlyFrames({ scripting });
    await f.sync(true);
    expect(scripting.registerContentScripts).not.toHaveBeenCalled();
    await f.sync(false);
    expect(scripting.unregisterContentScripts).toHaveBeenCalledWith({ ids: [FRAMES_SCRIPT_ID] });
    expect(scripting.ids.size).toBe(0);
  });

  it('is a no-op without the scripting API and never throws', async () => {
    await expect(new FriendlyFrames({}).sync(true)).resolves.toBeUndefined();
    const scripting = fakeScripting();
    scripting.registerContentScripts.mockRejectedValueOnce(new Error('nope'));
    await expect(new FriendlyFrames({ scripting }).sync(true)).resolves.toBeUndefined();
  });
});

describe('Bridge and the frames script', () => {
  class WS {
    static last: WS;
    onopen: any; onmessage: any; onclose: any; onerror: any;
    binaryType = '';
    constructor(public url: string) { WS.last = this; }
    send() {}
    close() {}
  }
  const tick = () => new Promise((r) => setTimeout(r, 5));

  it('registers on welcome and removes on disconnect', async () => {
    const sync = vi.fn(async () => {});
    const br = { permissions: { getAll: vi.fn(async () => ({ origins: [] })) }, storage: { local: { get: vi.fn(async () => ({ granted: [] })) } } };
    const b = new Bridge({
      WebSocketCtor: WS as any, browser: br, frames: { sync },
      getSettings: async () => ({ argusUrl: 'https://argus.local:8443', token: 't' }),
    });
    await b.connect();
    WS.last.onopen();
    WS.last.onmessage({ data: JSON.stringify({ t: 'welcome', sid: 'a'.repeat(32), v: 1 }) });
    await tick();
    expect(sync).toHaveBeenLastCalledWith(true);
    await b.stop();
    expect(sync).toHaveBeenLastCalledWith(false);
  });
});
