// The proxy's in-page boot script (crates/proxy-core/assets): run for real in happy-dom, built the
// way internal.rs builds it (procedural engine + AdGuard-only scriptlets + boot logic in one
// function). Kept next to the extension tests because that is where a JS runner lives.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const asset = (n: string) => readFileSync(resolve(process.cwd(), '../crates/proxy-core/assets', n), 'utf8');
const BODY = ['procedural.js', 'natives.js', 'boot.js'].map(asset).join('\n');
const argusBoot: (cfg?: any, nonce?: string, base?: string, css?: string) => void =
  new Function(`return function argusBoot(cfg0,nonce0,base0,css0){\n${BODY}\n}`)();

const w = window as any;
const tick = async (ms = 0) => { await vi.advanceTimersByTimeAsync(ms); };

function boot(cfg: object = {}, ...rest: [string?, string?, string?]) {
  delete (document as any)[Symbol.for('argus.boot')];
  argusBoot({ t: 'tok', u: 'https://page.test/p', ...cfg }, ...rest);
}

function page(classes: string[]) {
  document.body.innerHTML = classes.map((c) => `<div class="${c}"></div>`).join('');
}

function cosmetic(): string {
  return [...document.querySelectorAll('style')].map((s) => s.textContent).join('\n')
    + ((document as any).adoptedStyleSheets ?? []).map((s: any) => s.__t ?? '').join('\n');
}

beforeEach(() => {
  vi.useFakeTimers();
  document.head.innerHTML = '';
  document.body.innerHTML = '';
  delete w.__argusRuntime;
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const ok = (selectors: string[]) => ({ ok: true, json: async () => ({ selectors }) });

describe('class/id requests', () => {
  it('one invalid selector does not void the batch', async () => {
    page(['a', 'b', 'c']);
    vi.stubGlobal('fetch', vi.fn(async () => ok(['.a', '!!not a selector', '.c'])));
    boot({ o: 1 });
    await tick();
    const css = cosmetic();
    expect(css).toContain('.a,.c{display:none!important}');
    expect(css).not.toContain('not a selector');
  });

  it('marks tokens seen only after the POST succeeded, and retries with backoff', async () => {
    page(['a']);
    const f = vi.fn()
      .mockRejectedValueOnce(new TypeError('offline'))
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValue(ok(['.a']));
    vi.stubGlobal('fetch', f);
    boot({ o: 1 });
    await tick();
    expect(f).toHaveBeenCalledTimes(1);
    await tick(1000);
    expect(f).toHaveBeenCalledTimes(2); // 1 s back-off
    await tick(2000);
    expect(f).toHaveBeenCalledTimes(3); // 2 s back-off: succeeds
    const bodies = f.mock.calls.map((c) => JSON.parse(c[1].body));
    for (const b of bodies) expect(b.classes).toEqual(['a']);
    expect(cosmetic()).toContain('.a{display:none!important}');
    // Acknowledged: nothing is sent again for it.
    await tick(60_000);
    expect(f).toHaveBeenCalledTimes(3);
  });

  it('chunks requests under the 64 KiB cap and covers every token', async () => {
    const names = Array.from({ length: 3000 }, (_, i) => `cls-${String(i).padStart(5, '0')}-${'x'.repeat(40)}`);
    page(names);
    const f = vi.fn(async () => ok([]));
    vi.stubGlobal('fetch', f);
    boot({ o: 1 });
    await tick();
    expect(f.mock.calls.length).toBeGreaterThan(1);
    const sent = new Set<string>();
    for (const c of f.mock.calls as any[]) {
      expect(c[1].body.length).toBeLessThan(64 * 1024);
      JSON.parse(c[1].body).classes.forEach((x: string) => sent.add(x));
    }
    expect(sent.size).toBe(names.length);
  });

  it('a huge page URL cannot push a request over the cap', async () => {
    page(['a']);
    const f = vi.fn(async () => ok([]));
    vi.stubGlobal('fetch', f);
    boot({ o: 1, u: 'https://page.test/?' + 'q'.repeat(200_000) });
    await tick();
    for (const c of f.mock.calls as any[]) expect(c[1].body.length).toBeLessThan(64 * 1024);
    expect(f).toHaveBeenCalled();
  });
});

describe('AdGuard-only scriptlets', () => {
  const run = (name: string, ...args: string[]) => {
    boot();
    w.__argusRuntime.run('scriptlet', name, args);
  };

  it('prevent-element-src-loading swaps a matching src and leaves the rest', () => {
    run('prevent-element-src-loading', 'script', 'ads.example');
    const bad = document.createElement('script');
    bad.setAttribute('src', 'https://ads.example/x.js');
    expect(bad.getAttribute('src')).toMatch(/^data:text\/javascript/);
    const good = document.createElement('script');
    good.setAttribute('src', 'https://cdn.example/x.js');
    expect(good.getAttribute('src')).toBe('https://cdn.example/x.js');
    const img = document.createElement('img');
    img.setAttribute('src', 'https://ads.example/x.png');
    expect(img.getAttribute('src')).toBe('https://ads.example/x.png'); // other tag
  });

  it('prevent-fab-3.2.0 provides a FuckAdBlock that reports "not detected"', () => {
    run('prevent-fab-3.2.0');
    const hit = vi.fn();
    new w.FuckAdBlock().onNotDetected(hit).onDetected(() => { throw new Error('detected'); });
    expect(hit).toHaveBeenCalled();
    expect(typeof w.fuckAdBlock.check).toBe('function');
  });

  it('set-popads-dummy and no-topics define their stubs', async () => {
    run('set-popads-dummy');
    expect(w.PopAds).toEqual({});
    w.PopAds = 1;
    expect(w.PopAds).toEqual({});
    run('no-topics');
    expect(await (Document.prototype as any).browsingTopics()).toEqual([]);
  });

  it('metrika-yandex-tag answers goals with their callbacks', () => {
    run('metrika-yandex-tag');
    const cb = vi.fn();
    new w.Ya.Metrika({}).reachGoal('g', {}, cb);
    w.ym(1, 'reachGoal', 'g', cb);
    expect(cb).toHaveBeenCalledTimes(2);
  });

  it('google-ima3 provides a loader whose ads finish at once', async () => {
    run('google-ima3');
    const ima = w.google.ima;
    const loader = new ima.AdsLoader(new ima.AdDisplayContainer());
    const events: string[] = [];
    loader.addEventListener(ima.AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED, (e: any) => {
      const m = e.getAdsManager({});
      m.addEventListener(ima.AdEvent.Type.ALL_ADS_COMPLETED, () => events.push('done'));
      m.addEventListener(ima.AdEvent.Type.CONTENT_RESUME_REQUESTED, () => events.push('resume'));
      m.init(1, 1, 'normal');
      m.start();
    });
    loader.requestAds(new ima.AdsRequest());
    await tick(10);
    expect(events).toEqual(['resume', 'done']);
  });

  it('trusted-create-element and trusted-dispatch-event act on the page', async () => {
    document.body.innerHTML = '<div id="host"></div>';
    run('trusted-create-element', '#host', 'span', 'data-x=1 class="a b"', 'hi');
    await tick();
    const s = document.querySelector('#host > span')!;
    expect(s.getAttribute('data-x')).toBe('1');
    expect(s.className).toBe('a b');
    expect(s.textContent).toBe('hi');
    const seen = vi.fn();
    document.addEventListener('argus-test', seen);
    run('trusted-dispatch-event', 'argus-test');
    await tick();
    expect(seen).toHaveBeenCalled();
  });

  it('an unknown name is reported once, a known one is not', () => {
    const f = vi.fn(async () => ({ ok: true, json: async () => ({}) }));
    vi.stubGlobal('fetch', f);
    boot();
    w.__argusRuntime.run('scriptlet', 'no-such-scriptlet', []);
    w.__argusRuntime.run('scriptlet', 'no-such-scriptlet', []);
    w.__argusRuntime.run('scriptlet', 'noeval', []);
    return tick().then(() => {
      const bodies = f.mock.calls.map((c: any) => JSON.parse(c[1].body));
      expect(bodies).toHaveLength(1);
      expect(bodies[0].unsupported).toEqual(['unsupported scriptlet no-such-scriptlet']);
    });
  });
});

describe('friendly frames', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn(async () => ok([]))); });

  function fakeFrame(href: string) {
    let script: any = null;
    const doc: any = {
      documentElement: { appendChild: (s: any) => { script = s; } },
      head: null,
      createElement: (): any => ({ setAttribute(this: any, k: string, v: string) { this[k] = v; }, remove() {} }),
    };
    return { win: { document: doc, location: { href } } as any, injected: () => script };
  }

  it('injects scriptlets, boot and the page config into about:blank, srcdoc and blob: documents', () => {
    document.head.innerHTML = '<style id="__adblock_cosmetic">.ad{display:none!important}</style>';
    boot({ f: 1, p: [{ s: '.x', a: 'hide' }], k: [0, 0, 0, 0, 'KeyX'], pn: '/__adblock__/panel.js', sw: 1 }, 'N0NCE');
    w.__argusRuntime.sl = new Function('return function(){window.__sl=1}')();
    w.__argusRuntime.xs = 'window.__xs=1;';
    for (const href of ['about:blank', 'about:srcdoc', 'blob:https://page.test/1']) {
      const { win, injected } = fakeFrame(href);
      w.__argusRuntime.frame(win);
      const s = injected();
      expect(s, href).toBeTruthy();
      const code: string = s.textContent;
      expect(() => new Function(code), href).not.toThrow();
      expect(code).toContain('function argusBoot(cfg0,nonce0,base0,css0)');
      expect(code).toContain('window.__sl=1');
      expect(code).toContain('window.__xs=1;');
      expect(code).toContain('"N0NCE"');
      expect(code).toContain('.ad{display:none!important}');
      // The panel hotkey and the service-worker cleanup are the page's alone.
      expect(code).not.toContain('/__adblock__/panel.js');
      expect(code).not.toContain('"sw"');
      expect(code).toContain('"u":"https://page.test/p"');
      // Scriptlets run first, the extended-rule script last (after the boot's runtime exists).
      expect(code.indexOf('window.__sl=1')).toBeLessThan(code.indexOf('function argusBoot'));
      expect(code.lastIndexOf('window.__xs=1;')).toBeGreaterThan(code.indexOf('function argusBoot'));
    }
  });

  it('ignores a runtime forged by DOM clobbering', () => {
    // Markup can make window.__argusRuntime an element whose properties it controls.
    const forged: any = document.createElement('a');
    forged.sl = 'x:1/(window.__pwn=1)';
    forged.xs = 'window.__pwn=1;';
    forged.q = [['scriptlet', 'noeval', []]];
    w.__argusRuntime = forged;
    boot({ f: 1 });
    expect(w.__argusRuntime).not.toBe(forged);
    const a = fakeFrame('about:blank');
    w.__argusRuntime.frame(a.win);
    expect(a.injected().textContent).not.toContain('__pwn');
  });

  it('re-injects a reused window whose document was replaced', () => {
    boot({ f: 1 });
    const a = fakeFrame('about:blank');
    w.__argusRuntime.frame(a.win);
    const b = fakeFrame('about:srcdoc');
    a.win.document = b.win.document;
    w.__argusRuntime.frame(a.win);
    expect(b.injected()).toBeTruthy();
  });

  it('does each document once and leaves ordinary documents alone', () => {
    boot({ f: 1 });
    const a = fakeFrame('about:blank');
    w.__argusRuntime.frame(a.win);
    const first = a.injected();
    w.__argusRuntime.frame(a.win);
    expect(a.injected()).toBe(first);
    const real = fakeFrame('https://ads.example/frame.html');
    w.__argusRuntime.frame(real.win);
    expect(real.injected()).toBeNull();
    const cross: any = { get document() { throw new Error('SecurityError'); } };
    expect(() => w.__argusRuntime.frame(cross)).not.toThrow();
  });

  it('wraps contentWindow / contentDocument so a frame is reached already injected', () => {
    boot({ f: 1 });
    const iframe = document.createElement('iframe');
    document.body.appendChild(iframe);
    const proto = HTMLIFrameElement.prototype;
    expect(Object.getOwnPropertyDescriptor(proto, 'contentWindow')!.get!.toString()).toContain('native code');
    expect(Object.getOwnPropertyDescriptor(proto, 'contentDocument')!.get!.toString()).toContain('native code');
    expect(() => iframe.contentWindow).not.toThrow();
  });
});
