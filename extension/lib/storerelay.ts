import { storeSetCookies } from './setcookie';

/** Header that ties a relay fetch to its job; removed before the request is sent. */
export const JOB_HEADER = 'X-Argus-Job';

interface Active { storeId: string; requestIds: Set<string> }

/**
 * Relays for a non-default cookie store (a Firefox container or private window). A background
 * `fetch` always uses the default store, so such a fetch is made with `credentials: 'omit'` and
 * this class (a) puts that store's cookies, all of them, HttpOnly included, into the `Cookie`
 * header of every hop (blocking `onBeforeSendHeaders`, matched by the job marker header, which
 * is removed) and (b) takes `Set-Cookie` off every hop's response (blocking
 * `onHeadersReceived`) and writes it to that store. The default store is never read or written.
 */
export class StoreRelay {
  private jobs = new Map<string, Active>();
  private byRequest = new Map<string, string>();
  private installed = false;

  constructor(private br: any) {}

  register(marker: string, storeId: string) { this.jobs.set(marker, { storeId, requestIds: new Set() }); }

  release(marker: string) {
    const a = this.jobs.get(marker);
    if (a) for (const r of a.requestIds) this.byRequest.delete(r);
    this.jobs.delete(marker);
  }

  active(): number { return this.jobs.size; }

  /** Hook the browser's webRequest events (idempotent). */
  install(): boolean {
    const wr = this.br?.webRequest;
    if (this.installed) return true;
    if (!wr?.onBeforeSendHeaders?.addListener || !wr?.onHeadersReceived?.addListener) return false;
    const filter = { urls: ['<all_urls>'], types: ['xmlhttprequest'] };
    wr.onBeforeSendHeaders.addListener((d: any) => this.beforeSend(d), filter, ['blocking', 'requestHeaders', 'extraHeaders']);
    wr.onHeadersReceived.addListener((d: any) => this.received(d), filter, ['blocking', 'responseHeaders', 'extraHeaders']);
    this.installed = true;
    return true;
  }

  async beforeSend(d: { requestId: string; url: string; requestHeaders?: { name: string; value?: string }[] }) {
    const hs = d.requestHeaders ?? [];
    const mark = hs.find((h) => h.name.toLowerCase() === JOB_HEADER.toLowerCase());
    if (!mark?.value) return {};
    const job = this.jobs.get(mark.value);
    // A marker nobody registered (a page forging the header) is stripped and nothing is added.
    const out = hs.filter((h) => h.name.toLowerCase() !== JOB_HEADER.toLowerCase() && h.name.toLowerCase() !== 'cookie');
    if (!job) return { requestHeaders: out };
    job.requestIds.add(d.requestId);
    this.byRequest.set(d.requestId, mark.value);
    let cookies: any[] = [];
    try { cookies = await this.br.cookies.getAll({ url: d.url, storeId: job.storeId }); } catch { /* none */ }
    if (cookies.length) out.push({ name: 'Cookie', value: cookies.map((c) => `${c.name}=${c.value}`).join('; ') });
    return { requestHeaders: out };
  }

  async received(d: { requestId: string; url: string; responseHeaders?: { name: string; value?: string }[] }) {
    const marker = this.byRequest.get(d.requestId);
    const job = marker ? this.jobs.get(marker) : undefined;
    if (!job) return {};
    const hs = d.responseHeaders ?? [];
    const sc = hs.filter((h) => h.name.toLowerCase() === 'set-cookie').map((h) => h.value ?? '');
    if (sc.length) await storeSetCookies(this.br, d.url, job.storeId, sc);
    return { responseHeaders: hs.filter((h) => h.name.toLowerCase() !== 'set-cookie') };
  }
}
