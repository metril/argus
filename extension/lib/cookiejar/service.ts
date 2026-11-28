import { CookieError, CookieJar, type ConflictMode } from './api';
import { ChangeLog, listenForChanges, memoryArea, type ChangeEntry } from './changelog';
import { CODECS, snippet, type FormatId, type SnippetId } from './codecs';
import { AtRestCipher, CryptoError, decryptWithPassphrase, encryptWithPassphrase, idbKeyStore, isEncrypted, type KeyStore } from './crypto';
import { applyPlan, planImport, type ImportMode } from './detect';
import type { Cookie } from './model';
import { cookieRule, type CookieRuleOptions } from './rule';
import { ALARM_PREFIX, AutoDelete, Rules, type RuleSet } from './rules';
import { SnapshotStore } from './snapshots';
import { validateCookie } from './validate';

/** Requests the cookie manager page sends over the `cookies` port. */
export type CookieRequest =
  | { op: 'stores' }
  | { op: 'list'; site?: string; storeId?: string }
  | { op: 'validate'; cookie: Cookie; url?: string }
  | { op: 'create'; cookie: Cookie }
  | { op: 'edit'; old: Cookie; next: Cookie }
  | { op: 'remove'; cookies: Cookie[] }
  | { op: 'removeMany'; cookies: Cookie[] }
  | { op: 'copy'; cookies: Cookie[]; toStoreId: string; move?: boolean; conflict?: ConflictMode }
  | { op: 'export'; cookies: Cookie[]; format?: FormatId; snippet?: SnippetId; url?: string; passphrase?: string }
  | { op: 'import'; text: string; storeId: string; mode?: ImportMode; format?: FormatId; host?: string; passphrase?: string; dryRun?: boolean }
  | { op: 'snapshot.save'; name: string; site?: string; cookies?: Cookie[] }
  | { op: 'snapshot.list' }
  | { op: 'snapshot.delete'; id: string }
  | { op: 'snapshot.restore'; id: string }
  | { op: 'snapshot.diff'; id: string; other?: string }
  | { op: 'rules.get' }
  | { op: 'rules.set'; rules: Partial<RuleSet> }
  | { op: 'rules.protect'; cookies: Cookie[]; protect: boolean }
  | { op: 'activity.since'; since?: number }
  | { op: 'activity.clear' }
  | { op: 'rule.line'; cookie: Cookie; options: CookieRuleOptions };

/** `rid` correlates a reply with its request (the requests have their own fields, such as a snapshot `id`). */
export type CookieReply = { rid: number; ok: true; result: unknown } | { rid: number; ok: false; error: { code: string; message: string } };
export type CookieStream = { t: 'activity'; entry: ChangeEntry };

export interface ServiceDeps {
  jar: CookieJar;
  log: ChangeLog;
  rules: Rules;
  snapshots: SnapshotStore;
  auto: AutoDelete;
}

export function errorOf(e: unknown): { code: string; message: string } {
  if (e instanceof CookieError || e instanceof CryptoError) return { code: e.code, message: e.message };
  return { code: 'error', message: String((e as Error)?.message ?? e).slice(0, 200) };
}

/** The operations the cookie manager page needs, over one request/response shape. */
export class CookieService {
  constructor(readonly d: ServiceDeps, private readonly o: { iterations?: number } = {}) {}

  async handle(req: CookieRequest): Promise<unknown> {
    const { jar, log, rules, snapshots } = this.d;
    switch (req.op) {
      case 'stores': return jar.stores();
      case 'list': {
        const guard = await rules.guard();
        return (await jar.list({ ...(req.site ? { site: req.site } : {}), ...(req.storeId ? { storeId: req.storeId } : {}) })).map((c) => ({ ...c, isProtected: guard(c) }));
      }
      case 'validate': return validateCookie(req.cookie, req.url ? { url: req.url } : {});
      case 'create': return jar.create(req.cookie);
      case 'edit': return jar.edit(req.old, req.next);
      case 'remove': return jar.removeMany(req.cookies); // an explicit delete of what the user picked
      case 'removeMany': return jar.removeMany(req.cookies, { isProtected: await rules.guard() });
      case 'copy': return jar.copy(req.cookies, req.toStoreId, { move: !!req.move, ...(req.conflict ? { conflict: req.conflict } : {}), ...(req.move ? { isProtected: await rules.guard() } : {}) });
      case 'export': return this.export(req);
      case 'import': return this.import(req);
      case 'snapshot.save': {
        const cookies = req.cookies ?? (req.site ? await jar.list({ site: req.site }) : []);
        return snapshots.save(req.name, cookies, req.site ? { site: req.site } : {});
      }
      case 'snapshot.list': return snapshots.list();
      case 'snapshot.delete': return snapshots.delete(req.id);
      case 'snapshot.restore': return snapshots.restore(req.id, jar, { isProtected: await rules.guard() });
      case 'snapshot.diff': return req.other ? snapshots.diffSnapshots(req.id, req.other) : snapshots.diffWithLive(req.id, jar);
      case 'rules.get': return rules.get();
      case 'rules.set': return rules.update(req.rules);
      case 'rules.protect': return req.protect ? rules.protect(req.cookies) : rules.unprotect(req.cookies);
      case 'activity.since': return log.entries(req.since ?? 0);
      case 'activity.clear': return log.clear();
      case 'rule.line': return cookieRule(req.cookie, req.options);
    }
  }

  private async export(req: Extract<CookieRequest, { op: 'export' }>) {
    if (req.snippet) return { text: snippet(req.snippet, req.cookies, req.url ? { url: req.url } : {}), mime: 'text/plain', extension: 'sh' };
    const codec = CODECS[req.format ?? 'json'];
    const text = codec.export(req.cookies);
    if (req.passphrase) return { text: await encryptWithPassphrase(text, req.passphrase, this.o.iterations ? { iterations: this.o.iterations } : {}), mime: 'application/json', extension: 'enc.json' };
    return { text, mime: codec.mime, extension: codec.extension };
  }

  private async import(req: Extract<CookieRequest, { op: 'import' }>) {
    let text = req.text;
    if (isEncrypted(text)) {
      if (!req.passphrase) throw new CryptoError('wrong-passphrase', 'This export is encrypted; enter its passphrase.');
      text = await decryptWithPassphrase(text, req.passphrase);
    }
    const existing = await this.d.jar.list();
    const plan = planImport(text, { storeId: req.storeId, existing, firstPartyDomain: this.d.jar.caps.firstPartyDomain, ...(req.mode ? { mode: req.mode } : {}), ...(req.format ? { format: req.format } : {}), ...(req.host ? { host: req.host } : {}) });
    if (req.dryRun) return { plan: { ...plan, existing: [] } };
    const result = await applyPlan(this.d.jar, plan, { isProtected: await this.d.rules.guard() });
    return { plan: { ...plan, existing: [] }, result };
  }
}

/** Builds the service on a browser object, with the library's own storage areas. */
export function createCookieService(br: any, o: { keyStore?: KeyStore; iterations?: number } = {}): CookieService {
  const jar = new CookieJar(br);
  // Never the disk-backed local area: activity and open-tab state must not outlive the session.
  const session = br.storage.session ?? memoryArea();
  const log = new ChangeLog(session);
  const rules = new Rules(br.storage.local);
  const snapshots = new SnapshotStore(br.storage.local, new AtRestCipher(o.keyStore ?? idbKeyStore()));
  const auto = new AutoDelete(br, jar, rules, session);
  return new CookieService({ jar, log, rules, snapshots, auto }, o.iterations ? { iterations: o.iterations } : {});
}

/**
 * Top-level listeners of the background worker: activity log, auto-delete scheduling. Must be
 * called synchronously while the worker starts so the browser can wake it for these events.
 */
export function registerCookieListeners(br: any, svc: CookieService): void {
  const { log, auto } = svc.d;
  listenForChanges(br, log);
  void auto.init().catch(() => undefined);
  br.tabs?.onUpdated?.addListener((id: number, info: { url?: string }, tab?: { url?: string }) => { if (info.url) void auto.noteTab(id, info.url ?? tab?.url).catch(() => undefined); });
  br.tabs?.onRemoved?.addListener((id: number) => { void auto.tabRemoved(id).catch(() => undefined); });
  br.alarms?.onAlarm?.addListener((a: { name: string }) => { if (a.name.startsWith(ALARM_PREFIX)) void auto.alarm(a.name).catch(() => undefined); });
  br.runtime?.onStartup?.addListener(() => { void auto.init().then(() => auto.startup()).catch(() => undefined); });
}

/** Serves one page port: requests in, replies and live activity out. */
export function servePort(port: any, svc: CookieService): void {
  const post = (m: CookieReply | CookieStream) => { try { port.postMessage(m); } catch { /* page gone */ } };
  const off = svc.d.log.subscribe((entry) => post({ t: 'activity', entry }));
  port.onDisconnect.addListener(off);
  port.onMessage.addListener(async (msg: CookieRequest & { rid: number }) => {
    if (!msg || typeof msg.rid !== 'number') return;
    try { post({ rid: msg.rid, ok: true, result: await svc.handle(msg) }); } catch (e) { post({ rid: msg.rid, ok: false, error: errorOf(e) }); }
  });
}
