import { registrableDomain } from './stats';
import type { Arming } from './arming';

export interface PickerSender { id?: string; url?: string; tab?: { id?: number; url?: string } }
export interface PickerMsg { type?: string; rule?: string; confirmed?: boolean; allSites?: boolean }
export interface PickerDeps {
  arming: Arming;
  ownId: string;
  /** Adds the rule through `POST /ext/rules`; the token never leaves the background. */
  save(rule: string): Promise<{ ok: boolean; error?: string; scope?: boolean }>;
}

const host = (url?: string) => { try { return new URL(url ?? '').hostname; } catch { return ''; } };

/** Does the network rule's `$domain=` list name `site`? */
const domainOpt = (rule: string, site: string): boolean => {
  const o = rule.slice(rule.indexOf('$') + 1).split(',').find((x) => x.toLowerCase().startsWith('domain='));
  const ds = o ? o.slice(7).toLowerCase().split('|') : [];
  return !!site && rule.includes('$') && ds.length > 0 && ds.every((d) => d === site);
};

/**
 * Messages from the injected picker/zapper script. Accepted only from this extension's script in
 * the armed tab within the arming window; a save only in picker mode (not the zapper), with the
 * panel's trusted confirm click. A rule must name the tab's own site (`site##sel`, or `$domain=`
 * for a network rule); an all-sites rule needs `allSites`, set by the panel's trusted click.
 */
export async function handlePickerMessage(d: PickerDeps, msg: PickerMsg, sender: PickerSender): Promise<unknown> {
  const save = msg.type === 'picker-save';
  if (!(await d.arming.allows(sender, d.ownId, save ? 'picker' : undefined))) return { ok: false, error: 'not armed' };
  if (msg.type === 'picker-close') { await d.arming.disarm(sender.tab!.id); return { ok: true }; }
  if (!save) return { ok: false, error: 'unknown' };
  const rule = msg.rule;
  if (msg.confirmed !== true || typeof rule !== 'string' || rule.length > 2048 || /[\r\n]/.test(rule)) return { ok: false, error: 'rejected' };
  const site = registrableDomain(host(sender.tab?.url));
  const i = rule.indexOf('##');
  if (i > 0) {
    if (!/^[a-z0-9.-]+$/.test(rule.slice(0, i))) return { ok: false, error: 'rejected' };
    if (rule.slice(0, i) !== site) return { ok: false, error: 'wrong site' };
  } else if (i < 0 ? !domainOpt(rule, site) && msg.allSites !== true : msg.allSites !== true) {
    return { ok: false, error: 'all sites not confirmed' };
  }
  return d.save(rule);
}
