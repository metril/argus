import type { HostsMsg } from './bridge-types';

export const RULE_ID = 1;

export function buildRule(sid: string, msg: Pick<HostsMsg, 'wildcard' | 'hosts' | 'exclude'>) {
  const condition: Record<string, unknown> = { resourceTypes: ['main_frame', 'sub_frame'] };
  // `exclude` lists hosts Argus passes through without decrypting: the header must never reach
  // them, also when they sit below a listed host (a domain matches its subdomains).
  if (!msg.wildcard) {
    if (!msg.hosts.length) return null;
    condition.requestDomains = msg.hosts;
  }
  if (msg.exclude?.length) condition.excludedRequestDomains = msg.exclude;
  return {
    id: RULE_ID,
    priority: 1,
    action: { type: 'modifyHeaders', requestHeaders: [{ header: 'X-Argus-Ext', operation: 'set', value: sid }] },
    condition,
  };
}
