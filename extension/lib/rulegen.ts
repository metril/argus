/** Builds one filter rule from a logged request, as the "create rule" dialog offers it. */
export interface RuleOptions {
  action: 'block' | 'unblock';
  /** `site`: only on the page's site (`$domain=`); `everywhere`: no domain restriction. */
  scope: 'site' | 'everywhere';
  match: 'url' | 'path' | 'host';
  thirdParty: boolean;
  important: boolean;
  /** Registrable domain of the page that made the request. */
  site: string;
}

/** `*` stands in for the characters a pattern cannot carry (`$` starts the options, `|` anchors). */
const safe = (s: string) => s.replace(/[$|]/g, '*');

export function rulePattern(url: string, match: RuleOptions['match']): string {
  let u: URL;
  try { u = new URL(url); } catch { return safe(url); }
  const host = u.hostname;
  if (match === 'host') return `||${host}^`;
  if (match === 'path') {
    const dir = u.pathname.slice(0, u.pathname.lastIndexOf('/') + 1) || '/';
    return `||${host}${u.port ? ':' + u.port : ''}${safe(dir)}`;
  }
  return `|${safe(u.protocol + '//' + u.host + u.pathname + u.search)}|`;
}

export function makeRule(url: string, o: RuleOptions): string {
  const opts: string[] = [];
  if (o.important) opts.push('important');
  if (o.thirdParty) opts.push('third-party');
  if (o.scope === 'site' && o.site) opts.push(`domain=${o.site}`);
  return `${o.action === 'unblock' ? '@@' : ''}${rulePattern(url, o.match)}${opts.length ? '$' + opts.join(',') : ''}`;
}
