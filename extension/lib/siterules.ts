/** Per-site custom rules in the popup: the dynamic grid state and the reset flow. */
export type GridState = 'block' | 'allow' | 'default';

/** A custom rule scoped to the site; `exclusive` when it applies to this site only. */
export interface SiteRule { rule: string; exclusive: boolean }

export const gridRule = (host: string, site: string, state: Exclude<GridState, 'default'>): string =>
  `${state === 'allow' ? '@@' : ''}||${host.toLowerCase()}^$domain=${site.toLowerCase()}`;

/** The site or one of its subdomains (the proxy's rule). */
const isSite = (d: string, site: string): boolean => d === site || d.endsWith(`.${site}`);

/** `||host^` with options: whether it is an exception, its host and its `$domain=` list. */
function hostRule(rule: string): { allow: boolean; host: string; domains: string[] } | undefined {
  const r = rule.trim().toLowerCase();
  const allow = r.startsWith('@@');
  const m = /^\|\|([^^/$|*,]+)\^(?:\$(.*))?$/.exec(allow ? r.slice(2) : r);
  if (!m) return undefined;
  const dom = (m[2] ?? '').split(',').find((o) => o.startsWith('domain='));
  return { allow, host: m[1]!, domains: dom ? dom.slice(7).split('|') : [] };
}

/** What the existing rules say about `host` on `site`: the `$domain=` list names the site, other options are ignored. */
export function gridState(rules: readonly string[], host: string, site: string): GridState {
  let st: GridState = 'default';
  for (const r of rules) {
    const h = hostRule(r);
    if (!h || h.host !== host.toLowerCase() || !h.domains.includes(site.toLowerCase())) continue;
    if (h.allow) return 'allow';
    st = 'block';
  }
  return st;
}

/** `rule` without `site` in its domain list (cosmetic or `$domain=`): the rule itself when it never named it, null when no domain is left. */
export function dropSite(rule: string, site: string): string | null {
  const s = site.toLowerCase();
  const keep = (ds: string[]) => ds.filter((d) => d.startsWith('~') || !isSite(d.toLowerCase(), s));
  const left = (ds: string[]) => ds.some((d) => !d.startsWith('~'));
  const i = rule.indexOf('##');
  if (i >= 0 && /^[A-Za-z0-9.,~-]*$/.test(rule.slice(0, i))) {
    const ds = rule.slice(0, i).split(',').filter(Boolean);
    const k = keep(ds);
    if (k.length === ds.length) return rule;
    return left(k) ? `${k.join(',')}${rule.slice(i)}` : null;
  }
  const d = rule.indexOf('$');
  if (d < 0) return rule;
  const opts = rule.slice(d + 1).split(',');
  const j = opts.findIndex((o) => o.toLowerCase().startsWith('domain='));
  if (j < 0) return rule;
  const ds = opts[j]!.slice(7).split('|');
  const k = keep(ds);
  if (k.length === ds.length) return rule;
  if (!left(k)) return null;
  opts[j] = `domain=${k.join('|')}`;
  return `${rule.slice(0, d)}$${opts.join(',')}`;
}

type Post = (op: 'add' | 'remove', rule: string) => Promise<{ ok: boolean }>;

/** Replaces `old` by `next` (add first, so a failure never loses the rule); `null` just drops it. */
async function replace(post: Post, old: string, next: string | null): Promise<boolean> {
  if (next !== null && next !== old && !(await post('add', next)).ok) return false;
  return (await post('remove', old)).ok;
}

/**
 * Moves one host to `next`: the rules that give the old state lose this site (or go, when it was
 * their only one), the new one is added unless a rule already says so. Returns the new rule list,
 * or undefined on failure.
 */
export async function setGridState(post: Post, rules: readonly SiteRule[], host: string, site: string, next: GridState): Promise<SiteRule[] | undefined> {
  const cur = gridState(rules.map((r) => r.rule), host, site);
  if (cur === next) return [...rules];
  let out = [...rules];
  if (cur !== 'default') {
    for (const r of rules) {
      const h = hostRule(r.rule);
      if (!h || h.host !== host.toLowerCase() || !h.domains.includes(site.toLowerCase()) || h.allow !== (cur === 'allow')) continue;
      if (!(await replace(post, r.rule, dropSite(r.rule, site)))) return undefined;
      out = out.filter((x) => x.rule !== r.rule);
    }
  }
  if (next !== 'default') {
    const add = gridRule(host, site, next);
    if (!(await post('add', add)).ok) return undefined;
    if (!out.some((x) => x.rule === add)) out.push({ rule: add, exclusive: true });
  }
  return out;
}

/**
 * Resets the site: exclusive rules go, shared ones (a domain list with other sites) are rewritten
 * without it. All-sites rules are never listed and never touched. Returns what could not be changed.
 */
export async function resetSite(post: Post, rules: readonly SiteRule[], site: string): Promise<SiteRule[]> {
  const left: SiteRule[] = [];
  for (const r of rules) {
    const next = r.exclusive ? null : dropSite(r.rule, site);
    if (next === r.rule) { left.push(r); continue; }
    if (!(await replace(post, r.rule, next))) left.push(r);
  }
  return left;
}

export const isThirdParty = (host: string, site: string, reg: (h: string) => string): boolean => !!site && reg(host) !== site;
