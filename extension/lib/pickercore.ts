/** Pure parts of the element picker: selector candidates, rule text, and the all-sites check. */
import { makeRule, type RuleOptions } from './rulegen';

export interface Candidate { selector: string; count: number }

/** CSS identifier escape (`CSS.escape` is missing in some test DOMs). */
export function cssEscape(s: string): string {
  return Array.from(s).map((ch, i) => {
    const c = ch.codePointAt(0)!;
    if (c === 0) return '�';
    if ((c >= 1 && c <= 0x1f) || c === 0x7f || (i === 0 && c >= 0x30 && c <= 0x39) || (i === 1 && c >= 0x30 && c <= 0x39 && s[0] === '-')) return `\\${c.toString(16)} `;
    if (i === 0 && ch === '-' && s.length === 1) return '\\-';
    if (c >= 0x80 || ch === '-' || ch === '_' || /[A-Za-z0-9]/.test(ch)) return ch;
    return `\\${ch}`;
  }).join('');
}

const quote = (v: string) => `"${v.replace(/[\\"]/g, '\\$&')}"`;
/** Utility classes that change per build or state are poor anchors. */
const unstableClass = (c: string) => c.length > 40 || /\d{3,}/.test(c) || /^(css|jsx|sc|svelte|ember|ng)-/.test(c) || /^(hover|active|focus|is-|has-)/.test(c);
const ATTRS = ['data-testid', 'data-ad', 'data-ad-slot', 'data-ad-unit', 'data-id', 'data-type', 'aria-label', 'name', 'title', 'alt', 'role', 'href', 'src'];

function count(doc: Document, sel: string, el: Element): number {
  try {
    const all = doc.querySelectorAll(sel);
    return Array.prototype.includes.call(all, el) ? all.length : -1;
  } catch { return -1; }
}

/** `html`-free structural path from the nearest unique id (or body) down to `el`. */
export function pathSelector(el: Element): string {
  const doc = el.ownerDocument;
  const parts: string[] = [];
  let cur: Element | null = el;
  while (cur && cur !== doc.documentElement) {
    if (cur.id && count(doc, `#${cssEscape(cur.id)}`, cur) === 1) { parts.unshift(`#${cssEscape(cur.id)}`); break; }
    const tag = cur.localName;
    const sibs = cur.parentElement ? Array.from(cur.parentElement.children).filter((c) => c.localName === tag) : [cur];
    parts.unshift(`${tag}:nth-of-type(${sibs.indexOf(cur) + 1})`);
    cur = cur.parentElement;
  }
  return parts.join(' > ');
}

/** Candidate selectors for `el`, most specific (fewest matches) first, broadest last. Bare tags are never offered. */
export function candidates(el: Element): Candidate[] {
  const doc = el.ownerDocument;
  const tag = el.localName;
  const raw: string[] = [pathSelector(el)];
  if (el.id) raw.push(`${tag}#${cssEscape(el.id)}`, `#${cssEscape(el.id)}`);
  const cls = Array.from(el.classList).filter((c) => !unstableClass(c));
  if (cls.length) {
    const all = cls.map((c) => `.${cssEscape(c)}`).join('');
    raw.push(`${tag}${all}`, all);
    for (const c of cls) raw.push(`${tag}.${cssEscape(c)}`, `.${cssEscape(c)}`);
  }
  for (const a of ATTRS) {
    const v = el.getAttribute(a);
    if (!v || v.length > 120) continue;
    raw.push(a === 'href' || a === 'src' ? `${tag}[${a}^=${quote(v.split(/[?#]/)[0]!)}]` : `${tag}[${a}=${quote(v)}]`);
  }
  const seen = new Set<string>();
  const out: Candidate[] = [];
  for (const selector of raw) {
    if (!selector || seen.has(selector)) continue;
    seen.add(selector);
    const n = count(doc, selector, el);
    if (n > 0) out.push({ selector, count: n });
  }
  // Stable: fewer matches first; equal counts keep generation order (path, id, classes, attributes).
  return out.map((c, i) => ({ c, i })).sort((a, b) => a.c.count - b.c.count || a.i - b.i).map((x) => x.c);
}

/** The text of the cosmetic rule: `site##sel` for this site, `##sel` for all sites. */
export const cosmeticRule = (site: string, selector: string, scope: 'site' | 'everywhere'): string =>
  scope === 'site' && site ? `${site}##${selector}` : `##${selector}`;

/** Remove parenthesised groups and quoted strings, so `:not(.a)` and `[x="."]` name nothing. */
function strip(s: string): string {
  let out = '', depth = 0, q = '', esc = false;
  for (const ch of s) {
    if (esc) { esc = false; continue; }
    if (ch === '\\') { esc = true; continue; }
    if (q) { if (ch === q) q = ''; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (depth === 0) out += ch;
  }
  return out;
}

function topCommas(s: string): string[] {
  const parts: string[] = [];
  let depth = 0, q = '', esc = false, start = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (esc) { esc = false; continue; }
    if (ch === '\\') esc = true;
    else if (q) { if (ch === q) q = ''; }
    else if (ch === '"' || ch === "'") q = ch;
    else if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) { parts.push(s.slice(start, i)); start = i + 1; }
  }
  parts.push(s.slice(start));
  return parts;
}

/** Attribute groups `[...]` of `s` (quote-aware), without the brackets. */
function attrGroups(s: string): string[] {
  const out: string[] = [];
  let cur: string | null = null, q = '', esc = false;
  for (const ch of s) {
    if (cur === null) { if (ch === '[') cur = ''; continue; }
    if (esc) esc = false;
    else if (ch === '\\') esc = true;
    else if (q) { if (ch === q) q = ''; }
    else if (ch === '"' || ch === "'") q = ch;
    else if (ch === ']') { out.push(cur); cur = null; continue; }
    cur += ch;
  }
  return out;
}

/** An attribute selector too loose for an all-sites rule (the proxy's rule). */
function looseAttr(inner: string): boolean {
  const eq = inner.indexOf('=');
  if (eq < 0) return false;
  let name = inner.slice(0, eq);
  const op = /[*~^$|]$/.test(name) ? name.slice(-1) : '';
  if (op) name = name.slice(0, -1);
  if (op === '*' || op === '~') return true;
  if (['lang', 'dir', 'style', 'class', 'id'].includes(name.trim().toLowerCase())) return true;
  const v = inner.slice(eq + 1).trim().replace(/ [is]$/, '').trim().replace(/^["']+|["']+$/g, '');
  return [...v].length < 3;
}

/**
 * Mirrors the proxy's rule for `##selector`: each part's last compound carries an id, class or
 * attribute value, never html, body or :root, and no loose attribute (`*=`, `~=`, a value under
 * three characters, lang, dir, style, class or id as an attribute).
 */
export function specificForAllSites(selector: string): boolean {
  if (selector.endsWith('\\')) return false;
  return topCommas(selector).every((part) => {
    if (attrGroups(part).some(looseAttr)) return false;
    const flat = strip(part.trim());
    const last = flat.split(/[ >+~\t]/).filter(Boolean).pop() ?? '';
    const tag = (last.split(/[#.[:]/)[0] ?? '').toLowerCase();
    if (tag === 'html' || tag === 'body' || last.toLowerCase().includes(':root')) return false;
    const attr = last.split('[').slice(1).some((a) => { const inner = a.split(']')[0] ?? ''; return inner.includes('=') && !inner.startsWith('='); });
    return /[#.]/.test(last.replace(/\[[^\]]*\]/g, '')) || attr;
  });
}

const RES_TAGS = new Set(['img', 'iframe', 'video', 'audio', 'script', 'embed', 'source', 'picture']);
/** The URL of the resource an element loads, if it loads one over http(s). */
export function resourceUrl(el: Element): string | undefined {
  if (!RES_TAGS.has(el.localName)) return undefined;
  const e = el as HTMLImageElement;
  const raw = e.currentSrc || e.getAttribute('src') || (el.localName === 'picture' ? el.querySelector('img')?.getAttribute('src') : null) || '';
  try {
    const u = new URL(raw, el.ownerDocument.baseURI);
    return /^https?:$/.test(u.protocol) ? u.href : undefined;
  } catch { return undefined; }
}

/** Network rule for the element's resource, built by the same generator as the logger. */
export const resourceRule = (url: string, o: Pick<RuleOptions, 'scope' | 'match' | 'site'>): string =>
  makeRule(url, { action: 'block', thirdParty: false, important: false, ...o });
