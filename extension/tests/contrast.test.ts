import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const css = readFileSync(resolve(process.cwd(), 'ui/tokens.css'), 'utf8');

/** The declarations of the first block that starts with `selector {`. */
function block(selector: string): Record<string, string> {
  const i = css.indexOf(selector + '{');
  expect(i, selector).toBeGreaterThan(-1);
  const body = css.slice(i + selector.length + 1, css.indexOf('}', i));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim();
  return out;
}
const dark = block(':root'), light = block(':root[data-theme="light"]');

function rgb(c: string): [number, number, number, number] {
  const h = /^#([0-9a-f]{6})$/i.exec(c);
  if (h) return [parseInt(h[1]!.slice(0, 2), 16), parseInt(h[1]!.slice(2, 4), 16), parseInt(h[1]!.slice(4, 6), 16), 1];
  const m = /rgba\((\d+),(\d+),(\d+),([\d.]+)\)/.exec(c.replace(/\s/g, ''));
  if (!m) throw new Error(c);
  return [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
}
const over = (f: ReturnType<typeof rgb>, b: ReturnType<typeof rgb>): ReturnType<typeof rgb> => [0, 1, 2].map((i) => f[i]! * f[3] + b[i]! * (1 - f[3])) as never as ReturnType<typeof rgb>;
const lum = ([r, g, b]: number[]) => { const f = (v: number) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r!) + 0.7152 * f(g!) + 0.0722 * f(b!); };
const ratio = (a: ReturnType<typeof rgb>, b: ReturnType<typeof rgb>) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
const SURFACES = ['bg', 'surface', 'surface-2', 'surface-3'];

describe.each([['dark', dark], ['light', light]] as const)('%s palette: three text tones and control borders', (_name, t) => {
  const c = (k: string) => rgb(t[k]!);
  it('primary and secondary text reach 4.5:1 on every surface', () => {
    for (const s of SURFACES) for (const k of ['text', 'text-2']) expect(ratio(c(k), c(s)), `${k} on ${s}`).toBeGreaterThanOrEqual(4.5);
  });
  it('disabled text and control borders reach 3:1 on every surface', () => {
    for (const s of SURFACES) for (const k of ['text-3', 'ctl']) expect(ratio(c(k), c(s)), `${k} on ${s}`).toBeGreaterThanOrEqual(3);
  });
  it('status colours reach 4.5:1 as text on their tinted fills', () => {
    for (const k of ['allow', 'block', 'pass', 'error', 'accent']) {
      const soft = k === 'accent' ? 'accent-soft' : `${k}-soft`;
      for (const s of ['surface', 'surface-2']) expect(ratio(c(k), over(c(soft), c(s))), `${k} on ${soft}/${s}`).toBeGreaterThanOrEqual(4.5);
    }
  });
  it('the accent button text is readable on the accent fill', () => {
    expect(ratio(c('accent-ink'), c('accent'))).toBeGreaterThanOrEqual(4.5);
  });
});

describe('audited values', () => {
  it('match the audited tokens', () => {
    expect([light.text, light['text-2'], light['text-3'], light.ctl]).toEqual(['#131922', '#3d4757', '#6f7a8a', '#6f7a89']);
    expect([dark.text, dark['text-2'], dark['text-3'], dark.ctl]).toEqual(['#e2e7ee', '#b8c1ce', '#7f8998', '#6b7686']);
  });
});
