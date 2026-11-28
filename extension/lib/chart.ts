import { CATEGORIES, type Category, type SeriesPoint, type SeriesRange } from './api';

export type CategoryPick = 'all' | Category;

/** Blocked requests of one bucket for the picked category (`all`: the bucket's total). */
export function valueOf(p: SeriesPoint, c: CategoryPick): number {
  return c === 'all' ? p.blocked : p.by_category?.[c] ?? 0;
}

export interface ChartData {
  values: number[]; max: number; total: number;
  /** SVG polyline points in a `w` x `h` box with `pad` around it. */
  points: { x: number; y: number }[];
  path: string;
  labels: { x: number; text: string }[];
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export function bucketLabel(ts: number, range: SeriesRange): string {
  const d = new Date(ts * 1000);
  return range === 'm12' ? MONTHS[d.getUTCMonth()]! : `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
}

export function chartData(pts: SeriesPoint[], cat: CategoryPick, range: SeriesRange, w = 320, h = 90, pad = 4): ChartData {
  const values = pts.map((p) => valueOf(p, cat));
  const max = Math.max(1, ...values);
  const n = pts.length;
  const points = values.map((v, i) => ({
    x: n <= 1 ? pad : pad + (i * (w - 2 * pad)) / (n - 1),
    y: pad + (h - 2 * pad) * (1 - v / max),
  }));
  const r = (x: number) => Math.round(x * 10) / 10;
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${r(p.x)} ${r(p.y)}`).join(' ');
  // First, middle and last bucket carry a label.
  const idx = n === 0 ? [] : [...new Set([0, Math.floor((n - 1) / 2), n - 1])];
  return {
    values, max, total: values.reduce((a, b) => a + b, 0), points, path,
    labels: idx.map((i) => ({ x: points[i]!.x, text: bucketLabel(pts[i]!.ts, range) })),
  };
}

export const CATEGORY_PICKS: CategoryPick[] = ['all', ...CATEGORIES];
