import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Chromium before roughly 148 has no `globalThis.browser`: only WXT's auto-imported `browser`
 * (the polyfill/`chrome` alias it injects at build time) works there. The cookie manager page once
 * read the global directly, so it crashed on start in older Chromium and never loaded its cookies.
 */
describe('the cookie manager page and the extension API object', () => {
  const dir = join(__dirname, '../ui/cookies');
  const files = readdirSync(dir).filter((f) => /\.tsx?$/.test(f));
  it('has sources to check', () => { expect(files.length).toBeGreaterThan(5); });
  it.each(files)('%s does not read the browser object off globalThis', (f) => {
    expect(readFileSync(join(dir, f), 'utf8')).not.toMatch(/globalThis[^;\n]*\)?\.browser\b|window\.browser\b/);
  });
});
