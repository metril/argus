// Site registry: URL + browser-side extractor (common helpers prepended). Output schema per site:
// { site, url, ok, error?, score:{passed,total,percent}, categories:{name:{passed,total,percent}}, tests:[{category,name,pass}], meta }
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'extractors');
const common = fs.readFileSync(path.join(dir, '_common.js'), 'utf8');

export const SITES = [
  { id: 'turtlecute', url: 'https://adblock.turtlecute.org/', file: 'turtle' },
  { id: 'superadblocktest', url: 'https://superadblocktest.com/?run=1', file: 'super' },
  { id: 'adblock-tester', url: 'https://adblock-tester.com/', file: 'tester' },
  { id: 'blockify', url: 'https://getblockify.com/adblock-test', file: 'blockify' },
  { id: 'toolz', url: 'https://paileactivist.github.io/toolz/adblock.html', file: 'paile' },
];

// One expression evaluating to a Promise of the result; usable by page.evaluate (Playwright) and by
// executeAsyncScript (Selenium).
export function extractorSource(site) {
  const body = fs.readFileSync(path.join(dir, site.file + '.js'), 'utf8').replace(/^\/\/.*\n/gm, '');
  return `(() => { ${common}\n const run = ${body};\n return run(); })()`;
}
