// Downloads a pinned extension from extensions.json into .cache/, verifies its sha256, and (for zips)
// unpacks it so Chrome can --load-extension it. Firefox extensions stay signed .xpi files.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const manifest = JSON.parse(fs.readFileSync(path.join(here, 'extensions.json'), 'utf8'));
const cache = path.join(here, '.cache');

// Blocker id -> extensions.json key (the extension baselines).
export const EXT_KEY = { ubol: 'ubol', ubo: 'ubo', 'adguard-ext': 'adguard-ext' };

export async function ensureExtension(blocker, browser) {
  const pin = manifest[EXT_KEY[blocker]]?.[browser];
  if (!pin) throw new Error(`no pinned ${blocker} extension for ${browser} in extensions.json`);
  const base = path.join(cache, `${blocker}-${browser}-${pin.version}`);
  const archive = base + (pin.kind === 'xpi' ? '.xpi' : '.zip');
  fs.mkdirSync(cache, { recursive: true });
  if (!fs.existsSync(archive)) {
    const r = await fetch(pin.url, { redirect: 'follow' });
    if (!r.ok) throw new Error(`${pin.url}: HTTP ${r.status}`);
    fs.writeFileSync(archive, Buffer.from(await r.arrayBuffer()));
  }
  const got = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
  if (got !== pin.sha256) {
    fs.rmSync(archive);
    throw new Error(`sha256 mismatch for ${pin.url}: pinned ${pin.sha256}, got ${got}. Run update-extensions.mjs if the pin is stale.`);
  }
  if (pin.kind === 'xpi') return { path: archive, version: pin.version };
  if (!fs.existsSync(path.join(base, 'manifest.json'))) {
    fs.rmSync(base, { recursive: true, force: true });
    fs.mkdirSync(base, { recursive: true });
    const u = spawnSync('unzip', ['-q', '-o', archive, '-d', base]);
    if (u.status !== 0) {
      const t = spawnSync('tar', ['-xf', archive, '-C', base]);
      if (t.status !== 0) throw new Error('could not unzip ' + archive);
    }
  }
  return { path: base, version: pin.version };
}
