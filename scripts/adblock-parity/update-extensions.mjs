#!/usr/bin/env node
// Refreshes extensions.json to the latest releases and pins version + URL + sha256.
//   uBOL chrome            : GitHub release asset uBOLite_<v>.chromium.zip (uBlockOrigin/uBOL-home)
//   AdGuard ext chrome     : GitHub release asset chrome-mv3.zip (AdguardTeam/AdguardBrowserExtension),
//                            the same MV3 build the Chrome Web Store ships (CWS CRXs cannot be pinned by hash)
//   AdGuard for Windows   : versioned MSI (static.adtidy.org/windows/setup64-<v>.msi); latest version from the
//                            winget-pkgs manifest directory (the vendor URL agrd.io/adguard_setup64_msi is unversioned)
//   uBO / AdGuard firefox  : signed .xpi from AMO (immutable per-file URLs)
// Usage: node update-extensions.mjs [--dry]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const file = path.join(here, 'extensions.json');
const dry = process.argv.includes('--dry');
const ghHeaders = { Accept: 'application/vnd.github+json', ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };

const json = async (url, headers = {}) => {
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
};
const sha256 = async (url) => {
  const r = await fetch(url, { redirect: 'follow' });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return crypto.createHash('sha256').update(Buffer.from(await r.arrayBuffer())).digest('hex');
};
async function ghAsset(repo, match, { stable = true } = {}) {
  const rels = await json(`https://api.github.com/repos/${repo}/releases?per_page=20`, ghHeaders);
  for (const rel of rels) {
    if (rel.draft || (stable && rel.prerelease)) continue;
    const a = rel.assets.find((x) => match.test(x.name));
    if (a) return { version: rel.tag_name.replace(/^v/, ''), url: a.browser_download_url };
  }
  throw new Error(`no ${match} asset in ${repo}`);
}
async function amo(slug) {
  const d = await json(`https://addons.mozilla.org/api/v5/addons/addon/${slug}/`);
  return { version: d.current_version.version, url: d.current_version.file.url, sha256: d.current_version.file.hash.replace(/^sha256:/, '') };
}

async function adguardWindows() {
  const dirs = await json('https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/a/AdGuard/AdGuard', ghHeaders);
  const version = dirs.map((d) => d.name).filter((n) => /^\d+(\.\d+)+$/.test(n)).sort((a, b) => a.split('.').map(Number).reduce((r, x, i) => r || x - Number(b.split('.')[i] || 0), 0)).pop();
  const url = `https://static.adtidy.org/windows/setup64-${version}.msi`;
  return { version, url, sha256: await sha256(url), kind: 'msi' };
}

const out = {
  'adguard-desktop': { windows: await adguardWindows() },
  ubol: { chrome: { ...(await ghAsset('uBlockOrigin/uBOL-home', /\.chromium\.zip$/)), kind: 'zip' } },
  ubo: { firefox: { ...(await amo('ublock-origin')), kind: 'xpi' } },
  'adguard-ext': {
    chrome: { ...(await ghAsset('AdguardTeam/AdguardBrowserExtension', /^chrome-mv3\.zip$/)), kind: 'zip' },
    firefox: { ...(await amo('adguard-adblocker')), kind: 'xpi' },
  },
};
for (const b of [out.ubol.chrome, out['adguard-ext'].chrome]) b.sha256 = await sha256(b.url);

if (dry) console.log(JSON.stringify(out, null, 2));
else {
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
  console.log('wrote', file);
}
