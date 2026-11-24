import { fetchCert, getSettings } from '../../lib/api';

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const msg = document.getElementById('msg')!;

function normUrl(v: string) { return v.trim().replace(/\/+$/, ''); }

async function ensurePermission(url: string): Promise<boolean> {
  try {
    const origin = new URL(url).origin + '/*';
    return await browser.permissions.request({ origins: [origin] });
  } catch { return false; }
}

async function save() {
  const argusUrl = normUrl($('url').value);
  if (argusUrl && !(await ensurePermission(argusUrl))) { msg.textContent = 'Host permission denied.'; return false; }
  await browser.storage.local.set({ argusUrl, token: $('token').value.trim() });
  msg.textContent = 'Saved.';
  return true;
}

(async () => {
  const s = await getSettings();
  $('url').value = s.argusUrl;
  $('token').value = s.token;
})();

$('save').addEventListener('click', () => void save());
$('test').addEventListener('click', async () => {
  if (!(await save())) return;
  const r = await fetchCert(await getSettings(), 'connection-test.invalid');
  msg.textContent =
    r.kind === 'unseen' || r.kind === 'ok' ? 'Connected: URL and token are valid.' :
    r.kind === 'auth' ? `Auth failed (HTTP ${r.status}): check the token and that it has logs:read.` :
    r.kind === 'unconfigured' ? 'Enter a URL and token.' : `Failed: ${r.message}`;
});
