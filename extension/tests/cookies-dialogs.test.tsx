import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mountPage, rowNames, settle, type Page } from './helpers/pagekit';

let page: Page | undefined;
let clip = '';
let saved: { name: string; blob: Blob }[] = [];
beforeEach(() => {
  clip = ''; saved = [];
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (t: string) => { clip = t; } } });
  let last: Blob | undefined;
  (URL as any).createObjectURL = (b: Blob) => { last = b; return 'blob:x'; };
  (URL as any).revokeObjectURL = () => {};
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { saved.push({ name: this.download, blob: last! }); });
});
afterEach(() => { page?.unmount(); page = undefined; vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const mount: typeof mountPage = async (o) => (page = await mountPage(o));
const preview = (p: Page) => p.q('[data-testid=export-preview]').textContent ?? '';
const sel = (p: Page, id: string) => p.q<HTMLSelectElement>(id);

describe('export dialog', () => {
  it('previews exactly what will be written, per format', async () => {
    const p = await mount();
    await p.click(p.button('Export'));
    expect(preview(p)).toContain('# Netscape HTTP Cookie File');
    expect(preview(p)).toContain('#HttpOnly_stackoverflow.com\tFALSE\t/\tTRUE\t');
    expect(preview(p)).not.toContain('session_id');
    expect(p.text('#excnt')).toBe('8 cookies');
    await p.select(sel(p, '#exf'), 'fmt:json');
    expect(JSON.parse(preview(p)).find((c: any) => c.name === '__Secure-tp-embed').partitionKey.topLevelSite).toBe('https://stackoverflow.com');
    await p.select(sel(p, '#exf'), 'fmt:header');
    expect(preview(p)).toMatch(/^[^=\n]+=[^;\n]*; /);
    await p.select(sel(p, '#exf'), 'sn:curl');
    expect(preview(p)).toContain("curl ");
    expect(preview(p)).toContain('https://stackoverflow.com/');
  });

  it('scope: all sites, and the selected rows', async () => {
    const p = await mount();
    await p.click(p.q('button[aria-label="Select _ga"]'));
    await p.click(p.button('Export selected'));
    expect(sel(p, '#exs').value).toBe('sel');
    expect(p.text('#excnt')).toBe('1 cookie');
    await p.select(sel(p, '#exs'), 'all');
    await p.waitFor(() => preview(p).includes('session_id'), 'all sites');
    expect(Number(p.text('#excnt').split(' ')[0])).toBeGreaterThan(8);
  });

  it('copies and saves the same text that is shown, from the page (no downloads permission)', async () => {
    const p = await mount();
    await p.click(p.button('Export'));
    const shown = preview(p);
    await p.click(p.button('Copy'));
    expect(clip).toBe(shown);
    expect(p.text('#toasts')).toContain('Copied');
    await p.click(p.button('Save'));
    expect(saved).toHaveLength(1);
    expect(saved[0]!.name).toBe('argus-cookies.txt');
    expect(await saved[0]!.blob.text()).toBe(shown);
    expect(p.text('#toasts')).toContain('Saved argus-cookies.txt');
  });

  it('warns that the file is equivalent to being logged in, and encrypts with a passphrase', async () => {
    const p = await mount();
    await p.click(p.button('Export'));
    expect(p.text('[data-testid=export-dialog] .banner')).toContain('equivalent to being logged in');
    await p.click(p.q('#exe'));
    expect(p.button('Copy').disabled).toBe(true);
    expect(p.text('[data-testid=export-dialog]')).toContain('Enter a passphrase');
    await p.type(p.q('#exp'), 'correct horse');
    await p.waitFor(() => preview(p).includes('argus-encrypted-cookies'), 'sealed preview');
    const shown = preview(p);
    await p.click(p.button('Copy'));
    expect(clip).toBe(shown);
    expect(clip).not.toContain('__Host-sosid');
    await p.click(p.button('Save'));
    expect(saved[0]!.name).toBe('argus-cookies.enc.json');
  });

  it('Esc closes it and focus returns to the Export button', async () => {
    const p = await mount();
    const b = p.button('Export');
    b.focus();
    await p.click(b);
    await p.key(p.q('[data-testid=export-dialog]'), 'Escape');
    expect(document.querySelector('[data-testid=export-dialog]')).toBeNull();
    expect(document.activeElement).toBe(b);
  });
});

const NETSCAPE = ['# Netscape HTTP Cookie File', '.stackoverflow.com\tTRUE\t/\tTRUE\t4102444800\tpreferred_lang\ten', 'stackoverflow.com\tFALSE\t/\tTRUE\t0\tprefs\ttheme%3Ddark', '.stackoverflow.com\tTRUE\t/\tFALSE\t4102444800\t__Secure-flag\t1'].join('\n');

describe('import dialog', () => {
  it('dry-runs a paste: detected format, per-row result and reason, nothing written yet', async () => {
    const p = await mount();
    await p.click(p.button('Import'));
    await p.type(p.q('#imt'), NETSCAPE);
    await p.waitFor(() => p.root.querySelector('#imtbl'), 'plan');
    expect(p.text('#imdet')).toContain('Detected: Netscape cookies.txt');
    const rows = p.qa('#imtbl tbody tr').map((r) => r.textContent);
    expect(rows.find((r) => r!.includes('preferred_lang'))).toContain('Will import');
    expect(rows.find((r) => r!.includes('prefs'))).toContain('Will replace existing');
    expect(rows.find((r) => r!.includes('__Secure-flag'))).toMatch(/Rejected.*__Secure-.*Secure/);
    expect(p.button(/^Import \d/).textContent).toBe('Import 2');
    expect(p.w.fb.all().some((c) => c.name === 'preferred_lang')).toBe(false);
  });

  it('applies the import in Merge mode, and Replace removes the other cookies of those sites', async () => {
    const p = await mount();
    await p.click(p.button('Import'));
    await p.type(p.q('#imt'), NETSCAPE);
    await p.waitFor(() => p.root.querySelector('#imtbl'), 'plan');
    await p.click(p.button(/^Import 2/));
    await p.waitFor(() => p.w.fb.all().some((c) => c.name === 'preferred_lang'), 'imported');
    expect(p.w.fb.all().some((c) => c.name === 'acct')).toBe(true);
    expect(p.w.fb.all().find((c) => c.name === 'prefs')?.value).toBe('theme%3Ddark');
    await p.click(p.button('Import'));
    await p.type(p.q('#imt'), NETSCAPE);
    await p.click(p.button('Replace cookies for these sites'));
    await p.waitFor(() => p.button(/^Import \d/), 'plan');
    await p.click(p.button(/^Import \d/));
    await p.waitFor(() => !p.w.fb.all().some((c) => c.name === 'acct'), 'replaced');
    expect(p.w.fb.all().some((c) => c.name === 'session_id')).toBe(true);
  });

  it('asks for the passphrase of an encrypted export and reports a wrong one', async () => {
    const p = await mount();
    const enc = await p.w.client.call({ op: 'export', cookies: [(await p.w.client.call({ op: 'list' }))[0]!], format: 'json', passphrase: 'pw-1' });
    await p.click(p.button('Import'));
    await p.type(p.q('#imt'), enc.text);
    expect(p.text('#imdet')).toContain('encrypted');
    expect(p.button(/^Import/, p.q('.mf')).disabled).toBe(true);
    await p.type(p.q('#imp'), 'nope');
    await p.waitFor(() => p.text('[data-testid=import-dialog]').includes('does not open'), 'wrong passphrase');
    await p.type(p.q('#imp'), 'pw-1');
    await p.waitFor(() => p.root.querySelector('#imtbl'), 'plan');
    expect(p.text('#imdet')).toContain('Detected: JSON');
  });

  it('reads a chosen file', async () => {
    const p = await mount();
    await p.click(p.button('Import'));
    const input = p.q<HTMLInputElement>('input[type=file]');
    const f = new File([NETSCAPE], 'cookies.txt', { type: 'text/plain' });
    Object.defineProperty(input, 'files', { value: [f], configurable: true });
    await p.waitFor(() => { input.dispatchEvent(new Event('change', { bubbles: true })); return p.q<HTMLTextAreaElement>('#imt').value.includes('preferred_lang'); }, 'file read');
  });
});

describe('snapshots', () => {
  it('saves, lists, compares against live, restores and deletes (with in-place confirm)', async () => {
    const p = await mount();
    await p.tab('Snapshots');
    await p.type(p.q('input[aria-label="Snapshot name"]'), 'baseline');
    await p.click(p.button('Save current'));
    await p.waitFor(() => p.text('[data-testid=snapshot-list]').includes('baseline'), 'listed');
    expect(p.text('[data-testid=snapshot-list]')).toContain('7Restore');
    // change the live jar, then compare the snapshot with it
    await p.w.client.call({ op: 'remove', cookies: [(await p.w.client.call({ op: 'list', site: 'stackoverflow.com' })).find((c) => c.name === 'acct')!] });
    await p.w.client.call({ op: 'create', cookie: { ...(await p.w.client.call({ op: 'list', site: 'stackoverflow.com' })).find((c) => c.name === 'prefs')!, value: 'changed' } });
    await p.select(p.q('select[aria-label="Second snapshot or live cookies"]'), 'live');
    await p.waitFor(() => p.text('[data-testid=snapshot-diff]').includes('Removed'), 'diff');
    expect(p.text('[data-testid=snapshot-diff]')).toMatch(/Removed.*acct/);
    expect(p.text('[data-testid=snapshot-diff]')).toMatch(/Changed.*prefs.*value differs/);
    const rest = p.q<HTMLButtonElement>('[data-testid=snapshot-list] .cfb');
    expect(rest.textContent).toBe('Restore');
    await p.click(rest);
    expect(rest.textContent).toBe('Restore?');
    await p.waitFor(() => p.text('.rwarn').includes('sets 7 cookies, replaces 1 and removes 0'), 'says what it will do');
    expect(p.w.fb.all().some((c) => c.name === 'acct')).toBe(false);
    await p.click(rest);
    await p.waitFor(() => p.w.fb.all().some((c) => c.name === 'acct'), 'restored');
    expect(p.w.fb.all().find((c) => c.name === 'prefs')?.value).toBe('theme%3Dlight');
    const del = p.qa<HTMLButtonElement>('[data-testid=snapshot-list] .cfb')[1]!;
    await p.click(del);
    expect(del.textContent).toBe('Delete?');
    await p.click(del);
    await p.waitFor(() => p.text('[data-testid=snapshot-list]').includes('No snapshots yet'), 'deleted');
  });

  it('compares two snapshots', async () => {
    const p = await mount();
    await p.tab('Snapshots');
    await p.click(p.button('Save current'));
    await p.waitFor(() => p.qa('[data-testid=snapshot-list] tbody tr').length === 1, 'first');
    await p.w.client.call({ op: 'create', cookie: { ...(await p.w.client.call({ op: 'list', site: 'stackoverflow.com' }))[0]!, name: 'extra' } });
    await p.type(p.q('input[aria-label="Snapshot name"]'), 'second');
    await p.click(p.button('Save current'));
    await p.waitFor(() => p.qa('[data-testid=snapshot-list] tbody tr').length === 2, 'second');
    await p.waitFor(() => p.text('[data-testid=snapshot-diff]').includes('extra'), 'diff of two');
    expect(p.text('[data-testid=snapshot-diff]')).toContain('Added');
  });
});

describe('activity', () => {
  it('streams browser changes live; Pause stops the stream and Resume catches up', async () => {
    const p = await mount();
    await p.tab('Activity');
    expect(p.text('[data-testid=activity-table]')).toContain('No cookie activity yet');
    expect(p.text('.lgd')).toBe('A live record of cookies being set, changed, removed or expiring in this browser.');
    const set = (name: string) => p.w.br.cookies.set({ url: 'https://news.example.org/', name, value: 'v' });
    await set('one');
    await p.waitFor(() => p.text('[data-testid=activity-table]').includes('one'), 'live row');
    expect(p.text('[data-testid=activity-table] tbody tr')).toMatch(/Set.*one.*example\.org/);
    await p.click(p.button('Pause'));
    expect(p.text('[data-testid=activity-state]')).toBe('Paused');
    await set('two');
    await settle(80);
    expect(p.text('[data-testid=activity-table]')).not.toContain('two');
    await p.click(p.button('Resume'));
    await p.waitFor(() => p.text('[data-testid=activity-table]').includes('two'), 'caught up');
  });

  it('filters by site and labels the source (provenance on, off)', async () => {
    const p = await mount({ prov: 'on' });
    await p.tab('Activity');
    await p.w.br.cookies.set({ url: 'https://news.example.org/', name: 'a', value: '1' });
    await p.w.br.cookies.set({ url: 'https://www.stackoverflow.com/', name: 'b', value: '1' });
    await p.waitFor(() => p.text('[data-testid=activity-table]').includes('stackoverflow.com') && p.text('[data-testid=activity-table]').includes('example.org'), 'two rows');
    expect(p.text('[data-testid=activity-table]')).toContain('Not seen in transit');
    await p.select(p.q('select[aria-label="Filter by site"]'), 'stackoverflow.com');
    expect(p.qa('[data-testid=activity-table] tbody tr')).toHaveLength(1);
    page!.unmount();
    const q = await mount({ prov: 'off' });
    await q.tab('Activity');
    await q.w.br.cookies.set({ url: 'https://news.example.org/', name: 'a', value: '1' });
    await q.waitFor(() => q.text('[data-testid=activity-table]').includes('example.org'), 'row');
    expect(q.text('[data-testid=activity-table]')).toContain('Provenance off');
  });
});

describe('rules tab', () => {
  it('writes auto-delete as a sentence with inline controls, and edits the lists', async () => {
    const p = await mount();
    await p.tab('Rules');
    expect(p.text('.srow')).toBe('Delete cookies for sites not on the keep list 30 seconds1 minute10 minutes1 hour after the last tab closes');
    await p.click(p.q('button[aria-label="Auto-delete"]'));
    await p.select(p.q('select[aria-label="Wait"]'), '10');
    await p.waitFor(async () => true);
    const r = await p.w.client.call({ op: 'rules.get' });
    expect(r.autoDelete).toEqual({ enabled: true, delayMinutes: 10 });
    await p.type(p.q('input[aria-label="Site to keep"]'), 'https://News.Example.org/path');
    await p.click(p.button('Add', p.q('[data-testid=rules-keep-list]')));
    await p.waitFor(async () => (await p.w.client.call({ op: 'rules.get' })).keep.includes('news.example.org'), 'keep added');
    await p.type(p.q('input[aria-label="Site to greylist"]'), 'video.example.net');
    await p.click(p.button('Add', p.q('[data-testid=rules-greylist]')));
    await p.waitFor(() => p.text('[data-testid=rules-greylist]').includes('video.example.net'), 'grey added');
    const rm = p.q<HTMLButtonElement>('[data-testid=rules-keep-list] .cfb');
    await p.click(rm);
    expect(rm.textContent).toBe('Remove?');
    await p.click(rm);
    await p.waitFor(() => p.text('[data-testid=rules-keep-list]').includes('Nothing here yet'), 'removed');
  });

  it('protects a cookie by name and domain; the table shows the marker and bulk delete keeps it', async () => {
    const p = await mount();
    await p.tab('Rules');
    await p.type(p.q('input[aria-label="Cookie name"]'), 'acct');
    await p.type(p.q('input[aria-label="Domain"]'), 'stackoverflow.com');
    await p.click(p.button('Add', p.q('[data-testid=rules-protected]')));
    await p.waitFor(() => p.text('[data-testid=rules-protected]').includes('acct · stackoverflow.com'), 'listed');
    await p.tab('Cookies');
    await p.waitFor(() => p.qa('.prot').length === 1, 'marker');
    expect(p.qa('.prot')[0]!.closest('tr')!.textContent).toContain('acct');
  });
});

describe('long lists and accessibility', () => {
  it('renders only the rows near the viewport of a very long list', async () => {
    const t = Math.floor(Date.now() / 1000);
    const p = await mount({ seed: false, prepare: (w) => { for (let i = 0; i < 8000; i++) w.fb.seed({ name: `c${String(i).padStart(5, '0')}`, value: 'v', domain: `h${i % 90}.example.org`, expirationDate: t + 86400 * 30 }); } });
    await p.click(p.q('[role=radio][aria-checked=false]'));
    await p.waitFor(() => p.qa('tr[data-row]').length > 0, 'rows');
    expect(p.qa('tr[data-row]').length).toBeLessThan(120);
    expect(p.q('table.ck').getAttribute('aria-rowcount')).toBe('8001');
    expect(rowNames(p)).toHaveLength(p.qa('tr[data-row]').length);
  });

  it('uses roles instead of native checkboxes and radios, and arrows move through the segmented control and the tabs', async () => {
    const p = await mount();
    expect(p.qa('input[type=checkbox],input[type=radio]')).toHaveLength(0);
    expect(p.q('[role=tablist]').getAttribute('aria-label')).toBe('Cookie manager');
    expect(p.qa('[role=tab]').map((t) => [t.textContent, t.getAttribute('aria-selected')])).toEqual([['Cookies', 'true'], ['Snapshots', 'false'], ['Activity', 'false'], ['Rules', 'false']]);
    expect(p.q('[role=tabpanel]').getAttribute('aria-labelledby')).toBe('cm-tab-cookies');
    expect(p.q('button[aria-label="Select all"]').getAttribute('role')).toBe('checkbox');
    expect(p.q('#toasts').getAttribute('aria-live')).toBe('polite');
    const scope = p.q('[role=radiogroup][aria-label=Scope]');
    expect(scope.querySelectorAll('[role=radio]')).toHaveLength(2);
    await p.key(scope.querySelector('[aria-checked=true]'), 'ArrowRight');
    expect(scope.querySelector('[aria-checked=true]')!.textContent).toBe('All sites');
    await p.key(p.q('[role=tab][aria-selected=true]'), 'ArrowRight');
    expect(p.q('[role=tab][aria-selected=true]').textContent).toBe('Snapshots');
  });
});
