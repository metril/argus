import { afterEach, describe, expect, it, vi } from 'vitest';
import { identityKey, makeCookie } from '../lib/cookiejar/model';
import { joinProvenance, sentVsStored, type ProvenanceRecord } from '../lib/cookiejar/provenance';
import { mountPage, rowNames, settle, type Page } from './helpers/pagekit';

let page: Page | undefined;
afterEach(() => { page?.unmount(); page = undefined; vi.unstubAllGlobals(); });
const mount: typeof mountPage = async (o) => (page = await mountPage(o));
const openRow = async (p: Page, name: string) => { await p.click(p.qa('td.nm .lnk').find((e) => e.textContent === name)); await p.waitFor(() => document.querySelector('[data-testid=cookie-drawer]'), 'drawer'); await settle(200); };

describe('bulk actions only act on rows that are selected and shown', () => {
  it('the count, the header tick and Delete agree after a filter hides selected rows', async () => {
    const p = await mount();
    await p.click(p.q('button[aria-label="Select all"]'));
    const total = rowNames(p).length;
    expect(p.text('.bulk')).toContain(`${total} selected`);
    await p.type(p.q('input[type=search]'), 'optanon');
    expect(rowNames(p)).toEqual(['OptanonConsent']);
    expect(p.text('.bulk')).toContain('1 selected');
    expect(p.q('button[aria-label="Select all"]').getAttribute('aria-checked')).toBe('true');
    const before = p.w.fb.all().length;
    await p.click(p.q('[data-testid=bulk-delete]')); await p.click(p.q('[data-testid=bulk-delete]'));
    await p.waitFor(() => p.w.fb.all().length === before - 1, 'one deleted');
    expect(p.w.fb.all().some((c) => c.name === 'acct')).toBe(true);
    expect(p.w.fb.all().some((c) => c.name === 'OptanonConsent')).toBe(false);
  });

  it('Export selected exports only the shown selected rows', async () => {
    const p = await mount();
    await p.click(p.q('button[aria-label="Select all"]'));
    await p.type(p.q('input[type=search]'), 'prefs');
    await p.click(p.button('Export selected'));
    expect(p.text('#excnt')).toBe('1 cookie');
  });
});

describe('drawer escape', () => {
  it('closes at once when nothing was edited, even with focus in a field', async () => {
    const p = await mount();
    await openRow(p, 'acct');
    p.q('#dn').focus();
    await p.key(p.q('#dn'), 'Escape');
    expect(document.querySelector('[data-testid=cookie-drawer]')).toBeNull();
  });

  it('with unsaved edits the first Escape arms Cancel, the second discards', async () => {
    const p = await mount();
    await openRow(p, 'acct');
    await p.type(p.q('#dv'), 'edited');
    await p.key(p.q('#dv'), 'Escape');
    expect(document.querySelector('[data-testid=cookie-drawer]')).not.toBeNull();
    const cancel = p.button('Discard changes?');
    expect(document.activeElement).toBe(cancel);
    await p.key(cancel, 'Escape');
    expect(document.querySelector('[data-testid=cookie-drawer]')).toBeNull();
    expect(p.w.fb.all().find((c) => c.name === 'acct')?.value).not.toBe('edited');
  });

  it('focus falls back to the table when the opener is gone', async () => {
    const p = await mount();
    await openRow(p, 'acct');
    await p.click(p.button('Duplicate'));
    await settle(300);
    expect(document.querySelector('[data-testid=cookie-drawer]')).toBeNull();
    expect(document.activeElement === document.body).toBe(false);
  });
});

describe('import applies what was checked', () => {
  it('keeps Import disabled while the plan on screen is for older text', async () => {
    const p = await mount();
    await p.click(p.button('Import'));
    const good = '# Netscape HTTP Cookie File\n.stackoverflow.com\tTRUE\t/\tTRUE\t4102444800\tfirst\t1';
    await p.type(p.q('#imt'), good);
    await p.waitFor(() => p.button(/^Import \d/), 'plan');
    // typing again: the old plan no longer applies until the new dry run is back
    await act2(p, () => { const t = p.q<HTMLTextAreaElement>('#imt'); t.value = good + '\n.stackoverflow.com\tTRUE\t/\tTRUE\t4102444800\tsecond\t2'; t.dispatchEvent(new Event('input', { bubbles: true })); });
    expect(p.button(/^Import/, p.q('.mf')).disabled).toBe(true);
    await p.waitFor(() => p.button(/^Import 2/), 'new plan');
  });
});

async function act2(_p: Page, f: () => void) { const { act } = await import('preact/test-utils'); await act(async () => { f(); }); }

describe('provenance join keeps host-only and domain cookies apart', () => {
  const rec = (o: Partial<ProvenanceRecord> & { name: string }): ProvenanceRecord => ({ at: 1000, host: 'a.example', path: '/', sent: {}, ...o });
  it('a Domain-attribute record does not describe the host-only cookie of the same name', () => {
    const hostOnly = makeCookie({ name: 'n', domain: 'a.example', storeId: '0' });
    const domain = makeCookie({ name: 'n', domain: '.a.example', hostOnly: false, storeId: '0' });
    const j = joinProvenance([hostOnly, domain], [rec({ name: 'n', sent: { domain: 'a.example' } })]);
    expect(j.info.get(identityKey(domain))?.seen).toBe(true);
    expect(j.info.get(identityKey(hostOnly))?.seen).toBe(false);
    const j2 = joinProvenance([hostOnly, domain], [rec({ name: 'n' })]);
    expect(j2.info.get(identityKey(hostOnly))?.seen).toBe(true);
    expect(j2.info.get(identityKey(domain))?.seen).toBe(false);
  });
  it('shows no Lifetime line when sent and stored read the same', () => {
    const r = rec({ name: 'n', at: 0, sent: { maxAge: 30 * 86400 } });
    const c = makeCookie({ name: 'n', domain: 'a.example', session: false, expirationDate: 30 * 86400 + 3 * 3600, storeId: '0' });
    expect(sentVsStored(r, c)).toEqual([]);
  });
});
