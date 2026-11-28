import { afterEach, describe, expect, it, vi } from 'vitest';
import { settle, mountPage, rowNames, type Page } from './helpers/pagekit';

let page: Page | undefined;
afterEach(() => { page?.unmount(); page = undefined; vi.unstubAllGlobals(); });
const mount: typeof mountPage = async (o) => (page = await mountPage(o));

describe('cookies tab: list, filter, select', () => {
  it('lists this site by default, with masked values, flags, a protected marker and the site pill', async () => {
    const p = await mount();
    expect(p.text('.cmh')).toContain('stackoverflow.com');
    const names = rowNames(p);
    expect(names).toContain('__Host-sosid');
    expect(names).toContain('__Secure-tp-embed');
    expect(names).not.toContain('session_id');
    expect(p.q('td.val .vbtn').textContent).toBe('••••••');
    const row = p.qa('tr[data-row]').find((r) => r.textContent?.includes('__Host-sosid'))!;
    expect(row.textContent).toContain('Secure');
    expect(row.textContent).toContain('HttpOnly');
    expect(row.textContent).toContain('__Host-');
    const tp = p.qa('tr[data-row]').find((r) => r.textContent?.includes('__Secure-tp-embed'))!;
    expect(tp.textContent).toContain('Partitioned');
    expect(tp.textContent).toContain('Third-party');
  });

  it('reveals one value on demand and hides it again', async () => {
    const p = await mount();
    const row = p.qa('tr[data-row]').find((r) => r.textContent?.includes('prefs'))!;
    await p.click(row.querySelector('.vbtn'));
    expect(row.querySelector('.vbtn')!.textContent).toBe('theme%3Dlight');
    await p.click(row.querySelector('.vbtn'));
    expect(row.querySelector('.vbtn')!.textContent).toBe('••••••');
  });

  it('All sites shows every site, and the store select narrows it', async () => {
    const p = await mount();
    await p.click(p.q('[role=radio][aria-checked=false]'));
    expect(rowNames(p)).toContain('session_id');
    expect(rowNames(p)).toContain('cart_id');
    await p.select(p.q('#cstore'), '2');
    expect(rowNames(p)).toEqual(['autoplay']);
  });

  it('searches name, domain and value; the chips narrow the rows', async () => {
    const p = await mount();
    await p.type(p.q('input[type=search]'), 'optanon');
    expect(rowNames(p)).toEqual(['OptanonConsent']);
    await p.type(p.q('input[type=search]'), '');
    await p.click(p.button('Third-party'));
    expect(rowNames(p)).toEqual(['__Secure-tp-embed']);
    await p.click(p.button('Third-party'));
    await p.click(p.button('Partitioned'));
    expect(rowNames(p)).toEqual(['__Secure-tp-embed']);
    await p.click(p.button('Partitioned'));
    await p.click(p.button('Session'));
    expect(rowNames(p).sort()).toEqual(['acct', 'prefs']);
    await p.click(p.button('Session'));
    await p.click(p.button('HttpOnly'));
    expect(rowNames(p).sort()).toEqual(['__Host-sosid', '__cf_bm', 'acct']);
  });

  it('selecting rows swaps the chips for the selection bar in the same slot', async () => {
    const p = await mount();
    expect(p.q('.cslot').classList.contains('sel')).toBe(false);
    await p.click(p.q('button[aria-label="Select _ga"]'));
    expect(p.q('.cslot').classList.contains('sel')).toBe(true);
    expect(p.text('.bulk')).toContain('1 selected');
    await p.click(p.button('Clear selection'));
    expect(p.q('.cslot').classList.contains('sel')).toBe(false);
  });

  it('select all ticks every visible row and shows the count', async () => {
    const p = await mount();
    await p.click(p.q('button[aria-label="Select all"]'));
    expect(p.q('button[aria-label="Select all"]').getAttribute('aria-checked')).toBe('true');
    expect(p.text('.bulk')).toContain(`${rowNames(p).length} selected`);
  });

  it('deletes the selection only after an in-place confirm, and keeps protected cookies', async () => {
    const p = await mount();
    const before = p.w.fb.all().length;
    await p.click(p.q('button[aria-label="Select _ga"]'));
    await p.click(p.q('button[aria-label="Select acct"]'));
    const del = p.q<HTMLButtonElement>('[data-testid=bulk-delete]');
    expect(del.textContent).toBe('Delete');
    await p.click(del);
    expect(del.textContent).toBe('Delete?');
    expect(p.w.fb.all().length).toBe(before);
    await p.click(p.button('Cancel', p.q('.bulk')));
    expect(del.textContent).toBe('Delete');
    expect(p.w.fb.all().length).toBe(before);
    await p.click(del); await p.click(del);
    await p.waitFor(() => p.w.fb.all().length === before - 2, 'two cookies deleted');
    expect(rowNames(p)).not.toContain('_ga');
    expect(p.text('#toasts')).toContain('Deleted 2 cookies');
    // Undo puts them back.
    await p.click(p.button('Undo'));
    await p.waitFor(() => p.w.fb.all().length === before, 'undo');
  });

  it('never deletes a protected cookie in a bulk delete', async () => {
    const p = await mount();
    await p.click(p.q('button[aria-label="Select __Host-sosid"]'));
    await p.click(p.button('Protect'));
    await p.waitFor(() => p.qa('.prot').length === 1, 'protected marker');
    await p.click(p.q('button[aria-label="Select __Host-sosid"]'));
    await p.click(p.q('[data-testid=bulk-delete]')); await p.click(p.q('[data-testid=bulk-delete]'));
    await settle(60);
    expect(rowNames(p)).toContain('__Host-sosid');
    expect(p.text('#toasts')).toContain('kept 1 protected');
  });
});
