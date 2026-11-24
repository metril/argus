import { describe, expect, it, vi } from 'vitest';
import { respondAsync } from '../lib/messages';

describe('respondAsync', () => {
  it('answers through sendResponse and keeps the channel open (Chrome < 144 ignores returned promises)', async () => {
    const l = respondAsync<{ t: string }, object>((m) => (m.t === 'x' ? Promise.resolve({ ok: 1 }) : undefined));
    const send = vi.fn();
    expect(l({ t: 'x' }, {}, send)).toBe(true);
    await new Promise((r) => setTimeout(r, 0));
    expect(send).toHaveBeenCalledWith({ ok: 1 });
  });
  it('does not claim messages it does not handle, and answers undefined when the handler fails', async () => {
    const l = respondAsync<{ t: string }, object>((m) => (m.t === 'x' ? Promise.reject(new Error('no')) : undefined));
    const send = vi.fn();
    expect(l({ t: 'other' }, {}, send)).toBeUndefined();
    expect(send).not.toHaveBeenCalled();
    expect(l({ t: 'x' }, {}, send)).toBe(true);
    await new Promise((r) => setTimeout(r, 0));
    expect(send).toHaveBeenCalledWith(undefined);
  });
});
