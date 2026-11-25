import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import { onStorageChanged } from '../lib/changes';
import { recordGrant, revokeGrant } from '../lib/grants';
import type { MenuState } from '../lib/menudata';
import { Scripts } from '../ui/scripts';

beforeEach(() => {
  (globalThis as any).browser = fakeBrowser;
  fakeBrowser.reset();
});

describe('Scripts', () => {
  it('shows a grant request that arrives after the first render', async () => {
    const root = document.createElement('div');
    const none: MenuState = { kind: 'none' };
    await act(() => { render(<Scripts state={none} reload={() => {}} />, root); });
    expect(root.textContent).toBe('');
    const ok: MenuState = {
      kind: 'ok', commands: [],
      grants: [{ script: 's', scriptName: 'Gist sync', host: 'api.github.com', patterns: ['https://api.github.com/*'] }],
      call: { trigger: async () => true },
    };
    await act(() => { render(<Scripts state={ok} reload={() => {}} />, root); });
    expect(root.textContent).toContain('wants your login for');
    expect(root.textContent).toContain('Allow');
  });
});

describe('grant changes reach the proxy', () => {
  it('record and revoke each trigger sendPerms', async () => {
    const d = { clearCache: vi.fn(), bridge: { reconnect: vi.fn(async () => {}), sendPerms: vi.fn(async () => {}) }, proxy: { reload: vi.fn() } };
    fakeBrowser.storage.onChanged.addListener((c) => onStorageChanged(c, d));
    await recordGrant(browser, ['https://a.com/*']);
    await new Promise((r) => setTimeout(r, 0));
    expect(d.bridge.sendPerms).toHaveBeenCalledTimes(1);
    await revokeGrant(browser, 'https://a.com/*');
    await new Promise((r) => setTimeout(r, 0));
    expect(d.bridge.sendPerms).toHaveBeenCalledTimes(2);
    expect(d.bridge.reconnect).not.toHaveBeenCalled();
  });
});
