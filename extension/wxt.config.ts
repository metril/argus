import { defineConfig } from 'wxt';

const icons = { 16: 'icon/16.png', 32: 'icon/32.png', 48: 'icon/48.png', 128: 'icon/128.png' };

// The manifest version comes from package.json; CI asserts it equals the Cargo workspace version.
export default defineConfig({
  // Preact (no wxt module exists for it): JSX compiled by the bundler's esbuild.
  vite: () => ({ esbuild: { jsx: 'automatic', jsxImportSource: 'preact' } }),
  manifestVersion: 3,
  manifest: ({ browser }) => ({
    name: 'Argus',
    description: 'Shows the real upstream certificate Argus saw for the current site.',
    author: 'metril',
    homepage_url: 'https://github.com/metril/argus',
    icons,
    // Firefox's default MV3 policy adds `upgrade-insecure-requests`, which turns the channel's
    // `ws://` into `wss://` and breaks a plain-http Argus console; Chrome's has no such directive.
    // Stated explicitly so both behave the same (still no remote code).
    content_security_policy: { extension_pages: "script-src 'self'; object-src 'self';" },
    action: { default_icon: icons },
    permissions: [
      'storage', 'tabs', 'cookies', 'scripting', 'activeTab', 'alarms', 'proxy', 'webRequest',
      ...(browser === 'firefox' ? ['webRequestBlocking', 'contextualIdentities'] : ['webRequestAuthProvider']),
    ],
    // Chrome: a separate instance runs in incognito windows, with its own connection, session
    // and cookie store, so incognito pages bind and relay with incognito cookies.
    ...(browser === 'firefox' ? {} : { incognito: 'split' as const }),
    // Both browsers: webRequest (the proxy login) only sees hosts granted at install, and the
    // user-entered Argus address needs no prompt. `proxy` already warns about all sites.
    host_permissions: ['<all_urls>'],
    ...(browser === 'firefox'
      ? {
          // 140 is the first release that honours data_collection_permissions.
          browser_specific_settings: {
            gecko: { id: 'argus@metril.github.io', strict_min_version: '140.0', data_collection_permissions: { required: ['none'] } },
          },
        }
      : {}),
  }),
});
