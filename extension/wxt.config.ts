import { defineConfig } from 'wxt';

const icons = { 16: 'icon/16.png', 32: 'icon/32.png', 48: 'icon/48.png', 128: 'icon/128.png' };

// The manifest version comes from package.json; CI asserts it equals the Cargo workspace version.
export default defineConfig({
  manifestVersion: 3,
  manifest: ({ browser }) => ({
    name: 'Argus',
    description: 'Shows the real upstream certificate Argus saw for the current site.',
    author: 'metril',
    homepage_url: 'https://github.com/metril/argus',
    icons,
    action: { default_icon: icons },
    permissions: ['storage', 'tabs', ...(browser === 'firefox' ? ['webRequest', 'webRequestBlocking'] : [])],
    // Argus URL is user-entered: request its origin at runtime. Firefox needs <all_urls>
    // for webRequest observation of arbitrary sites.
    optional_host_permissions: ['http://*/*', 'https://*/*'],
    ...(browser === 'firefox'
      ? {
          host_permissions: ['<all_urls>'],
          // 140 is the first release that honours data_collection_permissions.
          browser_specific_settings: {
            gecko: { id: 'argus@metril.github.io', strict_min_version: '140.0', data_collection_permissions: { required: ['none'] } },
          },
        }
      : {}),
  }),
});
