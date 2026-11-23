import { defineConfig } from 'wxt';

export default defineConfig({
  manifestVersion: 3,
  manifest: ({ browser }) => ({
    name: 'Argus',
    description: 'Shows the real upstream certificate Argus saw for the current site.',
    permissions: ['storage', 'tabs', ...(browser === 'firefox' ? ['webRequest', 'webRequestBlocking'] : [])],
    // Argus URL is user-entered: request its origin at runtime. Firefox needs <all_urls>
    // for webRequest observation of arbitrary sites.
    optional_host_permissions: ['http://*/*', 'https://*/*'],
    ...(browser === 'firefox'
      ? { host_permissions: ['<all_urls>'], browser_specific_settings: { gecko: { id: 'argus@argus.invalid', data_collection_permissions: { required: ['none'] } } } }
      : {}),
  }),
});
