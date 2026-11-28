import { defineConfig } from 'vite';

// Dev-only visual harness: serves dev/*.html with the real page and popup on fake browser data.
// Not part of the shipped build (wxt only builds entrypoints/).
export default defineConfig({
  root: __dirname,
  publicDir: '../public',
  esbuild: { jsx: 'automatic', jsxImportSource: 'preact' },
  server: { host: '127.0.0.1', port: 5199, strictPort: true, fs: { allow: ['..'] } },
});
