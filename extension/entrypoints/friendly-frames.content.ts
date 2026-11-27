import { runInFrame } from '../lib/friendly-frames';

// Registered at runtime (see `FriendlyFrames`) while the extension is connected to Argus, not in
// the manifest: it only does anything for pages Argus injected into.
export default defineContentScript({
  registration: 'runtime',
  matches: ['<all_urls>'],
  allFrames: true,
  matchOriginAsFallback: true,
  runAt: 'document_start',
  world: 'MAIN',
  main() {
    runInFrame();
  },
});
