import { startPicker } from '../lib/pickerui';
import { registrableDomain } from '../lib/stats';

// Injected on demand by the background (activeTab). Holds no token: it only sends the chosen rule back.
export default defineUnlistedScript(() => {
  const g = globalThis as { __argusZapper?: boolean };
  if (g.__argusZapper) return;
  g.__argusZapper = true;
  startPicker({
    mode: 'zapper',
    site: registrableDomain(location.hostname),
    send: (m) => browser.runtime.sendMessage(m) as Promise<never>,
    onDone: () => { g.__argusZapper = false; },
  });
});
