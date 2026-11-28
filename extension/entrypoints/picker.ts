import { startPicker } from '../lib/pickerui';
import { registrableDomain } from '../lib/stats';

// Injected on demand by the background (activeTab). Holds no token: it only sends the chosen rule back.
export default defineUnlistedScript(() => {
  const g = globalThis as { __argusPicker?: boolean };
  if (g.__argusPicker) return;
  g.__argusPicker = true;
  startPicker({
    mode: 'picker',
    site: registrableDomain(location.hostname),
    send: (m) => browser.runtime.sendMessage(m) as Promise<never>,
    onDone: () => { g.__argusPicker = false; },
  });
});
