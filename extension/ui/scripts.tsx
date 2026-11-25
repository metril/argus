import { useEffect, useState } from 'preact/hooks';
import type { MenuGrant } from '../lib/bridge-types';
import { recordGrant } from '../lib/grants';
import type { MenuState } from '../lib/menudata';
import { Banner, CommandList, GrantRow } from './components';

export function Scripts({ state, reload }: { state: MenuState; reload: () => void }) {
  const [miss, setMiss] = useState(false);
  const [grants, setGrants] = useState<MenuGrant[]>([]);
  // Grants arrive with the menu, after mount: follow the prop.
  useEffect(() => { setGrants(state.kind === 'ok' ? state.grants : []); setMiss(false); }, [state]);
  if (state.kind === 'none') return null;
  if (state.kind === 'offline') {
    return <Banner tone="warn" slim title="Offline" body="Commands unavailable." action="Reconnect" onAction={() => { void browser.runtime.sendMessage({ type: 'bridge-reconnect' }).finally(reload); }} />;
  }
  if (state.kind === 'note') return <div class="note">{state.text}</div>;
  if (!state.commands.length && !grants.length) return null;
  return (
    <section class="sec">
      <div class="lbl">Userscripts</div>
      <CommandList commands={state.commands} onTrigger={async (c) => {
        if (await state.call.trigger(c)) { if (c.autoClose !== false) window.close(); } else setMiss(true);
      }} />
      {miss && <div class="note" role="status">Not delivered. Reload the page.</div>}
      {grants.map((g) => (
        <GrantRow key={g.script + g.host} grant={g} onAllow={(x) => {
          void recordGrant(browser, x.patterns).then(() => setGrants((cur) => cur.filter((y) => y !== x)));
        }} />
      ))}
    </section>
  );
}
