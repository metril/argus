import { useEffect, useMemo, useState } from 'preact/hooks';
import { siteOf } from '../../lib/cookiejar/model';
import { ActivityTab } from './ActivityTab';
import { ClientCtx, realClient, useClient, type CookieClient } from './client';
import { CookiesTab, type Scope } from './CookiesTab';
import { Icon } from '../icons';
import { useProvenance } from './data';
import { Pill, Tabs, ToastHost } from './kit';
import { noFilters, tabFromHash, type Filters } from './model';
import { RulesTab } from './RulesTab';
import { SnapshotsTab } from './SnapshotsTab';

export type CmTab = 'cookies' | 'snaps' | 'log' | 'rules';
const TABS: { v: CmTab; l: string }[] = [{ v: 'cookies', l: 'Cookies' }, { v: 'snaps', l: 'Snapshots' }, { v: 'log', l: 'Activity' }, { v: 'rules', l: 'Rules' }];

/** The site of the tab that opened the page (`#tab=N`), or '' when there is none. */
function useSite(): string {
  const [site, setSite] = useState('');
  useEffect(() => {
    const id = tabFromHash();
    if (id === undefined) return;
    void (globalThis as any).browser.tabs.get(id).then((t: { url?: string }) => {
      try { const u = new URL(t.url ?? ''); if (/^https?:$/.test(u.protocol)) setSite(siteOf(u.hostname)); } catch { /* not a web page */ }
    }, () => {});
  }, []);
  return site;
}

/** After an extension update or reload this page can no longer reach the background. */
function StaleNotice() {
  const client = useClient();
  const [dead, setDead] = useState(false);
  useEffect(() => client.onDead(() => setDead(true)), [client]);
  if (!dead) return null;
  return (
    <div class="banner warn" role="alert" data-testid="stale-notice">
      <Icon n="warn" size={16} /><span class="bt">Argus was updated. Reload this page.</span>
      <span class="ba"><button type="button" class="btn" onClick={() => location.reload()}>Reload</button></span>
    </div>
  );
}

function Body({ initialTab }: { initialTab: CmTab }) {
  const site = useSite();
  const [tab, setTab] = useState<CmTab>(initialTab);
  const [scope, setScope] = useState<Scope | null>(null);
  const [filters, setFilters] = useState<Filters>(noFilters);
  const eff: Scope = scope ?? (site ? 'site' : 'all');
  const prov = useProvenance(eff === 'site' ? site : '');
  return (
    <div class="cm" data-testid="cookie-manager">
      <div class="cmh">
        <h1>Cookie manager</h1>
        {site && <Pill kind="acc">{site}</Pill>}
      </div>
      <StaleNotice />
      <Tabs label="Cookie manager" idPrefix="cm" tabs={TABS} value={tab} onChange={setTab} />
      <div class="cm-panel" id="cm-panel" role="tabpanel" aria-labelledby={`cm-tab-${tab}`}>
        {tab === 'cookies' && <CookiesTab site={site} scope={eff} onScope={setScope} filters={filters} onFilters={setFilters} prov={prov} />}
        {tab === 'snaps' && <SnapshotsTab site={site} />}
        {tab === 'log' && <ActivityTab prov={prov} />}
        {tab === 'rules' && <RulesTab site={site} />}
      </div>
      <ToastHost />
    </div>
  );
}

export function CookiesPage({ client, tab = 'cookies' }: { client?: CookieClient; tab?: CmTab }) {
  const c = useMemo(() => client ?? realClient(), [client]);
  useEffect(() => () => { if (!client) c.close(); }, [c, client]);
  return <ClientCtx.Provider value={c}><Body initialTab={tab} /></ClientCtx.Provider>;
}
