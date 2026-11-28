/** The tab the user armed the element picker or zapper on; only that tab's script may ask to save. */
export const ARM_TTL_MS = 5 * 60_000;
export type PickerMode = 'picker' | 'zapper';

interface Area { get(k: string): Promise<Record<string, unknown>>; set(o: Record<string, unknown>): Promise<void>; remove(k: string): Promise<void> }
interface Armed { tabId: number; mode: PickerMode; expires: number }
const KEY = 'pickerArm';

export class Arming {
  constructor(private area: Area) {}
  async arm(tabId: number, mode: PickerMode, now = Date.now()): Promise<void> {
    await this.area.set({ [KEY]: { tabId, mode, expires: now + ARM_TTL_MS } satisfies Armed });
  }
  async disarm(tabId?: number): Promise<void> {
    const a = await this.get();
    if (a && (tabId === undefined || a.tabId === tabId)) await this.area.remove(KEY);
  }
  private async get(): Promise<Armed | undefined> {
    const a = (await this.area.get(KEY))[KEY] as Armed | undefined;
    return a && typeof a.tabId === 'number' ? a : undefined;
  }
  /** Is `sender` this extension's own script in the armed tab (in `mode`, when given), before the arming expired? */
  async allows(sender: { id?: string; tab?: { id?: number } } | undefined, ownId: string, mode?: PickerMode, now = Date.now()): Promise<boolean> {
    if (!sender || sender.id !== ownId || sender.tab?.id === undefined) return false;
    const a = await this.get();
    if (!a || now >= a.expires) { if (a) await this.area.remove(KEY); return false; }
    return a.tabId === sender.tab.id && (mode === undefined || a.mode === mode);
  }
}
