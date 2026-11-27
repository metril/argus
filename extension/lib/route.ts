/**
 * Per-tab routing: did this tab's main document actually pass through Argus?
 * The signal is the `x-argus` response header the proxy adds to every response it relays;
 * it is observed with webRequest, so it is true for this tab's load, not a lookup by host.
 */
export type Route = 'argus' | 'system' | 'direct' | 'unknown';
export const ROUTE_HEADER = 'x-argus';

/** `argus`: the extension routes it; `system`: intercepted while the extension is off (OS proxy). */
export function routeOf(seen: boolean | undefined, enabled: boolean): Route {
  if (seen === undefined) return 'unknown';
  if (!seen) return 'direct';
  return enabled ? 'argus' : 'system';
}

export function hasRouteHeader(headers: { name: string }[] | undefined): boolean {
  return !!headers?.some((h) => h.name.toLowerCase() === ROUTE_HEADER);
}

export class RouteTracker {
  private seen = new Map<number, boolean>();
  record(tabId: number, headers: { name: string }[] | undefined) { if (tabId >= 0) this.seen.set(tabId, hasRouteHeader(headers)); }
  forget(tabId: number) { this.seen.delete(tabId); }
  /** The toggle changed: what was observed under the old routing no longer holds. */
  reset() { this.seen.clear(); }
  route(tabId: number, enabled: boolean): Route { return routeOf(this.seen.get(tabId), enabled); }
}
