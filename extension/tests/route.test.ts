import { describe, expect, it } from 'vitest';
import { hasRouteHeader, RouteTracker, routeOf } from '../lib/route';

describe('routeOf', () => {
  it('maps the observation and the toggle to a route', () => {
    expect(routeOf(undefined, true)).toBe('unknown');
    expect(routeOf(undefined, false)).toBe('unknown');
    expect(routeOf(false, true)).toBe('direct');
    expect(routeOf(false, false)).toBe('direct');
    expect(routeOf(true, true)).toBe('argus');
    expect(routeOf(true, false)).toBe('system');
  });
});

describe('RouteTracker', () => {
  it('is per tab, header-driven, and reset when the toggle changes', () => {
    const t = new RouteTracker();
    t.record(1, [{ name: 'X-Argus' }]);
    t.record(2, [{ name: 'content-type' }]);
    expect(hasRouteHeader([{ name: 'x-argus' }])).toBe(true);
    expect(t.route(1, true)).toBe('argus');
    expect(t.route(1, false)).toBe('system');
    expect(t.route(2, true)).toBe('direct');
    expect(t.route(3, true)).toBe('unknown');
    t.record(-1, [{ name: 'x-argus' }]);
    expect(t.route(-1, true)).toBe('unknown');
    t.reset();
    expect(t.route(1, true)).toBe('unknown');
    t.record(1, undefined);
    t.forget(1);
    expect(t.route(1, true)).toBe('unknown');
  });
});
