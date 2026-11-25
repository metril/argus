import { signal } from '@preact/signals';
import { getSettings, type Settings } from '../lib/api';

/** Stored sign-in; null until first read. Kept in sync with storage. */
export const settings = signal<Settings | null>(null);

export async function refreshSettings() { settings.value = await getSettings(); }

export function watchSettings() {
  void refreshSettings();
  browser.storage.onChanged.addListener((c: Record<string, unknown>) => {
    if ('argusUrl' in c || 'token' in c || 'user' in c || 'since' in c) void refreshSettings();
  });
}

export const isSignedIn = (s: Settings | null) => !!(s && s.argusUrl && s.token);

export function hostLabel(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}
