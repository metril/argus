/** Reacts to storage changes: new sign-in reconnects, grants update the proxy's view, proxy settings reload. */
export function onStorageChanged(
  changes: Record<string, unknown>,
  d: { clearCache(): void; bridge: { reconnect(): Promise<void>; sendPerms(): Promise<void> }; proxy: { reload(): Promise<void> | void } },
) {
  if ('argusUrl' in changes || 'token' in changes) { d.clearCache(); void d.bridge.reconnect(); }
  if ('argusProxy' in changes) void d.proxy.reload();
  // Script-login consent lives in storage (browser permissions are all-sites), so tell the proxy.
  if ('granted' in changes) void d.bridge.sendPerms();
}
