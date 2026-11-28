/**
 * Adapts a handler that answers with a promise (or nothing) to the form every browser supports:
 * `sendResponse` plus `return true`. Chrome before 144 ignores a promise returned from an
 * `onMessage` listener (the sender then gets `undefined`), Firefox takes either.
 */
export function respondAsync<M, S>(handle: (msg: M, sender: S) => Promise<unknown> | undefined) {
  return (msg: M, sender: S, sendResponse: (r?: unknown) => void): boolean | undefined => {
    const r = handle(msg, sender);
    if (r === undefined) return undefined;
    r.then((v) => sendResponse(v), () => sendResponse(undefined));
    return true;
  };
}

/**
 * Whether a message or port comes from one of this extension's own pages (popup, options, logger):
 * a content script of another page shares the extension id, so the sender URL must be ours too.
 */
export function fromExtensionPage(sender: { id?: string; url?: string } | undefined, ownId: string, base: string): boolean {
  return !!sender && sender.id === ownId && typeof sender.url === 'string' && sender.url.startsWith(base);
}
