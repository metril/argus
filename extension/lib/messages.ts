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
