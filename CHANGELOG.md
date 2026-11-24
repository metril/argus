# Changelog

## Unreleased

* Extension bridge: the Argus extension can connect to the proxy (`GET /api/v1/ext/channel`, token
  scope `userscripts:bridge`). A random per-connection secret in the `X-Argus-Ext` request header
  (set by the extension on hosts where userscripts can run, never on passthrough hosts, always
  stripped by the proxy) binds a document to that browser. No client address is used.
* Userscript menu commands are listed and triggered from the extension popup; for pages opened in
  that browser the in-page button is not mounted, and it comes back when the extension is not
  serving the page. A freshly shown or re-attached badge ignores clicks for 300 ms.
* Scripts approved for browser logins (`browser_cookies`, granted only during review, off by
  default) send non-anonymous `GM_xmlhttpRequest` and `GM_cookie` through the extension, with the
  browser's real cookies (never HttpOnly ones). Every hop is checked against the script's `@connect`
  by the proxy; requests and approvals are audited. Without the extension the script's own cookie
  jar is used and its page shows "browser logins unavailable".
