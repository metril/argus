# Per-device profiles

A profile is a named filtering configuration. Devices are mapped to profiles; a device with no
mapping uses the built-in `default` profile.

## What a profile contains

- **Lists**: the filter lists enabled for it (any list in the catalogue, whether or not it is
  enabled globally). Profiles with the same set of lists share one compiled engine.
- **Rules**: custom rules text, compiled as a small overlay checked after the lists. An overlay
  exception beats a list block; an overlay block beats a list allow.
- **Userscripts and script policy**: stored under the profile's storage namespace (installed
  scripts, GM values and cookies, site and source rules, temporary grants, panel settings and PIN).
  The namespace is `default` for the default profile and `p<id>` for every other profile. It is
  derived from the profile id, never from its name, so renaming a profile only changes its label.

The `default` profile (id 0) is built in and cannot be edited, renamed or deleted. Its lists and
rules are the global list enablement and global custom rules.

## What is shared

- Statistics and the recent-blocked log are global; block events carry the profile id (restricted
  API tokens see only their own profiles' events, and no domain histogram).
- The adblock master switch is global: turning blocking off turns it off for every profile.
- Downloaded list contents. Lists enabled by any profile are downloaded and refreshed by the
  update schedule, even if they are not enabled globally.
- The global byte budget for GM requests. Concurrent GM request limits are per profile.

## How a device is identified

A device record holds addresses or prefixes and, optionally, a token. Resolution per connection:
a known token wins, then the most specific matching address or prefix, then `default`.

- **Explicit proxy mode**: the client sends the token as the proxy password
  (`Proxy-Authorization: Basic base64(any-user:abd_...)`). The token is read from the `CONNECT`
  request, or from the first request of a plain-HTTP proxy connection, and cannot change later on
  that connection.
- **Transparent mode**: no proxy credentials exist, so the device is identified by its source
  address.

Addresses and prefixes may nest across devices (a /32 inside another device's /24); the longest
match wins. Nesting is deliberate and available to unrestricted tokens and the owner only: a
profile-restricted API token may add an address only inside a range already assigned to its own
profiles' devices and never one overlapping another profile's devices, so it cannot capture
another device's traffic. An identical address on two devices is refused.

Source addresses on a LAN can be spoofed by another host; tokens are the stronger identity. Use
tokens where it matters.

`proxy.require_device_token = true` makes explicit-proxy connections without a known token fail
with `407`. It does not affect transparent mode. Revoking a token takes effect on open
connections at their next request.

## Rule limits

A profile's own rules support network, cosmetic and exception rules. Rules that rewrite pages or
responses (`$replace`, `$urltransform`, `#%#` scripts, snippets) are not applied from a profile's
rules; keep those in the global lists or rules.

## Per-site "ad blocking off" from the panel

The in-page panel writes the exception to the rules of the requesting device's profile only. For
the `default` profile it uses the global custom rules as before.

## Editing and rebuilding

Changes to profiles, devices or lists are compiled in the background and debounced. Profile edits
apply to open connections on their next request; device reassignment is picked up on the next
request too. If a rebuild fails (invalid rules, missing list), the profile keeps its previous
compiled state, or uses the default profile's engine if it was never built, and the error is
recorded in the build status.

## Deleting and renaming a profile

A profile that devices still use cannot be deleted. Deleting one removes everything under its
namespace: userscripts, GM values and cookies, script-policy rules, temporary grants, panel
settings, PIN and lockout state, and its script control. Profile ids are never reused (the store
keeps a high-water mark), so a profile created later, even with the same name, gets a new
namespace and starts empty.

Renaming a profile changes its label only. Its userscripts, GM values, policy and PIN state stay
where they are.

## Build status and device activity

The profile API reports the proxy's last build of each profile (`last_built`, and `last_error`
when the last attempt failed and the previous state is still serving). A device's `last_seen` is
the last time a connection resolved to it (second resolution). It is recorded in proxy memory at
connection resolve time, not per request, and is empty until the device connects after a proxy
start.
