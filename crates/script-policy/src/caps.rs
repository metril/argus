//! Capabilities, capability sets and presets' capability profiles.

use serde::{Deserialize, Serialize};

/// One thing a page may be allowed or forbidden to do.
///
/// *Source-keyed* capabilities depend on where the thing comes from (a script from
/// `cdn.example.net`); *page-level* ones are a property of the document alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    // --- source-keyed ---
    /// External `<script src>` and module scripts.
    Script,
    /// `<object>`, `<embed>`, `<applet>` (plugins).
    Object,
    /// `<audio>`, `<video>`, `<track>`.
    Media,
    /// `<iframe>`, `<frame>`.
    Frame,
    /// Web fonts.
    Font,
    /// `fetch`, XHR, WebSocket, EventSource, `sendBeacon`.
    Connect,
    /// Hyperlink auditing (`<a ping>`); beacons are not distinguishable from `connect` in CSP.
    Ping,
    /// Dedicated, shared and service workers.
    Worker,
    /// External stylesheets.
    Style,
    /// Images.
    Image,
    /// `<form action>` targets.
    FormAction,
    // --- page-level ---
    /// Inline `<script>` blocks and event-handler attributes.
    InlineScript,
    /// `eval`, `new Function`, string timers.
    Eval,
    /// WebAssembly compilation.
    Wasm,
    /// `<style>` blocks and `style=""` attributes.
    InlineStyle,
    /// Reveal `<noscript>` content when the page's own scripts are blocked.
    Noscript,
    /// Permissions-Policy: `camera`.
    Camera,
    /// Permissions-Policy: `microphone`.
    Microphone,
    /// Permissions-Policy: `geolocation`.
    Geolocation,
    /// Permissions-Policy: `payment`.
    Payment,
    /// Permissions-Policy: `usb`.
    Usb,
    /// Permissions-Policy: `display-capture`.
    DisplayCapture,
}

impl Capability {
    pub const ALL: [Capability; 22] = [
        Capability::Script,
        Capability::Object,
        Capability::Media,
        Capability::Frame,
        Capability::Font,
        Capability::Connect,
        Capability::Ping,
        Capability::Worker,
        Capability::Style,
        Capability::Image,
        Capability::FormAction,
        Capability::InlineScript,
        Capability::Eval,
        Capability::Wasm,
        Capability::InlineStyle,
        Capability::Noscript,
        Capability::Camera,
        Capability::Microphone,
        Capability::Geolocation,
        Capability::Payment,
        Capability::Usb,
        Capability::DisplayCapture,
    ];

    const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// Kebab-case name (the serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Script => "script",
            Capability::Object => "object",
            Capability::Media => "media",
            Capability::Frame => "frame",
            Capability::Font => "font",
            Capability::Connect => "connect",
            Capability::Ping => "ping",
            Capability::Worker => "worker",
            Capability::Style => "style",
            Capability::Image => "image",
            Capability::FormAction => "form-action",
            Capability::InlineScript => "inline-script",
            Capability::Eval => "eval",
            Capability::Wasm => "wasm",
            Capability::InlineStyle => "inline-style",
            Capability::Noscript => "noscript",
            Capability::Camera => "camera",
            Capability::Microphone => "microphone",
            Capability::Geolocation => "geolocation",
            Capability::Payment => "payment",
            Capability::Usb => "usb",
            Capability::DisplayCapture => "display-capture",
        }
    }

    pub fn parse(s: &str) -> Option<Capability> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// True when the capability depends on the source (host) of the thing.
    pub fn is_source_keyed(self) -> bool {
        CapSet::SOURCE_KEYED.contains(self)
    }

    /// The Permissions-Policy feature name, for the browser-feature capabilities.
    pub fn permissions_feature(self) -> Option<&'static str> {
        match self {
            Capability::Camera
            | Capability::Microphone
            | Capability::Geolocation
            | Capability::Payment
            | Capability::Usb
            | Capability::DisplayCapture => Some(self.as_str()),
            _ => None,
        }
    }
}

/// A set of capabilities (bitset).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct CapSet(u32);

impl std::fmt::Debug for CapSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl CapSet {
    pub const EMPTY: CapSet = CapSet(0);
    pub const ALL: CapSet = CapSet((1 << Capability::ALL.len() as u32) - 1);
    /// The first eleven capabilities in [`Capability::ALL`].
    pub const SOURCE_KEYED: CapSet = CapSet((1 << 11) - 1);
    pub const PAGE_LEVEL: CapSet = CapSet(Self::ALL.0 & !Self::SOURCE_KEYED.0);

    pub const fn of_const(caps: &[Capability]) -> CapSet {
        let mut i = 0;
        let mut b = 0;
        while i < caps.len() {
            b |= caps[i].bit();
            i += 1;
        }
        CapSet(b)
    }
    pub fn of(caps: &[Capability]) -> CapSet {
        caps.iter().fold(CapSet::EMPTY, |s, c| s.with(*c))
    }
    pub fn contains(self, c: Capability) -> bool {
        self.0 & c.bit() != 0
    }
    pub fn with(self, c: Capability) -> CapSet {
        CapSet(self.0 | c.bit())
    }
    pub fn without(self, c: Capability) -> CapSet {
        CapSet(self.0 & !c.bit())
    }
    pub fn union(self, o: CapSet) -> CapSet {
        CapSet(self.0 | o.0)
    }
    pub fn intersect(self, o: CapSet) -> CapSet {
        CapSet(self.0 & o.0)
    }
    pub fn minus(self, o: CapSet) -> CapSet {
        CapSet(self.0 & !o.0)
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }
}

impl Serialize for CapSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.iter())
    }
}
impl<'de> Deserialize<'de> for CapSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(CapSet::of(&Vec::<Capability>::deserialize(d)?))
    }
}

/// What a preset allows: page-level capabilities, and source-keyed capabilities split by
/// whether the source is first party (same registrable domain as the page) or third party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Profile {
    /// Allowed page-level capabilities (inline script, eval, ...).
    pub page: CapSet,
    /// Allowed source-keyed capabilities for first-party sources.
    pub first_party: CapSet,
    /// Allowed source-keyed capabilities for third-party sources.
    pub third_party: CapSet,
}

impl Profile {
    /// Everything allowed.
    pub const TRUSTED: Profile = Profile {
        page: CapSet::PAGE_LEVEL,
        first_party: CapSet::SOURCE_KEYED,
        third_party: CapSet::SOURCE_KEYED,
    };

    /// No script-like capability; passive content (images, styles, fonts, media, form posts)
    /// still works so the page renders.
    pub const UNTRUSTED: Profile = {
        let passive = CapSet(
            Self::bit_of(Capability::Media)
                | Self::bit_of(Capability::Font)
                | Self::bit_of(Capability::Style)
                | Self::bit_of(Capability::Image)
                | Self::bit_of(Capability::FormAction),
        );
        Profile {
            page: CapSet(
                Self::bit_of(Capability::InlineStyle) | Self::bit_of(Capability::Noscript),
            ),
            first_party: CapSet(passive.0 | Self::bit_of(Capability::Frame)),
            third_party: passive,
        }
    };

    /// Shipped default: first-party everything; third-party scripts, plugins, workers and pings
    /// blocked. Page-level capabilities stay allowed (blocking a site's own inline script breaks
    /// most pages and is what `Untrusted` is for).
    pub const SHIPPED_DEFAULT: Profile = Profile {
        page: CapSet::PAGE_LEVEL,
        first_party: CapSet::SOURCE_KEYED,
        third_party: CapSet(
            CapSet::SOURCE_KEYED.0
                & !(Self::bit_of(Capability::Script)
                    | Self::bit_of(Capability::Object)
                    | Self::bit_of(Capability::Worker)
                    | Self::bit_of(Capability::Ping)),
        ),
    };

    const fn bit_of(c: Capability) -> u32 {
        // Keep in sync with `Capability::ALL` order (checked by a unit test).
        1 << (c as u32)
    }

    /// Source-keyed capability check against the baseline (no source rules).
    pub fn allows_source(&self, cap: Capability, first_party: bool) -> bool {
        if first_party {
            self.first_party.contains(cap)
        } else {
            self.third_party.contains(cap)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_order_matches_all_and_bits() {
        for (i, c) in Capability::ALL.iter().enumerate() {
            assert_eq!(*c as usize, i);
            assert_eq!(c.bit(), 1 << i);
        }
        assert!(Capability::Frame.is_source_keyed());
        assert!(!Capability::Eval.is_source_keyed());
        assert_eq!(CapSet::PAGE_LEVEL.iter().count(), 11);
    }

    #[test]
    fn serde_round_trip() {
        let s = CapSet::of(&[Capability::Script, Capability::FormAction]);
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"["script","form-action"]"#);
        assert_eq!(serde_json::from_str::<CapSet>(&j).unwrap(), s);
    }
}
