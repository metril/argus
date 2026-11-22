//! In-page panel settings of one profile, and the panel PIN.
//!
//! The panel is read-only in the page; changes are confirmed on a proxy-owned origin. How the
//! confirmation is authenticated is [`PanelAuth`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How the confirmation page authenticates a change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PanelAuth {
    /// No writes from the panel; it links to the dashboard, where the logged-in session decides.
    Session,
    /// A per-profile PIN, entered on the confirmation page (default).
    #[default]
    Pin,
    /// A click on the confirmation page is enough. Only for a trusted LAN.
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PanelSettings {
    pub enabled: bool,
    /// `Alt+Shift+A`-style chord: modifiers `Ctrl`, `Alt`, `Shift`, `Meta` and one key.
    pub hotkey: String,
    pub auth: PanelAuth,
    /// `salt$hex(sha256(salt || pin))`; never exposed by the API.
    pub pin_hash: Option<String>,
}

pub const DEFAULT_HOTKEY: &str = "Alt+Shift+A";

impl Default for PanelSettings {
    fn default() -> Self {
        PanelSettings {
            enabled: true,
            hotkey: DEFAULT_HOTKEY.into(),
            auth: PanelAuth::Pin,
            pin_hash: None,
        }
    }
}

/// A chord is valid when it has at least one of Alt/Ctrl/Meta, and exactly one non-modifier key
/// (a single letter, digit or a named key such as `F2`).
pub fn valid_hotkey(h: &str) -> bool {
    let parts: Vec<&str> = h.split('+').collect();
    if parts.len() < 2 || parts.len() > 4 {
        return false;
    }
    let (key, mods) = parts.split_last().expect("non-empty");
    let mut seen = [false; 4];
    for m in mods {
        let i = match *m {
            "Ctrl" => 0,
            "Alt" => 1,
            "Shift" => 2,
            "Meta" => 3,
            _ => return false,
        };
        if std::mem::replace(&mut seen[i], true) {
            return false;
        }
    }
    if !(seen[0] || seen[1] || seen[3]) {
        return false;
    }
    let k = key.as_bytes();
    (k.len() == 1 && k[0].is_ascii_alphanumeric())
        || (key.len() <= 3
            && key.starts_with('F')
            && key[1..].parse::<u8>().is_ok_and(|n| (1..=24).contains(&n)))
}

fn hash_with(salt: &str, pin: &str) -> String {
    let d = Sha256::digest(format!("{salt}\0{pin}").as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hash a PIN (4 to 64 visible characters) with a fresh salt.
pub fn hash_pin(pin: &str, salt: &str) -> Result<String, &'static str> {
    if !(4..=64).contains(&pin.chars().count()) || pin.chars().any(char::is_control) {
        return Err("PIN must be 4 to 64 printable characters");
    }
    Ok(format!("{salt}${}", hash_with(salt, pin)))
}

/// Constant-time PIN check.
pub fn verify_pin(stored: &str, pin: &str) -> bool {
    let Some((salt, want)) = stored.split_once('$') else {
        return false;
    };
    let got = hash_with(salt, pin);
    got.len() == want.len()
        && got
            .bytes()
            .zip(want.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotkeys() {
        for ok in ["Alt+Shift+A", "Ctrl+Alt+P", "Alt+F2", "Meta+Shift+9"] {
            assert!(valid_hotkey(ok), "{ok}");
        }
        for bad in [
            "A",
            "Shift+A",
            "Alt+Alt+A",
            "Alt+",
            "Alt+AB",
            "Alt+Shift",
            "Hyper+A",
        ] {
            assert!(!valid_hotkey(bad), "{bad}");
        }
    }

    #[test]
    fn pin_roundtrip() {
        let h = hash_pin("1234", "salty").unwrap();
        assert!(verify_pin(&h, "1234") && !verify_pin(&h, "1235") && !verify_pin("x", "1234"));
        assert!(hash_pin("123", "s").is_err());
    }
}
