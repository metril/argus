//! In-page panel settings of one profile, and the panel PIN.
//!
//! The panel is read-only in the page; changes are confirmed on a proxy-owned origin. How the
//! confirmation is authenticated is [`PanelAuth`].

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

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
    /// Argon2id PHC string; never exposed by the API.
    pub pin_hash: Option<String>,
}

pub const DEFAULT_HOTKEY: &str = "Alt+Shift+A";

impl Default for PanelSettings {
    fn default() -> Self {
        PanelSettings {
            enabled: false,
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

fn argon() -> Argon2<'static> {
    // 19 MiB, 2 passes, 1 lane (OWASP's minimum for Argon2id): about 50 ms here, and it runs only
    // for a control-plane action, off the async threads.
    let params = Params::new(19 * 1024, 2, 1, None).expect("static argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub const MIN_PIN_LEN: usize = 6;

/// Hash a PIN (6 to 64 visible characters) with Argon2id and a fresh random salt; the result is
/// a PHC string.
pub fn hash_pin(pin: &str) -> Result<String, &'static str> {
    if !(MIN_PIN_LEN..=64).contains(&pin.chars().count()) || pin.chars().any(char::is_control) {
        return Err("PIN must be 6 to 64 printable characters");
    }
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|_| "could not salt the PIN")?;
    argon()
        .hash_password(pin.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| "could not hash the PIN")
}

/// Is `stored` a PIN hash this version can verify? Anything else (the old single SHA-256 form)
/// is dead: the PIN has to be set again.
pub fn is_current_hash(stored: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|h| h.algorithm == argon2::ARGON2ID_IDENT)
}

/// PIN check (the comparison is constant-time inside the `argon2` crate). CPU- and memory-heavy:
/// call from `spawn_blocking`.
pub fn verify_pin(stored: &str, pin: &str) -> bool {
    PasswordHash::new(stored)
        .ok()
        .filter(|h| h.algorithm == argon2::ARGON2ID_IDENT)
        .is_some_and(|h| argon().verify_password(pin.as_bytes(), &h).is_ok())
}

/// Seconds to wait after `fails` consecutive failures: none for the first `free`, then `base`
/// doubling per further failure, capped at `max`.
pub fn backoff_secs(fails: u32, free: u32, base: u64, max: u64) -> u64 {
    if fails < free {
        return 0;
    }
    base.saturating_mul(1u64 << (fails - free).min(20)).min(max)
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
    fn pin_is_argon2id_min_six_and_legacy_hashes_are_dead() {
        let h = hash_pin("123456").unwrap();
        assert!(h.starts_with("$argon2id$"), "{h}");
        assert!(hash_pin("12345").is_err(), "minimum length is 6");
        // The old single SHA-256 format no longer verifies (the PIN must be set again).
        let legacy = format!("salty${}", {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"salty\x00123456")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        });
        assert!(!verify_pin(&legacy, "123456"));
    }

    #[test]
    fn pin_roundtrip() {
        let h = hash_pin("123456").unwrap();
        assert!(
            verify_pin(&h, "123456") && !verify_pin(&h, "123457") && !verify_pin("x", "123456")
        );
        assert!(hash_pin("123").is_err());
    }
}
