//! Password hashing utilities
//!
//! bcrypt password hashing; the cost factor comes only from configuration.

use crate::error::{ApiError, ApiResult};

/// Lowest cost bcrypt itself accepts; anything below is rejected.
pub const MIN_BCRYPT_COST: u32 = 4;
/// Highest cost bcrypt accepts.
pub const MAX_BCRYPT_COST: u32 = 31;
/// Default cost (config default).
pub const DEFAULT_BCRYPT_COST: u32 = 12;
/// Costs below this are accepted (tests) but logged as weak at startup.
pub const RECOMMENDED_MIN_BCRYPT_COST: u32 = 10;

/// Check a configured bcrypt cost. The cost always comes from config (never from the build
/// profile); values below [`RECOMMENDED_MIN_BCRYPT_COST`] are valid but only meant for tests.
pub fn validate_bcrypt_cost(cost: u32) -> ApiResult<()> {
    if !(MIN_BCRYPT_COST..=MAX_BCRYPT_COST).contains(&cost) {
        return Err(ApiError::ValidationError(format!(
            "auth.bcrypt_cost must be between {MIN_BCRYPT_COST} and {MAX_BCRYPT_COST}, got {cost}"
        )));
    }
    Ok(())
}

/// Hash a password using bcrypt
///
/// # Arguments
/// * `password` - Plain text password to hash
/// * `cost` - bcrypt cost factor from `auth.bcrypt_cost` (12 is the default, ~250ms)
///
/// # Security
/// - Automatically generates a random salt
/// - Output is a 60-character string containing algorithm, cost, salt, and hash
pub fn hash_password(password: &str, cost: u32) -> ApiResult<String> {
    validate_bcrypt_cost(cost)?;
    bcrypt::hash(password, cost).map_err(ApiError::from)
}

/// Verify a password against a bcrypt hash
///
/// # Arguments
/// * `password` - Plain text password to verify
/// * `hash` - bcrypt hash string to verify against
///
/// # Returns
/// * `ApiResult<bool>` - true if password matches, false otherwise
///
/// # Security
/// - Uses constant-time comparison to prevent timing attacks
/// - Extracts cost and salt from the hash string automatically
pub fn verify_password(password: &str, hash: &str) -> ApiResult<bool> {
    bcrypt::verify(password, hash).map_err(ApiError::from)
}

/// Validate password strength
///
/// # Requirements
/// - Minimum 8 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
/// - At least one special character
///
/// # Returns
/// * `ApiResult<()>` - Ok if valid, Err with validation message otherwise
pub fn validate_password_strength(password: &str) -> ApiResult<()> {
    if password.len() < 8 {
        return Err(ApiError::ValidationError(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    if password.len() > 128 {
        return Err(ApiError::ValidationError(
            "Password must be at most 128 characters".to_string(),
        ));
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_uppercase {
        return Err(ApiError::ValidationError(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    if !has_lowercase {
        return Err(ApiError::ValidationError(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    if !has_digit {
        return Err(ApiError::ValidationError(
            "Password must contain at least one digit".to_string(),
        ));
    }

    if !has_special {
        return Err(ApiError::ValidationError(
            "Password must contain at least one special character".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "SecureP@ssw0rd!";
        let hash = hash_password(password, 4).unwrap();

        // Hash should be 60 characters (bcrypt format), carrying the requested cost
        assert_eq!(hash.len(), 60);
        assert!(hash.starts_with("$2b$04$"));

        // Verify correct password
        assert!(verify_password(password, &hash).unwrap());

        // Reject incorrect password
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_password_strength_validation() {
        // Valid password
        assert!(validate_password_strength("SecureP@ss1").is_ok());

        // Too short
        assert!(validate_password_strength("Sh0rt!").is_err());

        // Missing uppercase
        assert!(validate_password_strength("lowercase1!").is_err());

        // Missing lowercase
        assert!(validate_password_strength("UPPERCASE1!").is_err());

        // Missing digit
        assert!(validate_password_strength("NoDigits!@").is_err());

        // Missing special character
        assert!(validate_password_strength("NoSpecial1A").is_err());
    }

    #[test]
    fn cost_is_validated_not_defaulted_by_build_profile() {
        assert!(hash_password("x", 3).is_err());
        assert!(hash_password("x", 32).is_err());
        assert!(validate_bcrypt_cost(DEFAULT_BCRYPT_COST).is_ok());
        assert!(validate_bcrypt_cost(MIN_BCRYPT_COST).is_ok());
    }
}
