//! Password hashing utilities
//!
//! Uses bcrypt with cost factor 12 for secure password hashing.

use crate::error::{ApiError, ApiResult};

/// bcrypt cost factor (12 is recommended for production)
const BCRYPT_COST: u32 = 12;

/// Hash a password using bcrypt
///
/// # Arguments
/// * `password` - Plain text password to hash
///
/// # Returns
/// * `ApiResult<String>` - bcrypt hash string
///
/// # Security
/// - Uses cost factor 12 (approximately 250ms on modern hardware)
/// - Automatically generates a random salt
/// - Output is a 60-character string containing algorithm, cost, salt, and hash
pub fn hash_password(password: &str) -> ApiResult<String> {
    bcrypt::hash(password, BCRYPT_COST).map_err(ApiError::from)
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
        let hash = hash_password(password).unwrap();

        // Hash should be 60 characters (bcrypt format)
        assert_eq!(hash.len(), 60);

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
}
