//! CA private key encryption at rest
//!
//! Provides encryption and decryption for CA private keys using age encryption
//! with a passphrase.
//!
//! # Security Model
//!
//! - Private keys are encrypted with age passphrase encryption (scrypt-based)
//! - File permissions are set to 0600 on Unix systems
//!
//! # Usage
//!
//! ```ignore
//! // Encrypt a key
//! let encrypted = encrypt_ca_key(key_pem, "my-secure-passphrase")?;
//! std::fs::write("ca.key.enc", &encrypted)?;
//!
//! // Decrypt a key
//! let key_pem = decrypt_ca_key(&encrypted, "my-secure-passphrase")?;
//! ```

use crate::{Error, Result};
use secrecy::SecretString;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use tracing::info;

/// Minimum passphrase length
pub const MIN_PASSPHRASE_LENGTH: usize = 16;

/// Magic bytes to identify encrypted CA key files
const ENCRYPTED_KEY_MAGIC: &[u8] = b"ADBLOCKER_CA_KEY_V1\n";

/// Configuration for CA key encryption
#[derive(Debug, Clone)]
pub struct CaEncryptionConfig {
    /// Minimum passphrase length
    pub min_passphrase_length: usize,
}

impl Default for CaEncryptionConfig {
    fn default() -> Self {
        Self {
            min_passphrase_length: MIN_PASSPHRASE_LENGTH,
        }
    }
}

/// Encrypt a CA private key with a passphrase
///
/// # Arguments
/// * `key_pem` - The private key in PEM format
/// * `passphrase` - The encryption passphrase (must be at least 16 characters)
///
/// # Returns
/// The encrypted key as bytes (can be written to a file)
pub fn encrypt_ca_key(key_pem: &str, passphrase: &str) -> Result<Vec<u8>> {
    encrypt_ca_key_with_config(key_pem, passphrase, &CaEncryptionConfig::default())
}

/// Encrypt a CA private key with a passphrase and custom configuration
pub fn encrypt_ca_key_with_config(
    key_pem: &str,
    passphrase: &str,
    config: &CaEncryptionConfig,
) -> Result<Vec<u8>> {
    // Validate passphrase length
    if passphrase.len() < config.min_passphrase_length {
        return Err(Error::Certificate(format!(
            "Passphrase must be at least {} characters",
            config.min_passphrase_length
        )));
    }

    // Create age encryptor with passphrase
    let encryptor =
        age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()));

    // Encrypt the private key
    let mut encrypted = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| Error::Certificate(format!("Failed to wrap output: {}", e)))?;

        writer
            .write_all(key_pem.as_bytes())
            .map_err(|e| Error::Certificate(format!("Failed to encrypt key: {}", e)))?;

        writer
            .finish()
            .map_err(|e| Error::Certificate(format!("Failed to finish encryption: {}", e)))?;
    }

    // Create the output format: magic + encrypted data
    let mut output = Vec::new();
    output.extend_from_slice(ENCRYPTED_KEY_MAGIC);
    output.extend_from_slice(&encrypted);

    info!("CA private key encrypted successfully");

    Ok(output)
}

/// Decrypt a CA private key with a passphrase
///
/// # Arguments
/// * `encrypted_data` - The encrypted key data (as read from file)
/// * `passphrase` - The decryption passphrase
///
/// # Returns
/// The private key in PEM format
pub fn decrypt_ca_key(encrypted_data: &[u8], passphrase: &str) -> Result<String> {
    decrypt_ca_key_with_config(encrypted_data, passphrase, &CaEncryptionConfig::default())
}

/// Decrypt a CA private key with a passphrase and custom configuration
pub fn decrypt_ca_key_with_config(
    encrypted_data: &[u8],
    passphrase: &str,
    _config: &CaEncryptionConfig,
) -> Result<String> {
    // Check magic bytes
    if !encrypted_data.starts_with(ENCRYPTED_KEY_MAGIC) {
        return Err(Error::Certificate(
            "Invalid encrypted key format (missing magic bytes)".to_string(),
        ));
    }

    // Get the encrypted portion
    let encrypted = &encrypted_data[ENCRYPTED_KEY_MAGIC.len()..];

    // Create identity for decryption
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));

    // Decrypt
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| Error::Certificate(format!("Failed to create decryptor: {}", e)))?;

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| Error::Certificate(format!("Failed to decrypt: {}", e)))?;

    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| Error::Certificate(format!("Failed to read decrypted data: {}", e)))?;

    let key_pem = String::from_utf8(decrypted)
        .map_err(|_| Error::Certificate("Invalid UTF-8 in decrypted key".to_string()))?;

    info!("CA private key decrypted successfully");

    Ok(key_pem)
}

/// Check if a file contains an encrypted CA key
pub fn is_encrypted_key(data: &[u8]) -> bool {
    data.starts_with(ENCRYPTED_KEY_MAGIC)
}

/// Read and decrypt a CA key from a file
pub fn read_encrypted_key<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<String> {
    let data = fs::read(path.as_ref())
        .map_err(|e| Error::Certificate(format!("Failed to read encrypted key: {}", e)))?;

    decrypt_ca_key(&data, passphrase)
}

/// Encrypt and write a CA key to a file
pub fn write_encrypted_key<P: AsRef<Path>>(path: P, key_pem: &str, passphrase: &str) -> Result<()> {
    let path = path.as_ref();

    // Create parent directories
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Certificate(format!("Failed to create directory: {}", e)))?;
    }

    // Encrypt the key
    let encrypted = encrypt_ca_key(key_pem, passphrase)?;

    // Write to file
    fs::write(path, &encrypted)
        .map_err(|e| Error::Certificate(format!("Failed to write encrypted key: {}", e)))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| Error::Certificate(format!("Failed to get file metadata: {}", e)))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| Error::Certificate(format!("Failed to set permissions: {}", e)))?;
    }

    info!("Encrypted CA key written to {:?}", path);

    Ok(())
}

/// Validate a passphrase meets security requirements
pub fn validate_passphrase(passphrase: &str) -> std::result::Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        errors.push(format!(
            "Passphrase must be at least {} characters (got {})",
            MIN_PASSPHRASE_LENGTH,
            passphrase.len()
        ));
    }

    // Check for character variety
    let has_lowercase = passphrase.chars().any(|c| c.is_lowercase());
    let has_uppercase = passphrase.chars().any(|c| c.is_uppercase());
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

    let variety_count = [has_lowercase, has_uppercase, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if variety_count < 3 {
        errors.push(
            "Passphrase should contain at least 3 of: lowercase, uppercase, digits, special characters"
                .to_string(),
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY2N5YmVyIHNlY3Vy\naXR5IHRlc3Qga2V5IGhlcmUhIWhRANCAATy6x+3k7qb7rSWWyRYR7v8zR6+Fxv1B\ngKvLmXgqQqQr7k8wJWLDMwYwO+D7oXDkYLsSTg8O+D7oXDkYLsSTg8\n-----END PRIVATE KEY-----\n";
    const TEST_PASSPHRASE: &str = "TestP@ssw0rd!Secure";

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encrypted = encrypt_ca_key(TEST_KEY_PEM, TEST_PASSPHRASE).unwrap();

        assert!(is_encrypted_key(&encrypted));

        let decrypted = decrypt_ca_key(&encrypted, TEST_PASSPHRASE).unwrap();

        assert_eq!(decrypted, TEST_KEY_PEM);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let encrypted = encrypt_ca_key(TEST_KEY_PEM, TEST_PASSPHRASE).unwrap();

        let result = decrypt_ca_key(&encrypted, "WrongPassphrase!!");

        assert!(result.is_err());
    }

    #[test]
    fn test_short_passphrase_rejected() {
        let result = encrypt_ca_key(TEST_KEY_PEM, "short");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least"));
    }

    #[test]
    fn test_invalid_data_rejected() {
        let invalid_data = b"not encrypted data";

        let result = decrypt_ca_key(invalid_data, TEST_PASSPHRASE);

        assert!(result.is_err());
    }

    #[test]
    fn test_is_encrypted_key() {
        let encrypted = encrypt_ca_key(TEST_KEY_PEM, TEST_PASSPHRASE).unwrap();

        assert!(is_encrypted_key(&encrypted));
        assert!(!is_encrypted_key(b"not encrypted"));
        assert!(!is_encrypted_key(TEST_KEY_PEM.as_bytes()));
    }

    #[test]
    fn test_validate_passphrase() {
        // Good passphrase
        assert!(validate_passphrase("MySecure!P@ss123").is_ok());

        // Too short
        assert!(validate_passphrase("short").is_err());

        // Missing variety
        let result = validate_passphrase("alllowercaseletters");
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_config() {
        let config = CaEncryptionConfig {
            min_passphrase_length: 10,
        };

        let encrypted = encrypt_ca_key_with_config(TEST_KEY_PEM, "ShortPass!", &config).unwrap();
        let decrypted = decrypt_ca_key_with_config(&encrypted, "ShortPass!", &config).unwrap();

        assert_eq!(decrypted, TEST_KEY_PEM);
    }
}
