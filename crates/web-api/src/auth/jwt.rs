//! JWT token generation and validation
//!
//! Implements secure JWT handling with:
//! - Short-lived access tokens (15 minutes)
//! - Long-lived refresh tokens (7 days)
//! - Unique JTI for token revocation
//! - httpOnly cookie delivery

use crate::auth::models::{Claims, TokenType, UserRole};
use crate::error::{ApiError, ApiResult};
use crate::state::JwtConfig;
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

/// Token pair (access + refresh)
#[derive(Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    /// JTI of `refresh_token` (stored on the session for rotation).
    pub refresh_jti: String,
    pub access_expires_in: u64,
    pub refresh_expires_in: u64,
}

/// Generate an access token (short-lived, 15 minutes)
///
/// # Arguments
/// * `user_id` - User's UUID
/// * `username` - User's username
/// * `role` - User's role
/// * `config` - JWT configuration with secret
///
/// # Returns
/// * `ApiResult<String>` - Encoded JWT token
pub fn generate_access_token(
    user_id: &Uuid,
    username: &str,
    role: UserRole,
    sid: &Uuid,
    config: &JwtConfig,
) -> ApiResult<String> {
    let now = Utc::now().timestamp();
    let exp = now + config.access_token_expiry_secs as i64;

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role,
        iat: now,
        exp,
        jti: Uuid::new_v4().to_string(),
        sid: sid.to_string(),
        token_type: TokenType::Access,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )
    .map_err(ApiError::from)
}

/// Generate a refresh token (long-lived, 7 days)
///
/// # Arguments
/// * `user_id` - User's UUID
/// * `username` - User's username
/// * `role` - User's role
/// * `config` - JWT configuration with secret
///
/// # Returns
/// * `ApiResult<String>` - Encoded JWT token
pub fn generate_refresh_token(
    user_id: &Uuid,
    username: &str,
    role: UserRole,
    sid: &Uuid,
    config: &JwtConfig,
) -> ApiResult<String> {
    let now = Utc::now().timestamp();
    let exp = now + config.refresh_token_expiry_secs as i64;

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role,
        iat: now,
        exp,
        jti: Uuid::new_v4().to_string(),
        sid: sid.to_string(),
        token_type: TokenType::Refresh,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )
    .map_err(ApiError::from)
}

/// Generate both access and refresh tokens
///
/// # Arguments
/// * `user_id` - User's UUID
/// * `username` - User's username
/// * `role` - User's role
/// * `config` - JWT configuration with secret
///
/// # Returns
/// * `ApiResult<TokenPair>` - Both tokens with expiry information
pub fn generate_token_pair(
    user_id: &Uuid,
    username: &str,
    role: UserRole,
    sid: &Uuid,
    config: &JwtConfig,
) -> ApiResult<TokenPair> {
    let access_token = generate_access_token(user_id, username, role, sid, config)?;
    let refresh_token = generate_refresh_token(user_id, username, role, sid, config)?;
    let refresh_jti = validate_refresh_token(&refresh_token, config)?.jti;

    Ok(TokenPair {
        access_token,
        refresh_token,
        refresh_jti,
        access_expires_in: config.access_token_expiry_secs,
        refresh_expires_in: config.refresh_token_expiry_secs,
    })
}

/// Validate and decode a JWT token
///
/// # Arguments
/// * `token` - JWT token string
/// * `config` - JWT configuration with secret
///
/// # Returns
/// * `ApiResult<Claims>` - Decoded claims if valid
///
/// # Errors
/// - Expired tokens
/// - Invalid signatures
/// - Malformed tokens
pub fn validate_token(token: &str, config: &JwtConfig) -> ApiResult<Claims> {
    // Use default validation (validates exp, allows any issuer/audience)
    // Since we generate tokens without iss/aud claims, we don't validate them
    let validation = Validation::default();

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            ApiError::AuthenticationFailed("Token expired".to_string())
        }
        jsonwebtoken::errors::ErrorKind::InvalidToken => {
            ApiError::AuthenticationFailed("Invalid token".to_string())
        }
        jsonwebtoken::errors::ErrorKind::InvalidSignature => {
            ApiError::AuthenticationFailed("Invalid token signature".to_string())
        }
        _ => ApiError::AuthenticationFailed(format!("Token validation failed: {}", e)),
    })?;

    Ok(token_data.claims)
}

/// Validate specifically an access token (must be TokenType::Access)
pub fn validate_access_token(token: &str, config: &JwtConfig) -> ApiResult<Claims> {
    let claims = validate_token(token, config)?;

    if claims.token_type != TokenType::Access {
        return Err(ApiError::AuthenticationFailed(
            "Expected access token".to_string(),
        ));
    }

    Ok(claims)
}

/// Validate specifically a refresh token (must be TokenType::Refresh)
pub fn validate_refresh_token(token: &str, config: &JwtConfig) -> ApiResult<Claims> {
    let claims = validate_token(token, config)?;

    if claims.token_type != TokenType::Refresh {
        return Err(ApiError::AuthenticationFailed(
            "Expected refresh token".to_string(),
        ));
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JwtConfig {
        JwtConfig {
            secret: "test_secret_key_at_least_32_bytes_long".to_string(),
            access_token_expiry_secs: 900,
            refresh_token_expiry_secs: 604800,
            issuer: "test".to_string(),
            audience: "test".to_string(),
        }
    }

    #[test]
    fn test_generate_and_validate_access_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let token = generate_access_token(
            &user_id,
            "testuser",
            UserRole::User,
            &Uuid::new_v4(),
            &config,
        )
        .unwrap();

        let claims = validate_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.role, UserRole::User);
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_generate_and_validate_refresh_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let token = generate_refresh_token(
            &user_id,
            "testuser",
            UserRole::Admin,
            &Uuid::new_v4(),
            &config,
        )
        .unwrap();

        let claims = validate_refresh_token(&token, &config).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, TokenType::Refresh);
    }

    #[test]
    fn test_invalid_token() {
        let config = test_config();
        let result = validate_token("invalid.token.here", &config);
        assert!(result.is_err());
    }
}
