//! Authentication state management

use leptos::prelude::*;

use crate::api::auth::UserInfo;
use crate::api::{ApiClient, ApiError};

/// Authentication state
#[derive(Clone)]
pub struct AuthState {
    /// Current user (None if not authenticated)
    pub user: RwSignal<Option<UserInfo>>,
    /// Loading state
    pub is_loading: RwSignal<bool>,
    /// Error message
    pub error: RwSignal<Option<String>>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthState {
    /// Create a new auth state
    pub fn new() -> Self {
        Self {
            user: RwSignal::new(None),
            is_loading: RwSignal::new(false),
            error: RwSignal::new(None),
        }
    }

    /// Check if user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.user.get().is_some()
    }

    /// Get the current user
    pub fn current_user(&self) -> Option<UserInfo> {
        self.user.get()
    }

    /// Check the current session
    pub async fn check_session(&self) {
        let client = ApiClient::new();
        self.is_loading.set(true);
        self.error.set(None);

        match client.me().await {
            Ok(user) => {
                self.user.set(Some(user));
            }
            Err(ApiError::Unauthorized) => {
                // Try to refresh the token
                match client.refresh().await {
                    Ok(_) => {
                        // Retry getting user info
                        if let Ok(user) = client.me().await {
                            self.user.set(Some(user));
                        }
                    }
                    Err(_) => {
                        self.user.set(None);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Session check failed: {}", e);
                self.user.set(None);
            }
        }

        self.is_loading.set(false);
    }

    /// Login with username and password
    pub async fn login(&self, username: &str, password: &str) -> Result<(), ApiError> {
        let client = ApiClient::new();
        self.is_loading.set(true);
        self.error.set(None);

        match client.login(username, password).await {
            Ok(response) => {
                self.user.set(Some(response.user));
                self.is_loading.set(false);
                Ok(())
            }
            Err(e) => {
                self.error.set(Some(e.to_string()));
                self.is_loading.set(false);
                Err(e)
            }
        }
    }

    /// Register a new user
    pub async fn register(&self, username: &str, password: &str) -> Result<(), ApiError> {
        let client = ApiClient::new();
        self.is_loading.set(true);
        self.error.set(None);

        match client.register(username, password).await {
            Ok(response) => {
                self.user.set(Some(response.user));
                self.is_loading.set(false);
                Ok(())
            }
            Err(e) => {
                self.error.set(Some(e.to_string()));
                self.is_loading.set(false);
                Err(e)
            }
        }
    }

    /// Logout the current user
    pub async fn logout(&self) {
        let client = ApiClient::new();
        self.is_loading.set(true);

        // Attempt to logout on server (ignore errors)
        let _ = client.logout().await;

        // Clear local state
        self.user.set(None);
        self.error.set(None);
        self.is_loading.set(false);
    }

    /// Clear any error message
    pub fn clear_error(&self) {
        self.error.set(None);
    }
}

/// Provide auth state context
pub fn provide_auth_state() -> AuthState {
    let state = AuthState::new();
    provide_context(state.clone());
    state
}

/// Use auth state from context
pub fn use_auth_state() -> AuthState {
    expect_context::<AuthState>()
}
