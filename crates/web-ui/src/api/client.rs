//! HTTP client wrapper for API calls

use std::cell::Cell;

use gloo_net::http::Request;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use web_sys::RequestCredentials;

use crate::utils::api_base_url;

/// API error types
#[derive(Debug, Error, Clone)]
pub enum ApiError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Authentication required")]
    Unauthorized,

    #[error("Access denied: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Rate limited - please try again later")]
    RateLimited,

    #[error("Server error: {0}")]
    Server(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

/// HTTP method for the internal request helper.
#[derive(Clone, Copy)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

// Single-flight refresh coordination.
//
// The browser runs a single-threaded cooperative executor, so a synchronous
// check-and-set on these cells (no `.await` in between) is effectively atomic:
// exactly one in-flight `/api/auth/refresh` happens even when several requests
// 401 at the same moment. This matters because the server *rotates* refresh
// tokens (it revokes the old `jti` on every refresh), so two parallel refreshes
// would revoke each other and force a spurious logout.
thread_local! {
    static REFRESH_IN_FLIGHT: Cell<bool> = const { Cell::new(false) };
    static REFRESH_OK: Cell<bool> = const { Cell::new(false) };
}

/// API client for making authenticated requests
#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiClient {
    /// Create a new API client
    pub fn new() -> Self {
        Self {
            base_url: api_base_url(),
        }
    }

    /// Create a client with a custom base URL
    pub fn with_base_url(base_url: String) -> Self {
        Self { base_url }
    }

    /// Build a full URL from a path
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Make a GET request
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.request(HttpMethod::Get, path, None).await
    }

    /// Make a POST request with JSON body
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Parse(e.to_string()))?;
        self.request(HttpMethod::Post, path, Some(json)).await
    }

    /// Make a PUT request with JSON body
    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Parse(e.to_string()))?;
        self.request(HttpMethod::Put, path, Some(json)).await
    }

    /// Make a DELETE request
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.request(HttpMethod::Delete, path, None).await
    }

    /// Send a request, transparently refreshing the access token and retrying
    /// once on a `401`.
    ///
    /// The access token is short-lived; the refresh token lives for days. Rather
    /// than bouncing the user to the login page the instant the access token
    /// expires, a `401` triggers a single (coordinated) call to
    /// `/api/auth/refresh` and a replay of the original request. Only a *failed*
    /// refresh — i.e. the refresh token is genuinely dead — surfaces as
    /// `Unauthorized`.
    async fn request<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
    ) -> Result<T, ApiError> {
        let response = self.send_once(method, path, body.as_deref()).await?;

        if response.status() == 401 && !is_no_retry(path) {
            // Access token likely expired — refresh once and replay.
            self.ensure_refreshed().await?;
            let retried = self.send_once(method, path, body.as_deref()).await?;
            return self.handle_response(retried).await;
        }

        self.handle_response(response).await
    }

    /// Build and send a single request attempt.
    async fn send_once(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
    ) -> Result<gloo_net::http::Response, ApiError> {
        let url = self.url(path);
        let builder = match method {
            HttpMethod::Get => Request::get(&url),
            HttpMethod::Post => Request::post(&url),
            HttpMethod::Put => Request::put(&url),
            HttpMethod::Delete => Request::delete(&url),
        }
        .credentials(RequestCredentials::Include);

        let result = match body {
            Some(b) => {
                builder
                    .header("Content-Type", "application/json")
                    .body(b.to_string())
                    .map_err(|e| ApiError::Parse(e.to_string()))?
                    .send()
                    .await
            }
            None => builder.send().await,
        };

        result.map_err(|e| ApiError::Network(e.to_string()))
    }

    /// Ensure the access token has been refreshed, coordinating so that
    /// concurrent callers share a single `/api/auth/refresh` call.
    async fn ensure_refreshed(&self) -> Result<(), ApiError> {
        // A refresh is already running — wait for it instead of starting another
        // (parallel refreshes would revoke each other's rotated token).
        if REFRESH_IN_FLIGHT.with(Cell::get) {
            // Bounded wait (~6s) so a wedged refresh can't hang requests forever.
            for _ in 0..400 {
                gloo_timers::future::TimeoutFuture::new(15).await;
                if !REFRESH_IN_FLIGHT.with(Cell::get) {
                    break;
                }
            }
            return if REFRESH_OK.with(Cell::get) {
                Ok(())
            } else {
                Err(ApiError::Unauthorized)
            };
        }

        // We own the refresh. No `.await` between the check above and this set,
        // so on the single-threaded WASM executor this is race-free.
        REFRESH_IN_FLIGHT.with(|f| f.set(true));
        let result = self.do_refresh().await;
        REFRESH_OK.with(|c| c.set(result.is_ok()));
        REFRESH_IN_FLIGHT.with(|f| f.set(false));
        result
    }

    /// Perform the actual token refresh request.
    async fn do_refresh(&self) -> Result<(), ApiError> {
        let response = Request::post(&self.url("/api/auth/refresh"))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;

        if (200..300).contains(&response.status()) {
            Ok(())
        } else {
            Err(ApiError::Unauthorized)
        }
    }

    /// Handle the response, mapping status codes to errors
    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: gloo_net::http::Response,
    ) -> Result<T, ApiError> {
        let status = response.status();

        match status {
            200..=299 => response
                .json::<T>()
                .await
                .map_err(|e| ApiError::Parse(e.to_string())),
            400 => {
                let text = response.text().await.unwrap_or_default();
                Err(ApiError::Validation(text))
            }
            401 => Err(ApiError::Unauthorized),
            403 => {
                let text = response.text().await.unwrap_or_default();
                Err(ApiError::Forbidden(text))
            }
            404 => {
                let text = response.text().await.unwrap_or_default();
                Err(ApiError::NotFound(text))
            }
            422 => {
                let text = response.text().await.unwrap_or_default();
                Err(ApiError::Validation(text))
            }
            429 => Err(ApiError::RateLimited),
            500..=599 => {
                let text = response.text().await.unwrap_or_default();
                Err(ApiError::Server(text))
            }
            _ => {
                let text = response.text().await.unwrap_or_default();
                Err(ApiError::Network(format!(
                    "Unexpected status {}: {}",
                    status, text
                )))
            }
        }
    }
}

/// Endpoints that must not trigger a refresh-and-retry: the refresh call itself
/// (would recurse) and the credential endpoints (a `401` there is a real
/// authentication failure, not an expired access token).
fn is_no_retry(path: &str) -> bool {
    path.starts_with("/api/auth/refresh")
        || path.starts_with("/api/auth/login")
        || path.starts_with("/api/auth/register")
        || path.starts_with("/api/auth/logout")
}
