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

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limited - please try again later")]
    RateLimited,

    #[error("Server error: {0}")]
    Server(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

/// Versioned API prefix; every path passed to the client is relative to it.
pub const API_PREFIX: &str = "/api/v1";

/// Read a cookie from `document.cookie` (used for the CSRF token cookie, which is not HttpOnly).
fn read_cookie(name: &str) -> Option<String> {
    use wasm_bindgen::JsCast;
    let doc = web_sys::window()?.document()?;
    let cookies = doc
        .dyn_into::<web_sys::HtmlDocument>()
        .ok()?
        .cookie()
        .ok()?;
    let prefix = format!("{name}=");
    cookies
        .split(';')
        .find_map(|c| c.trim().strip_prefix(&prefix).map(str::to_string))
}

/// Turn a response body into a readable message: the `error.message` of the standard envelope
/// (with field details), or the raw text.
fn error_message(text: &str) -> String {
    match serde_json::from_str::<api_types::ErrorEnvelope>(text) {
        Ok(env) => {
            let mut msg = env.error.message;
            for d in env.error.details {
                msg.push_str(&format!("; {}: {}", d.field, d.message));
            }
            msg
        }
        Err(_) => text.to_string(),
    }
}

/// HTTP method for the internal request helper.
#[derive(Clone, Copy)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

// Single-flight refresh coordination.
//
// The browser runs a single-threaded cooperative executor, so a synchronous
// check-and-set on these cells (no `.await` in between) is effectively atomic:
// exactly one in-flight `/auth/refresh` happens even when several requests
// 401 at the same moment. This matters because the server *rotates* refresh
// tokens (it revokes the old `jti` on every refresh), so two parallel refreshes
// would revoke each other and force a spurious logout.
thread_local! {
    /// Profile the profile-scoped pages (script policy, userscripts) operate on; `"0"` is the
    /// default profile. Set by the profile selector.
    static CURRENT_PROFILE: std::cell::RefCell<String> = std::cell::RefCell::new("0".to_string());
}

/// Select the profile that profile-scoped calls (`/policy`, `/userscripts`,
/// `/rules/site-exceptions`) use from now on.
pub fn set_current_profile(id: &str) {
    CURRENT_PROFILE.with(|p| *p.borrow_mut() = id.to_string());
}

/// The selected profile id.
pub fn current_profile() -> String {
    CURRENT_PROFILE.with(|p| p.borrow().clone())
}

/// Append `profile=<id>` to a path that operates on one profile. Other paths and the default
/// profile (`0`) are left alone.
pub fn scope_to_profile(path: &str, profile: &str) -> String {
    let scoped = ["/userscripts", "/policy", "/rules/site-exceptions"]
        .iter()
        .any(|p| path.starts_with(p));
    if !scoped || profile == "0" || profile.is_empty() {
        return path.to_string();
    }
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}profile={profile}")
}

thread_local! {
    static REFRESH_IN_FLIGHT: Cell<bool> = const { Cell::new(false) };
    /// Outcome of the last refresh (`None` = succeeded), shared with waiting callers.
    static REFRESH_ERR: std::cell::RefCell<Option<ApiError>> = const { std::cell::RefCell::new(None) };
    /// `Date.now()` of the last failed refresh; a burst of requests that 401 right after
    /// reuses that verdict instead of each re-POSTing `/auth/refresh`.
    static REFRESH_FAILED_AT: Cell<f64> = const { Cell::new(0.0) };
}

/// Forget a failed refresh (after a fresh login the cookies are valid again).
pub fn reset_refresh_cooldown() {
    REFRESH_FAILED_AT.with(|c| c.set(0.0));
}

/// How long a failed refresh is trusted, in ms.
const REFRESH_FAIL_TTL_MS: f64 = 5000.0;

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
        format!(
            "{}{}{}",
            self.base_url,
            API_PREFIX,
            scope_to_profile(path, &current_profile())
        )
    }

    /// Make a GET request
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        Ok(self.request(HttpMethod::Get, path, None, None).await?.0)
    }

    /// GET returning the response `ETag` as well (for `If-Match` on the next update).
    pub async fn get_etag<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<(T, Option<String>), ApiError> {
        self.request(HttpMethod::Get, path, None, None).await
    }

    /// PUT with `If-Match`; returns the new `ETag`.
    pub async fn put_if_match<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        etag: &str,
    ) -> Result<(T, Option<String>), ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Parse(e.to_string()))?;
        self.request(HttpMethod::Put, path, Some(json), Some(etag))
            .await
    }

    /// Make a PATCH request with JSON body
    pub async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Parse(e.to_string()))?;
        Ok(self
            .request(HttpMethod::Patch, path, Some(json), None)
            .await?
            .0)
    }

    /// Make a POST request with JSON body
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Parse(e.to_string()))?;
        Ok(self
            .request(HttpMethod::Post, path, Some(json), None)
            .await?
            .0)
    }

    /// Make a PUT request with JSON body
    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Parse(e.to_string()))?;
        Ok(self
            .request(HttpMethod::Put, path, Some(json), None)
            .await?
            .0)
    }

    /// Make a DELETE request
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        Ok(self.request(HttpMethod::Delete, path, None, None).await?.0)
    }

    /// Send a request, transparently refreshing the access token and retrying
    /// once on a `401`.
    ///
    /// The access token is short-lived; the refresh token lives for days. Rather
    /// than bouncing the user to the login page the instant the access token
    /// expires, a `401` triggers a single (coordinated) call to
    /// `/auth/refresh` and a replay of the original request. Only a *failed*
    /// refresh — i.e. the refresh token is genuinely dead — surfaces as
    /// `Unauthorized`.
    async fn request<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
        if_match: Option<&str>,
    ) -> Result<(T, Option<String>), ApiError> {
        let response = self
            .send_once(method, path, body.as_deref(), if_match)
            .await?;

        if response.status() == 401 && !is_no_retry(path) {
            // Access token likely expired — refresh once and replay.
            self.ensure_refreshed().await?;
            let retried = self
                .send_once(method, path, body.as_deref(), if_match)
                .await?;
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
        if_match: Option<&str>,
    ) -> Result<gloo_net::http::Response, ApiError> {
        let url = self.url(path);
        let builder = match method {
            HttpMethod::Get => Request::get(&url),
            HttpMethod::Post => Request::post(&url),
            HttpMethod::Put => Request::put(&url),
            HttpMethod::Patch => Request::patch(&url),
            HttpMethod::Delete => Request::delete(&url),
        }
        .credentials(RequestCredentials::Include);
        // Cookie-authenticated writes must echo the CSRF cookie in a header.
        let builder = match (method, read_cookie("csrf_token")) {
            (HttpMethod::Get, _) | (_, None) => builder,
            (_, Some(t)) => builder.header("X-CSRF-Token", &t),
        };
        let builder = match if_match {
            Some(etag) => builder.header("If-Match", etag),
            None => builder,
        };

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
    /// concurrent callers share a single `/auth/refresh` call.
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
            return match REFRESH_ERR.with(|e| e.borrow().clone()) {
                None => Ok(()),
                Some(e) => Err(e),
            };
        }

        if js_sys::Date::now() - REFRESH_FAILED_AT.with(Cell::get) < REFRESH_FAIL_TTL_MS {
            return Err(ApiError::Unauthorized);
        }

        // We own the refresh. No `.await` between the check above and this set,
        // so on the single-threaded WASM executor this is race-free.
        REFRESH_IN_FLIGHT.with(|f| f.set(true));
        let result = self.do_refresh().await;
        REFRESH_ERR.with(|e| *e.borrow_mut() = result.clone().err());
        // Only a real auth rejection is cached; outages must stay retryable.
        if matches!(result, Err(ApiError::Unauthorized)) {
            REFRESH_FAILED_AT.with(|c| c.set(js_sys::Date::now()));
        }
        REFRESH_IN_FLIGHT.with(|f| f.set(false));
        result
    }

    /// Perform the actual token refresh request.
    async fn do_refresh(&self) -> Result<(), ApiError> {
        let response = Request::post(&self.url("/auth/refresh"))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;

        match response.status() {
            200..=299 => Ok(()),
            401 | 403 => Err(ApiError::Unauthorized),
            s => Err(ApiError::Server(format!("refresh failed with status {s}"))),
        }
    }

    /// Handle the response, mapping status codes to errors
    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: gloo_net::http::Response,
    ) -> Result<(T, Option<String>), ApiError> {
        let status = response.status();
        let etag = response.headers().get("etag");

        match status {
            200..=299 => response
                .json::<T>()
                .await
                .map(|v| (v, etag))
                .map_err(|e| ApiError::Parse(e.to_string())),
            400 => {
                let text = error_message(&response.text().await.unwrap_or_default());
                Err(ApiError::Validation(text))
            }
            401 => Err(ApiError::Unauthorized),
            403 => {
                let text = error_message(&response.text().await.unwrap_or_default());
                Err(ApiError::Forbidden(text))
            }
            404 => {
                let text = error_message(&response.text().await.unwrap_or_default());
                Err(ApiError::NotFound(text))
            }
            422 => {
                let text = error_message(&response.text().await.unwrap_or_default());
                Err(ApiError::Validation(text))
            }
            409 | 412 | 428 => {
                let text = error_message(&response.text().await.unwrap_or_default());
                Err(ApiError::Conflict(text))
            }
            429 => Err(ApiError::RateLimited),
            500..=599 => {
                let text = error_message(&response.text().await.unwrap_or_default());
                Err(ApiError::Server(text))
            }
            _ => {
                let text = error_message(&response.text().await.unwrap_or_default());
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
    path.starts_with("/auth/refresh")
        || path.starts_with("/auth/login")
        || path.starts_with("/auth/register")
        || path.starts_with("/auth/logout")
}

#[cfg(test)]
mod profile_scope_tests {
    use super::scope_to_profile;

    #[test]
    fn only_profile_scoped_paths_get_the_parameter() {
        assert_eq!(
            scope_to_profile("/userscripts", "3"),
            "/userscripts?profile=3"
        );
        assert_eq!(
            scope_to_profile("/policy/site-rules?limit=200", "3"),
            "/policy/site-rules?limit=200&profile=3"
        );
        assert_eq!(
            scope_to_profile("/rules/site-exceptions/a.com", "3"),
            "/rules/site-exceptions/a.com?profile=3"
        );
        assert_eq!(scope_to_profile("/userscripts", "0"), "/userscripts");
        assert_eq!(scope_to_profile("/lists", "3"), "/lists");
        assert_eq!(scope_to_profile("/rules/custom", "3"), "/rules/custom");
        assert_eq!(scope_to_profile("/profiles", "3"), "/profiles");
    }
}
