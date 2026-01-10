//! HTTP client wrapper for API calls

use gloo_net::http::Request;
use web_sys::RequestCredentials;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

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
        let response = Request::get(&self.url(path))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Make a POST request with JSON body
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let response = Request::post(&self.url(path))
            .credentials(RequestCredentials::Include)
            .header("Content-Type", "application/json")
            .json(body)
            .map_err(|e| ApiError::Parse(e.to_string()))?
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Make a PUT request with JSON body
    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let response = Request::put(&self.url(path))
            .credentials(RequestCredentials::Include)
            .header("Content-Type", "application/json")
            .json(body)
            .map_err(|e| ApiError::Parse(e.to_string()))?
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Make a DELETE request
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let response = Request::delete(&self.url(path))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Handle the response, mapping status codes to errors
    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: gloo_net::http::Response,
    ) -> Result<T, ApiError> {
        let status = response.status();

        match status {
            200..=299 => {
                response
                    .json::<T>()
                    .await
                    .map_err(|e| ApiError::Parse(e.to_string()))
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
                Err(ApiError::Network(format!("Unexpected status {}: {}", status, text)))
            }
        }
    }
}
