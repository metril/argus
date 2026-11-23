//! Browser extension download: the release asset matching the running version, fetched from
//! GitHub once and cached in the data directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::error::{ApiError, ApiPath, ApiResult};
use crate::state::AppState;

/// Where release assets live. Not user-configurable; tests inject a local server.
const RELEASE_BASE: &str = "https://github.com/metril/argus/releases/download";
const MAX_ASSET_BYTES: usize = 32 * 1024 * 1024;

/// Candidate asset file names for a browser, in preference order (Firefox prefers the signed xpi).
fn candidates(browser: &str, version: &str) -> Option<Vec<String>> {
    let n = |ext: &str| format!("argus-extension-{version}-{browser}.{ext}");
    match browser {
        "chrome" => Some(vec![n("zip")]),
        "firefox" => Some(vec![n("xpi"), n("zip")]),
        _ => None,
    }
}

fn content_type(name: &str) -> &'static str {
    if name.ends_with(".xpi") {
        "application/x-xpinstall"
    } else {
        "application/zip"
    }
}

fn bad_gateway(code: &'static str, msg: impl Into<String>) -> ApiError {
    ApiError::coded(StatusCode::BAD_GATEWAY, code, msg)
}

/// Cached asset bytes and name, downloading from `{base}/v{version}/{name}` on a cache miss.
async fn fetch_cached(
    client: &reqwest::Client,
    base: &str,
    cache_dir: &Path,
    browser: &str,
    version: &str,
) -> ApiResult<(String, Vec<u8>)> {
    let names = candidates(browser, version)
        .ok_or_else(|| ApiError::NotFound("Unknown browser: use chrome or firefox".into()))?;
    let dir: PathBuf = cache_dir.join("extension").join(version);
    for name in &names {
        if let Ok(bytes) = tokio::fs::read(dir.join(name)).await {
            return Ok((name.clone(), bytes));
        }
    }
    for name in &names {
        let url = format!("{base}/v{version}/{name}");
        let resp = client.get(&url).send().await.map_err(|e| {
            tracing::warn!("extension download {url}: {e}");
            bad_gateway("upstream_unreachable", "Could not reach the release server")
        })?;
        if resp.status() == StatusCode::NOT_FOUND {
            continue;
        }
        if !resp.status().is_success() {
            return Err(bad_gateway(
                "upstream_error",
                format!("Release server answered {}", resp.status()),
            ));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| bad_gateway("upstream_error", format!("Download failed: {e}")))?;
        if bytes.len() > MAX_ASSET_BYTES {
            return Err(bad_gateway("upstream_error", "Release asset too large"));
        }
        // Cache best-effort, atomically so a concurrent reader never sees a partial file.
        if tokio::fs::create_dir_all(&dir).await.is_ok() {
            let tmp = dir.join(format!("{name}.{}.tmp", uuid::Uuid::new_v4()));
            if tokio::fs::write(&tmp, &bytes).await.is_ok()
                && tokio::fs::rename(&tmp, dir.join(name)).await.is_err()
            {
                let _ = tokio::fs::remove_file(&tmp).await;
            }
        }
        return Ok((name.clone(), bytes.to_vec()));
    }
    Err(ApiError::NotFound(format!(
        "No {browser} extension is published for version {version}"
    )))
}

/// Download the browser extension build matching this Argus version.
#[utoipa::path(
    get, path = "/downloads/extension/{browser}", tag = "ca",
    security(("bearer_auth" = ["system:read"])),
    params(("browser" = String, Path, description = "`chrome` or `firefox`")),
    responses(
        (status = 200, description = "Extension package (zip, or signed xpi for Firefox)", content_type = "application/octet-stream", body = Vec<u8>),
        (status = 404, description = "Unknown browser or no release asset for this version"),
        (status = 502, description = "Release server unreachable")
    )
)]
pub async fn download_extension(
    State(state): State<Arc<AppState>>,
    ApiPath(browser): ApiPath<String>,
) -> ApiResult<Response> {
    let data_dir = state.proxy_state.config.read().adblock.data_dir.clone();
    let (name, bytes) = fetch_cached(
        &state.http_client,
        RELEASE_BASE,
        &data_dir,
        &browser,
        env!("CARGO_PKG_VERSION"),
    )
    .await?;
    Ok((
        [
            (header::CONTENT_TYPE, content_type(&name).to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn mock() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().route(
            "/v1.2.3/{name}",
            get(
                move |axum::extract::Path(name): axum::extract::Path<String>| {
                    h.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if name.ends_with(".zip") {
                            (StatusCode::OK, format!("bytes:{name}"))
                        } else {
                            (StatusCode::NOT_FOUND, String::new())
                        }
                    }
                },
            ),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, hits)
    }

    #[tokio::test]
    async fn fetches_caches_and_falls_back() {
        let (base, hits) = mock().await;
        let dir = tempfile::tempdir().unwrap();
        let c = reqwest::Client::new();

        let (name, b) = fetch_cached(&c, &base, dir.path(), "chrome", "1.2.3")
            .await
            .unwrap();
        assert_eq!(name, "argus-extension-1.2.3-chrome.zip");
        assert_eq!(b, b"bytes:argus-extension-1.2.3-chrome.zip");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // Second call is served from the cache.
        fetch_cached(&c, &base, dir.path(), "chrome", "1.2.3")
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // No xpi upstream: falls back to the zip.
        let (name, _) = fetch_cached(&c, &base, dir.path(), "firefox", "1.2.3")
            .await
            .unwrap();
        assert_eq!(name, "argus-extension-1.2.3-firefox.zip");
    }

    #[tokio::test]
    async fn unknown_browser_and_missing_version_are_404() {
        let (base, _) = mock().await;
        let dir = tempfile::tempdir().unwrap();
        let c = reqwest::Client::new();
        for (browser, version) in [("opera", "1.2.3"), ("chrome", "9.9.9")] {
            let err = fetch_cached(&c, &base, dir.path(), browser, version)
                .await
                .unwrap_err();
            assert!(matches!(err, ApiError::NotFound(_)), "{browser} {version}");
        }
    }
}
