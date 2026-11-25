//! Browser extension download: the release asset matching the running version, fetched from
//! GitHub once and cached in the data directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use common::net_policy::control_plane_client;

use crate::error::{ApiError, ApiPath, ApiResult};
use crate::middleware::ClientInfo;
use crate::state::AppState;

/// Where release assets live. Not user-configurable; tests inject a local server.
const RELEASE_BASE: &str = "https://github.com/metril/argus/releases/download";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
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
///
/// Names are tried in preference order, each on disk then upstream, so a signed xpi published
/// later beats an earlier zip. The Firefox zip fallback is never cached for the same reason.
async fn fetch_cached(
    client: &reqwest::Client,
    base: &str,
    cache_dir: &Path,
    browser: &str,
    version: &str,
    max: usize,
) -> ApiResult<(String, Vec<u8>)> {
    let names = candidates(browser, version)
        .ok_or_else(|| ApiError::NotFound("Unknown browser: use chrome or firefox".into()))?;
    let dir: PathBuf = cache_dir.join("extension").join(version);
    for name in &names {
        let cacheable = !(browser == "firefox" && name.ends_with(".zip"));
        if cacheable {
            if let Ok(bytes) = tokio::fs::read(dir.join(name)).await {
                return Ok((name.clone(), bytes));
            }
        }
        let url = format!("{base}/v{version}/{name}");
        let mut resp = client.get(&url).send().await.map_err(|e| {
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
        if resp.content_length().is_some_and(|l| l as usize > max) {
            return Err(bad_gateway("upstream_error", "Release asset too large"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| bad_gateway("upstream_error", format!("Download failed: {e}")))?
        {
            if bytes.len() + chunk.len() > max {
                return Err(bad_gateway("upstream_error", "Release asset too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        // Cache best-effort, atomically so a concurrent reader never sees a partial file.
        if cacheable && tokio::fs::create_dir_all(&dir).await.is_ok() {
            let tmp = dir.join(format!("{name}.{}.tmp", uuid::Uuid::new_v4()));
            let ok = tokio::fs::write(&tmp, &bytes).await.is_ok()
                && tokio::fs::rename(&tmp, dir.join(name)).await.is_ok();
            if !ok {
                let _ = tokio::fs::remove_file(&tmp).await;
            }
        }
        return Ok((name.clone(), bytes));
    }
    Err(ApiError::NotFound(format!(
        "No {browser} extension is published for version {version}"
    )))
}

/// Copy `zip` with an `argus.json` (`{"argusUrl": origin}`) at its root, so the extension can
/// prefill this server's address. An existing `argus.json` is replaced.
fn with_argus_json(zip: &[u8], origin: &str) -> Result<Vec<u8>, String> {
    use std::io::{Cursor, Write};
    let mut src = zip::ZipArchive::new(Cursor::new(zip)).map_err(|e| e.to_string())?;
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..src.len() {
        let f = src.by_index_raw(i).map_err(|e| e.to_string())?;
        if f.name() != "argus.json" {
            out.raw_copy_file(f).map_err(|e| e.to_string())?;
        }
    }
    out.start_file("argus.json", zip::write::SimpleFileOptions::default())
        .map_err(|e| e.to_string())?;
    let body = serde_json::json!({ "argusUrl": origin });
    out.write_all(body.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(out.finish().map_err(|e| e.to_string())?.into_inner())
}

/// A `Host`-style value: letters, digits and `. - : [ ]` only.
fn sane_host(h: &str) -> Option<&str> {
    let h = h.trim();
    (!h.is_empty()
        && h.len() <= 255
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')))
    .then_some(h)
}

/// This server's origin as the client reached it (`scheme://host`). Behind a trusted proxy the
/// host is its `X-Forwarded-Host` (first entry), matching how the scheme is decided.
fn request_origin(
    headers: &HeaderMap,
    https: bool,
    peer: Option<std::net::IpAddr>,
    trusted: &[std::net::IpAddr],
) -> Option<String> {
    let forwarded = peer
        .filter(|p| trusted.contains(p))
        .and_then(|_| headers.get("x-forwarded-host"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| sane_host(v.split(',').next().unwrap_or("")));
    let host = match forwarded {
        Some(h) => h,
        None => sane_host(headers.get(header::HOST)?.to_str().ok()?)?,
    };
    Some(format!("{}://{host}", if https { "https" } else { "http" }))
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
    axum::Extension(info): axum::Extension<ClientInfo>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    ApiPath(browser): ApiPath<String>,
) -> ApiResult<Response> {
    let data_dir = state.proxy_state.config.read().adblock.data_dir.clone();
    let client = control_plane_client(crate::userscript_ops::policy(&state)?)
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("Argus/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let (name, bytes) = fetch_cached(
        &client,
        RELEASE_BASE,
        &data_dir,
        &browser,
        env!("CARGO_PKG_VERSION"),
        MAX_ASSET_BYTES,
    )
    .await?;
    // Zips (the Chrome build) carry this server's address so the extension needs no URL typed.
    let bytes = match request_origin(
        &headers,
        info.https,
        peer.map(|p| p.0 .0.ip()),
        &state.api_config.network.trusted_proxies,
    ) {
        Some(origin) if name.ends_with(".zip") => match with_argus_json(&bytes, &origin) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("could not add argus.json to {name}: {e}");
                bytes
            }
        },
        _ => bytes,
    };
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

    const MAX: usize = 1024;

    #[test]
    fn argus_json_is_added_and_the_rest_kept() {
        use std::io::{Cursor, Read, Write};
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("manifest.json", o).unwrap();
        w.write_all(b"{}").unwrap();
        w.start_file("argus.json", o).unwrap();
        w.write_all(b"old").unwrap();
        let zip = w.finish().unwrap().into_inner();
        let out = with_argus_json(&zip, "https://argus.lan:8443").unwrap();
        let mut a = zip::ZipArchive::new(Cursor::new(out)).unwrap();
        assert_eq!(a.len(), 2);
        let mut s = String::new();
        a.by_name("argus.json")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, r#"{"argusUrl":"https://argus.lan:8443"}"#);
        assert!(a.by_name("manifest.json").is_ok());
        assert!(with_argus_json(b"nope", "x").is_err());
    }

    #[test]
    fn origin_trusts_forwarded_host_only_from_a_trusted_proxy() {
        let proxy: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let other: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "argus:8080".parse().unwrap());
        assert_eq!(
            request_origin(&h, false, Some(other), &[proxy]).as_deref(),
            Some("http://argus:8080")
        );
        h.insert("x-forwarded-host", "argus.lan, inner".parse().unwrap());
        assert_eq!(
            request_origin(&h, true, Some(other), &[proxy]).as_deref(),
            Some("https://argus:8080")
        );
        assert_eq!(
            request_origin(&h, true, Some(proxy), &[proxy]).as_deref(),
            Some("https://argus.lan")
        );
        h.insert("x-forwarded-host", "a/b".parse().unwrap());
        assert_eq!(
            request_origin(&h, true, Some(proxy), &[proxy]).as_deref(),
            Some("https://argus:8080")
        );
        h.insert(header::HOST, "a/b".parse().unwrap());
        assert!(request_origin(&h, false, None, &[]).is_none());
        assert!(request_origin(&HeaderMap::new(), false, None, &[]).is_none());
    }

    /// 1.2.3: zips only. 1.2.4: xpi and zip. 1.2.5: HTTP 500. 1.2.6: oversized zip.
    async fn mock() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().route(
            "/v{version}/{name}",
            get(
                move |axum::extract::Path((version, name)): axum::extract::Path<(
                    String,
                    String,
                )>| {
                    h.fetch_add(1, Ordering::SeqCst);
                    async move {
                        match (version.as_str(), name.ends_with(".zip")) {
                            ("1.2.5", _) => (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
                            ("1.2.6", true) => (StatusCode::OK, "x".repeat(MAX + 1)),
                            ("1.2.4", _) | ("1.2.3", true) => {
                                (StatusCode::OK, format!("bytes:{name}"))
                            }
                            _ => (StatusCode::NOT_FOUND, String::new()),
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

    async fn get_asset(
        base: &str,
        dir: &Path,
        browser: &str,
        version: &str,
    ) -> ApiResult<(String, Vec<u8>)> {
        let c = reqwest::Client::new();
        fetch_cached(&c, base, dir, browser, version, MAX).await
    }

    #[tokio::test]
    async fn fetches_caches_and_falls_back() {
        let (base, hits) = mock().await;
        let dir = tempfile::tempdir().unwrap();
        let (name, b) = get_asset(&base, dir.path(), "chrome", "1.2.3")
            .await
            .unwrap();
        assert_eq!(name, "argus-extension-1.2.3-chrome.zip");
        assert_eq!(b, b"bytes:argus-extension-1.2.3-chrome.zip");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        get_asset(&base, dir.path(), "chrome", "1.2.3")
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1, "second call is cached");

        // No xpi upstream: falls back to the zip, which is not cached.
        let (name, _) = get_asset(&base, dir.path(), "firefox", "1.2.3")
            .await
            .unwrap();
        assert_eq!(name, "argus-extension-1.2.3-firefox.zip");
        let before = hits.load(Ordering::SeqCst);
        get_asset(&base, dir.path(), "firefox", "1.2.3")
            .await
            .unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before + 2,
            "xpi 404 + zip refetched"
        );
    }

    #[tokio::test]
    async fn xpi_beats_a_cached_zip() {
        let (base, _) = mock().await;
        let dir = tempfile::tempdir().unwrap();
        let cached = dir.path().join("extension/1.2.4");
        std::fs::create_dir_all(&cached).unwrap();
        std::fs::write(cached.join("argus-extension-1.2.4-firefox.zip"), b"old").unwrap();
        let (name, b) = get_asset(&base, dir.path(), "firefox", "1.2.4")
            .await
            .unwrap();
        assert_eq!(name, "argus-extension-1.2.4-firefox.xpi");
        assert_eq!(b, b"bytes:argus-extension-1.2.4-firefox.xpi");
    }

    #[tokio::test]
    async fn errors_map_to_404_and_502() {
        let (base, _) = mock().await;
        let dir = tempfile::tempdir().unwrap();
        for (browser, version) in [("opera", "1.2.3"), ("chrome", "9.9.9")] {
            let err = get_asset(&base, dir.path(), browser, version)
                .await
                .unwrap_err();
            assert!(matches!(err, ApiError::NotFound(_)), "{browser} {version}");
        }
        for version in ["1.2.5", "1.2.6"] {
            let err = get_asset(&base, dir.path(), "chrome", version)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    ApiError::Coded {
                        status: StatusCode::BAD_GATEWAY,
                        ..
                    }
                ),
                "{version}"
            );
        }
    }
}
