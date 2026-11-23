//! Control-plane userscript logic shared by the handlers and the scheduled update check:
//! guarded fetching, the pending-plan store and the update flow.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use common::net_policy::{control_plane_client, NetPolicy, UrlRefusal};
use parking_lot::Mutex;
use url::Url;
use userscript_engine::install::{
    self, Approvals, Fetched, InstallPlan, MAX_ASSET_BYTES, MAX_REQUIRES, MAX_RESOURCES,
};
use userscript_engine::script::ScriptAssets;
use userscript_engine::{PendingUpdate, Userscript};

use crate::error::{ApiError, ApiResult};
use crate::handlers::lists::FETCH_DESTINATION_CODE;
use crate::state::AppState;

/// How long a plan waits for confirmation.
pub const PLAN_TTL: Duration = Duration::from_secs(15 * 60);
/// Plans kept at once; the oldest is evicted first.
pub const MAX_PLANS: usize = 32;
/// Total bytes fetched for one plan (script + dependencies).
const MAX_PLAN_BYTES: usize = 32 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// A planned install and what was fetched for it.
pub struct StoredPlan {
    pub plan: InstallPlan,
    pub fetched: Fetched,
    /// Fingerprint of the installed script this plan updates (None for a new install).
    pub base: Option<String>,
    /// Profile the plan was made for; confirming under another profile is refused.
    pub profile: String,
}

/// Identifies the installed script's source and assets, so a stale plan is refused.
pub fn source_fingerprint(s: &Userscript) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.source.as_bytes());
    for r in &s.assets.requires {
        h.update(r.url.as_bytes());
        h.update(r.content.as_bytes());
    }
    h.update([s.allow_connect_all as u8]);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl StoredPlan {
    pub fn fetched_clone(&self) -> Fetched {
        Fetched {
            requires: self.fetched.requires.clone(),
            resources: self.fetched.resources.clone(),
        }
    }
}

/// Bounded, expiring, in-memory store of pending install plans.
pub struct PlanStore {
    ttl: Duration,
    inner: Mutex<Vec<(String, Instant, Arc<StoredPlan>)>>,
}

impl Default for PlanStore {
    fn default() -> Self {
        Self {
            ttl: PLAN_TTL,
            inner: Mutex::new(Vec::new()),
        }
    }
}

impl PlanStore {
    fn prune(&self, v: &mut Vec<(String, Instant, Arc<StoredPlan>)>) {
        let ttl = self.ttl;
        v.retain(|(_, at, _)| at.elapsed() < ttl);
    }

    pub fn insert(&self, plan: StoredPlan) -> String {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let mut v = self.inner.lock();
        self.prune(&mut v);
        while v.len() >= MAX_PLANS {
            v.remove(0);
        }
        v.push((id.clone(), Instant::now(), Arc::new(plan)));
        id
    }

    pub fn get(&self, id: &str) -> Option<Arc<StoredPlan>> {
        let mut v = self.inner.lock();
        self.prune(&mut v);
        v.iter()
            .find(|(i, _, _)| i == id)
            .map(|(_, _, p)| p.clone())
    }

    pub fn remove(&self, id: &str) {
        self.inner.lock().retain(|(i, _, _)| i != id);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Age every plan past its TTL (tests).
    pub fn expire_all(&self) {
        self.inner.lock().clear();
    }
}

fn invalid(e: impl std::fmt::Display) -> ApiError {
    ApiError::ValidationError(format!("Invalid userscript: {e}"))
}

fn fetch_err(msg: impl Into<String>) -> ApiError {
    ApiError::coded(StatusCode::BAD_GATEWAY, "fetch_failed", msg)
}

fn policy(state: &AppState) -> ApiResult<Arc<NetPolicy>> {
    match state.list_service.fetch_policy() {
        Some(p) => Ok(p.clone()),
        None => NetPolicy::control_plane(&[])
            .map(Arc::new)
            .map_err(|e| ApiError::Internal(e.to_string())),
    }
}

/// Parse a base64 `data:` URL body.
fn data_url(url: &Url) -> ApiResult<(Vec<u8>, Option<String>)> {
    use base64::Engine;
    let s = url.as_str();
    let rest = s.strip_prefix("data:").unwrap_or(s);
    let (head, body) = rest
        .split_once(',')
        .ok_or_else(|| fetch_err("malformed data: URL"))?;
    let mut parts = head.split(';');
    let mime = parts.next().filter(|m| !m.is_empty()).map(str::to_string);
    if !parts.any(|p| p == "base64") {
        return Err(fetch_err("only base64 data: URLs are supported"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| fetch_err("invalid base64 in data: URL"))?;
    Ok((bytes, mime))
}

/// Fetch `url` under the control-plane policy (http/https only, guarded DNS, checked redirects,
/// timeout) with a body cap.
pub async fn fetch_limited(
    state: &AppState,
    url: &Url,
    max: usize,
) -> ApiResult<(Vec<u8>, Option<String>)> {
    if url.scheme() == "data" {
        let (b, m) = data_url(url)?;
        if b.len() > max {
            return Err(fetch_err("data: URL too large"));
        }
        return Ok((b, m));
    }
    let policy = policy(state)?;
    match policy.check_url(url.as_str()).await {
        Ok(_) => {}
        Err(e @ (UrlRefusal::Invalid | UrlRefusal::Scheme | UrlRefusal::NoHost)) => {
            return Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "invalid_fetch_url",
                e.to_string(),
            ))
        }
        Err(e) => {
            return Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                FETCH_DESTINATION_CODE,
                e.to_string(),
            ))
        }
    }
    let client = control_plane_client(policy)
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("Argus/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let mut resp = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| fetch_err(format!("{url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(fetch_err(format!("{url}: HTTP {}", resp.status())));
    }
    if resp.content_length().is_some_and(|l| l as usize > max) {
        return Err(fetch_err(format!("{url}: larger than {max} bytes")));
    }
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| fetch_err(format!("{url}: {e}")))?
    {
        if body.len() + chunk.len() > max {
            return Err(fetch_err(format!("{url}: larger than {max} bytes")));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, ct))
}

/// Fetch a script's source text.
pub async fn fetch_source(state: &AppState, url: &Url) -> ApiResult<String> {
    let (b, _) = fetch_limited(state, url, MAX_ASSET_BYTES).await?;
    String::from_utf8(b)
        .map(|s| s.trim_start_matches('\u{feff}').to_string())
        .map_err(|_| fetch_err(format!("{url}: not UTF-8")))
}

/// Download and verify every `@require`/`@resource` of `plan`.
pub async fn fetch_assets(state: &AppState, plan: &InstallPlan) -> ApiResult<Fetched> {
    let mut fetched = Fetched::default();
    let mut total = 0usize;
    for r in &plan.requires {
        let key = r.url.to_string();
        if fetched.requires.contains_key(&key) {
            continue;
        }
        let (b, _) = fetch_limited(state, &r.url, MAX_ASSET_BYTES).await?;
        total += b.len();
        install::verify_sri(&b, &r.sri).map_err(|e| invalid(format!("@require {key}: {e}")))?;
        fetched.requires.insert(key, b);
    }
    for r in &plan.resources {
        let (b, ct) = fetch_limited(state, &r.url, MAX_ASSET_BYTES).await?;
        total += b.len();
        install::verify_sri(&b, &r.sri)
            .map_err(|e| invalid(format!("@resource {}: {e}", r.name)))?;
        fetched.resources.insert(r.name.clone(), (b, ct));
    }
    if total > MAX_PLAN_BYTES {
        return Err(invalid("dependencies exceed the total size cap"));
    }
    Ok(fetched)
}

/// Parse `source` and fetch its dependencies.
pub async fn build_plan(
    state: &AppState,
    source: String,
    origin: Option<&Url>,
) -> ApiResult<StoredPlan> {
    let plan = install::plan_install(&source, origin).map_err(invalid)?;
    let fetched = fetch_assets(state, &plan).await?;
    Ok(StoredPlan {
        plan,
        fetched,
        base: None,
        profile: String::new(),
    })
}

/// A pattern that matches (nearly) every site.
pub fn is_broad_match(p: &str) -> bool {
    let p = p.trim();
    if p == "<all_urls>" || p == "*" {
        return true;
    }
    match p.split_once("://") {
        Some((scheme, rest)) => {
            matches!(scheme, "*" | "http" | "https" | "http*") && matches!(rest, "*" | "*/" | "*/*")
        }
        None => false,
    }
}

fn fetched_from_assets(a: &ScriptAssets) -> Fetched {
    let mut f = Fetched::default();
    for r in &a.requires {
        f.requires
            .insert(r.url.clone(), r.content.clone().into_bytes());
    }
    for r in &a.resources {
        f.resources
            .insert(r.name.clone(), (r.bytes(), Some(r.mime.clone())));
    }
    f
}

/// Result of an update check.
pub enum CheckOutcome {
    UpToDate,
    Updated,
    Pending(Box<PendingUpdate>),
}

/// Check one script for an update and apply it (only when `apply` and it does not widen
/// `@match`/`@connect`/`@grant`) or park it as the script's pending update.
pub async fn check_update(
    state: &AppState,
    profile: &str,
    id: &str,
    apply: bool,
) -> ApiResult<CheckOutcome> {
    let mgr = &state.userscript_manager;
    let script = mgr
        .get_in(profile, id)
        .ok_or_else(|| ApiError::NotFound(format!("Userscript '{id}' not found")))?;
    let check_url = install::update_check_url(&script.metadata).ok_or_else(|| {
        ApiError::bad_request("Script has no @version with an @updateURL/@downloadURL")
    })?;
    let now = chrono::Utc::now();
    let text = fetch_source(state, &check_url).await?;
    let mut origin = check_url.clone();
    let mut up = install::plan_update(&script, &text, Some(&check_url)).map_err(invalid)?;
    if !up.is_newer {
        let _ = mgr.modify_script(profile, id, |s| s.last_update_check = Some(now));
        return Ok(CheckOutcome::UpToDate);
    }
    // The check URL may serve metadata only: download the full script from its own URL.
    if let Some(dl) = install::update_download_url(&script.metadata) {
        if dl != check_url {
            let full = fetch_source(state, &dl).await?;
            up = install::plan_update(&script, &full, Some(&dl)).map_err(invalid)?;
            origin = dl;
        }
    }
    let fetched = fetch_assets(state, &up.plan).await?;
    stage_update(
        &state.userscript_manager,
        profile,
        &script,
        up,
        fetched,
        apply,
        &origin,
        now,
    )
}

/// Apply a planned update (only when `apply` and it does not widen `@match`/`@connect`/
/// `@grant`) or park it as the script's pending update.
#[allow(clippy::too_many_arguments)]
pub fn stage_update(
    mgr: &userscript_engine::UserscriptManager,
    profile: &str,
    script: &Userscript,
    up: install::UpdatePlan,
    fetched: Fetched,
    apply: bool,
    origin: &Url,
    now: chrono::DateTime<chrono::Utc>,
) -> ApiResult<CheckOutcome> {
    let id = script.id.as_str();
    let mut up = up;
    up.absorb_fetched(script, &fetched);
    let diff = up.diff.clone();
    let needs = diff.needs_reapproval();
    let new_version = up.new_version.clone();
    let source = up.plan.source.clone();
    // Built with approval only to verify the dependencies and obtain their stored form.
    let mut cand = install::finish_update(script, up, fetched, true, false).map_err(invalid)?;
    cand.last_update_check = Some(now);
    if apply && !needs {
        mgr.replace_script(profile, cand)?;
        return Ok(CheckOutcome::Updated);
    }
    let pending = PendingUpdate {
        source,
        assets: cand.assets,
        diff,
        new_version,
        found_at: now,
        origin_url: Some(origin.to_string()),
    };
    let p2 = pending.clone();
    mgr.modify_script(profile, id, |s| {
        s.pending_update = Some(p2);
        s.last_update_check = Some(now);
    })?;
    Ok(CheckOutcome::Pending(Box::new(pending)))
}

/// Apply a script's pending update.
pub fn approve_pending(
    state: &AppState,
    profile: &str,
    id: &str,
    allow_connect_all: bool,
) -> ApiResult<()> {
    let mgr = &state.userscript_manager;
    let script = mgr
        .get_in(profile, id)
        .ok_or_else(|| ApiError::NotFound(format!("Userscript '{id}' not found")))?;
    let pending = script
        .pending_update
        .clone()
        .ok_or_else(|| ApiError::NotFound(format!("Userscript '{id}' has no pending update")))?;
    let origin = pending
        .origin_url
        .as_deref()
        .and_then(|u| Url::parse(u).ok());
    let up = install::plan_update(&script, &pending.source, origin.as_ref()).map_err(invalid)?;
    if allow_connect_all && !up.plan.grants_summary.connect_all {
        return Err(ApiError::ValidationError(
            "allow_connect_all given but the update does not declare @connect *".into(),
        ));
    }
    let mut new = install::finish_update(
        &script,
        up,
        fetched_from_assets(&pending.assets),
        true,
        allow_connect_all,
    )
    .map_err(invalid)?;
    new.last_update_check = script.last_update_check;
    mgr.replace_script(profile, new)?;
    Ok(())
}

/// Validate an exported/imported script and build it: parses, enforces the dependency limits,
/// verifies integrity hashes against the bundled assets.
pub fn build_from_bundle(
    source: &str,
    assets: &api_types::ExportedAssets,
    allow_connect_all: bool,
) -> ApiResult<Userscript> {
    let plan = install::plan_install(source, None).map_err(invalid)?;
    if assets.requires.len() > MAX_REQUIRES || assets.resources.len() > MAX_RESOURCES {
        return Err(invalid("too many bundled dependencies"));
    }
    let mut fetched = Fetched::default();
    for r in &assets.requires {
        fetched
            .requires
            .insert(r.url.clone(), r.content.clone().into_bytes());
    }
    for r in &assets.resources {
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD
            .decode(&r.data_b64)
            .map_err(|_| invalid(format!("@resource {}: bad base64", r.name)))?;
        fetched
            .resources
            .insert(r.name.clone(), (b, Some(r.mime.clone())));
    }
    let allow = allow_connect_all && plan.grants_summary.connect_all;
    install::finish_install(
        plan,
        fetched,
        Approvals {
            allow_connect_all: allow,
        },
    )
    .map_err(invalid)
}

/// Check every script of every profile that has an update URL (scheduled run). Failures are
/// logged.
pub async fn check_all(state: &AppState, auto_apply: bool) {
    let profiles: Vec<String> = match state.profiles.list() {
        Ok(v) => v
            .into_iter()
            .map(|p| common::profile_store::namespace(p.id))
            .collect(),
        Err(e) => {
            tracing::warn!("Scheduled userscript update check: cannot list profiles: {e}");
            return;
        }
    };
    let mut total = 0usize;
    for profile in profiles {
        let ids: Vec<String> = state
            .userscript_manager
            .get_all_in(&profile)
            .into_iter()
            .filter(|s| install::update_check_url(&s.metadata).is_some())
            .map(|s| s.id)
            .collect();
        for id in ids {
            total += 1;
            match check_update(state, &profile, &id, auto_apply).await {
                Ok(CheckOutcome::UpToDate) => {}
                Ok(CheckOutcome::Updated) => {
                    tracing::info!("Userscript {id} ({profile}) updated automatically");
                }
                Ok(CheckOutcome::Pending(_)) => {
                    tracing::info!("Userscript {id} ({profile}) has an update awaiting approval");
                }
                Err(e) => {
                    tracing::warn!("Update check for userscript {id} ({profile}) failed: {e}");
                }
            }
        }
    }
    tracing::debug!("Scheduled userscript update check done: {total} scripts");
}
