//! Statistics handlers.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use api_types::{
    BlockedEntry, ConnectionStats, DomainCount, FaultStats, FilterStatsResponse, LogAction,
    LogMode, MessageResponse, MitmStats, Page, ProxyStatsResponse, RecentBlockedResponse,
    RequestLogEntry, RequestLogResponse, RequestStats, TimeseriesPoint, TimeseriesResponse,
    TransparentStatus,
};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{extract::State, Extension, Json};
use filter_engine::{EventAction, EventMode, RequestEvent};
use futures_util::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tracing::info;
use utoipa::IntoParams;

use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiQuery, ApiResult};
use crate::state::AppState;

pub fn filter_stats(state: &AppState) -> FilterStatsResponse {
    let s = state.filter_stats.snapshot();
    FilterStatsResponse {
        total_requests: s.total_requests,
        blocked_requests: s.blocked_requests,
        allowed_requests: s.allowed_requests,
        blocked_by_type: s.blocked_by_type,
        top_blocked_domains: s
            .top_blocked_domains
            .into_iter()
            .map(|(domain, count)| DomainCount { domain, count })
            .collect(),
        lifetime_blocked: 0,
        lifetime_total: 0,
        lifetime_by_category: Default::default(),
    }
}

pub fn proxy_stats(state: &AppState) -> ProxyStatsResponse {
    let mut s = state.proxy_state.stats.snapshot();
    // Byte totals come from the traffic accounting (the client-facing socket); they used to be
    // always 0. They reset together with the traffic statistics.
    if let Some((up, down)) = state.runtime.get().and_then(|r| r.traffic_totals()) {
        s.bytes_received = up;
        s.bytes_sent = down;
    }
    ProxyStatsResponse {
        bypassed_total: state.bypass().bypassed_total(),
        failsafe: {
            let f = state.bypass().failsafe();
            api_types::FailsafeDto {
                active: f.active,
                reason: f.reason,
            }
        },
        explicit: Default::default(),
        connections: ConnectionStats {
            total: s.connections_total,
            active: s.connections_active,
        },
        requests: RequestStats {
            total: s.requests_total,
            bytes_received: s.bytes_received,
            bytes_sent: s.bytes_sent,
            errors: s.errors_total,
        },
        faults: {
            let f = common::faults::snapshot();
            FaultStats {
                upstream_timeouts: f.upstream_timeouts,
                upstream_errors: f.upstream_errors,
                dns_failures: f.dns_failures,
                destination_refusals: f.policy_refusals,
            }
        },
        mitm: state.proxy_state.mitm_enabled.then(|| MitmStats {
            cached_certificates: state.proxy_state.mitm_cached_certs.load(Ordering::Relaxed)
                as usize,
        }),
        transparent: {
            let c = state.proxy_state.config.read();
            TransparentStatus {
                enabled: c.proxy.transparent_port.is_some(),
                address: c.proxy.transparent_port.map(|p| {
                    if c.proxy.host.contains(':') {
                        format!("[{}]:{p}", c.proxy.host)
                    } else {
                        format!("{}:{p}", c.proxy.host)
                    }
                }),
                tls_passthrough_hosts: c.proxy.tls_passthrough_hosts.clone(),
                counters: Default::default(),
            }
        },
    }
}

/// Blocking statistics.
#[utoipa::path(
    get, path = "/stats/filter", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    responses((status = 200, description = "Blocking statistics", body = FilterStatsResponse))
)]
pub async fn get_filter_stats(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> Json<FilterStatsResponse> {
    // Fold in what happened since the last sampler tick, so the lifetime totals are current.
    crate::server::sample_stats(&state).await;
    let mut s = filter_stats(&state);
    let (total, blocked, cats) = state.daily.lifetime();
    s.lifetime_total = total;
    s.lifetime_blocked = blocked;
    s.lifetime_by_category = crate::daily::CATEGORIES
        .iter()
        .zip(cats)
        .map(|(n, c)| (n.to_string(), c))
        .collect();
    if p.profiles.is_some() {
        // The domain histogram spans every profile's browsing: not for a restricted token.
        s.top_blocked_domains.clear();
    }
    Json(s)
}

/// Reset blocking statistics.
#[utoipa::path(
    post, path = "/stats/filter/reset", tag = "stats",
    security(("bearer_auth" = ["stats:reset"])),
    responses((status = 200, description = "Reset", body = MessageResponse))
)]
pub async fn reset_filter_stats(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> Json<MessageResponse> {
    state.timeseries.note_reset();
    state.daily.note_reset();
    state.filter_stats.reset();
    info!("Filter statistics reset by {}", p.username);
    Json(MessageResponse {
        message: "Statistics reset successfully".into(),
    })
}

/// Proxy connection and traffic statistics.
#[utoipa::path(
    get, path = "/stats/proxy", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    responses((status = 200, description = "Proxy statistics", body = ProxyStatsResponse))
)]
pub async fn get_proxy_stats(State(state): State<Arc<AppState>>) -> Json<ProxyStatsResponse> {
    let mut s = proxy_stats(&state);
    // The running listener's real address beats the configured one (port 0, `::` vs `0.0.0.0`).
    if let Some(rt) = state.runtime.get() {
        let (e, t) = rt.listener_counters();
        let conv = |c: crate::state::ListenerCounters| api_types::ListenerCounters {
            active_connections: c.active_connections,
            requests_per_sec: c.requests_per_sec,
            clients: c.clients,
        };
        s.explicit = conv(e);
        s.transparent.counters = conv(t);
        let bound = rt.proxy_bind().await;
        s.transparent.enabled = bound.as_ref().is_some_and(|b| b.transparent.is_some());
        if let Some(b) = bound {
            s.transparent.address = b.transparent.map(|a| a.to_string());
        }
    }
    Json(s)
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecentQuery {
    pub page: Option<u32>,
    /// Page size (1..=200, default 50).
    pub limit: Option<u32>,
    /// Only blocks of this profile (decimal id).
    pub client: Option<String>,
    /// Only requests to this host or its subdomains.
    pub host: Option<String>,
    /// Only blocks from this list id.
    pub list_id: Option<String>,
}

/// Recently blocked requests from the engine's bounded ring, newest first, filterable by
/// profile, host and list id. A profile-restricted token sees only blocks of its own profiles.
#[utoipa::path(
    get, path = "/stats/blocked/recent", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    params(RecentQuery),
    responses((status = 200, description = "Recent blocks", body = RecentBlockedResponse))
)]
pub async fn get_recent_blocked(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<RecentQuery>,
) -> ApiResult<Json<RecentBlockedResponse>> {
    let capacity = state.shared_engine.recent_blocked_capacity();
    let host = q.host.as_deref().map(|h| h.trim().to_ascii_lowercase());
    let events: Vec<BlockedEntry> = state
        .shared_engine
        .recent_blocked(capacity)
        .into_iter()
        .filter(|e| {
            // `client` is the profile id (see `Profile::label`). Events without one cannot be
            // attributed, so a restricted token never sees them.
            p.profiles.is_none() || e.client.as_deref().is_some_and(|c| p.may_access_profile(c))
        })
        .filter(|e| {
            q.client
                .as_deref()
                .is_none_or(|c| e.client.as_deref() == Some(c))
        })
        .filter(|e| {
            q.list_id
                .as_deref()
                .is_none_or(|l| e.list_id.as_deref() == Some(l))
        })
        .filter(|e| {
            host.as_deref().is_none_or(|h| {
                let eh = filter_engine::RequestMatcher::host_of(&e.url).to_ascii_lowercase();
                eh == h || eh.strip_suffix(h).is_some_and(|p| p.ends_with('.'))
            })
        })
        .map(|e| BlockedEntry {
            time: e.ts.to_rfc3339(),
            url: e.url,
            source_host: (!e.source_host.is_empty()).then_some(e.source_host),
            resource_type: e.request_type,
            rule: e.rule,
            list_id: e.list_id,
            client: e.client,
        })
        .collect();
    let p = Page::from_vec(events, q.page, q.limit);
    Ok(Json(RecentBlockedResponse {
        capacity,
        total: p.total,
        page: p.page,
        limit: p.limit,
        has_more: p.has_more,
        entries: p.items,
    }))
}

// ---------------------------------------------------------------------------
// Request log
// ---------------------------------------------------------------------------

/// Filters shared by the snapshot and the stream.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogFilterQuery {
    /// Only this outcome.
    pub action: Option<LogAction>,
    /// Only this profile (decimal id).
    pub client: Option<String>,
    /// Case-insensitive substring of the URL, source host, rule or method.
    pub q: Option<String>,
    /// Only this entry mode.
    pub mode: Option<LogMode>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    pub page: Option<u32>,
    /// Page size (1..=1000, default 50; the ring holds at most its capacity).
    pub limit: Option<u32>,
    pub action: Option<LogAction>,
    pub client: Option<String>,
    pub q: Option<String>,
    pub mode: Option<LogMode>,
    /// Only requests at or after this RFC 3339 time (re-seeding after a stream reconnect).
    #[param(value_type = Option<String>)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
}

/// A parsed filter plus the caller's profile restriction.
struct LogFilter {
    action: Option<EventAction>,
    mode: Option<EventMode>,
    client: Option<String>,
    q: Option<String>,
    principal: Principal,
}

impl LogFilter {
    fn new(
        p: Principal,
        action: Option<LogAction>,
        client: Option<String>,
        q: Option<String>,
        mode: Option<LogMode>,
    ) -> Self {
        Self {
            action: action.map(|a| match a {
                LogAction::Allowed => EventAction::Allowed,
                LogAction::Blocked => EventAction::Blocked,
                LogAction::Passthrough => EventAction::Passthrough,
                LogAction::Error => EventAction::Error,
            }),
            mode: mode.map(|m| match m {
                LogMode::Explicit => EventMode::Explicit,
                LogMode::Transparent => EventMode::Transparent,
            }),
            client: client.filter(|c| !c.is_empty()),
            q: q.map(|q| q.trim().to_lowercase()).filter(|q| !q.is_empty()),
            principal: p,
        }
    }

    /// `haystack`: the event's lowercase searchable text when already built (live events),
    /// else built here for the one event.
    fn matches(&self, e: &RequestEvent, haystack: Option<&str>) -> bool {
        // `client` is the profile id. Events without one cannot be attributed, so a restricted
        // token never sees them.
        if self.principal.profiles.is_some()
            && !e
                .client
                .as_deref()
                .is_some_and(|c| self.principal.may_access_profile(c))
        {
            return false;
        }
        self.action.is_none_or(|a| a == e.action)
            && self.mode.is_none_or(|m| m == e.mode)
            && self
                .client
                .as_deref()
                .is_none_or(|c| e.client.as_deref() == Some(c))
            && self.q.as_deref().is_none_or(|q| match haystack {
                Some(h) => h.contains(q),
                None => [&e.url, &e.source_host, &e.method]
                    .into_iter()
                    .chain(e.rule.as_ref())
                    .any(|f| f.to_lowercase().contains(q)),
            })
    }
}

fn log_entry(e: RequestEvent) -> RequestLogEntry {
    RequestLogEntry {
        ts: e.ts.to_rfc3339(),
        action: match e.action {
            EventAction::Allowed => LogAction::Allowed,
            EventAction::Blocked => LogAction::Blocked,
            EventAction::Passthrough => LogAction::Passthrough,
            EventAction::Error => LogAction::Error,
        },
        method: e.method,
        url: e.url,
        source_host: (!e.source_host.is_empty()).then_some(e.source_host),
        client: e.client,
        request_type: e.request_type,
        rule: e.rule,
        list_id: e.list_id,
        status: e.status,
        mode: match e.mode {
            EventMode::Explicit => LogMode::Explicit,
            EventMode::Transparent => LogMode::Transparent,
        },
        cert_fp: e.cert_fp,
        outcome: e.outcome.map(|o| match o {
            filter_engine::EventOutcome::Aborted => api_types::LogOutcome::Aborted,
            filter_engine::EventOutcome::Synthetic | filter_engine::EventOutcome::Redirected => {
                api_types::LogOutcome::Synthetic
            }
        }),
        error_kind: e.error_kind.map(|k| match k {
            filter_engine::ErrorKind::ClientRejectedCert => {
                api_types::LogErrorKind::ClientRejectedCert
            }
            filter_engine::ErrorKind::UpstreamTimeout => api_types::LogErrorKind::UpstreamTimeout,
            filter_engine::ErrorKind::UpstreamReset => api_types::LogErrorKind::UpstreamReset,
            filter_engine::ErrorKind::UpstreamTls => api_types::LogErrorKind::UpstreamTls,
            filter_engine::ErrorKind::Other => api_types::LogErrorKind::Other,
        }),
    }
}

/// Recent requests of every outcome from the engine's bounded ring, newest first, filterable
/// by action, profile, text and entry mode. A profile-restricted token sees only its profiles.
#[utoipa::path(
    get, path = "/logs/requests", tag = "stats",
    security(("bearer_auth" = ["logs:read"])),
    params(LogQuery),
    responses((status = 200, description = "Recent requests", body = RequestLogResponse))
)]
pub async fn get_request_log(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<LogQuery>,
) -> ApiResult<Json<RequestLogResponse>> {
    let capacity = state.shared_engine.recent_blocked_capacity();
    let filter = LogFilter::new(p, q.action, q.client, q.q, q.mode);
    let entries: Vec<RequestLogEntry> = state
        .shared_engine
        .recent_requests(capacity)
        .into_iter()
        .filter(|e| q.since.is_none_or(|s| e.ts >= s))
        .filter(|e| filter.matches(e, None))
        .map(log_entry)
        .collect();
    // Not `Page::from_vec`: it clamps to 200, which would cut a 300-entry seed short.
    let limit = q.limit.unwrap_or(50).clamp(1, 1000);
    let page = q.page.unwrap_or(1).max(1);
    let total = entries.len();
    let start = ((page - 1) as usize).saturating_mul(limit as usize);
    let items: Vec<RequestLogEntry> = entries
        .into_iter()
        .skip(start)
        .take(limit as usize)
        .collect();
    Ok(Json(RequestLogResponse {
        capacity,
        total,
        page,
        limit,
        has_more: start + items.len() < total,
        entries: items,
    }))
}

/// Live request log as server-sent events: one `request` event per matching request (JSON
/// `RequestLogEntry`), a `lagged` event (`{"skipped": n}`) when the client fell behind and
/// events were dropped, and a keep-alive comment every 15 seconds. Same filters as
/// `/logs/requests`.
#[utoipa::path(
    get, path = "/logs/stream", tag = "stats",
    security(("bearer_auth" = ["logs:read"])),
    params(LogFilterQuery),
    responses((status = 200, description = "text/event-stream of request events", content_type = "text/event-stream", body = String))
)]
pub async fn stream_request_log(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<LogFilterQuery>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let guard = state.log_streams.acquire(p.user_id)?;
    let rx = state.shared_engine.subscribe_requests();
    let filter = LogFilter::new(p.clone(), q.action, q.client, q.q, q.mode);
    let recheck = Recheck {
        state,
        principal: p,
    };
    Ok(
        Sse::new(request_events(rx, filter, recheck, guard)).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        ),
    )
}

/// What a stream needs to re-verify its caller.
struct Recheck {
    state: Arc<AppState>,
    principal: Principal,
}

impl Recheck {
    /// Still signed in (session active / token neither revoked nor expired), account enabled,
    /// role unchanged for sessions, and the role still grants `logs:read`.
    fn still_allowed(&self) -> bool {
        use crate::auth::authz::Actor;
        let live = match &self.principal.actor {
            Actor::Session { session_id } => self.state.session_manager.is_active(session_id),
            Actor::Token { token_id } => self.state.tokens.is_live(token_id),
        };
        if !live {
            return false;
        }
        let Ok(Some(user)) = self.state.session_store.get_user(&self.principal.user_id) else {
            return false;
        };
        user.enabled
            && user.role.scopes().contains(&api_types::Scope::LogsRead)
            && (self.principal.is_token() || user.role == self.principal.role)
    }
}

fn request_events(
    rx: tokio::sync::broadcast::Receiver<Arc<filter_engine::LiveEvent>>,
    filter: LogFilter,
    recheck: Recheck,
    guard: crate::state::LogStreamGuard,
) -> impl Stream<Item = Result<Event, Infallible>> {
    use tokio::sync::broadcast::error::RecvError;
    let every = recheck.state.log_streams.recheck_every();
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    futures_util::stream::unfold(
        (rx, filter, recheck, guard, tick),
        |(mut rx, filter, recheck, guard, mut tick)| async move {
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        // Revoked, disabled or demoted: end the stream (drops the slot too).
                        if !recheck.still_allowed() {
                            return None;
                        }
                    }
                    r = rx.recv() => match r {
                        Ok(e) if filter.matches(&e.event, Some(&e.haystack)) => {
                            let ev = Event::default()
                                .event("request")
                                .json_data(log_entry(e.event.clone()))
                                .unwrap_or_else(|_| Event::default().comment("encode error"));
                            return Some((Ok(ev), (rx, filter, recheck, guard, tick)));
                        }
                        Ok(_) => {}
                        Err(RecvError::Lagged(n)) => {
                            let ev = Event::default()
                                .event("lagged")
                                .data(format!("{{\"skipped\":{n}}}"));
                            return Some((Ok(ev), (rx, filter, recheck, guard, tick)));
                        }
                        Err(RecvError::Closed) => return None,
                    },
                }
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Time series
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimeseriesQuery {
    /// `6h`, `24h` (30-minute buckets) or `7d` (6-hour buckets) from the in-memory history, or
    /// the persisted history by category: `d7`, `d30` (UTC days) and `m12` (calendar months,
    /// kept 400 days). Default `6h`.
    pub range: Option<String>,
}

/// Requests and blocked requests per bucket. `6h`, `24h` and `7d` come from the in-memory history
/// (since the last start); `d7`, `d30` and `m12` from the persisted daily history, by category.
#[utoipa::path(
    get, path = "/stats/timeseries", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    params(TimeseriesQuery),
    responses((status = 200, description = "Buckets, oldest first", body = TimeseriesResponse))
)]
pub async fn get_timeseries(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<TimeseriesQuery>,
) -> ApiResult<Json<TimeseriesResponse>> {
    let range = q.range.unwrap_or_else(|| "6h".into());
    if matches!(range.as_str(), "d7" | "d30" | "m12") {
        crate::server::sample_stats(&state).await;
        let now = chrono::Utc::now().timestamp();
        let (step, pts) = match range.as_str() {
            "d7" => (86_400, state.daily.days(now, 7)),
            "d30" => (86_400, state.daily.days(now, 30)),
            _ => (30 * 86_400, state.daily.months(now, 12)),
        };
        let points = pts
            .into_iter()
            .map(|b| TimeseriesPoint {
                ts: b.ts,
                requests: b.requests,
                blocked: b.blocked,
                by_category: crate::daily::CATEGORIES
                    .iter()
                    .zip(b.cats)
                    .map(|(n, c)| (n.to_string(), c))
                    .collect(),
            })
            .collect();
        return Ok(Json(TimeseriesResponse {
            range,
            bucket_secs: step,
            points,
        }));
    }
    let (step, n) = match range.as_str() {
        "6h" => (crate::timeseries::BUCKET_SECS, 12),
        "24h" => (crate::timeseries::BUCKET_SECS, 48),
        "7d" => (6 * 3600, 28),
        o => {
            return Err(ApiError::ValidationError(format!(
                "unknown range '{o}' (6h, 24h, 7d, d7, d30, m12)"
            )))
        }
    };
    // Fold in what has happened since the last sampler tick.
    let now = chrono::Utc::now().timestamp();
    state.timeseries.sample(now, || {
        let s = state.filter_stats.snapshot();
        (s.total_requests, s.blocked_requests)
    });
    let points = state
        .timeseries
        .series(now, step, n)
        .into_iter()
        .map(|b| TimeseriesPoint {
            ts: b.ts,
            requests: b.requests,
            blocked: b.blocked,
            by_category: Default::default(),
        })
        .collect();
    Ok(Json(TimeseriesResponse {
        range,
        bucket_secs: step,
        points,
    }))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TrafficQuery {
    /// `device` (one row per device, default) or `host`.
    pub group: Option<String>,
    /// Only this device (an id from a `group=device` row).
    pub device: Option<String>,
    /// Most rows (1..=1000, default 100).
    pub limit: Option<u32>,
    /// `rate` (current up+down rate, default), `down` or `up` (cumulative bytes).
    pub sort: Option<String>,
}

/// The id shown for a device key: the token digest is cut short, never exposed whole.
fn public_device_id(key: &str) -> String {
    match key.strip_prefix("t:") {
        Some(hex) => format!("t:{}", &hex[..hex.len().min(12)]),
        None => key.to_string(),
    }
}

fn to_ms_rfc3339(ms: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms as i64)
        .unwrap_or_default()
        .to_rfc3339()
}

fn blank_row() -> api_types::TrafficRowDto {
    api_types::TrafficRowDto {
        device_id: None,
        device_name: None,
        profile_id: None,
        host: None,
        other: false,
        up: 0,
        down: 0,
        up_rate: 0.0,
        down_rate: 0.0,
        connections_total: 0,
        connections_active: 0,
        local_requests: 0,
        local_bytes: 0,
        handling: Default::default(),
        last_active: None,
        top_hosts: Vec::new(),
    }
}

fn add_row(d: &mut api_types::TrafficRowDto, r: &common::traffic::TrafficRow) {
    d.up += r.up;
    d.down += r.down;
    d.up_rate += r.up_rate;
    d.down_rate += r.down_rate;
    d.connections_total += r.connections_total;
    d.connections_active += r.connections_active;
    d.local_requests += r.local_requests;
    d.local_bytes += r.local_bytes;
    d.handling.decrypted += r.handling.decrypted;
    d.handling.tunnelled += r.handling.tunnelled;
    d.handling.plain += r.handling.plain;
    if let Some(ms) = r.last_active_ms {
        let cur = d
            .last_active
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.timestamp_millis() as u64)
            .unwrap_or(0);
        if ms > cur {
            d.last_active = Some(to_ms_rfc3339(ms));
        }
    }
}

const OTHER_HOSTS: &str = "(other hosts)";

fn unmap(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 => v4,
    }
}

/// Live traffic per device or host: bytes and smoothed rates counted on the client-facing
/// socket (TLS and HTTP framing included). Needs `stats:read`; the per-host figures (`top_hosts`
/// and `group=host`) are browsing history and also need `logs:read` (without it `top_hosts` is
/// empty, `hosts_visible` is false and `group=host` answers 403). A profile-restricted token sees
/// only the devices of its own profiles. A device's id is `i:<address>` (an unregistered
/// address), `t:<first 12 hex of the device token digest>` or `x:<extension token id>`.
#[utoipa::path(
    get, path = "/stats/traffic", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    params(TrafficQuery),
    responses((status = 200, description = "Traffic", body = api_types::TrafficResponse))
)]
pub async fn get_traffic(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<TrafficQuery>,
) -> ApiResult<Json<api_types::TrafficResponse>> {
    let group = q.group.as_deref().unwrap_or("device");
    if !["device", "host"].contains(&group) {
        return Err(ApiError::ValidationError(format!(
            "unknown group '{group}' (device, host)"
        )));
    }
    let sort = q.sort.as_deref().unwrap_or("rate");
    if !["rate", "down", "up"].contains(&sort) {
        return Err(ApiError::ValidationError(format!(
            "unknown sort '{sort}' (rate, down, up)"
        )));
    }
    let limit = match q.limit {
        None => 100,
        Some(l @ 1..=1000) => l as usize,
        Some(_) => {
            return Err(ApiError::ValidationError(
                "limit must be between 1 and 1000".into(),
            ))
        }
    };
    // Per-host figures are a browsing history: they need `logs:read` like the request log.
    let hosts_visible = p.has(api_types::Scope::LogsRead);
    if group == "host" && !hosts_visible {
        return Err(ApiError::coded(
            axum::http::StatusCode::FORBIDDEN,
            "insufficient_scope",
            "Missing required scope: logs:read (per-host traffic is browsing history)",
        ));
    }
    let snap = state
        .runtime
        .get()
        .and_then(|r| r.traffic_snapshot())
        .unwrap_or_default();
    let st = state.clone();
    let devices = crate::state::blocking(move || Ok(st.profiles.devices()?))
        .await
        .unwrap_or_default();
    let name_of = |key: &str| -> String {
        if let Some(hex) = key.strip_prefix("t:") {
            for d in &devices {
                if let Some(dg) = d.token_digest {
                    let h: String = dg.iter().map(|b| format!("{b:02x}")).collect();
                    if h == hex {
                        return d.name.clone();
                    }
                }
            }
            return "Device token".into();
        }
        if let Some(ip) = key.strip_prefix("i:") {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                let addr = unmap(addr);
                if let Some(d) = devices
                    .iter()
                    .find(|d| d.ips.iter().any(|n| n.contains(&addr)))
                {
                    return d.name.clone();
                }
            }
            return ip.to_string();
        }
        "Browser extension".into()
    };

    let visible: Vec<&common::traffic::DeviceTraffic> = snap
        .devices
        .iter()
        .filter(|d| p.may_access_profile(&d.profile_id.to_string()))
        .filter(|d| {
            q.device
                .as_deref()
                .is_none_or(|w| public_device_id(&d.key) == w)
        })
        .collect();

    let mut totals = api_types::TrafficTotals::default();
    if p.profiles.is_none() && q.device.is_none() {
        totals.up = snap.up_total;
        totals.down = snap.down_total;
    } else {
        for d in &visible {
            totals.up += d.row.up;
            totals.down += d.row.down;
        }
    }

    let mut rows: Vec<api_types::TrafficRowDto> = Vec::new();
    if group == "device" {
        for d in &visible {
            let mut r = blank_row();
            r.device_id = Some(public_device_id(&d.key));
            r.device_name = Some(name_of(&d.key));
            r.profile_id = Some(d.profile_id.to_string());
            add_row(&mut r, &d.row);
            let mut hosts: Vec<&common::traffic::HostTraffic> = d.hosts.iter().collect();
            let k = |h: &common::traffic::HostTraffic| {
                (
                    h.row.up_rate + h.row.down_rate,
                    (h.row.up + h.row.down) as f64,
                )
            };
            hosts.sort_by(|a, b| k(b).partial_cmp(&k(a)).unwrap_or(std::cmp::Ordering::Equal));
            r.top_hosts = hosts
                .into_iter()
                .filter(|_| hosts_visible)
                .take(5)
                .map(|h| api_types::TrafficTopHost {
                    host: h.host.clone(),
                    up: h.row.up,
                    down: h.row.down,
                    up_rate: h.row.up_rate,
                    down_rate: h.row.down_rate,
                    other: false,
                })
                .collect();
            rows.push(r);
        }
    } else {
        let single = q.device.is_some();
        let mut by_host: std::collections::HashMap<
            (Option<String>, String, bool),
            api_types::TrafficRowDto,
        > = Default::default();
        for d in &visible {
            let dev = single.then(|| public_device_id(&d.key));
            let other = (d.other.up + d.other.down > 0).then_some((OTHER_HOSTS, true, &d.other));
            let entries = d
                .hosts
                .iter()
                .map(|h| (h.host.as_str(), false, &h.row))
                .chain(other);
            for (host, is_other, row) in entries {
                let e = by_host
                    .entry((dev.clone(), host.to_string(), is_other))
                    .or_insert_with(|| {
                        let mut r = blank_row();
                        r.host = Some(host.to_string());
                        r.other = is_other;
                        if single {
                            r.device_id = Some(public_device_id(&d.key));
                            r.device_name = Some(name_of(&d.key));
                            r.profile_id = Some(d.profile_id.to_string());
                        }
                        r
                    });
                add_row(e, row);
            }
        }
        rows = by_host.into_values().collect();
    }
    rows.sort_by(|a, b| {
        let key = |r: &api_types::TrafficRowDto| match sort {
            "down" => (r.down as f64, r.up as f64),
            "up" => (r.up as f64, r.down as f64),
            _ => (r.up_rate + r.down_rate, (r.up + r.down) as f64),
        };
        key(b)
            .partial_cmp(&key(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.device_id.cmp(&b.device_id))
    });
    rows.truncate(limit);
    Ok(Json(api_types::TrafficResponse {
        group: group.into(),
        at: to_ms_rfc3339(snap.at_ms),
        at_ms: snap.at_ms,
        interval_ms: snap.interval_ms,
        hosts_visible,
        totals,
        rows,
    }))
}

/// Forget all traffic counted so far.
#[utoipa::path(
    post, path = "/stats/traffic/reset", tag = "stats",
    security(("bearer_auth" = ["stats:reset"])),
    responses((status = 200, description = "Reset", body = MessageResponse))
)]
pub async fn reset_traffic(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<MessageResponse>> {
    if p.profiles.is_some() {
        // The counters span every device: a profile-restricted token cannot clear them.
        return Err(ApiError::coded(
            axum::http::StatusCode::FORBIDDEN,
            "profile_restricted",
            "Traffic counters span all devices; a profile-restricted token cannot reset them",
        ));
    }
    if let Some(r) = state.runtime.get() {
        r.traffic_reset();
    }
    info!("Traffic statistics reset by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Traffic statistics reset successfully".into(),
    }))
}
