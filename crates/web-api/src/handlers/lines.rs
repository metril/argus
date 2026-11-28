//! `GET /lists/{id}/lines`: every source line of a list and what the build makes of it.

use std::sync::Arc;

use api_types::{ListLine, ListLinesPage};
use axum::{extract::State, Json};
use filter_engine::inspect::{matches_any, Classified, ExtState, Filter, Kind, Record, Stage};
use serde::Deserialize;
use utoipa::IntoParams;

use super::paging::ci_contains;
use crate::auth::profile::{ProfileParam, ProfileQuery};
use crate::error::{ApiError, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};
use list_service::inspect::Scope;

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LinesQuery {
    /// Comma-separated statuses to keep: `comment`, `inactive`, `network`, `cosmetic`,
    /// `extended`, `duplicate`, `covered`, `unsupported`, `invalid`, an extended-rule state
    /// (`enforced`, `needs_trust`, `not_enforced`, `not_applicable`), or the groups `issues`
    /// (unsupported, invalid, needs_trust, not_enforced), `applied` (network, cosmetic, enforced)
    /// and `ignored` (inactive, not_applicable). Default: all.
    pub status: Option<String>,
    /// Case-insensitive substring of the rule text.
    pub q: Option<String>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Page size, 1..=500 (default 100).
    pub limit: Option<u32>,
}

fn encode_cursor(generation: u64, digest: &str, seq: usize) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
        "{generation}:{}:{seq}",
        digest.get(..16).unwrap_or(digest)
    ))
}

fn decode_cursor(c: &str) -> ApiResult<(u64, String, usize)> {
    use base64::Engine;
    let bad = || ApiError::ValidationError("invalid cursor".into());
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(c)
        .map_err(|_| bad())?;
    let s = String::from_utf8(raw).map_err(|_| bad())?;
    let mut it = s.splitn(3, ':');
    let (g, d, i) = (it.next(), it.next(), it.next());
    match (g, d, i) {
        (Some(g), Some(d), Some(i)) => Ok((
            g.parse().map_err(|_| bad())?,
            d.to_string(),
            i.parse().map_err(|_| bad())?,
        )),
        _ => Err(bad()),
    }
}

fn parse_filters(status: Option<&str>) -> ApiResult<Vec<Filter>> {
    let mut out = Vec::new();
    for name in status
        .unwrap_or("")
        .split(',')
        .filter(|n| !n.trim().is_empty())
    {
        match Filter::parse(name) {
            Some(f) => out.extend(f),
            None => {
                return Err(ApiError::ValidationError(format!(
                    "unknown status '{}' (one of {}, or issues, applied, ignored)",
                    name.trim(),
                    Filter::all()
                        .iter()
                        .map(|f| f.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )))
            }
        }
    }
    Ok(out)
}

/// The API's name for a list id (the custom rules are stored under an internal id).
fn display_id(id: &str) -> &str {
    if id == list_service::CUSTOM_REPORT_ID {
        "custom"
    } else {
        id
    }
}

fn status_of(r: &Record) -> &'static str {
    match r.kind {
        Kind::Comment => "comment",
        Kind::Inactive => "inactive",
        Kind::Network => "network",
        Kind::Cosmetic => "cosmetic",
        Kind::Extended => "extended",
        Kind::Duplicate => "duplicate",
        Kind::Covered => "covered",
        Kind::Disabled => "disabled",
        Kind::Unsupported => "unsupported",
        Kind::Invalid => "invalid",
    }
}

fn line_of(c: &Classified, r: &Record) -> ListLine {
    let other = matches!(r.kind, Kind::Duplicate | Kind::Covered)
        .then(|| c.list_name(r.other).map(|n| display_id(n).to_string()))
        .flatten();
    ListLine {
        line: r.line as usize,
        status: status_of(r).into(),
        rule: c.rule(r).trim().to_string(),
        kind: r.ext_kind.map(|k| k.as_str().to_string()),
        state: r.ext_state().map(|s: ExtState| s.as_str().to_string()),
        reason: match r.kind {
            Kind::Disabled => Some("disabled by a $badfilter rule".to_string()),
            _ => c.reason(r).map(str::to_string),
        },
        stage: (r.kind == Kind::Invalid).then(|| {
            match r.stage {
                Stage::Conversion => "conversion",
                Stage::Compile => "compile",
            }
            .to_string()
        }),
        list: other,
        ip: r.ip,
    }
}

fn counts_of(c: &Classified) -> std::collections::BTreeMap<String, usize> {
    let mut m: std::collections::BTreeMap<String, usize> = Filter::all()
        .into_iter()
        .map(|f| (f.as_str().to_string(), c.count(f)))
        .collect();
    m.insert("all".into(), c.records.len());
    m.insert("issues".into(), c.group_counts[0]);
    m.insert("applied".into(), c.group_counts[1]);
    m.insert("ignored".into(), c.group_counts[2]);
    m
}

/// Longest accepted `q`.
const MAX_Q: usize = 256;

/// Where the lines come from.
enum Target {
    List(String),
    Custom,
}

async fn lines_for(
    state: Arc<AppState>,
    profile: ProfileParam,
    target: Target,
    q: LinesQuery,
) -> ApiResult<Json<ListLinesPage>> {
    let filters = parse_filters(q.status.as_deref())?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as usize;
    let needle = q.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    if needle.chars().count() > MAX_Q {
        return Err(ApiError::ValidationError(format!(
            "q is longer than {MAX_Q} characters"
        )));
    }
    // The profile's list set (the default profile uses the global engine).
    let record = if profile.id == 0 {
        None
    } else {
        let st = state.clone();
        let id = profile.id;
        blocking(move || Ok(st.profiles.get(id)?)).await?
    };
    let scope = match &record {
        Some(r) => Scope::Profile(r.lists.clone()),
        None => Scope::Global,
    };
    let internal_err = |e: list_service::Error| ApiError::Internal(e.to_string());
    let classified = match &target {
        Target::List(id) => {
            if !state.filter_store.exists(id)? {
                return Err(ApiError::NotFound(format!("Filter list '{id}' not found")));
            }
            state
                .list_service
                .classified(id, &scope)
                .await
                .map_err(internal_err)?
        }
        // A profile's own rules are its overlay; the default profile's are the custom rules.
        Target::Custom => match &record {
            Some(r) if r.rules.trim().is_empty() => None,
            Some(r) => Some(
                state
                    .list_service
                    .classified_rules(r.rules.clone())
                    .await
                    .map_err(internal_err)?,
            ),
            None => state
                .list_service
                .classified(list_service::CUSTOM_REPORT_ID, &Scope::Global)
                .await
                .map_err(internal_err)?,
        },
    };
    let Some((c, generation)) = classified else {
        if matches!(target, Target::Custom) {
            return Ok(Json(ListLinesPage {
                items: Vec::new(),
                total: 0,
                limit: limit as u32,
                has_more: false,
                next_cursor: None,
                counts: Default::default(),
                format: "abp".into(),
                in_build: false,
                total_lines: 0,
            }));
        }
        return Err(ApiError::NotFound(
            "The list has no downloaded text yet".into(),
        ));
    };
    let after = match q.cursor.as_deref().filter(|c| !c.is_empty()) {
        Some(cur) => {
            let (g, d, i) = decode_cursor(cur)?;
            if g != generation || !c.digest.starts_with(&d) {
                return Err(ApiError::conflict(
                    "lines_changed",
                    "The list or the build changed since this cursor was issued; restart from the first page",
                ));
            }
            Some(i)
        }
        None => None,
    };
    // The scan over a very large list runs off the async threads.
    let cc = c.clone();
    let (total, picked) = blocking(move || {
        let c = &*cc;
        let mut total = 0usize;
        let mut picked: Vec<usize> = Vec::with_capacity(limit + 1);
        for (i, r) in c.records.iter().enumerate() {
            if !matches_any(&filters, r) || !(needle.is_empty() || ci_contains(c.rule(r), &needle))
            {
                continue;
            }
            total += 1;
            if after.is_some_and(|a| i <= a) {
                continue;
            }
            if picked.len() <= limit {
                picked.push(i);
            }
        }
        Ok((total, picked))
    })
    .await?;
    let mut picked = picked;
    let has_more = picked.len() > limit;
    picked.truncate(limit);
    let next_cursor = has_more
        .then(|| {
            picked
                .last()
                .map(|&i| encode_cursor(generation, &c.digest, i))
        })
        .flatten();
    Ok(Json(ListLinesPage {
        items: picked.iter().map(|&i| line_of(&c, &c.records[i])).collect(),
        total,
        limit: limit as u32,
        has_more,
        next_cursor,
        counts: counts_of(&c),
        format: c.format.as_str().into(),
        in_build: c.in_build,
        total_lines: c.counts.lines,
    }))
}

/// Every line of a list's source text with the build's verdict: the rule's status (comment,
/// inactive, network, cosmetic, extended, duplicate, covered, disabled, unsupported, invalid),
/// true source line numbers, and counts per status for the whole list. The custom rules are
/// `GET /rules/custom/lines` (they need `rules:read`).
///
/// `profile` judges the list against that profile's engine and list set (default: the global
/// engine). A list that is disabled, not in the profile, or changed since the last build is
/// judged on its own (`in_build` false). Pages come from a cache of classified lists; a cursor
/// from another build or text gets 409 `lines_changed`; `q` is at most 256 characters.
///
/// Limits: `disabled` is reported for pure domain rules only (a `$badfilter` rule of another
/// list is invisible for engine rules: the build keeps rule texts as hashes and the engine
/// resolves `$badfilter` on parsed filters, so such a rule is shown as `network`). The extended
/// rules' state is judged per list, so a `$badfilter` in another list does not change it, and a
/// rule in the same list that an `@@` exception of another list neutralises is still `enforced`.
#[utoipa::path(
    get, path = "/lists/{id}/lines", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    params(("id" = String, Path, description = "List id"), ProfileQuery, LinesQuery),
    responses(
        (status = 200, description = "A page of lines", body = ListLinesPage),
        (status = 404, description = "No such list, or it has no text yet"),
        (status = 409, description = "The cursor belongs to another build (`lines_changed`)"),
    )
)]
pub async fn get_list_lines(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<LinesQuery>,
) -> ApiResult<Json<ListLinesPage>> {
    lines_for(state, profile, Target::List(id), q).await
}

/// The lines of the custom rules (of the profile's own rules with `profile`), as
/// `GET /lists/{id}/lines`. Needs `rules:read`, like `GET /rules/custom`.
#[utoipa::path(
    get, path = "/rules/custom/lines", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    params(ProfileQuery, LinesQuery),
    responses(
        (status = 200, description = "A page of lines", body = ListLinesPage),
        (status = 409, description = "The cursor belongs to another build (`lines_changed`)"),
    )
)]
pub async fn get_custom_lines(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    ApiQuery(q): ApiQuery<LinesQuery>,
) -> ApiResult<Json<ListLinesPage>> {
    lines_for(state, profile, Target::Custom, q).await
}
