//! Pure logic behind the token pages: expiry choices and dates, the permission selection model,
//! plain-language summaries, token status and validation. Kept free of the DOM so it is
//! unit-testable; every presentation fact about scopes comes from `api_types::scopes::GROUPS`
//! and `TEMPLATES`.

use api_types::scopes::{PermGroup, PermKind, PermRow, GROUPS, TEMPLATES};
use api_types::{
    ApiTokenInfo, CreateTokenRequest, RegenerateTokenRequest, Scope, TokenPurpose,
    UpdateTokenRequest,
};

// ---- expiry -------------------------------------------------------------------------------

/// Expiry presets shown in the select, as `(value, label)`.
pub const EXPIRY_OPTIONS: [(&str, &str); 8] = [
    ("7", "7 days"),
    ("30", "30 days"),
    ("60", "60 days"),
    ("90", "90 days"),
    ("180", "180 days"),
    ("365", "1 year"),
    ("custom", "Custom date…"),
    ("never", "No expiration"),
];

/// A calendar date `(year, month 1-12, day 1-31)`.
pub type Ymd = (i32, u32, u32);

/// Days since 1970-01-01 (proleptic Gregorian).
fn days_from_civil((y, m, d): Ymd) -> i64 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> Ymd {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (yoe + era * 400 + i64::from(m <= 2)) as i32;
    (y, m, d)
}

/// `date` shifted by `n` days.
pub fn add_days(date: Ymd, n: i64) -> Ymd {
    civil_from_days(days_from_civil(date) + n)
}

/// `YYYY-MM-DD` as a date (real calendar days only).
pub fn parse_ymd(s: &str) -> Option<Ymd> {
    let mut it = s.split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || y.len() != 4 {
        return None;
    }
    let date = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    (civil_from_days(days_from_civil(date)) == date && (1..=12).contains(&date.1)).then_some(date)
}

pub fn fmt_ymd((y, m, d): Ymd) -> String {
    format!("{y:04}-{m:02}-{d:02}")
}

/// "Fri, 12 Mar 2027".
pub fn long_date(date: Ymd) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]; // 1970-01-01 = Thu
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let wd = DAYS[days_from_civil(date).rem_euclid(7) as usize];
    format!(
        "{wd}, {} {} {}",
        date.2,
        MONTHS[date.1 as usize - 1],
        date.0
    )
}

/// What the form will send for the chosen expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expiry {
    Days(u32),
    /// A valid future date, to be sent as `expires_at` (end of that day).
    On(Ymd),
    Never,
    /// Custom chosen but no usable date yet.
    Invalid,
}

/// Resolve the select `choice` and the custom date text against `today`.
pub fn resolve_expiry(choice: &str, custom: &str, today: Ymd) -> Expiry {
    match choice {
        "never" => Expiry::Never,
        "custom" => match parse_ymd(custom) {
            Some(d) if days_from_civil(d) > days_from_civil(today) => Expiry::On(d),
            _ => Expiry::Invalid,
        },
        n => n.parse().map_or(Expiry::Never, Expiry::Days),
    }
}

/// The line under the expiry select.
pub fn expiry_line(e: &Expiry, today: Ymd) -> String {
    match e {
        Expiry::Days(n) => format!("Expires on {}", long_date(add_days(today, i64::from(*n)))),
        Expiry::On(d) => format!("Expires on {}", long_date(*d)),
        Expiry::Never => "This token never expires".into(),
        Expiry::Invalid => "Pick a date after today".into(),
    }
}

/// What to send for the expiry of an edited token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiryChange {
    /// Unchanged: send nothing, so the stored instant is not moved.
    Keep,
    Days(u32),
    At(Ymd),
    Never,
}

/// The select value and custom date text that describe an existing expiry (`None` = never).
pub fn expiry_choice_for(expires: Option<Ymd>, today: Ymd) -> (String, String) {
    let Some(d) = expires else {
        return ("never".into(), String::new());
    };
    let left = days_from_civil(d) - days_from_civil(today);
    match EXPIRY_OPTIONS
        .iter()
        .find(|(v, _)| v.parse::<i64>().is_ok_and(|n| n == left))
    {
        Some((v, _)) => ((*v).to_string(), String::new()),
        None => ("custom".into(), fmt_ymd(d)),
    }
}

/// True when the form's expiry is the one the token was loaded with.
pub fn expiry_kept(initial: &(String, String), choice: &str, custom: &str) -> bool {
    initial.0 == choice && (choice != "custom" || initial.1 == custom)
}

/// Compare the form's expiry with the one it was loaded with. `Err` when the new choice is not
/// usable yet (custom without a future date).
pub fn expiry_change(
    initial: &(String, String),
    choice: &str,
    custom: &str,
    today: Ymd,
) -> Option<ExpiryChange> {
    if expiry_kept(initial, choice, custom) {
        return Some(ExpiryChange::Keep);
    }
    match resolve_expiry(choice, custom, today) {
        Expiry::Days(n) => Some(ExpiryChange::Days(n)),
        Expiry::On(d) => Some(ExpiryChange::At(d)),
        Expiry::Never => Some(ExpiryChange::Never),
        Expiry::Invalid => None,
    }
}

// ---- time ---------------------------------------------------------------------------------

/// Seconds since the epoch of an RFC 3339 timestamp (`2026-11-28T08:00:00.123Z`, `+02:00`).
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let d = parse_ymd(date)?;
    let (clock, off) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "Z"),
    };
    let mut it = clock.split(':');
    let h: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let sec: i64 = it.next().unwrap_or("0").split('.').next()?.parse().ok()?;
    if !(0..24).contains(&h) || !(0..60).contains(&m) || !(0..61).contains(&sec) {
        return None;
    }
    let off_secs = match off.as_bytes().first()? {
        b'Z' | b'z' => 0,
        sign => {
            let (oh, om) = off[1..].split_once(':')?;
            let v = oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60;
            if *sign == b'-' {
                -v
            } else {
                v
            }
        }
    };
    Some(days_from_civil(d) * 86_400 + h * 3600 + m * 60 + sec - off_secs)
}

/// "in 5 days", "in 11 months", "expired 3 days ago" for an expiry `left` seconds away.
pub fn expiry_relative(left: i64) -> String {
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if left < 0 {
        let days = -left / 86_400;
        return if days == 0 {
            "expired today".into()
        } else {
            format!("expired {} ago", plural(days, "day"))
        };
    }
    let days = (left + 86_399) / 86_400;
    match days {
        0 | 1 if left < 86_400 => {
            let h = left / 3600;
            if h == 0 {
                "in under an hour".into()
            } else {
                format!("in {}", plural(h, "hour"))
            }
        }
        1..=59 => format!("in {}", plural(days, "day")),
        _ => format!("in {}", plural(days / 30, "month")),
    }
}

// ---- status -------------------------------------------------------------------------------

/// A token is "expiring" this many days before its expiry.
pub const EXPIRING_DAYS: i64 = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    /// Active, and expires within [`EXPIRING_DAYS`].
    Expiring,
    Expired,
    Revoked,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Active => "Active",
            Status::Expiring => "Expiring",
            Status::Expired => "Expired",
            Status::Revoked => "Revoked",
        }
    }
}

pub fn status_of(revoked: bool, expires_at: Option<&str>, now: i64) -> Status {
    if revoked {
        return Status::Revoked;
    }
    match expires_at.and_then(parse_rfc3339) {
        Some(t) if t <= now => Status::Expired,
        Some(t) if t - now <= EXPIRING_DAYS * 86_400 => Status::Expiring,
        _ => Status::Active,
    }
}

pub fn token_status(t: &ApiTokenInfo, now: i64) -> Status {
    status_of(t.revoked, t.expires_at.as_deref(), now)
}

/// The status filter of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// Not expired and not revoked (includes expiring ones).
    Active,
    Expiring,
    Expired,
    Revoked,
    All,
}

impl Filter {
    pub const ALL: [Filter; 5] = [
        Filter::Active,
        Filter::Expiring,
        Filter::Expired,
        Filter::Revoked,
        Filter::All,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Filter::Active => "active",
            Filter::Expiring => "expiring",
            Filter::Expired => "expired",
            Filter::Revoked => "revoked",
            Filter::All => "all",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Filter::Active => "Active",
            Filter::Expiring => "Expiring",
            Filter::Expired => "Expired",
            Filter::Revoked => "Revoked",
            Filter::All => "All",
        }
    }

    pub fn from_key(k: &str) -> Filter {
        Self::ALL
            .into_iter()
            .find(|f| f.key() == k)
            .unwrap_or(Filter::Active)
    }

    pub fn matches(self, s: Status) -> bool {
        match self {
            Filter::All => true,
            Filter::Active => matches!(s, Status::Active | Status::Expiring),
            Filter::Expiring => s == Status::Expiring,
            Filter::Expired => s == Status::Expired,
            Filter::Revoked => s == Status::Revoked,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub active: usize,
    pub expiring: usize,
    pub expired: usize,
    pub revoked: usize,
    pub all: usize,
}

impl Counts {
    pub fn of(&self, f: Filter) -> usize {
        match f {
            Filter::Active => self.active,
            Filter::Expiring => self.expiring,
            Filter::Expired => self.expired,
            Filter::Revoked => self.revoked,
            Filter::All => self.all,
        }
    }
}

pub fn counts(tokens: &[ApiTokenInfo], now: i64) -> Counts {
    let mut c = Counts {
        all: tokens.len(),
        ..Counts::default()
    };
    for t in tokens {
        match token_status(t, now) {
            Status::Active => c.active += 1,
            Status::Expiring => {
                c.active += 1;
                c.expiring += 1;
            }
            Status::Expired => c.expired += 1,
            Status::Revoked => c.revoked += 1,
        }
    }
    c
}

/// Expiry cell text: "Never", "in 5 days", "expired 3 days ago", "—" for a revoked token (its
/// name already says so).
pub fn expiry_cell(t: &ApiTokenInfo, now: i64) -> String {
    if t.revoked {
        return "\u{2014}".into();
    }
    match t.expires_at.as_deref().and_then(parse_rfc3339) {
        Some(at) => expiry_relative(at - now),
        None => "Never".into(),
    }
}

/// The expiring-soon banner: how many tokens, and the one that expires first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiringBanner {
    pub headline: String,
    pub name: String,
    pub id: String,
}

/// "today", "in 3 hours", "tomorrow" or "in 5 days" for an expiry `left` seconds away.
pub fn expires_when(left: i64) -> String {
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if left < 3600 {
        "today".into()
    } else if left < 86_400 {
        format!("in {}", plural(left / 3600, "hour"))
    } else if left < 2 * 86_400 {
        "tomorrow".into()
    } else {
        format!("in {}", plural((left + 86_399) / 86_400, "day"))
    }
}

pub fn expiring_banner(tokens: &[ApiTokenInfo], now: i64) -> Option<ExpiringBanner> {
    let mut soon: Vec<(i64, &ApiTokenInfo)> = tokens
        .iter()
        .filter(|t| token_status(t, now) == Status::Expiring)
        .filter_map(|t| Some((parse_rfc3339(t.expires_at.as_deref()?)?, t)))
        .collect();
    soon.sort_by_key(|(at, _)| *at);
    let (first_at, first) = *soon.first()?;
    let when = expires_when(first_at - now);
    let headline = if soon.len() == 1 {
        format!("1 token expires {when}")
    } else {
        format!(
            "{} tokens expire within {EXPIRING_DAYS} days, the first {when}",
            soon.len()
        )
    };
    Some(ExpiringBanner {
        headline,
        name: first.name.clone(),
        id: first.id.clone(),
    })
}

/// While the previous secret is still accepted: until when (epoch seconds).
pub fn grace_until(t: &ApiTokenInfo, now: i64) -> Option<i64> {
    t.prev_valid_until
        .as_deref()
        .and_then(parse_rfc3339)
        .filter(|u| *u > now)
}

// ---- permission selection model -----------------------------------------------------------

/// Every scope a row controls.
pub fn row_scopes(row: &PermRow) -> Vec<Scope> {
    row.scopes_at(row.level_count())
}

/// Make `selected` grant level `n` (0 = none) of `row`, leaving every other scope alone.
pub fn set_level(selected: &mut Vec<Scope>, row: &PermRow, n: usize) {
    let own = row_scopes(row);
    selected.retain(|s| !own.contains(s));
    selected.extend(row.scopes_at(n));
}

/// `(value, label)` options of a row's segmented control for someone who holds `held`:
/// "No access" plus each level they can grant.
pub fn level_options(row: &PermRow, held: &[Scope]) -> Vec<(String, String)> {
    let mut out = vec![("0".to_string(), "No access".to_string())];
    if let PermKind::Levels(levels) = row.kind {
        for (i, l) in levels.iter().enumerate().take(row.available(held)) {
            out.push(((i + 1).to_string(), l.label.to_string()));
        }
    }
    out
}

/// A group with the rows the creator may grant at all.
pub struct VisibleGroup {
    pub group: &'static PermGroup,
    pub rows: Vec<&'static PermRow>,
}

/// The groups and rows shown to someone who holds `held`; rows they cannot grant are left out.
pub fn visible_groups(held: &[Scope]) -> Vec<VisibleGroup> {
    GROUPS
        .iter()
        .map(|group| VisibleGroup {
            group,
            rows: group
                .rows
                .iter()
                .filter(|r| r.available(held) > 0)
                .collect(),
        })
        .filter(|g| !g.rows.is_empty())
        .collect()
}

/// How many rows are hidden because the creator cannot grant them.
pub fn hidden_row_count(held: &[Scope]) -> usize {
    GROUPS
        .iter()
        .flat_map(|g| g.rows)
        .filter(|r| r.available(held) == 0)
        .count()
}

/// The one-line explanation shown when rows are hidden.
pub fn hidden_note(held: &[Scope]) -> Option<String> {
    match hidden_row_count(held) {
        0 => None,
        1 => Some("1 permission is not shown because your account does not have it.".into()),
        n => Some(format!(
            "{n} permissions are not shown because your account does not have them."
        )),
    }
}

/// The Sensitive pills of a row's label: `(always, edit_only)`.
pub fn row_flags(group: &PermGroup, row: &PermRow) -> (bool, bool) {
    let flags: Vec<bool> = (1..=row.level_count())
        .map(|n| row.sensitive_at(n))
        .collect();
    let first = flags.first().copied().unwrap_or(false);
    let later = flags.iter().skip(1).any(|f| *f);
    (
        group.sensitive || first,
        !first && !group.sensitive && later,
    )
}

fn lc_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Sentence of every row granted at its current level, in table order.
pub fn can_list(selected: &[Scope]) -> Vec<&'static str> {
    GROUPS
        .iter()
        .flat_map(|g| g.rows)
        .filter_map(|r| r.summary_at(r.level_of(selected)))
        .collect()
}

/// Labels of the rows the token has no access to.
pub fn cannot_list(selected: &[Scope]) -> Vec<&'static str> {
    GROUPS
        .iter()
        .flat_map(|g| g.rows)
        .filter(|r| r.level_of(selected) == 0)
        .map(|r| r.label)
        .collect()
}

/// True when the selection holds every scope.
pub fn is_full_access(selected: &[Scope]) -> bool {
    Scope::ALL.iter().all(|s| selected.contains(s))
}

fn join_phrases(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// One sentence for the Review step and the drawer.
pub fn summary_sentence(selected: &[Scope]) -> String {
    if is_full_access(selected) {
        return "This token has full access.".into();
    }
    let can = can_list(selected);
    if can.is_empty() {
        return "This token has no access yet.".into();
    }
    if can.len() > 3 {
        return format!(
            "This token has access to {} areas, listed below.",
            can.len()
        );
    }
    let parts: Vec<String> = can.iter().map(|s| lc_first(s)).collect();
    format!("This token can {}.", join_phrases(&parts))
}

/// "It cannot" line of the live summary.
pub fn cannot_sentence(selected: &[Scope]) -> String {
    let n = cannot_list(selected);
    if n.is_empty() {
        return "Nothing. This token has full access.".into();
    }
    let shown: Vec<&str> = n.iter().take(7).copied().collect();
    let mut s = shown.join(", ");
    if n.len() > 7 {
        s.push_str(&format!(" and {} more areas", n.len() - 7));
    }
    s
}

/// Access column of the list: `(short text, full text)`.
pub fn access_summary(scopes: &[Scope], unknown: usize) -> (String, String) {
    if is_full_access(scopes) {
        return ("Full access".into(), "Full access".into());
    }
    let can = can_list(scopes);
    if can.is_empty() && unknown == 0 {
        return ("No access".into(), "No access".into());
    }
    let full = can
        .iter()
        .map(|s| s.to_string())
        .chain((unknown > 0).then(|| format!("{unknown} not recognised by this version")))
        .collect::<Vec<_>>()
        .join("; ");
    let shown = can.len().min(2);
    let mut short = can
        .iter()
        .take(shown)
        .enumerate()
        .map(|(i, s)| if i == 0 { s.to_string() } else { lc_first(s) })
        .collect::<Vec<_>>()
        .join("; ");
    let more = can.len() - shown + usize::from(unknown > 0);
    if shown == 0 {
        short = format!("{unknown} not recognised by this version");
    } else if more > 0 {
        short.push_str(&format!(" +{more} more"));
    }
    (short, full)
}

/// One line of the dense permission list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedRow {
    pub area: &'static str,
    pub level: &'static str,
    pub scopes: Vec<&'static str>,
    pub sensitive: bool,
    /// Edit review: what the row was before, as "was View"; set only on changed rows.
    pub was: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedGroup {
    pub label: &'static str,
    pub rows: Vec<GrantedRow>,
}

/// The granted permissions grouped like the permission table (Review step and drawer).
pub fn granted(selected: &[Scope]) -> Vec<GrantedGroup> {
    granted_vs(selected, None)
}

/// "No access", "On" or the level's label.
pub fn level_label(row: &PermRow, n: usize) -> &'static str {
    match (n, row.kind) {
        (0, _) => "No access",
        (_, PermKind::Switch { .. }) => "On",
        (n, PermKind::Levels(l)) => l[n - 1].label,
    }
}

/// Like [`granted`]; with `before` (the token as it was), changed rows carry `was`, and rows
/// that lost all access are listed too.
pub fn granted_vs(selected: &[Scope], before: Option<&[Scope]>) -> Vec<GrantedGroup> {
    GROUPS
        .iter()
        .filter_map(|g| {
            let rows: Vec<GrantedRow> = g
                .rows
                .iter()
                .filter_map(|r| {
                    let n = r.level_of(selected);
                    let was = before
                        .map(|b| r.level_of(b))
                        .filter(|w| *w != n)
                        .map(|w| format!("was {}", level_label(r, w)));
                    (n > 0 || was.is_some()).then(|| GrantedRow {
                        area: r.label,
                        level: if n == 0 { "None" } else { level_label(r, n) },
                        was,
                        scopes: row_scopes(r)
                            .into_iter()
                            .filter(|s| selected.contains(s))
                            .map(|s| s.as_str())
                            .collect(),
                        sensitive: n > 0 && (g.sensitive || r.sensitive_at(n)),
                    })
                })
                .collect();
            (!rows.is_empty()).then_some(GrantedGroup {
                label: g.label,
                rows,
            })
        })
        .collect()
}

// ---- purposes -----------------------------------------------------------------------------

/// Purposes shown as cards, in order; Read-only and Custom are links.
pub const CARD_PURPOSES: [TokenPurpose; 4] = [
    TokenPurpose::Extension,
    TokenPurpose::Monitoring,
    TokenPurpose::Script,
    TokenPurpose::Full,
];

pub fn purpose_title(p: TokenPurpose) -> &'static str {
    match p {
        TokenPurpose::Extension => "Browser extension",
        TokenPurpose::Monitoring => "Monitoring and dashboards",
        TokenPurpose::Script => "Script for lists and rules",
        TokenPurpose::Full => "Full access",
        TokenPurpose::ReadOnly => "Read-only",
        TokenPurpose::Custom => "Custom",
    }
}

pub fn purpose_desc(p: TokenPurpose) -> &'static str {
    match p {
        TokenPurpose::Extension => "Lets the Argus extension block, log and bypass sites.",
        TokenPurpose::Monitoring => "Read statistics and system status from Grafana or similar.",
        TokenPurpose::Script => "Update lists and rules from a cron job or CI.",
        TokenPurpose::Full => "Everything, including administration. Use sparingly.",
        TokenPurpose::ReadOnly => "See everything, change nothing.",
        TokenPurpose::Custom => "Choose every permission yourself.",
    }
}

/// The expiry choice a purpose preselects.
pub fn purpose_expiry(p: TokenPurpose) -> &'static str {
    match p {
        TokenPurpose::Extension | TokenPurpose::Monitoring => "365",
        TokenPurpose::Script | TokenPurpose::ReadOnly => "90",
        TokenPurpose::Full | TokenPurpose::Custom => "30",
    }
}

/// "1 year", "90 days" for a preset value.
pub fn expiry_label(choice: &str) -> &'static str {
    EXPIRY_OPTIONS
        .iter()
        .find(|(v, _)| *v == choice)
        .map_or("", |(_, l)| l)
}

/// The scopes a purpose starts with for someone who holds `held` (never more than `held`).
pub fn purpose_scopes(p: TokenPurpose, held: &[Scope]) -> Vec<Scope> {
    TEMPLATES
        .iter()
        .find(|t| t.purpose == p)
        .map(|t| t.scopes_for(held))
        .unwrap_or_default()
}

/// How to use a fresh secret. The secret itself is never part of the text.
pub fn howto(p: TokenPurpose, origin: &str) -> String {
    match p {
        TokenPurpose::Extension => format!(
            "In the Argus extension, open Settings and choose Sign in with token.\nPaste the token above.\nArgus address: {origin}"
        ),
        TokenPurpose::Monitoring => format!(
            "curl -H \"Authorization: Bearer $ARGUS_TOKEN\" \\\n  {origin}/api/v1/stats/filter"
        ),
        TokenPurpose::Script => format!(
            "curl -X POST -H \"Authorization: Bearer $ARGUS_TOKEN\" \\\n  {origin}/api/v1/lists/refresh"
        ),
        _ => format!(
            "curl -H \"Authorization: Bearer $ARGUS_TOKEN\" \\\n  {origin}/api/v1/system/status"
        ),
    }
}

/// "Old secret keeps working for" choices as `(seconds, label)`.
pub const GRACE_OPTIONS: [(&str, &str); 4] = [
    ("0", "Not at all"),
    ("3600", "1 hour"),
    ("86400", "1 day"),
    ("604800", "7 days"),
];

/// Reveal-panel note about the old secret, from the new token's `prev_valid_until` (seconds
/// since the epoch) and the same instant written out for the reader.
pub fn grace_sentence(prev_valid_until: &str, now: i64, written: &str) -> Option<String> {
    let until = parse_rfc3339(prev_valid_until)?;
    (until > now).then(|| format!("The old secret keeps working until {written}."))
}

// ---- validation ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Expiry,
    Profiles,
    Access,
}

/// What [`validate`] looks at.
pub struct Check<'a> {
    pub name: &'a str,
    pub expiry: &'a Expiry,
    /// The expiry is the one the token was loaded with: it needs no future date.
    pub expiry_kept: bool,
    pub profiles_empty: bool,
    /// Profile ids that no longer exist are still chosen.
    pub stale_profiles: bool,
    pub scopes: &'a [Scope],
}

/// First problem that blocks the Review step or the save, in form order.
pub fn validate(c: &Check) -> Option<(Field, &'static str)> {
    let name = c.name.trim();
    if name.is_empty() {
        return Some((Field::Name, "Give the token a name."));
    }
    if name.chars().count() > 100 {
        return Some((Field::Name, "Use 100 characters or fewer."));
    }
    if *c.expiry == Expiry::Invalid && !c.expiry_kept {
        return Some((Field::Expiry, "Pick a date in the future."));
    }
    if c.profiles_empty {
        return Some((
            Field::Profiles,
            "Choose at least one profile, or pick All profiles.",
        ));
    }
    if c.stale_profiles {
        return Some((
            Field::Profiles,
            "Remove the deleted profile, it no longer exists.",
        ));
    }
    if c.scopes.is_empty() {
        return Some((Field::Access, "Pick a level for at least one area."));
    }
    None
}

/// Plain wording for a server refusal: keyed on the error `code`, with the server's own text as
/// the fallback (older servers and unknown codes).
pub fn plain_error(code: Option<&str>, text: &str) -> String {
    match code {
        Some("scope_escalation") => match refused_scope(text) {
            Some(what) => format!("You can't add {what} because your account doesn't have it."),
            None => "You can't give a token access that you don't have yourself. Remove that permission or profile and try again.".into(),
        },
        Some("token_outside_grant") => "This token has more access than the token you are signed in with. Sign in with your account to change it.".into(),
        Some("expiry_outside_grant") => "A token can't outlive the token you are signed in with. Choose an earlier expiry.".into(),
        Some("token_expired") => "This token has expired. Regenerate it with a new expiry to use it again.".into(),
        Some("profile_restricted") => "Your account is limited to certain profiles, and this change goes beyond them.".into(),
        Some("validation_failed" | "bad_request") | None | Some(_) => text.to_string(),
    }
}

/// "Users: Edit" for the scope a server refusal names (`Cannot grant scope 'users:admin' ...`):
/// the row label and the level that includes it, from the permission table.
pub fn refused_scope(text: &str) -> Option<String> {
    let name = text.split('\'').nth(1)?;
    let scope: Scope = name.parse().ok()?;
    GROUPS.iter().flat_map(|g| g.rows).find_map(|r| {
        let n = (1..=r.level_count()).find(|n| r.scopes_at(*n).contains(&scope))?;
        Some(match r.kind {
            PermKind::Switch { .. } => r.label.to_string(),
            PermKind::Levels(_) => format!("{}: {}", r.label, level_label(r, n)),
        })
    })
}

/// One info line for permissions the creator's account does not have: the rows hidden from the
/// table plus, on a duplicate, scopes of the original that were left out.
pub fn permissions_note(hidden_rows: usize, dropped: usize) -> Option<String> {
    match hidden_rows + dropped {
        0 => None,
        1 => {
            Some("1 permission is hidden or left out because your account doesn't have it.".into())
        }
        n => Some(format!(
            "{n} permissions are hidden or left out because your account doesn't have them."
        )),
    }
}

/// Text under the token list when the chosen filter shows nothing.
pub fn empty_text(filter: Filter, any_tokens: bool) -> &'static str {
    if !any_tokens || filter == Filter::All {
        return "No tokens yet. Create one with New token.";
    }
    match filter {
        Filter::Active => "No active tokens.",
        Filter::Expiring => "No tokens are about to expire.",
        Filter::Expired => "No expired tokens.",
        _ => "No revoked tokens.",
    }
}

/// "Expires today, in 3 hours" for a token whose expiry is on today's date and still ahead.
pub fn expires_today_text(left: i64, same_day: bool) -> Option<String> {
    if left <= 0 || !same_day {
        return None;
    }
    let when = expires_when(left);
    Some(if when == "today" {
        "Expires today".to_string()
    } else {
        format!("Expires today, {when}")
    })
}

// ---- request building ---------------------------------------------------------------------

/// What the form holds, as the builders below need it.
#[derive(Debug, Clone)]
pub struct FormValues {
    pub name: String,
    pub choice: String,
    pub custom: String,
    pub all_profiles: bool,
    pub chosen: Vec<String>,
    pub selected: Vec<Scope>,
    pub purpose: TokenPurpose,
}

/// An existing token as the edit form opened it.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub name: String,
    pub expiry: (String, String),
    /// The expiry written out ("Fri, 12 Mar 2027" or "No expiration").
    pub expiry_text: String,
    /// The expiry instant (epoch seconds); `None` = never.
    pub expires_secs: Option<i64>,
    pub profiles: Option<Vec<String>>,
    pub scopes: Vec<Scope>,
}

fn sorted(mut s: Vec<Scope>) -> Vec<Scope> {
    s.sort();
    s.dedup();
    s
}

fn same_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

/// True when the token holds a higher level of `row` than the editor can grant (or any of a row
/// the editor cannot grant at all). Such a row is shown as it is and cannot be changed.
pub fn row_locked(row: &PermRow, initial: &[Scope], held: &[Scope]) -> bool {
    row.level_of(initial) > row.available(held)
}

/// Scopes of `initial` the editor must leave alone: the scopes of every locked row, and any scope
/// the editor does not hold.
pub fn carried_scopes(initial: &[Scope], held: &[Scope]) -> Vec<Scope> {
    let locked: Vec<Scope> = GROUPS
        .iter()
        .flat_map(|g| g.rows)
        .filter(|r| row_locked(r, initial, held))
        .flat_map(row_scopes)
        .collect();
    initial
        .iter()
        .copied()
        .filter(|s| !held.contains(s) || locked.contains(s))
        .collect()
}

/// The scopes a duplicate starts with: the original's, limited to what the creator holds, and
/// how many were left out.
pub fn duplicate_selection(scopes: &[Scope], held: &[Scope]) -> (Vec<Scope>, usize) {
    let kept: Vec<Scope> = scopes
        .iter()
        .copied()
        .filter(|s| held.contains(s))
        .collect();
    let dropped = scopes.len() - kept.len();
    (kept, dropped)
}

/// How the profile restriction differs from the loaded one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileChange {
    Keep,
    Set(Vec<String>),
    Clear,
}

pub fn profile_change(base: &Option<Vec<String>>, all: bool, chosen: &[String]) -> ProfileChange {
    match (base, all) {
        (None, true) => ProfileChange::Keep,
        (Some(_), true) => ProfileChange::Clear,
        (Some(b), false) if same_set(b, chosen) => ProfileChange::Keep,
        (_, false) => ProfileChange::Set(chosen.to_vec()),
    }
}

/// Chosen profile ids that are not in `known`.
pub fn stale_profiles(chosen: &[String], known: &[String]) -> Vec<String> {
    chosen
        .iter()
        .filter(|c| !known.contains(c))
        .cloned()
        .collect()
}

/// RFC 3339 instant for the end of a local day (supplied by the page, which knows the zone).
pub type EndOfDay<'a> = &'a dyn Fn(Ymd) -> String;

/// The create request for a new or duplicated token.
pub fn build_create(v: &FormValues, today: Ymd, eod: EndOfDay) -> CreateTokenRequest {
    let (expires_in_days, expires_at) = match resolve_expiry(&v.choice, &v.custom, today) {
        Expiry::Days(n) => (Some(n), None),
        Expiry::On(d) => (None, Some(eod(d))),
        Expiry::Never | Expiry::Invalid => (None, None),
    };
    CreateTokenRequest {
        name: v.name.trim().to_string(),
        scopes: sorted(v.selected.clone()),
        expires_in_days,
        expires_at,
        profiles: (!v.all_profiles).then(|| v.chosen.clone()),
        purpose: Some(v.purpose),
    }
}

/// The PATCH for an edit: only what changed. `scopes` is sent only when the selection differs,
/// and then keeps every scope the editor cannot see or grant exactly as the token has it.
pub fn build_update(
    base: &Baseline,
    v: &FormValues,
    held: &[Scope],
    today: Ymd,
    eod: EndOfDay,
) -> UpdateTokenRequest {
    let mut req = UpdateTokenRequest::default();
    let name = v.name.trim();
    if name != base.name {
        req.name = Some(name.to_string());
    }
    let carried = carried_scopes(&base.scopes, held);
    let next = sorted(
        v.selected
            .iter()
            .copied()
            .filter(|s| !carried.contains(s))
            .chain(carried.iter().copied())
            .collect(),
    );
    if next != sorted(base.scopes.clone()) {
        req.scopes = Some(next);
    }
    match profile_change(&base.profiles, v.all_profiles, &v.chosen) {
        ProfileChange::Keep => {}
        ProfileChange::Set(ids) => req.profiles = Some(ids),
        ProfileChange::Clear => req.clear_profiles = true,
    }
    match expiry_change(&base.expiry, &v.choice, &v.custom, today) {
        Some(ExpiryChange::Keep) | None => {}
        Some(ExpiryChange::Days(n)) => req.expires_in_days = Some(n),
        Some(ExpiryChange::At(d)) => req.expires_at = Some(eod(d)),
        Some(ExpiryChange::Never) => req.never_expires = true,
    }
    req
}

/// True when a PATCH would change nothing.
pub fn update_is_empty(r: &UpdateTokenRequest) -> bool {
    r.name.is_none()
        && r.scopes.is_none()
        && r.profiles.is_none()
        && !r.clear_profiles
        && r.purpose.is_none()
        && r.expires_in_days.is_none()
        && r.expires_at.is_none()
        && !r.never_expires
}

/// The regenerate request. `new_expiry` is `Some((choice, custom))` when the token has expired
/// (the server then requires one); `Err` when that choice is not usable yet.
pub fn build_regenerate(
    grace: &str,
    new_expiry: Option<(&str, &str)>,
    today: Ymd,
    eod: EndOfDay,
) -> Result<RegenerateTokenRequest, &'static str> {
    // An expired secret no longer works, so a grace period would promise something false.
    let mut req = RegenerateTokenRequest {
        grace_secs: if new_expiry.is_some() {
            0
        } else {
            grace.parse().unwrap_or(0)
        },
        ..Default::default()
    };
    if let Some((choice, custom)) = new_expiry {
        match resolve_expiry(choice, custom, today) {
            Expiry::Days(n) => req.expires_in_days = Some(n),
            Expiry::On(d) => req.expires_at = Some(eod(d)),
            Expiry::Never => req.never_expires = true,
            Expiry::Invalid => return Err("Pick a date in the future."),
        }
    }
    Ok(req)
}

/// The expiry as the Review step writes it. A kept custom date (which may be today) reads as
/// its date, not as "pick a date".
pub fn expiry_summary(v_choice: &str, v_custom: &str, kept: bool, today: Ymd) -> String {
    match resolve_expiry(v_choice, v_custom, today) {
        Expiry::Never => "No expiration".into(),
        Expiry::Invalid if kept => parse_ymd(v_custom).map_or("Pick a date".into(), |d| {
            format!("Expires on {}", long_date(d))
        }),
        Expiry::Invalid => "Pick a date".into(),
        e => expiry_line(&e, today),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_types::scopes::{
        TEMPLATE_BROWSER_EXTENSION, TEMPLATE_MONITORING, TEMPLATE_SCRIPT_LISTS_RULES,
    };
    use api_types::UserRole;

    const TODAY: Ymd = (2026, 11, 24);
    const NOW: i64 = 1_795_000_000; // 2026-11-18T...

    fn held_admin() -> Vec<Scope> {
        UserRole::Admin.scopes()
    }

    fn token(revoked: bool, expires_at: Option<&str>) -> ApiTokenInfo {
        serde_json::from_value(serde_json::json!({
            "id": "t1", "name": "n", "scopes": ["lists:read"], "profiles": null,
            "created_by": "u", "created_by_name": "u", "created_at": "2026-01-01T00:00:00Z",
            "expires_at": expires_at, "last_used_at": null, "revoked": revoked,
        }))
        .unwrap()
    }

    fn at(offset_days: i64) -> String {
        at_secs(offset_days * 86_400)
    }

    fn at_secs(offset: i64) -> String {
        let s = NOW + offset;
        // Build an RFC 3339 string for `s` through the same calendar maths.
        let (y, m, d) = civil_from_days(s.div_euclid(86_400));
        let r = s.rem_euclid(86_400);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            r / 3600,
            r % 3600 / 60,
            r % 60
        )
    }

    // ---- expiry ----

    #[test]
    fn date_math_and_names() {
        assert_eq!(add_days(TODAY, 90), (2027, 2, 22));
        assert_eq!(add_days((2024, 2, 28), 2), (2024, 3, 1));
        assert_eq!(long_date((1970, 1, 1)), "Thu, 1 Jan 1970");
        assert_eq!(long_date(TODAY), "Tue, 24 Nov 2026");
        assert_eq!(parse_ymd("2027-02-29"), None);
        assert_eq!(parse_ymd("2028-02-29"), Some((2028, 2, 29)));
        assert_eq!(parse_ymd("2027-13-01"), None);
        assert_eq!(parse_ymd("junk"), None);
        assert_eq!(fmt_ymd((2027, 3, 5)), "2027-03-05");
    }

    #[test]
    fn expiry_choices_resolve_and_describe() {
        let line = |c, d| expiry_line(&resolve_expiry(c, d, TODAY), TODAY);
        assert_eq!(line("90", ""), "Expires on Mon, 22 Feb 2027");
        assert_eq!(line("365", ""), "Expires on Wed, 24 Nov 2027");
        assert_eq!(line("never", ""), "This token never expires");
        assert_eq!(line("custom", "2026-12-25"), "Expires on Fri, 25 Dec 2026");
        assert_eq!(line("custom", "2026-11-24"), "Pick a date after today");
        assert_eq!(line("custom", "2026-11-23"), "Pick a date after today");
        assert_eq!(line("custom", "2026-02-30"), "Pick a date after today");
        assert_eq!(line("custom", ""), "Pick a date after today");
        assert_eq!(resolve_expiry("7", "", TODAY), Expiry::Days(7));
        assert_eq!(
            resolve_expiry("custom", "2026-11-25", TODAY),
            Expiry::On((2026, 11, 25))
        );
    }

    #[test]
    fn every_option_resolves_and_purposes_preselect_one() {
        for (v, _) in EXPIRY_OPTIONS {
            let e = resolve_expiry(v, "2027-01-01", TODAY);
            assert_ne!(e, Expiry::Invalid, "{v}");
        }
        for p in [
            TokenPurpose::Extension,
            TokenPurpose::Monitoring,
            TokenPurpose::Script,
            TokenPurpose::Full,
            TokenPurpose::ReadOnly,
            TokenPurpose::Custom,
        ] {
            assert!(EXPIRY_OPTIONS.iter().any(|(v, _)| *v == purpose_expiry(p)));
        }
        assert_eq!(
            expiry_label(purpose_expiry(TokenPurpose::Extension)),
            "1 year"
        );
        assert_eq!(
            expiry_label(purpose_expiry(TokenPurpose::Script)),
            "90 days"
        );
        assert_eq!(expiry_label(purpose_expiry(TokenPurpose::Full)), "30 days");
    }

    #[test]
    fn edit_prefill_and_change_detection() {
        assert_eq!(
            expiry_choice_for(None, TODAY),
            ("never".into(), String::new())
        );
        assert_eq!(expiry_choice_for(Some(add_days(TODAY, 90)), TODAY).0, "90");
        assert_eq!(
            expiry_choice_for(Some((2027, 1, 5)), TODAY),
            ("custom".into(), "2027-01-05".into())
        );
        let init = ("90".to_string(), String::new());
        assert_eq!(
            expiry_change(&init, "90", "", TODAY),
            Some(ExpiryChange::Keep)
        );
        assert_eq!(
            expiry_change(&init, "30", "", TODAY),
            Some(ExpiryChange::Days(30))
        );
        assert_eq!(
            expiry_change(&init, "never", "", TODAY),
            Some(ExpiryChange::Never)
        );
        assert_eq!(expiry_change(&init, "custom", "", TODAY), None);
        assert_eq!(
            expiry_change(&init, "custom", "2027-01-01", TODAY),
            Some(ExpiryChange::At((2027, 1, 1)))
        );
        let cust = ("custom".to_string(), "2027-01-05".to_string());
        assert_eq!(
            expiry_change(&cust, "custom", "2027-01-05", TODAY),
            Some(ExpiryChange::Keep)
        );
        assert_eq!(
            expiry_change(&cust, "custom", "2027-01-06", TODAY),
            Some(ExpiryChange::At((2027, 1, 6)))
        );
    }

    #[test]
    fn rfc3339_parses_offsets_and_fractions() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-02T00:00:00.123456Z"), Some(86_400));
        assert_eq!(parse_rfc3339("1970-01-01T02:00:00+02:00"), Some(0));
        assert_eq!(parse_rfc3339("1969-12-31T19:00:00-05:00"), Some(0));
        assert_eq!(parse_rfc3339("nope"), None);
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-01-01T25:00:00Z"), None);
        assert_eq!(parse_rfc3339(&at(0)), Some(NOW));
    }

    #[test]
    fn relative_expiry_wording() {
        assert_eq!(expiry_relative(5 * 86_400), "in 5 days");
        assert_eq!(expiry_relative(86_400), "in 1 day");
        assert_eq!(expiry_relative(4 * 86_400 + 3600), "in 5 days");
        assert_eq!(expiry_relative(335 * 86_400), "in 11 months");
        assert_eq!(expiry_relative(365 * 86_400), "in 12 months");
        assert_eq!(expiry_relative(3 * 3600 + 1), "in 3 hours");
        assert_eq!(expiry_relative(10), "in under an hour");
        assert_eq!(expiry_relative(-10), "expired today");
        assert_eq!(expiry_relative(-3 * 86_400 - 5), "expired 3 days ago");
    }

    // ---- status ----

    #[test]
    fn status_classification_and_counts() {
        let toks = vec![
            token(false, None),
            token(false, Some(&at(5))),
            token(false, Some(&at(14))),
            token(false, Some(&at(15))),
            token(false, Some(&at(-1))),
            token(true, Some(&at(-1))),
            token(true, None),
        ];
        let st: Vec<Status> = toks.iter().map(|t| token_status(t, NOW)).collect();
        assert_eq!(
            st,
            vec![
                Status::Active,
                Status::Expiring,
                Status::Expiring,
                Status::Active,
                Status::Expired,
                Status::Revoked,
                Status::Revoked
            ]
        );
        let c = counts(&toks, NOW);
        assert_eq!(
            c,
            Counts {
                active: 4,
                expiring: 2,
                expired: 1,
                revoked: 2,
                all: 7
            }
        );
        // Each filter selects exactly its count.
        for f in Filter::ALL {
            let n = st.iter().filter(|s| f.matches(**s)).count();
            assert_eq!(n, c.of(f), "{f:?}");
        }
        assert_eq!(Filter::from_key("expired"), Filter::Expired);
        assert_eq!(Filter::from_key("zzz"), Filter::Active);
        assert_eq!(expiry_cell(&toks[0], NOW), "Never");
        assert_eq!(expiry_cell(&toks[1], NOW), "in 5 days");
        assert_eq!(expiry_cell(&toks[5], NOW), "\u{2014}");
    }

    #[test]
    fn banner_names_the_first_to_expire() {
        assert_eq!(expiring_banner(&[token(false, None)], NOW), None);
        let mut a = token(false, Some(&at(9)));
        a.name = "later".into();
        a.id = "a".into();
        let mut b = token(false, Some(&at(5)));
        b.name = "sooner".into();
        b.id = "b".into();
        let one = expiring_banner(std::slice::from_ref(&b), NOW).unwrap();
        assert_eq!(one.headline, "1 token expires in 5 days");
        assert_eq!((one.name.as_str(), one.id.as_str()), ("sooner", "b"));
        let two = expiring_banner(&[a, b], NOW).unwrap();
        assert_eq!(
            two.headline,
            "2 tokens expire within 14 days, the first in 5 days"
        );
        assert_eq!(two.id, "b");
    }

    #[test]
    fn grace_is_only_reported_while_in_the_future() {
        let mut t = token(false, None);
        assert_eq!(grace_until(&t, NOW), None);
        t.prev_valid_until = Some(at(1));
        assert_eq!(grace_until(&t, NOW), Some(NOW + 86_400));
        t.prev_valid_until = Some(at(-1));
        assert_eq!(grace_until(&t, NOW), None);
    }

    // ---- selection model ----

    #[test]
    fn every_scope_has_exactly_one_row() {
        for s in Scope::ALL {
            let n = GROUPS
                .iter()
                .flat_map(|g| g.rows)
                .filter(|r| row_scopes(r).contains(s))
                .count();
            assert_eq!(n, 1, "{s}");
        }
    }

    #[test]
    fn levels_round_trip_and_leave_other_rows_alone() {
        let find = |l: &str| {
            GROUPS
                .iter()
                .flat_map(|g| g.rows)
                .find(|r| r.label == l)
                .unwrap()
        };
        let (lists, logs) = (find("Filter lists"), find("Request log"));
        let mut sel = vec![];
        set_level(&mut sel, logs, 1);
        set_level(&mut sel, lists, 2);
        assert_eq!(lists.level_of(&sel), 2);
        set_level(&mut sel, lists, 1);
        assert_eq!(sel, vec![Scope::LogsRead, Scope::ListsRead]);
        set_level(&mut sel, lists, 0);
        assert_eq!(sel, vec![Scope::LogsRead]);
        // Every row and level reads back as the level that produced it.
        for r in GROUPS.iter().flat_map(|g| g.rows) {
            for n in 0..=r.level_count() {
                assert_eq!(r.level_of(&r.scopes_at(n)), n, "{} {n}", r.label);
            }
        }
    }

    #[test]
    fn any_scope_set_is_kept_as_is_until_a_row_is_touched() {
        // A write without its read is shown as Edit but not rewritten.
        let sel = vec![Scope::RulesWrite, Scope::StatsRead];
        let rules = GROUPS
            .iter()
            .flat_map(|g| g.rows)
            .find(|r| r.label == "Rules")
            .unwrap();
        assert_eq!(rules.level_of(&sel), 2);
        let mut copy = sel.clone();
        set_level(
            &mut copy,
            GROUPS[1]
                .rows
                .iter()
                .find(|r| r.label == "Request log")
                .unwrap(),
            0,
        );
        assert_eq!(copy, sel);
        // Subsets of every size: untouched rows keep their scopes.
        let all = Scope::ALL;
        for k in 0..all.len() {
            let subset: Vec<Scope> = all.iter().copied().skip(k).step_by(3).collect();
            let mut after = subset.clone();
            let row = GROUPS[0].rows.first().unwrap();
            let before = row.level_of(&after);
            set_level(&mut after, row, before);
            // Re-applying the same level may only add the row's own lower levels.
            let outside: Vec<_> = after
                .iter()
                .filter(|s| !row_scopes(row).contains(s))
                .collect();
            let kept: Vec<_> = subset
                .iter()
                .filter(|s| !row_scopes(row).contains(s))
                .collect();
            assert_eq!(outside, kept);
        }
    }

    #[test]
    fn levels_offered_follow_what_the_creator_holds() {
        let find = |l: &str| {
            GROUPS
                .iter()
                .flat_map(|g| g.rows)
                .find(|r| r.label == l)
                .unwrap()
        };
        let user = UserRole::User.scopes();
        let viewer = UserRole::Viewer.scopes();
        let labels = |row: &PermRow, held: &[Scope]| -> Vec<String> {
            level_options(row, held)
                .into_iter()
                .map(|(_, l)| l)
                .collect()
        };
        assert_eq!(
            labels(find("Filter lists"), &user),
            ["No access", "View", "Edit"]
        );
        assert_eq!(labels(find("Filter lists"), &viewer), ["No access", "View"]);
        assert_eq!(labels(find("Request log"), &user), ["No access", "View"]);
        assert_eq!(labels(find("Engine rebuild"), &held_admin()), ["No access"]);
    }

    #[test]
    fn rows_the_creator_cannot_grant_are_hidden_with_a_note() {
        let admin = held_admin();
        assert_eq!(hidden_row_count(&admin), 0);
        assert_eq!(hidden_note(&admin), None);
        let viewer = UserRole::Viewer.scopes();
        let groups = visible_groups(&viewer);
        let labels: Vec<&str> = groups
            .iter()
            .flat_map(|g| g.rows.iter().map(|r| r.label))
            .collect();
        assert!(labels.contains(&"Statistics"));
        assert!(!labels.contains(&"Users"));
        assert!(!labels.contains(&"Request log"));
        assert!(groups.iter().all(|g| g.group.label != "Administration"));
        let total: usize = GROUPS.iter().map(|g| g.rows.len()).sum();
        let shown: usize = groups.iter().map(|g| g.rows.len()).sum();
        assert_eq!(hidden_row_count(&viewer), total - shown);
        assert!(hidden_note(&viewer)
            .unwrap()
            .contains("not shown because your account"));
        // A row with a held View but no Edit is still shown.
        assert!(labels.contains(&"Filter lists"));
    }

    #[test]
    fn sensitive_flags_follow_the_table() {
        let find = |l: &str| {
            GROUPS
                .iter()
                .find_map(|g| g.rows.iter().find(|r| r.label == l).map(|r| (g, r)))
                .unwrap()
        };
        let (g, r) = find("Request log");
        assert_eq!(row_flags(g, r), (true, false));
        let (g, r) = find("Configuration");
        assert_eq!(row_flags(g, r), (false, true));
        let (g, r) = find("Users");
        assert_eq!(row_flags(g, r), (true, false));
        let (g, r) = find("Rules");
        assert_eq!(row_flags(g, r), (false, false));
    }

    // ---- summaries ----

    #[test]
    fn summaries_read_as_plain_sentences() {
        assert_eq!(summary_sentence(&[]), "This token has no access yet.");
        assert_eq!(summary_sentence(Scope::ALL), "This token has full access.");
        let one = summary_sentence(&[Scope::StatsRead]);
        assert_eq!(one, "This token can see blocking statistics.");
        let two = summary_sentence(&[Scope::StatsRead, Scope::SystemRead]);
        assert_eq!(
            two,
            "This token can see blocking statistics and see system status and metrics."
        );
        let script = summary_sentence(TEMPLATE_SCRIPT_LISTS_RULES);
        assert_eq!(
            script,
            "This token can change filter lists, change your custom rules and rebuild the blocking engine."
        );
        // Past three areas the sentence counts them instead of cutting the list short.
        let many = summary_sentence(TEMPLATE_BROWSER_EXTENSION);
        assert!(!many.contains("more thing"), "{many}");
        assert!(
            many.starts_with("This token has access to ")
                && many.ends_with(" areas, listed below."),
            "{many}"
        );
        assert_eq!(can_list(&[]), Vec::<&str>::new());
        assert!(cannot_list(&[]).len() > 10);
        assert_eq!(
            cannot_sentence(Scope::ALL),
            "Nothing. This token has full access."
        );
        assert!(cannot_sentence(&[]).contains("more areas"));
    }

    #[test]
    fn access_column_is_short_with_a_full_version() {
        assert_eq!(access_summary(&[], 0).0, "No access");
        assert_eq!(access_summary(Scope::ALL, 0).0, "Full access");
        let (short, full) = access_summary(TEMPLATE_BROWSER_EXTENSION, 0);
        assert!(short.contains(" +"), "{short}");
        assert!(full.contains("; "));
        let (short, _) = access_summary(&[Scope::StatsRead], 0);
        assert_eq!(short, "See blocking statistics");
        // Unknown scopes count and are named in the full text.
        let (short, full) = access_summary(&[], 2);
        assert_eq!(short, "2 not recognised by this version");
        assert!(full.contains("2 not recognised"));
        assert!(access_summary(&[Scope::StatsRead], 1)
            .0
            .ends_with("+1 more"));
    }

    #[test]
    fn granted_list_carries_level_scopes_and_sensitivity() {
        let g = granted(&[
            Scope::RulesRead,
            Scope::RulesWrite,
            Scope::LogsRead,
            Scope::UserscriptsBridge,
        ]);
        let find = |a: &str| {
            g.iter()
                .flat_map(|g| &g.rows)
                .find(|r| r.area == a)
                .unwrap()
                .clone()
        };
        let rules = find("Rules");
        assert_eq!(
            (rules.level, rules.scopes.clone(), rules.sensitive),
            ("Edit", vec!["rules:read", "rules:write"], false)
        );
        let log = find("Request log");
        assert_eq!((log.level, log.sensitive), ("View", true));
        let sw = find("Connect to this browser");
        assert_eq!(
            (sw.level, sw.scopes.clone()),
            ("On", vec!["userscripts:bridge"])
        );
        assert_eq!(g[0].label, "Filtering");
        assert!(granted(&[]).is_empty());
        let admin = granted(&[Scope::AuditRead]);
        assert!(admin[0].rows[0].sensitive);
    }

    // ---- purposes ----

    #[test]
    fn every_template_yields_exactly_its_scopes() {
        let admin = held_admin();
        let sorted = |mut v: Vec<Scope>| {
            v.sort();
            v
        };
        assert_eq!(
            sorted(purpose_scopes(TokenPurpose::Extension, &admin)),
            sorted(TEMPLATE_BROWSER_EXTENSION.to_vec())
        );
        assert_eq!(
            sorted(purpose_scopes(TokenPurpose::Monitoring, &admin)),
            sorted(TEMPLATE_MONITORING.to_vec())
        );
        assert_eq!(
            sorted(purpose_scopes(TokenPurpose::Script, &admin)),
            sorted(TEMPLATE_SCRIPT_LISTS_RULES.to_vec())
        );
        assert_eq!(
            sorted(purpose_scopes(TokenPurpose::Full, &admin)),
            sorted(admin.clone())
        );
        let ro = purpose_scopes(TokenPurpose::ReadOnly, &admin);
        assert!(!ro.is_empty());
        // Read-only is every View level and nothing more.
        let views: Vec<Scope> = GROUPS
            .iter()
            .flat_map(|g| g.rows)
            .filter_map(|r| match r.kind {
                PermKind::Levels(l) if l[0].label == "View" => Some(l[0].scopes.to_vec()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(sorted(ro), sorted(views));
        assert!(purpose_scopes(TokenPurpose::Custom, &admin).is_empty());
        // Never more than the creator holds.
        let viewer = UserRole::Viewer.scopes();
        for p in CARD_PURPOSES.into_iter().chain([TokenPurpose::ReadOnly]) {
            assert!(
                purpose_scopes(p, &viewer)
                    .iter()
                    .all(|s| viewer.contains(s)),
                "{p:?}"
            );
        }
        assert_eq!(
            purpose_scopes(TokenPurpose::Extension, &viewer),
            vec![Scope::StatsRead]
        );
        // The cards show the plan's titles.
        assert_eq!(
            CARD_PURPOSES.map(purpose_title),
            [
                "Browser extension",
                "Monitoring and dashboards",
                "Script for lists and rules",
                "Full access"
            ]
        );
    }

    #[test]
    fn howto_never_contains_a_secret_and_matches_the_purpose() {
        let ext = howto(TokenPurpose::Extension, "https://argus.local:8443");
        assert!(ext.contains("Sign in with token") && ext.contains("argus.local:8443"));
        assert!(howto(TokenPurpose::Monitoring, "o").contains("$ARGUS_TOKEN"));
        assert!(howto(TokenPurpose::Script, "o").contains("-X POST"));
        assert!(!howto(TokenPurpose::Custom, "o").contains("abk_"));
    }

    #[test]
    fn grace_note_follows_the_returned_instant() {
        let later = at(1);
        assert_eq!(
            grace_sentence(&later, NOW, "Sat, 28 Nov 2026, 04:48").unwrap(),
            "The old secret keeps working until Sat, 28 Nov 2026, 04:48."
        );
        // Already over, or absent from the response: no note.
        assert_eq!(grace_sentence(&at(-1), NOW, "x"), None);
        assert_eq!(grace_sentence("not a date", NOW, "x"), None);
    }

    // ---- validation ----

    fn check<'a>(name: &'a str, expiry: &'a Expiry, scopes: &'a [Scope]) -> Check<'a> {
        Check {
            name,
            expiry,
            expiry_kept: false,
            profiles_empty: false,
            stale_profiles: false,
            scopes,
        }
    }

    #[test]
    fn validation_reports_the_first_problem_in_form_order() {
        let ok = Expiry::Days(30);
        let s = [Scope::StatsRead];
        assert_eq!(validate(&check("ci", &ok, &s)), None);
        assert_eq!(validate(&check("  ", &ok, &s)).unwrap().0, Field::Name);
        let long = "x".repeat(101);
        assert_eq!(validate(&check(&long, &ok, &s)).unwrap().0, Field::Name);
        assert_eq!(validate(&check(&"x".repeat(100), &ok, &s)), None);
        assert_eq!(
            validate(&check("ci", &Expiry::Invalid, &s)).unwrap().0,
            Field::Expiry
        );
        assert_eq!(validate(&check("ci", &Expiry::Never, &s)), None);
        let empty = Check {
            profiles_empty: true,
            ..check("ci", &ok, &s)
        };
        assert_eq!(validate(&empty).unwrap().0, Field::Profiles);
        let stale = Check {
            stale_profiles: true,
            ..check("ci", &ok, &s)
        };
        assert!(validate(&stale).unwrap().1.contains("deleted profile"));
        assert_eq!(validate(&check("ci", &ok, &[])).unwrap().0, Field::Access);
        let all_wrong = Check {
            profiles_empty: true,
            ..check("", &Expiry::Invalid, &[])
        };
        assert_eq!(validate(&all_wrong).unwrap().0, Field::Name);
    }

    #[test]
    fn an_unchanged_expiry_that_is_today_is_still_valid() {
        // expiry_choice_for gives ("custom", today) for a token that expires today; resolve_expiry
        // calls that Invalid (not after today), but an edit that leaves it alone must save.
        let init = expiry_choice_for(Some(TODAY), TODAY);
        assert_eq!(init, ("custom".to_string(), "2026-11-24".to_string()));
        assert_eq!(resolve_expiry(&init.0, &init.1, TODAY), Expiry::Invalid);
        let kept = expiry_kept(&init, &init.0, &init.1);
        assert!(kept);
        let s = [Scope::StatsRead];
        let c = Check {
            expiry_kept: kept,
            ..check("ci", &Expiry::Invalid, &s)
        };
        assert_eq!(validate(&c), None);
        // Picking another past date is still refused.
        assert!(!expiry_kept(&init, "custom", "2026-11-20"));
        assert_eq!(
            expiry_summary("custom", "2026-11-24", true, TODAY),
            "Expires on Tue, 24 Nov 2026"
        );
    }

    #[test]
    fn server_refusals_are_worded_by_code_with_the_text_as_fallback() {
        let text = "anything the server says";
        assert!(plain_error(Some("scope_escalation"), text)
            .starts_with("You can't give a token access"));
        assert!(plain_error(Some("token_outside_grant"), text).contains("signed in with"));
        assert!(plain_error(Some("expiry_outside_grant"), text).contains("earlier expiry"));
        assert!(plain_error(Some("token_expired"), text).contains("Regenerate"));
        assert!(plain_error(Some("profile_restricted"), text).contains("profiles"));
        // Validation and unknown or missing codes show the server's own words.
        assert_eq!(
            plain_error(Some("validation_failed"), "Name must be 1-100 characters"),
            "Name must be 1-100 characters"
        );
        assert_eq!(plain_error(Some("something_new"), text), text);
        assert_eq!(plain_error(None, text), text);
        // A reworded server message does not lose the plain wording while the code is the same.
        assert!(plain_error(Some("scope_escalation"), "Not allowed").contains("don't have"));
    }

    // ---- request builders ----

    fn eod(d: Ymd) -> String {
        format!("{}T23:59:59Z", fmt_ymd(d))
    }

    fn values(selected: &[Scope]) -> FormValues {
        FormValues {
            name: "ci".into(),
            choice: "90".into(),
            custom: String::new(),
            all_profiles: true,
            chosen: Vec::new(),
            selected: selected.to_vec(),
            purpose: TokenPurpose::Custom,
        }
    }

    fn baseline(scopes: &[Scope]) -> Baseline {
        Baseline {
            name: "ci".into(),
            expiry: ("90".into(), String::new()),
            expiry_text: "Mon, 22 Feb 2027".into(),
            expires_secs: None,
            profiles: None,
            scopes: scopes.to_vec(),
        }
    }

    /// An editor who holds only `lists:read` and `stats:read` (a demoted admin).
    fn small_editor() -> Vec<Scope> {
        vec![Scope::ListsRead, Scope::StatsRead]
    }

    #[test]
    fn create_request_carries_expiry_profiles_and_sorted_scopes() {
        let mut v = values(&[Scope::StatsRead, Scope::ListsRead, Scope::StatsRead]);
        v.name = "  ci  ".into();
        let r = build_create(&v, TODAY, &eod);
        assert_eq!(r.name, "ci");
        assert_eq!(r.expires_in_days, Some(90));
        assert_eq!((r.expires_at, r.profiles), (None, None));
        assert_eq!(r.scopes.len(), 2);
        let mut sorted = r.scopes.clone();
        sorted.sort();
        assert_eq!(r.scopes, sorted);
        v.choice = "custom".into();
        v.custom = "2027-01-05".into();
        v.all_profiles = false;
        v.chosen = vec!["p1".into()];
        let r = build_create(&v, TODAY, &eod);
        assert_eq!(r.expires_in_days, None);
        assert_eq!(r.expires_at.as_deref(), Some("2027-01-05T23:59:59Z"));
        assert_eq!(r.profiles, Some(vec!["p1".to_string()]));
        v.choice = "never".into();
        let r = build_create(&v, TODAY, &eod);
        assert_eq!((r.expires_in_days, r.expires_at), (None, None));
    }

    #[test]
    fn an_edit_sends_only_what_changed() {
        let held = held_admin();
        let b = baseline(&[Scope::StatsRead, Scope::ListsRead]);
        let same = values(&[Scope::ListsRead, Scope::StatsRead]);
        let none = build_update(&b, &same, &held, TODAY, &eod);
        assert!(update_is_empty(&none), "{none:?}");
        // A rename alone sends the name and nothing else.
        let mut v = same.clone();
        v.name = "renamed".into();
        let r = build_update(&b, &v, &held, TODAY, &eod);
        assert_eq!(r.name.as_deref(), Some("renamed"));
        assert!(r.scopes.is_none() && r.profiles.is_none() && !r.clear_profiles);
        assert!(r.expires_in_days.is_none() && r.expires_at.is_none() && !r.never_expires);
        // Changing the selection sends the scopes.
        let mut v = same.clone();
        v.selected.push(Scope::RulesRead);
        let r = build_update(&b, &v, &held, TODAY, &eod);
        assert_eq!(r.scopes.unwrap().len(), 3);
        assert!(r.name.is_none());
        // Whitespace around an unchanged name is not a change.
        let mut v = same;
        v.name = " ci ".into();
        assert!(update_is_empty(&build_update(&b, &v, &held, TODAY, &eod)));
    }

    #[test]
    fn scopes_the_editor_cannot_see_or_grant_are_never_dropped() {
        let held = small_editor();
        // The token holds users:admin (hidden row) and config:write; the editor holds neither.
        let base = [Scope::ListsRead, Scope::UsersAdmin, Scope::ConfigWrite];
        let b = baseline(&base);
        // Rename only: scopes are not sent at all, so the hidden ones cannot be refused.
        let mut v = values(&base);
        v.name = "renamed".into();
        let r = build_update(&b, &v, &held, TODAY, &eod);
        assert!(r.scopes.is_none());
        // Adding a permission the editor can grant carries the hidden ones through unchanged.
        let mut v = values(&base);
        v.selected.push(Scope::StatsRead);
        let sent = build_update(&b, &v, &held, TODAY, &eod).scopes.unwrap();
        for s in [
            Scope::ListsRead,
            Scope::UsersAdmin,
            Scope::ConfigWrite,
            Scope::StatsRead,
        ] {
            assert!(sent.contains(&s), "{s} missing from {sent:?}");
        }
        // Even if the form state lost them, they are put back.
        let mut v = values(&[Scope::ListsRead, Scope::StatsRead]);
        v.name = "ci".into();
        let sent = build_update(&b, &v, &held, TODAY, &eod).scopes.unwrap();
        assert!(sent.contains(&Scope::UsersAdmin) && sent.contains(&Scope::ConfigWrite));
        // Removing something the editor can change still works.
        let v = values(&[Scope::UsersAdmin, Scope::ConfigWrite]);
        let sent = build_update(&b, &v, &held, TODAY, &eod).scopes.unwrap();
        assert!(!sent.contains(&Scope::ListsRead) && sent.contains(&Scope::UsersAdmin));
    }

    #[test]
    fn a_partly_held_row_is_locked_at_its_true_level() {
        let lists = GROUPS
            .iter()
            .flat_map(|g| g.rows)
            .find(|r| r.label == "Filter lists")
            .expect("lists row");
        let held = vec![Scope::ListsRead];
        let initial = [Scope::ListsRead, Scope::ListsWrite];
        // The token has Edit, the editor can grant View: locked, shown as Edit.
        assert!(row_locked(lists, &initial, &held));
        assert_eq!(level_label(lists, lists.level_of(&initial)), "Edit");
        // At or below what the editor can grant it is an ordinary row.
        assert!(!row_locked(lists, &[Scope::ListsRead], &held));
        assert!(!row_locked(lists, &[], &held));
        // Both its scopes are carried, including the one the editor does hold, so the row can
        // never be lowered by accident.
        let carried = carried_scopes(&initial, &held);
        assert!(carried.contains(&Scope::ListsRead) && carried.contains(&Scope::ListsWrite));
        let b = baseline(&initial);
        let mut v = values(&[Scope::ListsRead, Scope::ListsWrite, Scope::StatsRead]);
        v.name = "ci".into();
        let sent = build_update(&b, &v, &[Scope::ListsRead, Scope::StatsRead], TODAY, &eod)
            .scopes
            .unwrap();
        assert!(sent.contains(&Scope::ListsWrite) && sent.contains(&Scope::ListsRead));
        // Lowering to View through the form state changes nothing for that row.
        let lowered = values(&[Scope::ListsRead]);
        let r = build_update(&b, &lowered, &held, TODAY, &eod);
        assert!(r.scopes.is_none(), "{r:?}");
    }

    #[test]
    fn duplicate_copies_only_what_the_creator_holds() {
        let held = small_editor();
        let original = [
            Scope::ListsRead,
            Scope::ListsWrite,
            Scope::UsersAdmin,
            Scope::StatsRead,
        ];
        let (kept, dropped) = duplicate_selection(&original, &held);
        assert_eq!(kept, vec![Scope::ListsRead, Scope::StatsRead]);
        assert_eq!(dropped, 2);
        assert!(permissions_note(1, dropped)
            .unwrap()
            .starts_with("3 permissions are hidden or left out"));
        assert!(permissions_note(0, 1)
            .unwrap()
            .starts_with("1 permission is hidden"));
        assert_eq!(permissions_note(0, 0), None);
        // An admin loses nothing.
        let (all, none) = duplicate_selection(&original, &held_admin());
        assert_eq!((all.len(), none), (4, 0));
        // And the create request built from it holds nothing the creator lacks.
        let r = build_create(&values(&kept), TODAY, &eod);
        assert!(r.scopes.iter().all(|s| held.contains(s)));
    }

    #[test]
    fn profiles_are_sent_only_when_they_changed() {
        let held = held_admin();
        let s = [Scope::StatsRead];
        let mut b = baseline(&s);
        b.profiles = Some(vec!["a".into(), "gone".into()]);
        let mut v = values(&s);
        v.all_profiles = false;
        v.chosen = vec!["gone".into(), "a".into()];
        // Same set, any order: nothing sent (an id of a deleted profile cannot cause a refusal).
        assert_eq!(
            profile_change(&b.profiles, false, &v.chosen),
            ProfileChange::Keep
        );
        assert!(update_is_empty(&build_update(&b, &v, &held, TODAY, &eod)));
        // Removing the deleted one sends the new list.
        v.chosen = vec!["a".into()];
        let r = build_update(&b, &v, &held, TODAY, &eod);
        assert_eq!(r.profiles, Some(vec!["a".to_string()]));
        assert!(!r.clear_profiles);
        // Back to all profiles clears the restriction.
        v.all_profiles = true;
        let r = build_update(&b, &v, &held, TODAY, &eod);
        assert!(r.clear_profiles && r.profiles.is_none());
        // An unrestricted token that becomes restricted sets them.
        let b2 = baseline(&s);
        let mut v2 = values(&s);
        v2.all_profiles = false;
        v2.chosen = vec!["x".into()];
        assert_eq!(
            build_update(&b2, &v2, &held, TODAY, &eod).profiles,
            Some(vec!["x".to_string()])
        );
        // Unrestricted and still unrestricted: nothing.
        assert!(update_is_empty(&build_update(
            &b2,
            &values(&s),
            &held,
            TODAY,
            &eod
        )));
        // Ids that no longer exist are found against the known list.
        assert_eq!(
            stale_profiles(&["a".into(), "gone".into()], &["a".into()]),
            vec!["gone".to_string()]
        );
    }

    #[test]
    fn expiry_changes_use_the_right_field() {
        let held = held_admin();
        let s = [Scope::StatsRead];
        let b = baseline(&s);
        let mut v = values(&s);
        v.choice = "30".into();
        assert_eq!(
            build_update(&b, &v, &held, TODAY, &eod).expires_in_days,
            Some(30)
        );
        v.choice = "never".into();
        assert!(build_update(&b, &v, &held, TODAY, &eod).never_expires);
        v.choice = "custom".into();
        v.custom = "2027-03-01".into();
        let r = build_update(&b, &v, &held, TODAY, &eod);
        assert_eq!(r.expires_at.as_deref(), Some("2027-03-01T23:59:59Z"));
        assert!(r.expires_in_days.is_none() && !r.never_expires);
    }

    #[test]
    fn regenerate_of_an_expired_token_needs_a_usable_expiry() {
        // A live token: only the grace window.
        let r = build_regenerate("86400", None, TODAY, &eod).unwrap();
        assert_eq!(r.grace_secs, 86_400);
        assert!(r.expires_in_days.is_none() && r.expires_at.is_none() && !r.never_expires);
        // Expired: the chosen expiry goes along.
        let r = build_regenerate("0", Some(("90", "")), TODAY, &eod).unwrap();
        assert_eq!(r.expires_in_days, Some(90));
        let r = build_regenerate("0", Some(("custom", "2027-01-05")), TODAY, &eod).unwrap();
        assert_eq!(r.expires_at.as_deref(), Some("2027-01-05T23:59:59Z"));
        assert!(
            build_regenerate("0", Some(("never", "")), TODAY, &eod)
                .unwrap()
                .never_expires
        );
        // An expired secret does not work, so no grace period is sent with a new expiry.
        let r = build_regenerate("86400", Some(("90", "")), TODAY, &eod).unwrap();
        assert_eq!(r.grace_secs, 0);
        // A custom choice without a future date is refused before anything is sent.
        assert!(build_regenerate("0", Some(("custom", "")), TODAY, &eod).is_err());
        assert!(build_regenerate("0", Some(("custom", "2026-11-24")), TODAY, &eod).is_err());
    }

    #[test]
    fn review_marks_changed_rows_with_was_and_lists_removed_ones() {
        let before = [Scope::RulesRead, Scope::StatsRead, Scope::LogsRead];
        let now = [Scope::RulesRead, Scope::RulesWrite, Scope::StatsRead];
        let g = granted_vs(&now, Some(&before));
        let find = |a: &str| {
            g.iter()
                .flat_map(|g| &g.rows)
                .find(|r| r.area == a)
                .unwrap()
                .clone()
        };
        assert_eq!(find("Rules").was.as_deref(), Some("was View"));
        assert_eq!(find("Statistics").was, None);
        let log = find("Request log");
        assert_eq!(log.was.as_deref(), Some("was View"));
        assert_eq!((log.level, log.sensitive), ("None", false));
        // Without a baseline nothing is marked.
        assert!(granted(&now)
            .iter()
            .flat_map(|g| &g.rows)
            .all(|r| r.was.is_none()));
    }

    #[test]
    fn refusals_name_the_permission_in_plain_words() {
        let text = "Cannot grant scope 'users:admin' that you do not hold";
        let m = plain_error(Some("scope_escalation"), text);
        assert!(
            m.starts_with("You can't add Users: ")
                && m.ends_with("because your account doesn't have it."),
            "{m}"
        );
        let sw = plain_error(
            Some("scope_escalation"),
            "Cannot grant scope 'userscripts:bridge' that you do not hold",
        );
        assert_eq!(
            sw,
            "You can't add Connect to this browser because your account doesn't have it."
        );
        assert!(
            plain_error(Some("scope_escalation"), "profile 7 is outside yours")
                .contains("Remove that permission or profile")
        );
    }

    #[test]
    fn empty_texts_and_expiry_today_wording() {
        assert_eq!(empty_text(Filter::Expired, true), "No expired tokens.");
        assert_eq!(
            empty_text(Filter::Active, false),
            "No tokens yet. Create one with New token."
        );
        assert_eq!(
            empty_text(Filter::All, true),
            "No tokens yet. Create one with New token."
        );
        assert_eq!(
            expires_today_text(3 * 3600 + 5, true).as_deref(),
            Some("Expires today, in 3 hours")
        );
        assert_eq!(
            expires_today_text(600, true).as_deref(),
            Some("Expires today")
        );
        assert_eq!(expires_today_text(3600, false), None);
        assert_eq!(expires_today_text(-5, true), None);
    }

    #[test]
    fn expiry_wording_follows_the_time_left() {
        assert_eq!(expires_when(1800), "today");
        assert_eq!(expires_when(3 * 3600 + 5), "in 3 hours");
        assert_eq!(expires_when(3600), "in 1 hour");
        assert_eq!(expires_when(30 * 3600), "tomorrow");
        assert_eq!(expires_when(5 * 86_400), "in 5 days");
        let soon = token(false, Some(&at_secs(3 * 3600 + 30)));
        assert_eq!(
            expiring_banner(&[soon], NOW).unwrap().headline,
            "1 token expires in 3 hours"
        );
        let today = token(false, Some(&at_secs(900)));
        assert_eq!(
            expiring_banner(&[today], NOW).unwrap().headline,
            "1 token expires today"
        );
    }
}
