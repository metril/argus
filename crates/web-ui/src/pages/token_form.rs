//! Pure logic behind the token form: expiry choices and dates, scope levels, templates and the
//! token-list summary. Kept free of the DOM so it is unit-testable.

use api_types::scopes::{Resource, RESOURCES, TEMPLATE_BROWSER_EXTENSION, TEMPLATE_MONITORING};
use api_types::Scope;

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

// ---- scopes -------------------------------------------------------------------------------

/// Make `selected` grant level `n` (0 = none) of resource `r`, leaving other resources alone.
pub fn set_level(selected: &mut Vec<Scope>, r: &Resource, n: usize) {
    selected.retain(|s| !r.levels.iter().any(|l| l.scopes.contains(s)));
    selected.extend(r.scopes_at(n));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    ReadOnly,
    BrowserExtension,
    Monitoring,
    Custom,
}

impl Template {
    pub const ALL: [Template; 4] = [
        Template::ReadOnly,
        Template::BrowserExtension,
        Template::Monitoring,
        Template::Custom,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Template::ReadOnly => "read",
            Template::BrowserExtension => "ext",
            Template::Monitoring => "mon",
            Template::Custom => "custom",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Template::ReadOnly => "Read-only",
            Template::BrowserExtension => "Browser extension",
            Template::Monitoring => "Monitoring",
            Template::Custom => "Custom",
        }
    }

    pub fn from_key(k: &str) -> Template {
        Self::ALL
            .into_iter()
            .find(|t| t.key() == k)
            .unwrap_or(Template::Custom)
    }

    /// The scopes this template grants to someone who holds `held`; `None` for Custom.
    pub fn scopes(self, held: &[Scope]) -> Option<Vec<Scope>> {
        let keep = |list: Vec<Scope>| {
            let mut v: Vec<Scope> = list.into_iter().filter(|s| held.contains(s)).collect();
            v.sort();
            v
        };
        match self {
            Template::ReadOnly => Some(keep(
                held.iter()
                    .copied()
                    .filter(|s| s.action() == "read")
                    .collect(),
            )),
            Template::BrowserExtension => Some(keep(TEMPLATE_BROWSER_EXTENSION.to_vec())),
            Template::Monitoring => Some(keep(TEMPLATE_MONITORING.to_vec())),
            Template::Custom => None,
        }
    }
}

/// Which template `selected` equals exactly (otherwise Custom).
pub fn template_of(selected: &[Scope], held: &[Scope]) -> Template {
    let mut sel = selected.to_vec();
    sel.sort();
    Template::ALL
        .into_iter()
        .find(|t| t.scopes(held).is_some_and(|s| !s.is_empty() && s == sel))
        .unwrap_or(Template::Custom)
}

/// Resources split into the everyday rows and the admin ones, restricted to what `held` allows.
pub fn rows(held: &[Scope], admin: bool) -> Vec<&'static Resource> {
    RESOURCES
        .iter()
        .filter(|r| r.admin == admin && r.available(held) > 0)
        .collect()
}

/// Short and full description of a token's scopes: "Lists: read & write · Logs: read · +3".
pub fn summarize(scopes: &[Scope]) -> (String, String) {
    let parts: Vec<String> = RESOURCES
        .iter()
        .filter_map(|r| {
            let n = r.level_of(scopes);
            (n > 0).then(|| format!("{}: {}", r.label, r.levels[n - 1].label.to_lowercase()))
        })
        .collect();
    let full = parts.join(", ");
    let short = match parts.len() {
        0 => "No access".to_string(),
        1..=2 => parts.join(" · "),
        n => format!("{} · +{}", parts[..2].join(" · "), n - 2),
    };
    (short, full)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: Ymd = (2026, 11, 24);

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
        assert_eq!(line("never", ""), "This token never expires");
        assert_eq!(line("custom", "2026-12-25"), "Expires on Fri, 25 Dec 2026");
        assert_eq!(line("custom", "2026-11-24"), "Pick a date after today");
        assert_eq!(line("custom", ""), "Pick a date after today");
        assert_eq!(resolve_expiry("7", "", TODAY), Expiry::Days(7));
    }

    #[test]
    fn levels_round_trip_and_leave_other_rows_alone() {
        let lists = &RESOURCES[0];
        let logs = RESOURCES.iter().find(|r| r.label == "Logs").unwrap();
        let mut sel = vec![];
        set_level(&mut sel, logs, 1);
        set_level(&mut sel, lists, 2);
        assert_eq!(lists.level_of(&sel), 2);
        set_level(&mut sel, lists, 1);
        assert_eq!(sel, vec![Scope::LogsRead, Scope::ListsRead]);
        set_level(&mut sel, lists, 0);
        assert_eq!(sel, vec![Scope::LogsRead]);
    }

    #[test]
    fn templates_match_exactly_and_editing_means_custom() {
        let held = api_types::UserRole::User.scopes();
        let ext = Template::BrowserExtension.scopes(&held).unwrap();
        assert_eq!(template_of(&ext, &held), Template::BrowserExtension);
        let mut edited = ext.clone();
        edited.push(Scope::ListsRead);
        assert_eq!(template_of(&edited, &held), Template::Custom);
        assert_eq!(template_of(&[], &held), Template::Custom);
        // A template only grants what the holder has: a viewer keeps only stats:read.
        let viewer = api_types::UserRole::Viewer.scopes();
        assert_eq!(
            Template::BrowserExtension.scopes(&viewer).unwrap(),
            vec![Scope::StatsRead]
        );
        let ro = Template::ReadOnly.scopes(&held).unwrap();
        assert!(ro.iter().all(|s| s.action() == "read"));
        assert_eq!(template_of(&ro, &held), Template::ReadOnly);
    }

    #[test]
    fn admin_rows_are_separate_and_follow_what_is_held() {
        let user = api_types::UserRole::User.scopes();
        assert!(rows(&user, true).is_empty());
        assert!(!rows(&user, false).is_empty());
        let admin = api_types::UserRole::Admin.scopes();
        assert!(rows(&admin, true).iter().any(|r| r.label == "Users"));
        assert!(rows(&admin, false).iter().all(|r| !r.admin));
    }

    #[test]
    fn summary_is_short_with_a_full_version() {
        let (short, full) = summarize(&[Scope::ListsRead, Scope::ListsWrite, Scope::LogsRead]);
        assert_eq!(short, "Lists: read & write · Logs: read");
        assert_eq!(full, "Lists: read & write, Logs: read");
        let many = [
            Scope::ListsRead,
            Scope::LogsRead,
            Scope::StatsRead,
            Scope::SystemRead,
            Scope::CaRead,
        ];
        let (short, _) = summarize(&many);
        assert!(short.ends_with("· +3"), "{short}");
        assert_eq!(summarize(&[]).0, "No access");
    }
}
