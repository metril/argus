//! API scopes: the single definition of every `resource:action` permission, its description and
//! the role bundles. Route declarations, token creation, the OpenAPI security scheme, the docs
//! table and the web-ui checklist all derive from [`Scope`].

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::UserRole;

macro_rules! scopes {
    ($($variant:ident => $name:literal, $desc:literal;)+) => {
        /// A fine-grained permission, written `resource:action` on the wire.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
        pub enum Scope {
            $(
                #[serde(rename = $name)]
                $variant,
            )+
        }

        impl Scope {
            /// Every scope, in declaration order.
            pub const ALL: &'static [Scope] = &[$(Scope::$variant),+];

            /// The wire form, e.g. `lists:write`.
            pub fn as_str(&self) -> &'static str {
                match self { $(Scope::$variant => $name),+ }
            }

            /// Human description (flows into the OpenAPI spec and docs).
            pub fn description(&self) -> &'static str {
                match self { $(Scope::$variant => $desc),+ }
            }
        }
    };
}

scopes! {
    ListsRead => "lists:read", "View filter lists, their status and the update schedule.";
    ListsWrite => "lists:write", "Add, edit, remove and refresh filter lists; change the update schedule.";
    RulesRead => "rules:read", "Read custom rules; validate rules and test URLs against the engine (no changes).";
    RulesWrite => "rules:write", "Replace the custom rules.";
    RulesSite => "rules:site", "Switch ad blocking off or on for a single site (a document exception in the custom rules); nothing else in the rules.";
    RulesExt => "rules:ext", "Add or remove one custom rule at a time through the browser extension (a single validated line); nothing else in the rules.";
    BypassSite => "bypass:site", "Stop Argus decrypting a single site (a no-decrypt bypass entry made through the browser extension); nothing else in the bypass lists.";
    EngineReload => "engine:reload", "Trigger a rebuild of the blocking engine.";
    StatsRead => "stats:read", "Read blocking, proxy and engine statistics.";
    LogsRead => "logs:read", "Read the request log, live and recent (full browsing history of every client the token may see).";
    StatsReset => "stats:reset", "Reset blocking statistics.";
    ConfigRead => "config:read", "Read the proxy configuration.";
    ConfigWrite => "config:write", "Change or reload the proxy configuration.";
    CaRead => "ca:read", "Read CA certificate details (fingerprint, expiry, subject).";
    CaAdmin => "ca:admin", "Manage the CA certificate (reserved).";
    ScriptsRead => "scripts:read", "View userscripts and their source.";
    ScriptsWrite => "scripts:write", "Install, update, enable, disable and remove userscripts; view and clear their stored values.";
    UserscriptsBridge => "userscripts:bridge", "Connect the browser extension to userscripts: list and trigger a page's menu commands, and let approved scripts use this browser's logins.";
    PolicyRead => "policy:read", "View script policy rules, explanations, temporary permissions and blocked-source reports.";
    PolicyWrite => "policy:write", "Change script policy settings, rules and temporary permissions; import policy.";
    ProfilesRead => "profiles:read", "List and view filtering profiles (lists and overlay rules) the token may access.";
    ProfilesWrite => "profiles:write", "Create, edit and delete filtering profiles.";
    DevicesRead => "devices:read", "List and view devices (profile, addresses, token state; never the token).";
    DevicesWrite => "devices:write", "Create, edit and delete devices; issue and revoke device tokens.";
    UsersRead => "users:read", "List and view user accounts.";
    UsersAdmin => "users:admin", "Create, update, disable and delete user accounts.";
    TokensSelf => "tokens:self", "Create, list and revoke your own API tokens.";
    TokensAdmin => "tokens:admin", "List and revoke any user's API tokens.";
    SessionsSelf => "sessions:self", "Log out, change your password, list and revoke your own sessions.";
    SessionsAdmin => "sessions:admin", "List and revoke any user's sessions.";
    AuditRead => "audit:read", "Read the audit log.";
    SystemRead => "system:read", "Read system status and metrics (JSON and Prometheus).";
}

impl Scope {
    /// The resource part (`lists` in `lists:read`).
    pub fn resource(&self) -> &'static str {
        self.as_str().split(':').next().unwrap_or("")
    }

    /// The action part (`read` in `lists:read`).
    pub fn action(&self) -> &'static str {
        self.as_str().split(':').nth(1).unwrap_or("")
    }

    /// Viewer bundle: every `*:read` except users, audit and the request log, plus `sessions:self`.
    fn in_viewer_bundle(&self) -> bool {
        (self.action() == "read"
            && !matches!(self, Scope::UsersRead | Scope::AuditRead | Scope::LogsRead))
            || matches!(self, Scope::SessionsSelf)
    }

    /// User bundle: viewer plus the request log and writes on lists, rules, scripts, policy and
    /// own tokens.
    fn in_user_bundle(&self) -> bool {
        self.in_viewer_bundle()
            || matches!(
                self,
                Scope::ListsWrite
                    | Scope::RulesWrite
                    | Scope::RulesSite
                    | Scope::RulesExt
                    | Scope::BypassSite
                    | Scope::ScriptsWrite
                    | Scope::UserscriptsBridge
                    | Scope::PolicyWrite
                    | Scope::TokensSelf
                    | Scope::LogsRead
            )
    }
}

/// Template: the scopes of the browser extension. The same constant is minted by
/// `POST /auth/extension-token`.
pub const TEMPLATE_BROWSER_EXTENSION: &[Scope] = &[
    Scope::UserscriptsBridge,
    Scope::RulesSite,
    Scope::RulesExt,
    Scope::BypassSite,
    Scope::LogsRead,
    Scope::StatsRead,
];
pub const TEMPLATE_MONITORING: &[Scope] = &[Scope::StatsRead, Scope::SystemRead];
pub const TEMPLATE_SCRIPT_LISTS_RULES: &[Scope] = &[
    Scope::ListsRead,
    Scope::ListsWrite,
    Scope::RulesRead,
    Scope::RulesWrite,
    Scope::EngineReload,
];

/// One access level of a [`PermRow`]: the scopes it adds on top of the levels before it, and the
/// plain sentence the live summary shows when it is chosen.
#[derive(Debug, Clone, Copy)]
pub struct PermLevel {
    /// `View` or `Edit`.
    pub label: &'static str,
    pub scopes: &'static [Scope],
    pub summary: &'static str,
    /// Flagged with a Sensitive pill.
    pub sensitive: bool,
}

/// What a row of the permission table controls.
#[derive(Debug, Clone, Copy)]
pub enum PermKind {
    /// No access, then each level in order (choosing level `n` grants levels `1..=n`).
    Levels(&'static [PermLevel]),
    /// A single on/off permission.
    Switch {
        scope: Scope,
        summary: &'static str,
        sensitive: bool,
    },
}

/// A row of the permission table.
#[derive(Debug, Clone, Copy)]
pub struct PermRow {
    pub label: &'static str,
    pub description: Option<&'static str>,
    pub kind: PermKind,
}

/// A group of rows.
#[derive(Debug, Clone, Copy)]
pub struct PermGroup {
    pub label: &'static str,
    pub hint: Option<&'static str>,
    /// Every row of the group is sensitive.
    pub sensitive: bool,
    pub rows: &'static [PermRow],
}

macro_rules! lvl {
    ($label:literal, [$($s:expr),+], $sum:literal) => {
        PermLevel { label: $label, scopes: &[$($s),+], summary: $sum, sensitive: false }
    };
    ($label:literal, [$($s:expr),+], $sum:literal, sensitive) => {
        PermLevel { label: $label, scopes: &[$($s),+], summary: $sum, sensitive: true }
    };
}

macro_rules! row {
    ($label:literal, $desc:expr, [$($lv:expr),+]) => {
        PermRow { label: $label, description: $desc, kind: PermKind::Levels(&[$($lv),+]) }
    };
}

macro_rules! switch {
    ($label:literal, $scope:expr, $sum:literal) => {
        PermRow {
            label: $label,
            description: None,
            kind: PermKind::Switch {
                scope: $scope,
                summary: $sum,
                sensitive: false,
            },
        }
    };
}

/// The permission table: the single source of truth for how scopes are presented. Every scope
/// appears in exactly one row (enforced by a test), so a new scope cannot be forgotten.
pub const GROUPS: &[PermGroup] = &[
    PermGroup {
        label: "Filtering",
        hint: None,
        sensitive: false,
        rows: &[
            row!(
                "Filter lists",
                None,
                [
                    lvl!(
                        "View",
                        [Scope::ListsRead],
                        "See filter lists and their status"
                    ),
                    lvl!("Edit", [Scope::ListsWrite], "Change filter lists")
                ]
            ),
            row!(
                "Rules",
                Some("Your custom rules list"),
                [
                    lvl!("View", [Scope::RulesRead], "Read your custom rules"),
                    lvl!("Edit", [Scope::RulesWrite], "Change your custom rules")
                ]
            ),
            switch!(
                "Engine rebuild",
                Scope::EngineReload,
                "Rebuild the blocking engine"
            ),
            row!(
                "Profiles",
                None,
                [
                    lvl!("View", [Scope::ProfilesRead], "See filtering profiles"),
                    lvl!("Edit", [Scope::ProfilesWrite], "Change filtering profiles")
                ]
            ),
        ],
    },
    PermGroup {
        label: "Monitoring",
        hint: None,
        sensitive: false,
        rows: &[
            row!(
                "Statistics",
                None,
                [
                    lvl!("View", [Scope::StatsRead], "See blocking statistics"),
                    lvl!("Edit", [Scope::StatsReset], "Reset blocking statistics")
                ]
            ),
            row!(
                "Request log",
                None,
                [lvl!(
                    "View",
                    [Scope::LogsRead],
                    "See the request log, including browsing history",
                    sensitive
                )]
            ),
            row!(
                "System status and metrics",
                None,
                [lvl!(
                    "View",
                    [Scope::SystemRead],
                    "See system status and metrics"
                )]
            ),
        ],
    },
    PermGroup {
        label: "Browser extension",
        hint: Some("What the Argus browser extension is allowed to do"),
        sensitive: false,
        rows: &[
            switch!(
                "Connect to this browser",
                Scope::UserscriptsBridge,
                "Connect to this browser's userscripts"
            ),
            switch!(
                "Turn Argus on or off for one site",
                Scope::RulesSite,
                "Turn Argus on or off for a single site"
            ),
            switch!(
                "Add single rules",
                Scope::RulesExt,
                "Add or remove single custom rules"
            ),
            switch!(
                "Don't decrypt a site",
                Scope::BypassSite,
                "Stop Argus decrypting a single site"
            ),
        ],
    },
    PermGroup {
        label: "Scripts",
        hint: None,
        sensitive: false,
        rows: &[
            row!(
                "Userscripts",
                None,
                [
                    lvl!(
                        "View",
                        [Scope::ScriptsRead],
                        "See userscripts and their source"
                    ),
                    lvl!(
                        "Edit",
                        [Scope::ScriptsWrite],
                        "Install, change and remove userscripts"
                    )
                ]
            ),
            row!(
                "Script policy",
                None,
                [
                    lvl!("View", [Scope::PolicyRead], "See the script policy"),
                    lvl!("Edit", [Scope::PolicyWrite], "Change the script policy")
                ]
            ),
        ],
    },
    PermGroup {
        label: "Setup",
        hint: None,
        sensitive: false,
        rows: &[
            row!(
                "Configuration",
                None,
                [
                    lvl!("View", [Scope::ConfigRead], "See the proxy configuration"),
                    lvl!(
                        "Edit",
                        [Scope::ConfigWrite],
                        "Change the proxy configuration",
                        sensitive
                    )
                ]
            ),
            row!(
                "Devices",
                None,
                [
                    lvl!("View", [Scope::DevicesRead], "See devices"),
                    lvl!(
                        "Edit",
                        [Scope::DevicesWrite],
                        "Change devices and their tokens"
                    )
                ]
            ),
            row!(
                "Certificate",
                None,
                [
                    lvl!("View", [Scope::CaRead], "See certificate details"),
                    lvl!("Edit", [Scope::CaAdmin], "Manage the certificate")
                ]
            ),
        ],
    },
    PermGroup {
        label: "Your account",
        hint: None,
        sensitive: false,
        rows: &[
            switch!(
                "Your API tokens",
                Scope::TokensSelf,
                "Manage your own API tokens"
            ),
            switch!(
                "Your sessions",
                Scope::SessionsSelf,
                "Manage your own sessions and password"
            ),
        ],
    },
    PermGroup {
        label: "Administration",
        hint: None,
        sensitive: true,
        rows: &[
            row!(
                "Users",
                None,
                [
                    lvl!("View", [Scope::UsersRead], "See user accounts"),
                    lvl!(
                        "Edit",
                        [Scope::UsersAdmin],
                        "Create, change and delete user accounts"
                    )
                ]
            ),
            switch!(
                "Everyone's tokens",
                Scope::TokensAdmin,
                "See and revoke any user's tokens"
            ),
            switch!(
                "Everyone's sessions",
                Scope::SessionsAdmin,
                "See and revoke any user's sessions"
            ),
            row!(
                "Audit log",
                None,
                [lvl!("View", [Scope::AuditRead], "Read the audit log")]
            ),
        ],
    },
];

impl PermRow {
    fn levels(&self) -> &'static [PermLevel] {
        match self.kind {
            PermKind::Levels(l) => l,
            PermKind::Switch { .. } => &[],
        }
    }

    /// Number of levels above "no access" (a switch counts as one).
    pub fn level_count(&self) -> usize {
        match self.kind {
            PermKind::Levels(l) => l.len(),
            PermKind::Switch { .. } => 1,
        }
    }

    /// Scopes granted by level `n` (`0` = none): the union of levels `1..=n`.
    pub fn scopes_at(&self, n: usize) -> Vec<Scope> {
        match self.kind {
            PermKind::Switch { scope, .. } => (n > 0).then_some(scope).into_iter().collect(),
            PermKind::Levels(l) => l
                .iter()
                .take(n)
                .flat_map(|l| l.scopes.iter().copied())
                .collect(),
        }
    }

    /// The highest level (`0` = none) that has any scope in `selected`.
    pub fn level_of(&self, selected: &[Scope]) -> usize {
        match self.kind {
            PermKind::Switch { scope, .. } => usize::from(selected.contains(&scope)),
            PermKind::Levels(l) => l
                .iter()
                .rposition(|l| l.scopes.iter().any(|s| selected.contains(s)))
                .map_or(0, |i| i + 1),
        }
    }

    /// The highest level the holder of `held` can grant (`0` = none).
    pub fn available(&self, held: &[Scope]) -> usize {
        (1..=self.level_count())
            .take_while(|n| self.scopes_at(*n).iter().all(|s| held.contains(s)))
            .count()
    }

    /// Sentence for the live summary at level `n` (`None` for no access).
    pub fn summary_at(&self, n: usize) -> Option<&'static str> {
        match self.kind {
            PermKind::Switch { summary, .. } => (n > 0).then_some(summary),
            PermKind::Levels(l) => n.checked_sub(1).and_then(|i| l.get(i)).map(|l| l.summary),
        }
    }

    /// Whether level `n` is flagged Sensitive.
    pub fn sensitive_at(&self, n: usize) -> bool {
        match self.kind {
            PermKind::Switch { sensitive, .. } => n > 0 && sensitive,
            PermKind::Levels(l) => n
                .checked_sub(1)
                .and_then(|i| l.get(i))
                .is_some_and(|l| l.sensitive),
        }
    }

    /// The scopes of every `View` level (the first level of a row with levels).
    fn view_scopes(&self) -> &'static [Scope] {
        match self.levels().first() {
            Some(l) if l.label == "View" => l.scopes,
            _ => &[],
        }
    }
}

/// Every View scope in `held`: the Read-only template.
pub fn read_only_scopes(held: &[Scope]) -> Vec<Scope> {
    GROUPS
        .iter()
        .flat_map(|g| g.rows)
        .flat_map(|r| r.view_scopes().iter().copied())
        .filter(|s| held.contains(s))
        .collect()
}

/// A named starting point for a token.
#[derive(Debug, Clone, Copy)]
pub struct Template {
    pub purpose: crate::TokenPurpose,
    pub label: &'static str,
    /// `None`: derived from what the creator holds (Full access, Read-only).
    pub scopes: Option<&'static [Scope]>,
}

pub const TEMPLATES: &[Template] = &[
    Template {
        purpose: crate::TokenPurpose::Extension,
        label: "Browser extension",
        scopes: Some(TEMPLATE_BROWSER_EXTENSION),
    },
    Template {
        purpose: crate::TokenPurpose::Monitoring,
        label: "Monitoring",
        scopes: Some(TEMPLATE_MONITORING),
    },
    Template {
        purpose: crate::TokenPurpose::Script,
        label: "Script for lists and rules",
        scopes: Some(TEMPLATE_SCRIPT_LISTS_RULES),
    },
    Template {
        purpose: crate::TokenPurpose::Full,
        label: "Full access",
        scopes: None,
    },
    Template {
        purpose: crate::TokenPurpose::ReadOnly,
        label: "Read-only",
        scopes: None,
    },
];

impl Template {
    /// The scopes this template grants to a creator holding `held` (never more than `held`).
    pub fn scopes_for(&self, held: &[Scope]) -> Vec<Scope> {
        match (self.scopes, self.purpose) {
            (Some(fixed), _) => fixed.iter().copied().filter(|s| held.contains(s)).collect(),
            (None, crate::TokenPurpose::ReadOnly) => read_only_scopes(held),
            (None, _) => held.to_vec(),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Scope::ALL
            .iter()
            .copied()
            .find(|sc| sc.as_str() == s)
            .ok_or_else(|| format!("unknown scope '{s}'"))
    }
}

impl UserRole {
    /// The named scope bundle this role grants.
    pub fn scopes(&self) -> Vec<Scope> {
        Scope::ALL
            .iter()
            .copied()
            .filter(|s| match self {
                UserRole::Admin => true,
                UserRole::User => s.in_user_bundle(),
                UserRole::Viewer => s.in_viewer_bundle(),
            })
            .collect()
    }
}

/// Markdown table of every scope with the roles that include it (generates docs/API.md).
pub fn scope_table_markdown() -> String {
    let mut out =
        String::from("| Scope | Viewer | User | Admin | Description |\n|---|---|---|---|---|\n");
    for s in Scope::ALL {
        let mark = |r: UserRole| if r.scopes().contains(s) { "yes" } else { "-" };
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            s,
            mark(UserRole::Viewer),
            mark(UserRole::User),
            mark(UserRole::Admin),
            s.description()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_bundles_nest() {
        for s in Scope::ALL {
            assert_eq!(s.as_str().parse::<Scope>().unwrap(), *s);
            assert_eq!(
                serde_json::to_string(s).unwrap(),
                format!("\"{}\"", s.as_str())
            );
        }
        let v = UserRole::Viewer.scopes();
        let u = UserRole::User.scopes();
        assert!(v.iter().all(|s| u.contains(s)));
        assert_eq!(UserRole::Admin.scopes().len(), Scope::ALL.len());
        assert!(!v.contains(&Scope::UsersRead) && !v.contains(&Scope::AuditRead));
        assert!(u.contains(&Scope::ListsWrite) && !u.contains(&Scope::ConfigWrite));
    }

    #[test]
    fn every_scope_is_in_exactly_one_group_row() {
        for s in Scope::ALL {
            let n = GROUPS
                .iter()
                .flat_map(|g| g.rows)
                .filter(|r| (1..=r.level_count()).any(|n| r.scopes_at(n).contains(s)))
                .count();
            assert_eq!(n, 1, "{s} appears in {n} rows");
        }
    }

    #[test]
    fn rows_round_trip_and_templates_use_known_scopes() {
        for r in GROUPS.iter().flat_map(|g| g.rows) {
            for n in 0..=r.level_count() {
                assert_eq!(r.level_of(&r.scopes_at(n)), n, "{}", r.label);
                assert_eq!(r.summary_at(n).is_some(), n > 0, "{}", r.label);
            }
        }
        for t in TEMPLATES {
            for s in t.scopes.unwrap_or(&[]) {
                assert!(Scope::ALL.contains(s));
            }
        }
        let all = Scope::ALL.to_vec();
        let ro = read_only_scopes(&all);
        assert!(ro.contains(&Scope::ListsRead) && !ro.contains(&Scope::ListsWrite));
        assert!(!ro.contains(&Scope::RulesSite) && ro.contains(&Scope::AuditRead));
        let ext = TEMPLATES[0].scopes_for(&all);
        assert_eq!(ext, TEMPLATE_BROWSER_EXTENSION);
        assert!(ext.contains(&Scope::BypassSite));
        assert_eq!(TEMPLATES[3].scopes_for(&all), all);
        // Never more than held.
        assert_eq!(
            TEMPLATES[1].scopes_for(&[Scope::StatsRead]),
            vec![Scope::StatsRead]
        );
    }

    #[test]
    fn bypass_site_is_in_user_and_admin_bundles_only() {
        assert!(UserRole::User.scopes().contains(&Scope::BypassSite));
        assert!(UserRole::Admin.scopes().contains(&Scope::BypassSite));
        assert!(!UserRole::Viewer.scopes().contains(&Scope::BypassSite));
    }

    #[test]
    fn levels_round_trip() {
        for r in GROUPS.iter().flat_map(|g| g.rows) {
            for n in 0..=r.level_count() {
                assert_eq!(r.level_of(&r.scopes_at(n)), n, "{}", r.label);
            }
        }
        let lists = GROUPS[0].rows.first().unwrap();
        assert_eq!(
            lists.scopes_at(2),
            vec![Scope::ListsRead, Scope::ListsWrite]
        );
        assert_eq!(lists.available(&[Scope::ListsRead]), 1);
        assert_eq!(lists.available(&[]), 0);
    }
}
