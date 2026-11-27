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
                    | Scope::ScriptsWrite
                    | Scope::UserscriptsBridge
                    | Scope::PolicyWrite
                    | Scope::TokensSelf
                    | Scope::LogsRead
            )
    }
}

/// One access level of a [`Resource`]: the scopes it adds on top of the levels before it.
#[derive(Debug, Clone, Copy)]
pub struct Level {
    pub label: &'static str,
    pub scopes: &'static [Scope],
}

/// A row of the token form: a resource with ordered access levels (none, then each level here).
/// Choosing level `n` grants every scope of levels `1..=n`.
#[derive(Debug, Clone, Copy)]
pub struct Resource {
    pub label: &'static str,
    /// Shown in the collapsed "Admin access" section.
    pub admin: bool,
    pub levels: &'static [Level],
}

const fn lv(label: &'static str, scopes: &'static [Scope]) -> Level {
    Level { label, scopes }
}

/// Every scope appears in exactly one level of exactly one resource (enforced by a test), so a
/// new scope cannot be forgotten by the token form.
pub const RESOURCES: &[Resource] = &[
    Resource {
        label: "Lists",
        admin: false,
        levels: &[
            lv("Read", &[Scope::ListsRead]),
            lv("Read & write", &[Scope::ListsWrite]),
        ],
    },
    Resource {
        label: "Rules",
        admin: false,
        levels: &[
            lv("Read", &[Scope::RulesRead]),
            lv("Per-site switch", &[Scope::RulesSite]),
            lv("Read & write", &[Scope::RulesWrite]),
        ],
    },
    Resource {
        label: "Engine",
        admin: false,
        levels: &[lv("Reload", &[Scope::EngineReload])],
    },
    Resource {
        label: "Stats",
        admin: false,
        levels: &[
            lv("Read", &[Scope::StatsRead]),
            lv("Read + reset", &[Scope::StatsReset]),
        ],
    },
    Resource {
        label: "Logs",
        admin: false,
        levels: &[lv("Read", &[Scope::LogsRead])],
    },
    Resource {
        label: "Config",
        admin: false,
        levels: &[
            lv("Read", &[Scope::ConfigRead]),
            lv("Read & write", &[Scope::ConfigWrite]),
        ],
    },
    Resource {
        label: "Certificate",
        admin: false,
        levels: &[lv("Read", &[Scope::CaRead])],
    },
    Resource {
        label: "Userscripts",
        admin: false,
        levels: &[
            lv("Read", &[Scope::ScriptsRead]),
            lv("Read & write", &[Scope::ScriptsWrite]),
        ],
    },
    Resource {
        label: "Extension",
        admin: false,
        levels: &[lv("Connect", &[Scope::UserscriptsBridge])],
    },
    Resource {
        label: "Policy",
        admin: false,
        levels: &[
            lv("Read", &[Scope::PolicyRead]),
            lv("Read & write", &[Scope::PolicyWrite]),
        ],
    },
    Resource {
        label: "Profiles",
        admin: false,
        levels: &[
            lv("Read", &[Scope::ProfilesRead]),
            lv("Read & write", &[Scope::ProfilesWrite]),
        ],
    },
    Resource {
        label: "Devices",
        admin: false,
        levels: &[
            lv("Read", &[Scope::DevicesRead]),
            lv("Read & write", &[Scope::DevicesWrite]),
        ],
    },
    Resource {
        label: "Own tokens",
        admin: false,
        levels: &[lv("Manage", &[Scope::TokensSelf])],
    },
    Resource {
        label: "Own sessions",
        admin: false,
        levels: &[lv("Manage", &[Scope::SessionsSelf])],
    },
    Resource {
        label: "System",
        admin: false,
        levels: &[lv("Read", &[Scope::SystemRead])],
    },
    Resource {
        label: "Users",
        admin: true,
        levels: &[
            lv("Read", &[Scope::UsersRead]),
            lv("Manage", &[Scope::UsersAdmin]),
        ],
    },
    Resource {
        label: "All tokens",
        admin: true,
        levels: &[lv("Manage", &[Scope::TokensAdmin])],
    },
    Resource {
        label: "All sessions",
        admin: true,
        levels: &[lv("Manage", &[Scope::SessionsAdmin])],
    },
    Resource {
        label: "Certificate admin",
        admin: true,
        levels: &[lv("Manage", &[Scope::CaAdmin])],
    },
    Resource {
        label: "Audit log",
        admin: true,
        levels: &[lv("Read", &[Scope::AuditRead])],
    },
];

impl Resource {
    /// Scopes granted by level `n` (`0` = none): the union of levels `1..=n`.
    pub fn scopes_at(&self, n: usize) -> Vec<Scope> {
        self.levels
            .iter()
            .take(n)
            .flat_map(|l| l.scopes.iter().copied())
            .collect()
    }

    /// The highest level (`0` = none) that has any scope in `selected`.
    pub fn level_of(&self, selected: &[Scope]) -> usize {
        self.levels
            .iter()
            .rposition(|l| l.scopes.iter().any(|s| selected.contains(s)))
            .map_or(0, |i| i + 1)
    }

    /// Whether the holder of `held` can grant at least the first level.
    pub fn available(&self, held: &[Scope]) -> usize {
        (1..=self.levels.len())
            .take_while(|n| self.scopes_at(*n).iter().all(|s| held.contains(s)))
            .count()
    }
}

/// Template: scopes for a one-click preset.
pub const TEMPLATE_BROWSER_EXTENSION: &[Scope] = &[
    Scope::LogsRead,
    Scope::UserscriptsBridge,
    Scope::StatsRead,
    Scope::RulesSite,
];
pub const TEMPLATE_MONITORING: &[Scope] = &[Scope::StatsRead, Scope::SystemRead];

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
    fn every_scope_is_in_exactly_one_level() {
        for s in Scope::ALL {
            let n = RESOURCES
                .iter()
                .flat_map(|r| r.levels)
                .filter(|l| l.scopes.contains(s))
                .count();
            assert_eq!(n, 1, "{s} appears in {n} levels");
        }
    }

    #[test]
    fn levels_round_trip() {
        for r in RESOURCES {
            for n in 0..=r.levels.len() {
                assert_eq!(r.level_of(&r.scopes_at(n)), n, "{}", r.label);
            }
        }
        let lists = &RESOURCES[0];
        assert_eq!(
            lists.scopes_at(2),
            vec![Scope::ListsRead, Scope::ListsWrite]
        );
        assert_eq!(lists.available(&[Scope::ListsRead]), 1);
        assert_eq!(lists.available(&[]), 0);
    }
}
