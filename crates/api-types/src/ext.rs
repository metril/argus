//! Extension bridge DTOs (`/ext/menu`, `/ext/menu/trigger`).

use serde::{Deserialize, Serialize};

fn yes() -> bool {
    true
}

/// One userscript menu command of a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtMenuCommand {
    /// Script id.
    pub script: String,
    pub script_name: String,
    /// Command id (opaque, unique within the script).
    pub cmd: String,
    pub name: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub title: String,
    /// Close the popup after triggering (default true).
    #[serde(default = "yes")]
    pub auto_close: bool,
}

/// A script that wants this browser's logins for hosts the extension holds no permission for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtGrant {
    pub script: String,
    pub script_name: String,
    /// Host (or `*.host`) shown to the user.
    pub host: String,
    /// Host permission patterns to request, e.g. `*://a.com/*`.
    pub patterns: Vec<String>,
}

/// Menu commands of one document plus host grants its scripts are waiting for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtMenuResponse {
    pub commands: Vec<ExtMenuCommand>,
    pub grants: Vec<ExtGrant>,
}

/// Trigger one command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtTriggerRequest {
    pub mdoc: String,
    pub script: String,
    pub cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtTriggerResponse {
    /// The page's runtime was waiting (or the command was queued for it).
    pub delivered: bool,
}

// ---- plain types shared by the proxy hub and the web API (not part of the OpenAPI document)

/// Who opened an extension channel (the bridge token's owner).
#[derive(Debug, Clone)]
pub struct ExtIdent {
    pub token_id: String,
    pub user: String,
    /// Profile ids (decimal) the token is restricted to; `None`: all profiles.
    pub profiles: Option<Vec<String>>,
}

/// What the hub asks the channel handler to put on the socket.
#[derive(Debug)]
pub enum ExtOut {
    Text(String),
    Binary(Vec<u8>),
    Close(u16),
}

/// Why a menu call was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtError {
    /// The document is not bound to the caller's session (or the session is gone).
    Forbidden,
    NotFound,
}

/// An audit record the hub raises for the persisted audit log.
#[derive(Debug, Clone)]
pub struct ExtAuditEvent {
    pub actor: String,
    /// `session_open`, `session_close`, `perms`, `relay`, ...
    pub action: String,
    pub target: Option<String>,
}

/// One request of the extension session's log (`GET /ext/log`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtLogEntry {
    /// Position in the session's log; pass the highest one seen as `since`.
    pub seq: u64,
    /// RFC 3339.
    pub time: String,
    /// The full request URL, query included.
    pub url: String,
    pub method: String,
    /// Request type (`script`, `image`, `xhr`, ...).
    #[serde(rename = "type")]
    pub request_type: String,
    /// Whether the request went to another registrable domain than the page; `null` when the
    /// page is unknown.
    pub third_party: Option<bool>,
    /// `blocked`, `allowed`, `redirected`, `modified` or `aborted`.
    pub outcome: String,
    /// The matched rule text.
    pub rule: Option<String>,
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    /// The rule is one of the user's custom rules.
    pub user_rule: bool,
    /// Host of the page that made the request.
    pub source_host: String,
}

/// The requests of one extension session after `since`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtLogResponse {
    /// Pass as `since` next time.
    pub next: u64,
    /// Oldest first.
    pub entries: Vec<ExtLogEntry>,
}

/// One attribute a `$cookie` rule changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtCookieChange {
    /// `max_age`, `expires` or `same_site`.
    pub attr: String,
    /// The value the server sent (`max_age` and `expires` in seconds, `expires` since the epoch;
    /// `same_site` lowercase); absent when it sent none.
    pub from: Option<String>,
    /// The value after the rule; absent when the rule removed the attribute.
    pub to: Option<String>,
    /// The rule whose value is the one that was applied (a later rule's value can win over an
    /// earlier one's, per attribute; `expires` follows `max_age`).
    pub rule: Option<String>,
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    /// The rule is one of the user's custom rules.
    pub user_rule: bool,
}

/// The attributes of a `Set-Cookie` exactly as the server sent them. Never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtCookieAttrs {
    /// Lowercase, without the leading dot; absent for a host-only cookie.
    pub domain: Option<String>,
    /// Absent when the server sent none (the browser then uses the request's default path).
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    /// `none`, `lax` or `strict`; absent when the server sent none.
    pub same_site: Option<String>,
    /// Seconds; zero or negative expires the cookie at once.
    pub max_age: Option<i64>,
    /// Seconds since the epoch.
    pub expires: Option<i64>,
    pub partitioned: bool,
}

/// One cookie event seen in transit (`GET /ext/cookies/provenance`). Carries no cookie value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtCookieRecord {
    /// Position in the session's records; pass the highest one seen (or `next_since`) as `since`.
    pub seq: u64,
    /// RFC 3339, millisecond precision.
    pub time: String,
    /// `set` (passed through unchanged), `changed` (a rule changed attributes), `stripped` (a rule
    /// removed the `Set-Cookie`) or `blocked_send` (a rule removed the cookie from a request).
    pub effect: String,
    pub name: String,
    /// Host of the request whose response set the cookie (or whose request carried it).
    pub host: String,
    /// Path of that request, without the query string.
    pub path: String,
    /// Host of the page that made the request (the request's own host for a document); empty when
    /// unknown.
    pub page_host: String,
    /// Whether `host` is on another registrable domain than the page; absent when unknown.
    pub third_party: Option<bool>,
    /// The attributes as the server sent them (all defaults for `blocked_send`).
    pub attrs: ExtCookieAttrs,
    /// What a rule changed (`changed` only).
    pub changes: Vec<ExtCookieChange>,
    /// `__Host-` or `__Secure-` when the name carries that prefix.
    pub prefix: Option<String>,
    /// Whether the attributes satisfy what the prefix implies; absent without a prefix.
    pub prefix_valid: Option<bool>,
    /// The rule that changed, removed or blocked the cookie.
    pub rule: Option<String>,
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    /// The rule is one of the user's custom rules.
    pub user_rule: bool,
}

/// The cookie provenance of one extension session after `since`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtCookieProvenance {
    /// False while the setting is off (`records` is then empty).
    pub enabled: bool,
    /// Oldest first.
    pub records: Vec<ExtCookieRecord>,
    /// Pass as `since` next time.
    pub next_since: u64,
    /// More records follow: ask again with `next_since` right away.
    pub more: bool,
}

/// Add or remove one custom rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtRuleRequest {
    /// `add` or `remove`.
    pub op: String,
    /// One rule line (at most 2 KB; no comments, includes or preprocessor lines).
    pub rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtRuleResult {
    /// Number of custom rules after the change.
    pub rule_count: usize,
    /// The custom rules actually changed.
    pub changed: bool,
}

/// The custom rules scoped to a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtSiteRules {
    pub site: String,
    pub rules: Vec<ExtSiteRule>,
}

/// One custom rule scoped to a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtSiteRule {
    pub rule: String,
    /// True when the rule is scoped to this site only (not shared with other domains).
    pub exclusive: bool,
}

#[cfg(test)]
mod cookie_wire_tests {
    use super::*;

    fn keys<T: Serialize>(v: &T) -> Vec<String> {
        let mut k: Vec<String> = serde_json::to_value(v)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    }

    /// The cookie provenance wire types carry names, attributes, hosts and rules, never a value:
    /// a new field fails this list until the owner reviews it.
    #[test]
    fn cookie_provenance_types_have_no_field_that_could_hold_a_value() {
        let change = ExtCookieChange {
            attr: String::new(),
            from: None,
            to: None,
            rule: None,
            list_id: None,
            list_name: None,
            user_rule: false,
        };
        assert_eq!(
            keys(&change),
            [
                "attr",
                "from",
                "list_id",
                "list_name",
                "rule",
                "to",
                "user_rule"
            ]
        );
        assert_eq!(
            keys(&ExtCookieAttrs::default()),
            [
                "domain",
                "expires",
                "http_only",
                "max_age",
                "partitioned",
                "path",
                "same_site",
                "secure"
            ]
        );
        let rec = ExtCookieRecord {
            seq: 0,
            time: String::new(),
            effect: String::new(),
            name: String::new(),
            host: String::new(),
            path: String::new(),
            page_host: String::new(),
            third_party: None,
            attrs: ExtCookieAttrs::default(),
            changes: vec![],
            prefix: None,
            prefix_valid: None,
            rule: None,
            list_id: None,
            list_name: None,
            user_rule: false,
        };
        assert_eq!(
            keys(&rec),
            [
                "attrs",
                "changes",
                "effect",
                "host",
                "list_id",
                "list_name",
                "name",
                "page_host",
                "path",
                "prefix",
                "prefix_valid",
                "rule",
                "seq",
                "third_party",
                "time",
                "user_rule"
            ]
        );
        assert_eq!(
            keys(&ExtCookieProvenance {
                enabled: false,
                records: vec![],
                next_since: 0,
                more: false
            }),
            ["enabled", "more", "next_since", "records"]
        );
    }
}
