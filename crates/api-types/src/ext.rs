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

/// The custom rules that mention a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtSiteRules {
    pub site: String,
    pub rules: Vec<String>,
}
