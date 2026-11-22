//! The API route table. Every route is registered through `routes!`, i.e. through its
//! `#[utoipa::path]`, so registration and documentation are one act.

use std::sync::Arc;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::handlers::{
    audit, auth, certificate, health, lists, proxy, rules, stats, tokens, users, userscripts,
};
use crate::state::AppState;

/// Mount point of the versioned API.
pub const API_PREFIX: &str = "/api/v1";

/// All v1 routes (paths relative to [`API_PREFIX`]).
pub fn api_router() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        // system
        .routes(routes!(health::health_check))
        .routes(routes!(health::openapi_json))
        .routes(routes!(health::system_status))
        .routes(routes!(health::metrics))
        .routes(routes!(health::metrics_prometheus))
        // CA
        .routes(routes!(certificate::download_ca))
        .routes(routes!(certificate::download_ca_der))
        .routes(routes!(certificate::ca_info))
        // auth + sessions
        .routes(routes!(auth::register))
        .routes(routes!(auth::login))
        .routes(routes!(auth::refresh))
        .routes(routes!(auth::logout))
        .routes(routes!(auth::me))
        .routes(routes!(auth::change_password))
        .routes(routes!(auth::list_sessions))
        .routes(routes!(auth::revoke_session))
        .routes(routes!(auth::admin_list_sessions))
        .routes(routes!(auth::admin_revoke_session))
        // users
        .routes(routes!(users::list_users, users::create_user))
        .routes(routes!(
            users::get_user,
            users::update_user,
            users::delete_user
        ))
        // tokens
        .routes(routes!(tokens::list_tokens, tokens::create_token))
        .routes(routes!(tokens::revoke_token))
        .routes(routes!(tokens::admin_list_tokens))
        .routes(routes!(tokens::admin_revoke_token))
        // lists
        .routes(routes!(lists::list_filter_lists, lists::add_filter_list))
        .routes(routes!(lists::refresh_all_lists))
        .routes(routes!(lists::get_catalogue))
        .routes(routes!(lists::add_from_catalogue))
        .routes(routes!(lists::get_schedule, lists::put_schedule))
        .routes(routes!(
            lists::get_filter_list,
            lists::update_filter_list,
            lists::delete_filter_list
        ))
        .routes(routes!(lists::get_list_status))
        .routes(routes!(lists::get_list_report))
        .routes(routes!(lists::refresh_list))
        // engine
        .routes(routes!(lists::reload_engine))
        .routes(routes!(lists::get_engine_status))
        .routes(routes!(lists::get_build_summary))
        // rules
        .routes(routes!(rules::get_custom_rules, rules::update_custom_rules))
        .routes(routes!(rules::get_custom_report))
        .routes(routes!(lists::list_ext_rules))
        .routes(routes!(rules::validate))
        .routes(routes!(rules::test_url))
        // stats
        .routes(routes!(stats::get_filter_stats))
        .routes(routes!(stats::reset_filter_stats))
        .routes(routes!(stats::get_proxy_stats))
        .routes(routes!(stats::get_recent_blocked))
        // config
        .routes(routes!(proxy::get_config, proxy::update_config))
        .routes(routes!(proxy::reload_config))
        // userscripts
        .routes(routes!(
            userscripts::list_userscripts,
            userscripts::install_userscript
        ))
        .routes(routes!(userscripts::get_stats))
        .routes(routes!(
            userscripts::get_userscript,
            userscripts::update_userscript,
            userscripts::uninstall_userscript
        ))
        .routes(routes!(userscripts::get_userscript_source))
        .routes(routes!(userscripts::set_enabled))
        // audit
        .routes(routes!(audit::list_audit))
}
