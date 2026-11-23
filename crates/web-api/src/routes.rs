//! The API route table. Every route is registered through `routes!`, i.e. through its
//! `#[utoipa::path]`, so registration and documentation are one act.

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use utoipa_axum::{
    router::{OpenApiRouter, UtoipaMethodRouterExt},
    routes,
};

use crate::handlers::{
    audit, auth, bypass, certificate, certs, devices, health, lists, policy, profiles, proxy,
    rules, stats, tokens, users, userscripts,
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
        // upstream certificates
        .routes(routes!(certs::get_cert))
        .routes(routes!(certs::get_cert_by_host))
        // auth + sessions
        .routes(routes!(auth::register))
        .routes(routes!(auth::registration_status))
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
        .routes(routes!(rules::list_site_exceptions))
        .routes(routes!(
            rules::put_site_exception,
            rules::delete_site_exception
        ))
        .routes(routes!(lists::list_ext_rules))
        .routes(routes!(rules::validate))
        .routes(routes!(rules::test_url))
        // stats
        .routes(routes!(stats::get_filter_stats))
        .routes(routes!(stats::reset_filter_stats))
        .routes(routes!(stats::get_proxy_stats))
        .routes(routes!(stats::get_recent_blocked))
        .routes(routes!(stats::get_timeseries))
        .routes(routes!(stats::get_request_log))
        .routes(routes!(stats::stream_request_log))
        // config
        .routes(routes!(proxy::get_config, proxy::update_config))
        .routes(routes!(proxy::get_config_defaults))
        // bypass
        .routes(routes!(bypass::list_categories))
        .routes(routes!(bypass::update_category))
        .routes(routes!(bypass::category_hosts))
        .routes(routes!(bypass::list_entries, bypass::create_entry))
        .routes(routes!(bypass::update_entry, bypass::delete_entry))
        .routes(routes!(
            bypass::list_subscriptions,
            bypass::create_subscription
        ))
        .routes(routes!(
            bypass::update_subscription,
            bypass::delete_subscription
        ))
        .routes(routes!(bypass::refresh_subscription_now))
        .routes(routes!(bypass::suggested))
        .routes(routes!(bypass::get_argus_lists))
        .routes(routes!(bypass::refresh_argus_lists))
        .routes(routes!(
            bypass::get_bypass_settings,
            bypass::update_bypass_settings
        ))
        .routes(routes!(bypass::check_host))
        .routes(routes!(proxy::reload_config))
        // userscripts
        .routes(routes!(
            userscripts::list_userscripts,
            userscripts::install_userscript
        ))
        .routes(routes!(userscripts::get_stats))
        .routes(routes!(userscripts::plan_userscript))
        .routes(routes!(userscripts::confirm_plan))
        .routes(routes!(userscripts::export_userscripts))
        .routes(
            routes!(userscripts::import_userscripts)
                .layer(DefaultBodyLimit::max(userscripts::MAX_IMPORT_BYTES)),
        )
        .routes(routes!(userscripts::check_update))
        .routes(routes!(userscripts::approve_update))
        .routes(routes!(userscripts::discard_update))
        .routes(routes!(
            userscripts::get_storage,
            userscripts::clear_storage
        ))
        .routes(routes!(userscripts::delete_storage_value))
        .routes(routes!(
            userscripts::get_userscript,
            userscripts::uninstall_userscript
        ))
        .routes(routes!(userscripts::get_userscript_source))
        .routes(routes!(userscripts::set_enabled))
        // script policy
        .routes(routes!(policy::get_settings, policy::put_settings))
        .routes(routes!(policy::list_site_rules, policy::create_site_rule))
        .routes(routes!(policy::update_site_rule, policy::delete_site_rule))
        .routes(routes!(
            policy::list_source_rules,
            policy::create_source_rule
        ))
        .routes(routes!(
            policy::update_source_rule,
            policy::delete_source_rule
        ))
        .routes(routes!(
            policy::list_temp,
            policy::grant_temp,
            policy::revoke_all_temp
        ))
        .routes(routes!(policy::revoke_temp))
        .routes(routes!(policy::explain))
        .routes(routes!(policy::preview))
        .routes(routes!(policy::export))
        .routes(routes!(policy::import))
        .routes(routes!(policy::reports))
        .routes(routes!(policy::get_panel, policy::put_panel))
        // profiles and devices
        .routes(routes!(profiles::list_profiles, profiles::create_profile))
        .routes(routes!(
            profiles::get_profile,
            profiles::update_profile,
            profiles::delete_profile
        ))
        .routes(routes!(devices::list_devices, devices::create_device))
        .routes(routes!(
            devices::get_device,
            devices::update_device,
            devices::delete_device
        ))
        .routes(routes!(
            devices::issue_device_token,
            devices::revoke_device_token
        ))
        // audit
        .routes(routes!(audit::list_audit))
}
