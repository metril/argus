//! Settings card: built-in HTTPS for the web UI (Argus CA certificate or an uploaded one).
//! Applied by its own button: the page moves to the other protocol when HTTPS is switched on or off.

use leptos::prelude::*;

use crate::api::proxy::{WebUiTlsMode, WebUiTlsRequest, WebUiTlsStatus, WebUiTlsUpload};
use crate::api::ApiClient;
use crate::components::{ConfirmButton, TagInput};
use crate::state::use_app_state;
use crate::utils::api_base_url;

fn mode_key(m: WebUiTlsMode) -> &'static str {
    match m {
        WebUiTlsMode::Off => "off",
        WebUiTlsMode::ArgusCa => "argus_ca",
        WebUiTlsMode::Uploaded => "uploaded",
    }
}

fn parse_mode(s: &str) -> WebUiTlsMode {
    match s {
        "argus_ca" => WebUiTlsMode::ArgusCa,
        "uploaded" => WebUiTlsMode::Uploaded,
        _ => WebUiTlsMode::Off,
    }
}

/// The page's own host name (what a certificate for this page must cover).
fn current_hostname() -> String {
    web_sys::window()
        .and_then(|w| w.location().hostname().ok())
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .to_string()
}

/// Whether this page was loaded over HTTPS (directly or through a TLS proxy).
fn page_is_https() -> bool {
    web_sys::window()
        .and_then(|w| w.location().protocol().ok())
        .is_some_and(|p| p == "https:")
}

/// Whether applying `target_https` should send the browser to the other protocol: switching
/// built-in HTTPS on from an http page, or off from an https page that the built-in TLS was
/// serving. A page behind a TLS proxy (https, built-in off) stays where it is.
fn must_navigate(target_https: bool, was_active: bool) -> bool {
    if target_https {
        !page_is_https()
    } else {
        was_active && page_is_https()
    }
}

/// Move the browser to the same page on the other protocol once the target answers (up to ~10 s
/// for HTTPS; the browser blocks probing http from an https page, so that waits a moment
/// instead). Returns false when the target never became reachable.
async fn move_to(https: bool) -> bool {
    let Some(loc) = web_sys::window().map(|w| w.location()) else {
        return false;
    };
    let origin = format!(
        "{}//{}",
        if https { "https:" } else { "http:" },
        loc.host().unwrap_or_default()
    );
    if https {
        let probe = format!("{origin}/api/v1/health");
        let mut ok = false;
        for _ in 0..10 {
            // A no-cors request resolves once a TLS connection is established and fails on a
            // certificate or connection error, which is all that is needed here.
            if gloo_net::http::Request::get(&probe)
                .mode(web_sys::RequestMode::NoCors)
                .send()
                .await
                .is_ok()
            {
                ok = true;
                break;
            }
            gloo_timers::future::TimeoutFuture::new(1000).await;
        }
        if !ok {
            return false;
        }
    } else {
        gloo_timers::future::TimeoutFuture::new(1500).await;
    }
    let _ = loc.set_href(&format!("{origin}/settings"));
    true
}

#[component]
pub fn HttpsCard() -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let status = RwSignal::new(Option::<WebUiTlsStatus>::None);
    let mode = RwSignal::new("off".to_string());
    let sans = RwSignal::new(Vec::<String>::new());
    let redirect = RwSignal::new(false);
    let cert_pem = RwSignal::new(String::new());
    let key_pem = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let san_err = RwSignal::new(Option::<String>::None);

    let load = move |s: WebUiTlsStatus| {
        mode.set(mode_key(s.mode).to_string());
        let mut names = s.sans.clone();
        if names.is_empty() {
            let h = current_hostname();
            if !h.is_empty() {
                names.push(h);
            }
        }
        sans.set(names);
        redirect.set(s.redirect_http);
        status.set(Some(s));
    };
    wasm_bindgen_futures::spawn_local(async move {
        match ApiClient::new().get_webui_tls().await {
            Ok(s) => load(s),
            Err(e) => app
                .get_value()
                .error(format!("Could not load HTTPS settings: {e}")),
        }
    });

    let was_active = move || status.get_untracked().is_some_and(|s| s.active);
    let after = move |r: Result<WebUiTlsStatus, crate::api::ApiError>, was: bool| {
        busy.set(false);
        match r {
            Ok(s) => {
                let now = s.active;
                load(s);
                key_pem.set(String::new());
                cert_pem.set(String::new());
                if must_navigate(now, was) {
                    app.get_value().success(if now {
                        "HTTPS is on. Moving this page to https://..."
                    } else {
                        "HTTPS is off. Moving this page to http://..."
                    });
                    wasm_bindgen_futures::spawn_local(async move {
                        if !move_to(now).await {
                            app.get_value().error(
                                "https:// is not reachable from this browser yet. Install and trust the Argus CA, then open the https:// address yourself.",
                            );
                        }
                    });
                } else {
                    app.get_value().success("HTTPS settings applied");
                }
            }
            Err(e) => app.get_value().error(e.to_string()),
        }
    };

    let apply = move || {
        let was = was_active();
        busy.set(true);
        let req = WebUiTlsRequest {
            mode: parse_mode(&mode.get_untracked()),
            sans: sans.get_untracked(),
            redirect_http: redirect.get_untracked(),
        };
        wasm_bindgen_futures::spawn_local(async move {
            after(ApiClient::new().put_webui_tls(&req).await, was);
        });
    };
    let upload = move || {
        let was = was_active();
        busy.set(true);
        let req = WebUiTlsUpload {
            cert_pem: cert_pem.get_untracked(),
            key_pem: key_pem.get_untracked(),
            redirect_http: redirect.get_untracked(),
        };
        wasm_bindgen_futures::spawn_local(async move {
            after(ApiClient::new().upload_webui_tls(&req).await, was);
        });
    };

    // Switching HTTPS on or off moves this page to another address: ask first.
    let moves = move || {
        let on = parse_mode(&mode.get()) != WebUiTlsMode::Off;
        status.get().is_some_and(|s| must_navigate(on, s.active))
    };
    // Going from https to http drops the session: its cookies are Secure.
    let logs_out = move || {
        parse_mode(&mode.get()) == WebUiTlsMode::Off
            && status.get().is_some_and(|s| must_navigate(false, s.active))
    };
    let ca_url = format!("{}/api/v1/ca.crt", api_base_url());

    view! {
        <div class="card" id="set-https">
            <div class="card-h"><h3>"HTTPS"</h3><span class="sub">"Serve the web UI over TLS on the same port. Applied live; no restart."</span></div>
            <div class="card-b">
                <fieldset style="border:0;padding:0;margin:0 0 var(--s3)">
                    <legend class="lname">"Certificate"</legend>
                    {[("off", "Off", "Plain HTTP. Use this behind a reverse proxy that terminates TLS."),
                      ("argus_ca", "Issued by the Argus CA", "Valid for 397 days and renewed automatically. Browsers must trust the Argus CA."),
                      ("uploaded", "Uploaded certificate", "Your own certificate chain and private key (for example from Let's Encrypt).")]
                        .into_iter().map(|(v, t, d)| view! {
                        <label style="display:flex;gap:8px;align-items:flex-start;margin:6px 0">
                            <input type="radio" name="https-mode" value=v
                                prop:checked=move || mode.get() == v
                                on:change=move |_| mode.set(v.to_string()) />
                            <span><b>{t}</b><br /><small class="hint">{d}</small></span>
                        </label>
                    }).collect_view()}
                </fieldset>

                <Show when=move || mode.get() == "argus_ca">
                    <div style="margin-bottom:var(--s3)">
                        <TagInput
                            tags=sans
                            label="Names in the certificate"
                            placeholder="host name or IP, then Enter"
                            error=san_err
                        />
                        <small class="hint">"Prefilled with the address you opened this page with. Add every name or IP address clients use."</small>
                        {move || san_err.get().map(|e| view! { <span class="fmsg bad" role="alert">{e}</span> })}
                    </div>
                </Show>

                <Show when=move || mode.get() == "uploaded">
                    <div style="margin-bottom:var(--s3)">
                        <label class="lname" for="https-cert">"Certificate chain (PEM, server certificate first)"</label>
                        <textarea id="https-cert" class="input" rows="5" spellcheck="false"
                            placeholder="-----BEGIN CERTIFICATE-----"
                            prop:value=move || cert_pem.get()
                            on:input=move |ev| cert_pem.set(event_target_value(&ev))></textarea>
                        <label class="lname" for="https-key" style="margin-top:8px;display:block">"Private key (PEM)"</label>
                        <textarea id="https-key" class="input" rows="4" spellcheck="false" autocomplete="off"
                            placeholder="-----BEGIN PRIVATE KEY-----"
                            prop:value=move || key_pem.get()
                            on:input=move |ev| key_pem.set(event_target_value(&ev))></textarea>
                        <div style="margin-top:8px">
                            <button class="btn primary sm" type="button"
                                disabled=move || busy.get() || cert_pem.get().trim().is_empty() || key_pem.get().trim().is_empty()
                                on:click=move |_| upload()>"Upload and use"</button>
                            <small class="hint" style="margin-left:8px">"The key is stored on the server with owner-only permissions and is never shown again."</small>
                        </div>
                    </div>
                </Show>

                <Show when=move || mode.get() != "off">
                    <label style="display:flex;gap:8px;align-items:center;margin-bottom:var(--s3)">
                        <input type="checkbox" prop:checked=move || redirect.get()
                            on:change=move |ev| redirect.set(event_target_checked(&ev)) />
                        <span>"Redirect plain HTTP on this port to HTTPS"</span>
                    </label>
                </Show>

                {move || status.get().and_then(|s| s.cert.map(|c| view! {
                    <dl class="kv" style="margin-bottom:var(--s3)">
                        <dt>"Subject"</dt><dd class="mono">{c.subject}</dd>
                        <dt>"Issuer"</dt><dd class="mono">{c.issuer}</dd>
                        <dt>"Names"</dt><dd class="mono">{c.sans.join(", ")}</dd>
                        <dt>"Expires"</dt><dd class="mono">{c.not_after}</dd>
                        <dt>"SHA-256"</dt><dd class="mono" style="word-break:break-all">{c.fingerprint_sha256}</dd>
                    </dl>
                }))}
                {move || status.get().and_then(|s| s.error).map(|e| view! { <p class="fmsg bad" role="alert">{e}</p> })}

                <Show when=move || moves()>
                    <p class="hint" role="note" style="margin-bottom:var(--s2)">
                        "Saving moves this page to the other address (https:// or http://). Browsers must trust the Argus CA before https:// opens without a warning: "
                        <a href=ca_url.clone() download="argus-ca.crt" style="color:var(--accent)">"download the CA certificate"</a>
                        ", install it, then apply. The CA stays downloadable over http:// on this port."
                    </p>
                </Show>
                <Show when=move || logs_out()>
                    <p class="fmsg bad" role="note" style="margin-bottom:var(--s2)">
                        "Turning HTTPS off moves this page to http:// and signs you out: session cookies are marked Secure and are not sent over http. Log in again afterwards."
                    </p>
                </Show>
                <div>
                    <Show when=move || moves() fallback=move || view! {
                        <button class="btn primary" type="button" disabled=move || busy.get() on:click=move |_| apply()>"Apply HTTPS settings"</button>
                    }>
                        <ConfirmButton
                            label="Apply and move this page"
                            confirm_label="Confirm: move this page"
                            large=true
                            disabled=Signal::derive(move || busy.get())
                            on_confirm=Callback::new(move |_| apply())
                        />
                    </Show>
                </div>
            </div>
        </div>
    }
}
