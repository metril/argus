//! Lazy "View certificate" panel for the request-log drawer.

use api_types::{CertFailReason, CertInfo, CertVerdict};
use leptos::prelude::*;

use super::icon::Icon;
use super::pill::Pill;
use crate::api::ApiClient;
use crate::utils::{copy_text, fmt_datetime};

fn reason_text(r: Option<CertFailReason>) -> &'static str {
    match r {
        Some(CertFailReason::Expired) => "Certificate has expired",
        Some(CertFailReason::NotYetValid) => "Certificate is not valid yet",
        Some(CertFailReason::NameMismatch) => "Certificate does not match the host name",
        Some(CertFailReason::UnknownIssuer) => "Issuer is not trusted",
        Some(CertFailReason::Other) | None => "Verification failed",
    }
}

fn validity(nb: &str, na: &str) -> String {
    format!("{} to {}", fmt_datetime(nb), fmt_datetime(na))
}

/// Fetches `/certs/{fp}` the first time the user expands the panel.
#[component]
pub fn CertPanel(
    #[prop(into)] fp: String,
    /// Host the request went to; selects the verdict shown.
    #[prop(into, optional)]
    host: String,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let started = RwSignal::new(false);
    let info = RwSignal::new(Option::<Result<CertInfo, String>>::None);
    let fp_fetch = fp.clone();
    let host_fetch = host.clone();
    let toggle = move |_| {
        let o = !open.get_untracked();
        open.set(o);
        if o && !started.get_untracked() {
            started.set(true);
            let fp = fp_fetch.clone();
            let host = host_fetch.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let r = ApiClient::new()
                    .get_cert(&fp, &host)
                    .await
                    .map_err(|e| e.to_string());
                info.set(Some(r));
            });
        }
    };
    view! {
        <div class="cert">
            <button class="btn sm" type="button" aria-expanded=move || open.get().to_string() on:click=toggle>
                <Icon name="policy" />{move || if open.get() { "Hide certificate" } else { "View certificate" }}
            </button>
            <Show when=move || open.get()>
                {move || match info.get() {
                    None => view! { <div class="hint" role="status">"Loading certificate..."</div> }.into_any(),
                    Some(Err(e)) => view! { <div class="hint" role="alert">{format!("Could not load certificate: {e}")}</div> }.into_any(),
                    Some(Ok(c)) => cert_body(c).into_any(),
                }}
            </Show>
        </div>
    }
}

fn cert_body(c: CertInfo) -> impl IntoView {
    let ok = c.verdict == CertVerdict::Ok;
    let fp = c.fp.clone();
    let sans = if c.sans.is_empty() {
        "-".to_string()
    } else {
        c.sans.join(", ")
    };
    let chain = c.chain.clone();
    view! {
        <div class="cert-body">
            <div class="row-gap">
                {if ok {
                    view! { <Pill kind="ok" text="Valid" /> }.into_any()
                } else {
                    view! { <Pill kind="error" text="Invalid" /> }.into_any()
                }}
                {c.ev.then(|| view! { <span class="tag ok">"EV"</span> })}
            </div>
            {(!ok).then(|| view! {
                <div class="hint">
                    {reason_text(c.reason)}
                    {c.detail.clone().map(|d| view! { <span class="mono">" ("{d}")"</span> })}
                </div>
            })}
            <dl class="kv">
                <dt>"Subject"</dt><dd class="mono">{c.subject.clone()}</dd>
                <dt>"Issuer"</dt><dd class="mono">{c.issuer.clone()}</dd>
                <dt>"Validity"</dt><dd class="num">{validity(&c.not_before, &c.not_after)}</dd>
                <dt>"Serial"</dt><dd class="mono">{c.serial.clone()}</dd>
                <dt>"SANs"</dt><dd class="mono">{sans}</dd>
                <dt>"SHA-256"</dt>
                <dd class="mono cert-fp">
                    {c.fp.clone()}
                    <button class="icon-btn" type="button" aria-label="Copy fingerprint" on:click=move |_| { copy_text(&fp); }>
                        <Icon name="copy" />
                    </button>
                </dd>
            </dl>
            <ol class="cert-chain" aria-label="Certificate chain">
                {chain.into_iter().map(|e| view! {
                    <li>
                        <b class="mono">{e.subject}</b>
                        <small class="mono">"issued by "{e.issuer}</small>
                        <small class="num">{validity(&e.not_before, &e.not_after)}</small>
                    </li>
                }).collect_view()}
            </ol>
        </div>
    }
}
