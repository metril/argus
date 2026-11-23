//! Utility functions for the web UI

use web_sys::window;

/// Get the current window location origin (e.g., "http://localhost:3000")
pub fn get_origin() -> String {
    window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "http://localhost:3000".to_string())
}

/// Get the API base URL
pub fn api_base_url() -> String {
    // In development, the API runs on port 3000
    // In production, it's served from the same origin
    #[cfg(debug_assertions)]
    {
        "http://localhost:3000".to_string()
    }
    #[cfg(not(debug_assertions))]
    {
        get_origin()
    }
}

/// Format a number with thousand separators
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Parse a relative time string (e.g., "2 hours ago")
pub fn format_relative_time(timestamp: &str) -> String {
    // Simple implementation - could use chrono if needed
    timestamp.to_string()
}

/// Local `HH:MM:SS` for an RFC 3339 timestamp (falls back to the raw text).
pub fn fmt_time(ts: &str) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(ts));
    if d.get_time().is_nan() {
        return ts.to_string();
    }
    format!(
        "{:02}:{:02}:{:02}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds()
    )
}

/// Local `YYYY-MM-DD HH:MM` for an RFC 3339 timestamp.
pub fn fmt_datetime(ts: &str) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(ts));
    if d.get_time().is_nan() {
        return ts.to_string();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        d.get_full_year(),
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes()
    )
}

/// "3 min ago" style text for an RFC 3339 timestamp.
pub fn fmt_ago(ts: &str) -> String {
    let t = js_sys::Date::parse(ts);
    if t.is_nan() {
        return ts.to_string();
    }
    let secs = ((js_sys::Date::now() - t) / 1000.0).max(0.0) as u64;
    match secs {
        0..=44 => "just now".into(),
        45..=3599 => format!("{} min ago", (secs / 60).max(1)),
        3600..=86399 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86400),
    }
}

/// Split a URL into (host, path+query) for display.
pub fn split_url(url: &str) -> (String, String) {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    match rest.find(['/', '?']) {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), String::new()),
    }
}

/// `host[:port]` of a URL (userinfo dropped), as the certificate lookup expects it.
pub fn url_hostport(url: &str) -> String {
    let a = split_url(url).0;
    a.rsplit('@').next().unwrap_or(&a).to_string()
}

/// Host part of a URL (without port-less userinfo handling; good enough for display/rules).
pub fn url_host(url: &str) -> String {
    let h = split_url(url).0;
    let h = h.rsplit('@').next().unwrap_or(&h).to_string();
    // strip :port but keep IPv6 literals intact
    if h.starts_with('[') {
        return h;
    }
    h.split(':').next().unwrap_or(&h).to_string()
}

/// Copy text to the clipboard (async API when available, `execCommand` fallback otherwise).
pub fn copy_text(text: &str) -> bool {
    use wasm_bindgen::JsCast;
    let Some(win) = web_sys::window() else {
        return false;
    };
    let nav = win.navigator();
    if let Ok(cb) = js_sys::Reflect::get(&nav, &"clipboard".into()) {
        if !cb.is_undefined() && !cb.is_null() {
            if let Ok(f) = js_sys::Reflect::get(&cb, &"writeText".into()) {
                if let Ok(f) = f.dyn_into::<js_sys::Function>() {
                    if f.call1(&cb, &text.into()).is_ok() {
                        return true;
                    }
                }
            }
        }
    }
    let Some(doc) = win.document() else {
        return false;
    };
    let Ok(el) = doc.create_element("textarea") else {
        return false;
    };
    let Ok(ta) = el.dyn_into::<web_sys::HtmlTextAreaElement>() else {
        return false;
    };
    ta.set_value(text);
    let _ = ta.set_attribute("style", "position:fixed;opacity:0");
    let Some(body) = doc.body() else {
        return false;
    };
    let _ = body.append_child(&ta);
    ta.select();
    let ok = doc
        .dyn_into::<web_sys::HtmlDocument>()
        .ok()
        .and_then(|d| d.exec_command("copy").ok())
        .unwrap_or(false);
    ta.remove();
    ok
}
