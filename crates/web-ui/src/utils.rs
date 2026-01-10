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
