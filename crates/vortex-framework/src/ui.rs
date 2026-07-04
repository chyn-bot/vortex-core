//! Core UI helpers shared by the host binary and every plugin.
//!
//! These are stateless HTML and HTTP utilities that every plugin crate
//! needs. Before Phase 0.3b they lived in `vortex-cli/src/commands/server.rs`
//! and plugin crates could not use them without a circular dependency
//! on the binary. Moving them here breaks that cycle.
//!
//! What lives here vs. what lives in the host binary:
//!
//! - **Here**: pure functions that operate on strings / primitive
//!   values (`html_escape`, `get_initials`, `format_time_ago`,
//!   `forbidden_page`, `error_response`). No handler state, no route
//!   context, no DB access.
//! - **In the host binary**: full handlers with state and route
//!   registration (`login_page`, `users_list`, etc.). Those stay in
//!   `vortex-cli/src/commands/server.rs` because they are the host's
//!   own concerns, not framework-level primitives.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, Utc};

/// HTML-escape a string to prevent XSS when injecting DB-sourced values
/// into HTML templates. OWASP-recommended minimum escape set.
///
/// ```
/// use vortex_framework::ui::html_escape;
/// assert_eq!(html_escape("<script>"), "&lt;script&gt;");
/// assert_eq!(html_escape(r#"o"neill & sons"#), "o&quot;neill &amp; sons");
/// ```
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Return the first letter of the first two whitespace-separated words
/// of a name, uppercased. Used for avatar placeholders.
///
/// ```
/// use vortex_framework::ui::get_initials;
/// assert_eq!(get_initials("Alice Example"), "AE");
/// assert_eq!(get_initials("alice"), "A");
/// assert_eq!(get_initials(""), "");
/// ```
pub fn get_initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

/// Render a short relative-time string like `"5 min ago"` for a past
/// timestamp.
pub fn format_time_ago(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(dt);
    if duration.num_seconds() < 60 {
        "Just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{} min ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{} hr ago", duration.num_hours())
    } else {
        format!("{} days ago", duration.num_days())
    }
}

/// Build the standard HTMX-friendly error response. Returns 200 so
/// HTMX will still swap the DOM (HTMX ignores 4xx by default); the
/// inline alert markup makes the error visible to the user.
pub fn error_response(message: &str) -> Response {
    (
        StatusCode::OK,
        Html(format!(
            r#"<div class="alert alert-error mb-4">
    <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
    <span>{}</span>
</div>"#,
            html_escape(message)
        )),
    )
        .into_response()
}

/// Format an integer with comma separators (e.g. `50064` → `"50,064"`).
///
/// Used throughout list/table rendering for row counts, pagination
/// totals, and currency display.
pub fn format_number(n: i64) -> String {
    let s = n.to_string();
    let (sign, digits) = if let Some(rest) = s.strip_prefix('-') {
        ("-", rest)
    } else {
        ("", s.as_str())
    };
    let bytes = digits.as_bytes();
    let mut result = String::with_capacity(sign.len() + digits.len() + digits.len() / 3);
    result.push_str(sign);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(b as char);
    }
    result
}

/// Build DaisyUI-styled pagination controls.
///
/// `page` is 1-based, `per_page` is items per page, `total` is total
/// item count. `base_url` should be the path + query string without a
/// `page` parameter (e.g. `"/list/contacts?search=foo&per_page=80"`).
/// Used by every list view that paginates — core and plugin alike.
pub fn build_pagination_html(page: i64, per_page: i64, total: i64, base_url: &str) -> String {
    if total == 0 {
        return String::new();
    }
    let last_page = (total + per_page - 1) / per_page;
    let page = page.max(1).min(last_page);
    let start = (page - 1) * per_page + 1;
    let end = (page * per_page).min(total);

    let sep = if base_url.contains('?') { "&" } else { "?" };

    let mut html = String::with_capacity(2048);
    html.push_str(r#"<div class="flex flex-col sm:flex-row items-center justify-between mt-4 gap-2">"#);
    html.push_str(&format!(
        r#"<span class="text-sm text-base-content/60">Showing {}-{} of {}</span>"#,
        format_number(start), format_number(end), format_number(total)
    ));

    html.push_str(r#"<div class="join">"#);

    if page > 1 {
        html.push_str(&format!(
            r#"<a href="{}{}page={}" class="join-item btn btn-sm">&laquo; Prev</a>"#,
            base_url, sep, page - 1
        ));
    } else {
        html.push_str(r#"<button class="join-item btn btn-sm btn-disabled">&laquo; Prev</button>"#);
    }

    let mut pages_to_show: Vec<i64> = Vec::new();
    pages_to_show.push(1);
    for p in (page - 2)..=(page + 2) {
        if p > 1 && p < last_page {
            pages_to_show.push(p);
        }
    }
    if last_page > 1 {
        pages_to_show.push(last_page);
    }
    pages_to_show.dedup();

    let mut prev_p: i64 = 0;
    for &p in &pages_to_show {
        if p > prev_p + 1 {
            html.push_str(r#"<button class="join-item btn btn-sm btn-disabled">...</button>"#);
        }
        if p == page {
            html.push_str(&format!(
                r#"<button class="join-item btn btn-sm btn-active">{}</button>"#, p
            ));
        } else {
            html.push_str(&format!(
                r#"<a href="{}{}page={}" class="join-item btn btn-sm">{}</a>"#,
                base_url, sep, p, p
            ));
        }
        prev_p = p;
    }

    if page < last_page {
        html.push_str(&format!(
            r#"<a href="{}{}page={}" class="join-item btn btn-sm">Next &raquo;</a>"#,
            base_url, sep, page + 1
        ));
    } else {
        html.push_str(r#"<button class="join-item btn btn-sm btn-disabled">Next &raquo;</button>"#);
    }

    html.push_str("</div></div>");
    html
}

/// Build a standalone 403 Access Denied page.
pub fn forbidden_page(action: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Vortex</title>
    <link href="/static/vendor/daisyui.min.css" rel="stylesheet">
    <script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200 flex items-center justify-center">
    <div class="card bg-base-100 shadow-xl max-w-md">
        <div class="card-body text-center">
            <div class="text-6xl mb-4">🔒</div>
            <h1 class="text-2xl font-bold text-error">Access Denied</h1>
            <p class="text-base-content/70 mt-2">
                You do not have permission to access <strong>{}</strong>.
            </p>
            <p class="text-sm text-base-content/50 mt-4">
                This action requires Administrator or System Administrator privileges.
            </p>
            <div class="card-actions justify-center mt-6">
                <a href="/dashboard" class="btn btn-primary">Return to Dashboard</a>
            </div>
        </div>
    </div>
</body>
</html>"#,
        html_escape(action)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_covers_owasp_set() {
        assert_eq!(html_escape("<>\"'&"), "&lt;&gt;&quot;&#x27;&amp;");
    }

    #[test]
    fn html_escape_leaves_plain_text_alone() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn initials_two_words() {
        assert_eq!(get_initials("Alice Example"), "AE");
    }

    #[test]
    fn initials_single_word() {
        assert_eq!(get_initials("alice"), "A");
    }

    #[test]
    fn initials_empty() {
        assert_eq!(get_initials(""), "");
    }

    #[test]
    fn initials_many_words_takes_two() {
        assert_eq!(get_initials("Alice B Charles D"), "AB");
    }

    #[test]
    fn forbidden_page_escapes_action() {
        let page = forbidden_page("<script>alert(1)</script>");
        assert!(page.contains("&lt;script&gt;"));
        assert!(!page.contains("<script>alert(1)</script>"));
    }
}
