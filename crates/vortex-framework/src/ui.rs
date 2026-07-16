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

use axum::http::{HeaderMap, StatusCode};
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

/// Canonical URL of a record's generic form page.
///
/// The generic view layer has exactly one record route — `/form/{model}/{id}`
/// (registered as `dynamic_form`). Historically list rows, kanban cards, and
/// several "+ New" buttons hand-wrote `/{model}/{id}`, which does not exist, so
/// every generic drill-in 404'd (§2 #1). This is the single definition of the
/// record-link shape: every list, kanban, calendar, and cross-plugin link must
/// build record URLs through here (and [`new_record_url`]) so a route change
/// can never again silently desynchronise from the links that target it.
///
/// The `model` and `id` are URL path segments, not HTML — callers that embed
/// the result in markup still [`html_escape`] it as usual.
///
/// ```
/// use vortex_framework::ui::record_url;
/// assert_eq!(record_url("sales_order", "42"), "/form/sales_order/42");
/// ```
pub fn record_url(model: &str, id: &str) -> String {
    format!("/form/{}/{}", model, id)
}

/// Canonical URL of the generic "new record" form for a model. See
/// [`record_url`] for why links must not hand-write this path.
///
/// ```
/// use vortex_framework::ui::new_record_url;
/// assert_eq!(new_record_url("sales_order"), "/form/sales_order/new");
/// ```
pub fn new_record_url(model: &str) -> String {
    format!("/form/{}/new", model)
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

/// Build a "back to list" href that preserves the caller's list state
/// (search / sort / filters / page) by reading it off the request `Referer`.
///
/// A record page opened from `/contacts?search=foo&page=3` should return to
/// that exact view, not the bare list. Same-origin navigation carries the
/// full list URL in the `Referer` under the platform's
/// `strict-origin-when-cross-origin` policy, so this recovers it without
/// threading list state through every record link.
///
/// The result is **only ever** a path+query on `list_path`: a `Referer`
/// pointing at a record page, another module, or an external origin falls
/// back to the bare `list_path`. The host portion is stripped, so the return
/// value is always a relative path on our own origin — it can never become
/// an open redirect. Because the query portion is attacker-influenceable,
/// **callers must HTML-escape the value** before embedding it in an
/// attribute (e.g. via [`html_escape`]).
///
/// ```
/// use axum::http::HeaderMap;
/// use vortex_framework::ui::list_return_href;
///
/// let mut h = HeaderMap::new();
/// h.insert("referer", "http://host/contacts?search=foo&page=3".parse().unwrap());
/// assert_eq!(list_return_href(&h, "/contacts"), "/contacts?search=foo&page=3");
///
/// // Wrong path or no referer → bare list path.
/// assert_eq!(list_return_href(&HeaderMap::new(), "/contacts"), "/contacts");
/// ```
pub fn list_return_href(headers: &HeaderMap, list_path: &str) -> String {
    let referer = match headers.get("referer").and_then(|v| v.to_str().ok()) {
        Some(r) => r,
        None => return list_path.to_string(),
    };
    // Reduce an absolute referer (scheme://host/path?q) to path+query.
    let path_and_query = match referer.find("://") {
        Some(i) => match referer[i + 3..].find('/') {
            Some(j) => &referer[i + 3 + j..],
            None => return list_path.to_string(),
        },
        None => referer, // already relative
    };
    // Honor it only when the path is exactly the list path.
    let path = path_and_query
        .split(|c| c == '?' || c == '#')
        .next()
        .unwrap_or("");
    if path == list_path {
        path_and_query.to_string()
    } else {
        list_path.to_string()
    }
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
    // A full, styled document — not a bare fragment. When a handler returns this
    // as a whole-page response (e.g. a failed form save), a fragment renders as
    // an unstyled near-blank "white page"; a complete page with the stylesheet
    // shows the message clearly and offers a way back (which preserves the
    // half-filled form via the browser's back cache).
    let body = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Something went wrong</title>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<link href="/static/vendor/daisyui.min.css" rel="stylesheet">
<link href="/static/vortex.css?v=20" rel="stylesheet"/>
<link href="/static/tailwind.css?v=21" rel="stylesheet"/>
</head>
<body class="min-h-screen bg-base-200 flex items-center justify-center p-6">
<div class="card bg-base-100 shadow-xl max-w-lg w-full"><div class="card-body">
<div class="flex items-center gap-3">
<svg xmlns="http://www.w3.org/2000/svg" class="text-error shrink-0 h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
</svg>
<h1 class="card-title">That didn’t go through</h1>
</div>
<p class="text-base-content/80 mt-1">{msg}</p>
<div class="card-actions justify-end mt-4">
<button class="btn btn-ghost" onclick="history.back()">← Go back</button>
</div>
</div></div>
</body></html>"##,
        msg = html_escape(message)
    );
    (StatusCode::OK, Html(body)).into_response()
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
    <link href="/static/vortex.css?v=20" rel="stylesheet">
    <script src="/static/vortex.js?v=20" defer></script>
    <link href="/static/tailwind.css?v=21" rel="stylesheet"/>
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
                <a href="/home" class="btn btn-primary">Return to Home</a>
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

    fn referer(r: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("referer", r.parse().unwrap());
        h
    }

    #[test]
    fn list_return_href_preserves_query_from_absolute_referer() {
        let h = referer("http://localhost:3003/contacts?search=23356&page=3");
        assert_eq!(list_return_href(&h, "/contacts"), "/contacts?search=23356&page=3");
    }

    #[test]
    fn list_return_href_preserves_query_from_relative_referer() {
        let h = referer("/accounting?sort=date&dir=desc");
        assert_eq!(list_return_href(&h, "/accounting"), "/accounting?sort=date&dir=desc");
    }

    #[test]
    fn list_return_href_falls_back_without_or_on_wrong_referer() {
        assert_eq!(list_return_href(&HeaderMap::new(), "/inventory"), "/inventory");
        // A record page under the same module is not the list itself.
        let h = referer("http://host/inventory/abc-123");
        assert_eq!(list_return_href(&h, "/inventory"), "/inventory");
        // A different module's list.
        let h = referer("http://host/contacts?search=x");
        assert_eq!(list_return_href(&h, "/inventory"), "/inventory");
    }

    #[test]
    fn list_return_href_output_is_always_relative_never_cross_origin() {
        // Host is stripped by design: a crafted cross-origin referer yields
        // only a relative link to our own list, never an open redirect.
        let h = referer("http://evil.example/contacts?x=1");
        let out = list_return_href(&h, "/contacts");
        assert_eq!(out, "/contacts?x=1");
        assert!(out.starts_with('/'));
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
