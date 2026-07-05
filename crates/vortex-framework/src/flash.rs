//! One-shot flash messages across a redirect.
//!
//! Server-rendered actions redirect after POST; without feedback the
//! user assumes nothing happened and clicks again. `flash_redirect`
//! attaches a short-lived cookie to the redirect; the shared
//! `/static/vortex.js` reads it on the next page, shows a toast, and
//! deletes it. Works on every page shell with no per-page wiring.
//!
//! ```rust,ignore
//! return flash_redirect(
//!     &format!("/accounting/documents/{id}"),
//!     FlashKind::Success,
//!     "Queued for LHDN submission — the status updates automatically.",
//! );
//! ```

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashKind {
    Success,
    Error,
    Info,
}

impl FlashKind {
    fn as_str(self) -> &'static str {
        match self {
            FlashKind::Success => "success",
            FlashKind::Error => "error",
            FlashKind::Info => "info",
        }
    }
}

/// Percent-encode for a cookie value (RFC 6265-safe subset).
fn cookie_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b' ' => {
                if b == b' ' { "+".to_string() } else { (b as char).to_string() }
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Redirect with a one-shot toast on the destination page. The cookie
/// is deliberately NOT HttpOnly — the shared front-end script consumes
/// and deletes it; it never carries secrets.
pub fn flash_redirect(to: &str, kind: FlashKind, message: &str) -> Response {
    let cookie = format!(
        "vortex_flash={}:{}; Path=/; Max-Age=30; SameSite=Strict",
        kind.as_str(),
        cookie_encode(message),
    );
    let mut resp = Redirect::to(to).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}
