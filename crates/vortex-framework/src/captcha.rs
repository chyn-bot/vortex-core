//! Pluggable CAPTCHA verification for public Intake forms.
//!
//! This mirrors the [`crate::antivirus`] hook. The default backend is a no-op
//! that accepts everything (`is_active() == false`), so an install that hasn't
//! configured a provider behaves exactly as before. A real backend verifies a
//! client-solved token **server-side** against the provider's `siteverify`
//! endpoint — the token from the page is never trusted on its own.
//!
//! Cloudflare Turnstile, hCaptcha and reCAPTCHA v2 all share the same shape:
//! render a widget `<div>` with a public *sitekey*, load one provider script
//! that injects a hidden response field into the form, then POST
//! `secret + response` to a `siteverify` URL and read back `{"success": bool}`.
//! One [`SiteverifyVerifier`] parameterised by [`CaptchaProvider`] therefore
//! covers all three with no per-provider code paths.
//!
//! Global config lives in `[captcha]` in `vortex.toml` (provider + public
//! sitekey + private secret); a form opts in per-form via its `captcha`
//! setting. The signed nonce + honeypot + min-fill-time already defend every
//! public form against replay and dumb bots — CAPTCHA is the human-verification
//! escalation for high-value or heavily-spammed forms, not a replacement.
//!
//! Fail policy matches the AV hook: a provider that can't be reached either
//! fails **closed** (reject — the default when you deliberately turned CAPTCHA
//! on) or **open** (accept and log) per `fail_open`. A *definitive* failed
//! challenge (`Ok(false)`) always rejects regardless of `fail_open`.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use crate::ui::html_escape;

/// A scan could not be completed (transport or protocol problem). A backend
/// configured `fail_open` converts these into an accept itself, so a caller that
/// receives `Err` should treat the challenge as unverifiable and fail closed.
#[derive(Debug, thiserror::Error)]
pub enum CaptchaError {
    #[error("captcha provider unreachable: {0}")]
    Unreachable(String),
    #[error("captcha protocol error: {0}")]
    Protocol(String),
}

/// A pluggable CAPTCHA verifier. Implementations must be safe for concurrent use.
#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    /// Verify a client-solved `token`. `Ok(true)` = human, `Ok(false)` = a
    /// definitive failed challenge (missing/invalid token), `Err` = the check
    /// itself couldn't complete. `remote_ip` is forwarded to the provider when
    /// available (an optional anti-abuse signal).
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<bool, CaptchaError>;

    /// Short backend name for startup logs and health output.
    fn backend_name(&self) -> &'static str;

    /// `true` when a real challenge is enforced; `false` for the no-op default.
    fn is_active(&self) -> bool {
        true
    }

    /// The client-side widget markup to inject into a form (empty for no-op).
    fn widget_html(&self) -> String {
        String::new()
    }

    /// The provider script URL to load (`None` for no-op). Rendered as an
    /// external `<script src>` — no inline script, CSP-compliant.
    fn script_url(&self) -> Option<&str> {
        None
    }

    /// The POSTed field the solved token arrives in (e.g.
    /// `cf-turnstile-response`). Empty for no-op.
    fn response_field(&self) -> &'static str {
        ""
    }

    /// Extra external hosts this widget needs, applied to `script-src`,
    /// `frame-src` and `connect-src` in the page CSP. Empty for the no-op.
    fn csp_hosts(&self) -> &'static [&'static str] {
        &[]
    }
}

/// The default: accept everything. Used when `[captcha]` is absent/`none` or a
/// form doesn't opt in.
pub struct NoopVerifier;

#[async_trait]
impl CaptchaVerifier for NoopVerifier {
    async fn verify(&self, _token: &str, _remote_ip: Option<&str>) -> Result<bool, CaptchaError> {
        Ok(true)
    }
    fn backend_name(&self) -> &'static str {
        "none"
    }
    fn is_active(&self) -> bool {
        false
    }
}

/// A `siteverify`-style provider. The three supported providers differ only in
/// their endpoint, script, widget class, response field name, and the external
/// hosts their widget contacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaProvider {
    /// Cloudflare Turnstile — privacy-friendly, single host.
    Turnstile,
    /// hCaptcha.
    Hcaptcha,
    /// Google reCAPTCHA v2 ("I'm not a robot" checkbox).
    Recaptcha,
}

impl CaptchaProvider {
    /// Parse a provider name from config (case-insensitive). Returns `None` for
    /// an unrecognised name so the caller can warn and disable.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "turnstile" | "cloudflare" => Some(Self::Turnstile),
            "hcaptcha" => Some(Self::Hcaptcha),
            "recaptcha" | "recaptcha-v2" | "recaptcha_v2" => Some(Self::Recaptcha),
            _ => None,
        }
    }

    fn backend_name(self) -> &'static str {
        match self {
            Self::Turnstile => "turnstile",
            Self::Hcaptcha => "hcaptcha",
            Self::Recaptcha => "recaptcha",
        }
    }

    fn default_verify_url(self) -> &'static str {
        match self {
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Self::Hcaptcha => "https://api.hcaptcha.com/siteverify",
            Self::Recaptcha => "https://www.google.com/recaptcha/api/siteverify",
        }
    }

    fn script_url(self) -> &'static str {
        match self {
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
            Self::Hcaptcha => "https://js.hcaptcha.com/1/api.js",
            Self::Recaptcha => "https://www.google.com/recaptcha/api.js",
        }
    }

    /// The CSS class the provider script auto-renders into a widget.
    fn widget_class(self) -> &'static str {
        match self {
            Self::Turnstile => "cf-turnstile",
            Self::Hcaptcha => "h-captcha",
            Self::Recaptcha => "g-recaptcha",
        }
    }

    fn response_field(self) -> &'static str {
        match self {
            Self::Turnstile => "cf-turnstile-response",
            Self::Hcaptcha => "h-captcha-response",
            Self::Recaptcha => "g-recaptcha-response",
        }
    }

    /// External hosts the widget/script contact — for CSP `script-src` /
    /// `frame-src` / `connect-src`.
    fn csp_hosts(self) -> &'static [&'static str] {
        match self {
            Self::Turnstile => &["https://challenges.cloudflare.com"],
            Self::Hcaptcha => &[
                "https://js.hcaptcha.com",
                "https://newassets.hcaptcha.com",
                "https://api.hcaptcha.com",
                "https://hcaptcha.com",
            ],
            Self::Recaptcha => &[
                "https://www.google.com",
                "https://www.gstatic.com",
                "https://www.recaptcha.net",
            ],
        }
    }
}

/// A `siteverify` HTTP verifier for the supported providers.
pub struct SiteverifyVerifier {
    provider: CaptchaProvider,
    verify_url: String,
    secret: String,
    fail_open: bool,
    widget_html: String,
    client: reqwest::Client,
}

impl SiteverifyVerifier {
    pub fn new(
        provider: CaptchaProvider,
        sitekey: String,
        secret: String,
        verify_url: Option<String>,
        fail_open: bool,
    ) -> Self {
        // The sitekey is public (it ships in the page), but escape it anyway —
        // it lands in an HTML attribute and must never break out of it.
        let widget_html = format!(
            r#"<div class="{class}" data-sitekey="{sitekey}"></div>"#,
            class = provider.widget_class(),
            sitekey = html_escape(&sitekey),
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            provider,
            verify_url: verify_url
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| provider.default_verify_url().to_string()),
            secret,
            fail_open,
            widget_html,
            client,
        }
    }

    /// The raw siteverify exchange — definitive `Ok(pass)` or transport `Err`.
    async fn do_verify(&self, token: &str, remote_ip: Option<&str>) -> Result<bool, CaptchaError> {
        let mut form: Vec<(&str, &str)> =
            vec![("secret", self.secret.as_str()), ("response", token)];
        if let Some(ip) = remote_ip {
            form.push(("remoteip", ip));
        }
        let resp = self
            .client
            .post(&self.verify_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| CaptchaError::Unreachable(e.to_string()))?;
        let body: SiteverifyResponse = resp
            .json()
            .await
            .map_err(|e| CaptchaError::Protocol(e.to_string()))?;
        if !body.success && !body.error_codes.is_empty() {
            tracing::warn!(errors = ?body.error_codes, "captcha challenge rejected by provider");
        }
        Ok(body.success)
    }
}

#[async_trait]
impl CaptchaVerifier for SiteverifyVerifier {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<bool, CaptchaError> {
        // No token ⇒ the widget was never solved. Definitive fail; never a
        // provider round-trip.
        if token.trim().is_empty() {
            return Ok(false);
        }
        match self.do_verify(token, remote_ip).await {
            Ok(pass) => Ok(pass),
            Err(e) if self.fail_open => {
                tracing::warn!(error = %e, "captcha verify failed, failing open");
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }
    fn backend_name(&self) -> &'static str {
        self.provider.backend_name()
    }
    fn widget_html(&self) -> String {
        self.widget_html.clone()
    }
    fn script_url(&self) -> Option<&str> {
        Some(self.provider.script_url())
    }
    fn response_field(&self) -> &'static str {
        self.provider.response_field()
    }
    fn csp_hosts(&self) -> &'static [&'static str] {
        self.provider.csp_hosts()
    }
}

/// The subset of a siteverify response we act on. Extra fields (`challenge_ts`,
/// `hostname`, `score`, …) are ignored.
#[derive(serde::Deserialize)]
struct SiteverifyResponse {
    #[serde(default)]
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

/// Configuration parsed from `[captcha]` in vortex.toml by the host.
#[derive(Debug, Clone)]
pub enum CaptchaConfig {
    /// No CAPTCHA — forms behave as if the `captcha` toggle is off (default).
    Disabled,
    Enabled {
        provider: CaptchaProvider,
        sitekey: String,
        secret: String,
        /// Override the provider's default siteverify endpoint (self-hosted
        /// proxy / testing). `None` uses the provider default.
        verify_url: Option<String>,
        fail_open: bool,
    },
}

/// Build the configured verifier. Never fails — a bad secret/endpoint surfaces
/// at verify time (subject to `fail_open`), so a misconfiguration can't stop the
/// server from starting.
pub fn from_config(config: &CaptchaConfig) -> Arc<dyn CaptchaVerifier> {
    match config {
        CaptchaConfig::Disabled => Arc::new(NoopVerifier),
        CaptchaConfig::Enabled { provider, sitekey, secret, verify_url, fail_open } => Arc::new(
            SiteverifyVerifier::new(
                *provider,
                sitekey.clone(),
                secret.clone(),
                verify_url.clone(),
                *fail_open,
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parse_is_case_insensitive_and_bounded() {
        assert_eq!(CaptchaProvider::parse("Turnstile"), Some(CaptchaProvider::Turnstile));
        assert_eq!(CaptchaProvider::parse("cloudflare"), Some(CaptchaProvider::Turnstile));
        assert_eq!(CaptchaProvider::parse(" hCaptcha "), Some(CaptchaProvider::Hcaptcha));
        assert_eq!(CaptchaProvider::parse("recaptcha-v2"), Some(CaptchaProvider::Recaptcha));
        assert_eq!(CaptchaProvider::parse("nope"), None);
    }

    #[test]
    fn widget_html_escapes_sitekey_and_uses_provider_class() {
        let v = SiteverifyVerifier::new(
            CaptchaProvider::Turnstile,
            r#"key"><script>x"#.into(),
            "secret".into(),
            None,
            false,
        );
        let html = v.widget_html();
        assert!(html.contains(r#"class="cf-turnstile""#));
        assert!(!html.contains("<script>"), "sitekey must be HTML-escaped");
        assert_eq!(v.response_field(), "cf-turnstile-response");
        assert_eq!(v.csp_hosts(), &["https://challenges.cloudflare.com"]);
    }

    #[tokio::test]
    async fn noop_accepts_everything_and_is_inactive() {
        let v = NoopVerifier;
        assert!(v.verify("", None).await.unwrap());
        assert!(!v.is_active());
        assert!(v.widget_html().is_empty());
        assert!(v.script_url().is_none());
    }

    #[tokio::test]
    async fn empty_token_is_a_definitive_fail_without_network() {
        // verify_url is unreachable, but an empty token short-circuits before
        // any round-trip — so this must resolve to Ok(false), not an error.
        let v = SiteverifyVerifier::new(
            CaptchaProvider::Hcaptcha,
            "sitekey".into(),
            "secret".into(),
            Some("http://127.0.0.1:1/verify".into()),
            false,
        );
        assert_eq!(v.verify("   ", None).await.unwrap(), false);
    }

    #[tokio::test]
    async fn unreachable_provider_respects_fail_policy() {
        let closed = SiteverifyVerifier::new(
            CaptchaProvider::Turnstile,
            "sitekey".into(),
            "secret".into(),
            Some("http://127.0.0.1:1/verify".into()),
            false,
        );
        assert!(closed.verify("tok", None).await.is_err(), "fail-closed surfaces the error");
        let open = SiteverifyVerifier::new(
            CaptchaProvider::Turnstile,
            "sitekey".into(),
            "secret".into(),
            Some("http://127.0.0.1:1/verify".into()),
            true,
        );
        assert!(open.verify("tok", None).await.unwrap(), "fail-open accepts");
    }
}
