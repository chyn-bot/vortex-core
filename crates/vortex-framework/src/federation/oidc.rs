//! OIDC authorization-code client.
//!
//! Flow: `/auth/oidc/login` builds the [`authorize_url`] (with a signed
//! `state` binding tenant + nonce, so no server-side session store is needed
//! for CSRF/replay protection) and redirects to the IdP. The IdP redirects
//! back to `/auth/oidc/callback` with `code` + `state`; the handler
//! [`verify_state`]s it, [`exchange_code`]s the code for an ID token, and
//! [`validate_id_token`]s the token (signature via the IdP's JWKS, plus
//! issuer/audience/expiry/nonce). The verified [`OidcClaims`] then resolve to a
//! local user.
//!
//! Kept deliberately dependency-light — `reqwest` (already in-tree) for the
//! HTTP calls and `jsonwebtoken` for RS256 verification, no `openidconnect`
//! crate — matching the workspace convention of hand-rolling small, auditable
//! crypto surfaces.

use base64::Engine;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use vortex_security::crypto;

/// Resolved OIDC provider configuration (an `identity_provider` row with its
/// `client_secret_enc` already decrypted by the caller via the key provider).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub provider_id: Uuid,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub subject_claim: String,
    pub email_claim: String,
    pub name_claim: String,
    pub jit: bool,
    pub default_role: Option<String>,
}

/// The subset of an OIDC discovery document Vortex needs.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

/// Verified identity claims extracted from a validated ID token.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

/// Fetch and parse the IdP's discovery document from
/// `{issuer}/.well-known/openid-configuration`.
pub async fn discover(issuer: &str) -> Result<Discovery, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("discovery fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("discovery returned HTTP {}", resp.status()));
    }
    let disc: Discovery = resp
        .json()
        .await
        .map_err(|e| format!("discovery parse failed: {e}"))?;
    Ok(disc)
}

/// Build the IdP authorization URL to redirect the user to.
pub fn authorize_url(cfg: &OidcConfig, disc: &Discovery, state: &str, nonce: &str) -> Result<String, String> {
    let scope = if cfg.scopes.split_whitespace().any(|s| s == "openid") {
        cfg.scopes.clone()
    } else {
        format!("openid {}", cfg.scopes)
    };
    let url = reqwest::Url::parse_with_params(
        &disc.authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", &cfg.client_id),
            ("redirect_uri", &cfg.redirect_uri),
            ("scope", &scope),
            ("state", state),
            ("nonce", nonce),
        ],
    )
    .map_err(|e| format!("authorize url build failed: {e}"))?;
    Ok(url.to_string())
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    access_token: Option<String>,
}

/// Exchange an authorization `code` for an ID token at the token endpoint.
pub async fn exchange_code(cfg: &OidcConfig, disc: &Discovery, code: &str) -> Result<String, String> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
    ];
    let resp = reqwest::Client::new()
        .post(&disc.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("token endpoint returned HTTP {}", resp.status()));
    }
    let tok: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("token response parse failed: {e}"))?;
    Ok(tok.id_token)
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    kty: Option<String>,
}

/// Validate an ID token: RS256 signature against the IdP JWKS, plus issuer,
/// audience (`client_id`), expiry, and the `nonce` bound in our signed state.
/// Returns the mapped [`OidcClaims`].
pub async fn validate_id_token(
    cfg: &OidcConfig,
    disc: &Discovery,
    id_token: &str,
    expected_nonce: &str,
) -> Result<OidcClaims, String> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(id_token).map_err(|e| format!("bad token header: {e}"))?;
    if header.alg != Algorithm::RS256 {
        return Err(format!("unsupported ID-token algorithm: {:?}", header.alg));
    }

    // Fetch JWKS and select the key matching the token's `kid`.
    let jwks: Jwks = reqwest::Client::new()
        .get(&disc.jwks_uri)
        .send()
        .await
        .map_err(|e| format!("jwks fetch failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("jwks parse failed: {e}"))?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| match (&header.kid, &k.kid) {
            (Some(h), Some(k)) => h == k,
            // No kid on the token: accept the sole RSA key if there is one.
            (None, _) => k.kty.as_deref() == Some("RSA"),
            _ => false,
        })
        .ok_or("no matching JWKS key for token kid")?;

    let (n, e) = match (&jwk.n, &jwk.e) {
        (Some(n), Some(e)) => (n, e),
        _ => return Err("JWKS key missing RSA components".to_string()),
    };
    let key = DecodingKey::from_rsa_components(n, e)
        .map_err(|e| format!("bad JWKS RSA key: {e}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&cfg.client_id]);
    validation.set_issuer(&[&disc.issuer]);
    // exp is validated by default; require it to be present.
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let data = decode::<serde_json::Value>(id_token, &key, &validation)
        .map_err(|e| format!("ID token validation failed: {e}"))?;
    let claims = data.claims;

    // Bind the token to our authorization request: the nonce must match the
    // one we signed into `state` and passed to the IdP.
    let token_nonce = claims.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if token_nonce.is_empty() || !constant_time_eq(token_nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err("ID token nonce mismatch (possible replay)".to_string());
    }

    let subject = claims
        .get(&cfg.subject_claim)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or("ID token missing subject claim")?;
    let email = claims.get(&cfg.email_claim).and_then(|v| v.as_str()).map(str::to_string);
    let name = claims.get(&cfg.name_claim).and_then(|v| v.as_str()).map(str::to_string);

    Ok(OidcClaims { subject, email, name })
}

// ---------------------------------------------------------------------------
// Signed state (CSRF + replay protection without a server-side store)
// ---------------------------------------------------------------------------

/// Data carried through the OIDC round-trip in the signed `state` parameter.
#[derive(Debug, Clone)]
pub struct StateData {
    pub db_name: String,
    pub provider_id: Uuid,
    pub nonce: String,
    pub issued_at: u64,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Produce a tamper-proof `state` value: `base64url(payload).hmac_hex`, where
/// the HMAC key is derived from the master key. No server-side store is needed
/// — the callback re-verifies the signature and freshness.
pub fn sign_state(db_name: &str, provider_id: Uuid, nonce: &str, key: &[u8]) -> String {
    let payload = format!("{}|{}|{}|{}", db_name, provider_id, nonce, now_secs());
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let mac = crypto::hmac_sha256_hex(key, b64.as_bytes());
    format!("{b64}.{mac}")
}

/// Verify and parse a `state` produced by [`sign_state`]. Rejects a bad
/// signature or a state older than `max_age_secs` (replay window).
pub fn verify_state(state: &str, key: &[u8], max_age_secs: u64) -> Result<StateData, String> {
    let (b64, mac) = state.split_once('.').ok_or("malformed state")?;
    let expected = crypto::hmac_sha256_hex(key, b64.as_bytes());
    if !constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
        return Err("state signature mismatch".to_string());
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| "state decode failed")?;
    let payload = String::from_utf8(raw).map_err(|_| "state utf8 failed")?;
    let parts: Vec<&str> = payload.split('|').collect();
    if parts.len() != 4 {
        return Err("state field count".to_string());
    }
    let issued_at: u64 = parts[3].parse().map_err(|_| "state timestamp")?;
    if now_secs().saturating_sub(issued_at) > max_age_secs {
        return Err("state expired".to_string());
    }
    Ok(StateData {
        db_name: parts[0].to_string(),
        provider_id: Uuid::parse_str(parts[1]).map_err(|_| "state provider id")?,
        nonce: parts[2].to_string(),
        issued_at,
    })
}

/// Constant-time byte comparison, so signature/nonce checks don't leak via
/// timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_detects_tampering() {
        let key = [42u8; 32];
        let pid = Uuid::from_u128(0x1234);
        let state = sign_state("acc_dev", pid, "nonce-abc", &key);
        let parsed = verify_state(&state, &key, 600).expect("valid");
        assert_eq!(parsed.db_name, "acc_dev");
        assert_eq!(parsed.provider_id, pid);
        assert_eq!(parsed.nonce, "nonce-abc");

        // Flip a byte in the payload → signature mismatch.
        let mut bad = state.clone();
        let mid = bad.find('.').unwrap() / 2;
        bad.replace_range(mid..mid + 1, if &bad[mid..mid + 1] == "A" { "B" } else { "A" });
        assert!(verify_state(&bad, &key, 600).is_err());

        // Wrong key → mismatch.
        assert!(verify_state(&state, &[7u8; 32], 600).is_err());
    }

    #[test]
    fn state_expires() {
        let key = [9u8; 32];
        // Hand-craft a validly-signed state with an ancient timestamp (epoch
        // 1000) so the freshness check, not the signature, is what rejects it.
        let payload = format!("db|{}|n|1000", Uuid::nil());
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let mac = crypto::hmac_sha256_hex(&key, b64.as_bytes());
        let old_state = format!("{b64}.{mac}");
        assert!(verify_state(&old_state, &key, 600).is_err(), "ancient state must be rejected");

        // A freshly-signed state passes with a sane window.
        let fresh = sign_state("db", Uuid::nil(), "n", &key);
        assert!(verify_state(&fresh, &key, 600).is_ok());
    }

    #[test]
    fn authorize_url_includes_openid_scope_and_params() {
        let cfg = OidcConfig {
            provider_id: Uuid::nil(),
            display_name: "Test".into(),
            issuer: "https://idp.example".into(),
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            scopes: "email profile".into(), // no openid → must be prepended
            subject_claim: "sub".into(),
            email_claim: "email".into(),
            name_claim: "name".into(),
            jit: true,
            default_role: None,
        };
        let disc = Discovery {
            issuer: "https://idp.example".into(),
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            jwks_uri: "https://idp.example/jwks".into(),
            userinfo_endpoint: None,
        };
        let url = authorize_url(&cfg, &disc, "state123", "nonce123").unwrap();
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("nonce=nonce123"));
        assert!(url.contains("scope=openid"));
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
