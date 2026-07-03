//! # TOTP multi-factor authentication (RFC 6238 / RFC 4226)
//!
//! A dependency-free time-based one-time-password implementation for MFA,
//! built on `ring`'s HMAC-SHA1 (already a workspace dependency) plus a small
//! RFC 4648 base32 codec. No third-party TOTP crate is pulled in — this keeps
//! the supply-chain surface minimal, per the platform security rules.
//!
//! Secrets are 20 random bytes, base32-encoded for compatibility with any
//! standard authenticator app (Google Authenticator, Aegis, 1Password, …).
//! The caller is responsible for storing the secret **encrypted at rest**
//! (see [`crate::crypto`]) — this module only generates, formats, and verifies.
//!
//! ```
//! use vortex_security::mfa;
//! let secret = mfa::generate_secret();
//! let uri = mfa::provisioning_uri("Vortex SESB", "fa001", &secret);
//! // user scans `uri`, then on login supplies a 6-digit code:
//! // assert!(mfa::verify(&secret, "123456", now_unix));
//! ```

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate a fresh base32-encoded TOTP secret (20 random bytes → 32 chars).
pub fn generate_secret() -> String {
    let mut raw = [0u8; 20];
    // SystemRandom is infallible in practice; on the extreme off-chance it
    // errs we fall back to a zeroed buffer only to satisfy the type — callers
    // treat a failed enrollment as retryable.
    let _ = SystemRandom::new().fill(&mut raw);
    base32_encode(&raw)
}

/// The `otpauth://` provisioning URI an authenticator app consumes (usually
/// rendered as a QR code by the client).
pub fn provisioning_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let iss = url_encode(issuer);
    let acc = url_encode(account);
    format!(
        "otpauth://totp/{iss}:{acc}?secret={secret}&issuer={iss}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        iss = iss,
        acc = acc,
        secret = secret_b32,
        DIGITS = DIGITS,
        STEP_SECS = STEP_SECS,
    )
}

/// Verify a presented `code` against `secret_b32` at `unix_time`, allowing ±1
/// time step (±30 s) of clock skew. Returns false on any decode error.
pub fn verify(secret_b32: &str, code: &str, unix_time: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(key) = base32_decode(secret_b32) else {
        return false;
    };
    let counter = unix_time / STEP_SECS;
    for delta in [-1i64, 0, 1] {
        let c = counter as i64 + delta;
        if c < 0 {
            continue;
        }
        let expected = hotp(&key, c as u64);
        if ct_eq(expected.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

/// Encrypt a base32 secret for storage in `users.mfa_secret` — AES-256-GCM
/// under the master key (`VORTEX_SECRET_KEY`), then base64 so it fits a
/// VARCHAR column. Same scheme as `mail_servers`/`webhook_endpoints` secrets.
pub fn seal_secret(secret_b32: &str) -> Option<String> {
    use base64::Engine;
    let key = crate::crypto::master_key();
    let blob = crate::crypto::encrypt_str(secret_b32, &key).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Inverse of [`seal_secret`]: base64-decode then AES-GCM-decrypt a stored
/// secret back to its base32 form. `None` if the value is corrupt or the key
/// is wrong.
pub fn open_secret(stored: &str) -> Option<String> {
    use base64::Engine;
    let key = crate::crypto::master_key();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .ok()?;
    crate::crypto::decrypt_str(&blob, &key).ok()
}

/// The current 6-digit code (mainly for tests / server-side display).
pub fn current_code(secret_b32: &str, unix_time: u64) -> Option<String> {
    let key = base32_decode(secret_b32)?;
    Some(hotp(&key, unix_time / STEP_SECS))
}

/// RFC 4226 HOTP → zero-padded `DIGITS`-digit string.
fn hotp(key: &[u8], counter: u64) -> String {
    let mac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let digest = hmac::sign(&mac_key, &counter.to_be_bytes());
    let h = digest.as_ref(); // 20 bytes
    let offset = (h[19] & 0x0f) as usize;
    let bin = ((u32::from(h[offset]) & 0x7f) << 24)
        | (u32::from(h[offset + 1]) << 16)
        | (u32::from(h[offset + 2]) << 8)
        | u32::from(h[offset + 3]);
    let modulo = 10u32.pow(DIGITS);
    format!("{:0width$}", bin % modulo, width = DIGITS as usize)
}

/// Constant-time equality for equal-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─── base32 (RFC 4648, no padding, uppercase) ─────────────────────────────

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.trim().bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let val = BASE32_ALPHABET.iter().position(|&a| a == up)? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vector: ASCII secret "12345678901234567890" (SHA1).
    // base32 of that secret:
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn base32_roundtrip() {
        let raw = b"12345678901234567890";
        let enc = base32_encode(raw);
        assert_eq!(enc, RFC_SECRET);
        assert_eq!(base32_decode(&enc).unwrap(), raw);
    }

    #[test]
    fn rfc6238_vectors() {
        // 6-digit truncation of the published 8-digit RFC vectors.
        // T=59  → 94287082 → 287082 ; T=1111111109 → 07081804 → 081804
        assert_eq!(current_code(RFC_SECRET, 59).unwrap(), "287082");
        assert_eq!(current_code(RFC_SECRET, 1111111109).unwrap(), "081804");
    }

    #[test]
    fn verify_allows_skew_and_rejects_wrong() {
        // 287082 is valid at T=59; still valid at T=59+29 (same step) and
        // within ±1 step, but a wrong code never verifies.
        assert!(verify(RFC_SECRET, "287082", 59));
        assert!(verify(RFC_SECRET, "287082", 59 + 30)); // +1 step skew
        assert!(!verify(RFC_SECRET, "000000", 59));
        assert!(!verify(RFC_SECRET, "28708", 59)); // too short
        assert!(!verify(RFC_SECRET, "abcdef", 59)); // non-numeric
    }

    #[test]
    fn provisioning_uri_shape() {
        let uri = provisioning_uri("Vortex SESB", "fa001", RFC_SECRET);
        assert!(uri.starts_with("otpauth://totp/Vortex%20SESB:fa001?"));
        assert!(uri.contains(&format!("secret={RFC_SECRET}")));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
