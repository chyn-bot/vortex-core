//! Symmetric encryption for secrets at rest (SMTP passwords, API keys, …).
//!
//! AES-256-GCM via `ring`. The stored blob is `nonce(12) || ciphertext || tag`,
//! so a row carries everything needed to decrypt except the master key. The
//! master key comes from the `VORTEX_SECRET_KEY` environment variable
//! (base64-encoded 32 bytes); in a dev environment without it, a fixed
//! development key is used and a warning is logged — production MUST set it.
//!
//! ```ignore
//! let key = crypto::master_key();
//! let blob = crypto::encrypt(b"smtp-password", &key)?;   // store blob (BYTEA)
//! let plain = crypto::decrypt(&blob, &key)?;             // on use
//! ```

use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

/// Errors from the crypto layer. Deliberately opaque — never leak whether a
/// failure was a bad key, bad nonce, or tampered ciphertext.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid key: must be 32 bytes")]
    BadKey,
    #[error("ciphertext too short")]
    Truncated,
    /// A pluggable key provider (KMS / Vault) failed to wrap or unwrap a data
    /// key. Deliberately opaque to callers; the concrete cause (network,
    /// auth, throttling) is logged internally, never surfaced, so the error
    /// cannot become a decryption oracle.
    #[error("key provider unavailable")]
    Provider,
    /// A sealed blob did not parse as a valid envelope.
    #[error("malformed sealed envelope")]
    Envelope,
}

const KEY_LEN: usize = 32;

/// Env var holding the base64-encoded 32-byte master key.
pub const MASTER_KEY_ENV: &str = "VORTEX_SECRET_KEY";

/// Resolve the 32-byte master key from `VORTEX_SECRET_KEY` (base64). Falls
/// back to a fixed development key (with a warning) when unset, so local dev
/// works out of the box — production deployments MUST set the env var.
pub fn master_key() -> [u8; KEY_LEN] {
    if let Ok(b64) = std::env::var(MASTER_KEY_ENV) {
        match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            Ok(bytes) if bytes.len() == KEY_LEN => {
                let mut k = [0u8; KEY_LEN];
                k.copy_from_slice(&bytes);
                return k;
            }
            _ => {
                tracing::error!(
                    "{MASTER_KEY_ENV} is set but is not base64 of exactly 32 bytes; \
                     falling back to the insecure development key"
                );
            }
        }
    } else {
        tracing::warn!(
            "{MASTER_KEY_ENV} not set — using the insecure development encryption key. \
             Set it (base64 of 32 random bytes) before storing real secrets."
        );
    }
    // Fixed development key — NOT secret. Only reachable when the env is unset
    // or malformed; production must set a real key.
    *b"vortex-dev-insecure-key-32bytes!"
}

/// Env var that explicitly authorises running on the built-in development
/// key. Only a developer should ever set this; production deployments must
/// supply a real key instead.
pub const ALLOW_DEV_KEY_ENV: &str = "VORTEX_ALLOW_DEV_KEY";

/// Whether `VORTEX_SECRET_KEY` is present and well-formed (base64 of exactly
/// 32 bytes). `false` means [`master_key`] would fall back to the built-in
/// development key.
pub fn master_key_configured() -> bool {
    std::env::var(MASTER_KEY_ENV)
        .ok()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok())
        .map(|bytes| bytes.len() == KEY_LEN)
        .unwrap_or(false)
}

/// Fail-closed startup gate for the master encryption key.
///
/// Returns `Err(message)` when no usable key is configured and the operator
/// has not explicitly opted into the insecure development key via
/// `VORTEX_ALLOW_DEV_KEY`. Callers are expected to refuse to start: a process
/// that seals tenant secrets under a key published in this source file offers
/// no confidentiality at all, so booting anyway would be worse than not
/// booting.
pub fn require_master_key() -> Result<(), String> {
    if master_key_configured() {
        return Ok(());
    }
    let allowed = std::env::var(ALLOW_DEV_KEY_ENV)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if allowed {
        tracing::warn!(
            "{MASTER_KEY_ENV} is not set and {ALLOW_DEV_KEY_ENV} is on — running on the \
             built-in development key. Secrets sealed now are NOT confidential."
        );
        return Ok(());
    }
    Err(format!(
        "{MASTER_KEY_ENV} is not set (or is not base64 of exactly 32 bytes).\n\
         Secrets at rest — SMTP passwords, API keys, TOTP seeds — would be sealed under a \
         development key that is published in the Vortex source, and the MFA pre-auth token \
         would be forgeable.\n\n\
         Generate one with:  openssl rand -base64 32\n\
         then set it, e.g.:  {MASTER_KEY_ENV}=<base64-32-bytes>\n\n\
         For local development only, set {ALLOW_DEV_KEY_ENV}=1 to proceed on the insecure key."
    ))
}

/// Generate a fresh random 32-byte key, base64-encoded — for operators to
/// drop into `VORTEX_SECRET_KEY`.
pub fn generate_key_base64() -> Result<String, CryptoError> {
    let mut k = [0u8; KEY_LEN];
    SystemRandom::new().fill(&mut k).map_err(|_| CryptoError::Encrypt)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(k))
}

/// Encrypt `plaintext`, returning `nonce || ciphertext || tag`.
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::BadKey);
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::BadKey)?;
    let sealing = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::Encrypt)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt`].
pub fn decrypt(blob: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::BadKey);
    }
    if blob.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err(CryptoError::Truncated);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::BadKey)?;
    let opening = LessSafeKey::new(unbound);

    let mut in_out = ct.to_vec();
    let plain = opening
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(plain.to_vec())
}

/// Convenience: encrypt a string secret to a storable blob.
pub fn encrypt_str(plaintext: &str, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt(plaintext.as_bytes(), key)
}

/// Convenience: decrypt a blob back to a UTF-8 string.
pub fn decrypt_str(blob: &[u8], key: &[u8]) -> Result<String, CryptoError> {
    let bytes = decrypt(blob, key)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::Decrypt)
}

/// Raw HMAC-SHA256 of `message` under `key`. Chainable — AWS SigV4-style
/// derived-key schemes feed one tag in as the next key.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use ring::hmac;
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, message).as_ref().to_vec()
}

/// HMAC-SHA256 of `message` under `key`, hex-encoded. Used to sign outbound
/// webhook payloads so receivers can verify authenticity and integrity
/// (`X-Vortex-Signature: sha256=<hex>`). Not reversible — a keyed digest, not
/// encryption.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    hex::encode(hmac_sha256(key, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = [7u8; 32];
        let blob = encrypt_str("hunter2", &key).unwrap();
        assert_ne!(blob, b"hunter2");
        assert_eq!(decrypt_str(&blob, &key).unwrap(), "hunter2");
    }

    #[test]
    fn distinct_nonces_differ() {
        let key = [9u8; 32];
        // Same plaintext encrypts to different blobs (random nonce).
        assert_ne!(encrypt_str("x", &key).unwrap(), encrypt_str("x", &key).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt_str("secret", &[1u8; 32]).unwrap();
        assert!(decrypt_str(&blob, &[2u8; 32]).is_err());
    }

    #[test]
    fn tamper_fails() {
        let key = [3u8; 32];
        let mut blob = encrypt_str("secret", &key).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(decrypt(&blob, &key).is_err());
    }

    #[test]
    fn bad_key_len() {
        assert!(matches!(encrypt(b"x", &[0u8; 16]), Err(CryptoError::BadKey)));
    }
}
