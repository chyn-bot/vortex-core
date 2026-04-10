//! Cryptographic signing for the WORM audit ledger.
//!
//! Every entry in the audit chain is optionally signed by an Ed25519 key,
//! with the key identifier recorded alongside the signature so verification
//! can be performed later even after the key rotates. The signed payload
//! is the JCS canonical serialization of the audit row (see
//! [`crate::audit::canonical`]) concatenated with the entry hash; signing
//! after hashing lets verifiers recompute the chain first and then verify
//! signatures independently.
//!
//! # Key sources
//!
//! In Phase 0 the signing key is loaded from the environment variable
//! `VORTEX_AUDIT_SIGNING_KEY`. The value is base64-encoded PKCS#8 DER —
//! the format OpenSSL emits after stripping PEM armor:
//!
//! ```sh
//! openssl genpkey -algorithm ed25519 -outform DER | base64 -w0
//! ```
//!
//! The key ID is read from `VORTEX_AUDIT_SIGNING_KEY_ID`; if unset, it
//! defaults to `"default"`. Verifiers look up the public key in the
//! `audit_signing_keys` table by this ID.
//!
//! A future phase will replace the env-var source with a KMS/HSM broker;
//! the [`SigningKey`] trait is the seam for that substitution.

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use thiserror::Error;

/// Algorithm identifier stored alongside each signature. Must match the
/// `algorithm` column in `audit_signing_keys`.
pub const ALG_ED25519: &str = "ed25519";

/// Environment variable holding the base64-encoded PKCS#8 DER key.
pub const ENV_SIGNING_KEY: &str = "VORTEX_AUDIT_SIGNING_KEY";

/// Environment variable holding the key ID (optional, defaults to "default").
pub const ENV_SIGNING_KEY_ID: &str = "VORTEX_AUDIT_SIGNING_KEY_ID";

/// Environment variable toggling signing mode. Set to `disabled` to skip
/// signing entirely — the hash chain still guarantees tamper evidence, but
/// the ledger cannot prove *who* signed each entry. Intended for local
/// development only.
pub const ENV_SIGNING_MODE: &str = "VORTEX_AUDIT_SIGNING_MODE";

/// Errors produced by the signing subsystem.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("environment variable {0} is not set")]
    MissingEnvVar(&'static str),
    #[error("failed to decode base64 key: {0}")]
    Base64(String),
    #[error("failed to parse PKCS#8 Ed25519 key: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    VerificationFailed,
}

/// A signing key capable of producing detached signatures over arbitrary
/// byte sequences. Implementations are expected to be thread-safe; the
/// audit writer will hold a single [`std::sync::Arc<dyn SigningKey>`] for
/// the lifetime of the server.
pub trait SigningKey: Send + Sync {
    /// Stable identifier for this key, used to look up the matching public
    /// key in the `audit_signing_keys` table during verification.
    fn key_id(&self) -> &str;

    /// Algorithm code (see [`ALG_ED25519`]).
    fn algorithm(&self) -> &'static str;

    /// Produce a signature over the given bytes.
    fn sign(&self, bytes: &[u8]) -> Vec<u8>;

    /// Return the raw public key bytes (32 bytes for Ed25519).
    fn public_key(&self) -> Vec<u8>;
}

/// Ed25519 signing key backed by the `ring` crate.
pub struct Ed25519Key {
    key_id: String,
    key_pair: Ed25519KeyPair,
}

impl Ed25519Key {
    /// Construct from a raw PKCS#8 DER blob.
    pub fn from_pkcs8(key_id: impl Into<String>, pkcs8: &[u8]) -> Result<Self, SigningError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        Ok(Self {
            key_id: key_id.into(),
            key_pair,
        })
    }

    /// Load from environment: `VORTEX_AUDIT_SIGNING_KEY` (required,
    /// base64-encoded PKCS#8) and `VORTEX_AUDIT_SIGNING_KEY_ID` (optional,
    /// defaults to `"default"`).
    pub fn from_env() -> Result<Self, SigningError> {
        let raw = std::env::var(ENV_SIGNING_KEY)
            .map_err(|_| SigningError::MissingEnvVar(ENV_SIGNING_KEY))?;
        let key_id =
            std::env::var(ENV_SIGNING_KEY_ID).unwrap_or_else(|_| "default".to_string());

        // Accept either raw base64 or PEM-wrapped base64.
        let cleaned: String = if raw.contains("-----BEGIN") {
            raw.lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("")
        } else {
            raw.trim().to_string()
        };

        let pkcs8 = base64::engine::general_purpose::STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|e| SigningError::Base64(e.to_string()))?;

        Self::from_pkcs8(key_id, &pkcs8)
    }

    /// Generate a fresh in-memory Ed25519 key. Intended for tests and
    /// development; real deployments must load a persistent key via
    /// [`Self::from_env`].
    pub fn generate(key_id: impl Into<String>) -> Result<(Self, Vec<u8>), SigningError> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        let pkcs8_bytes = pkcs8.as_ref().to_vec();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        Ok((
            Self {
                key_id: key_id.into(),
                key_pair: kp,
            },
            pkcs8_bytes,
        ))
    }
}

impl SigningKey for Ed25519Key {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        ALG_ED25519
    }

    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        self.key_pair.sign(bytes).as_ref().to_vec()
    }

    fn public_key(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }
}

/// Verify an Ed25519 signature against a known public key.
///
/// Returns `Ok(())` if the signature matches. Used by
/// `vortex audit verify` to validate historical entries against the
/// public keys recorded in `audit_signing_keys`.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
    let parsed = UnparsedPublicKey::new(&ED25519, public_key);
    parsed
        .verify(message, signature)
        .map_err(|_| SigningError::VerificationFailed)
}

/// Resolved signing mode for the running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Every audit entry is signed. This is the default and the only
    /// mode acceptable for production.
    Enabled,
    /// Entries are chained but not signed. For local development only.
    Disabled,
}

impl SigningMode {
    pub fn from_env() -> Self {
        match std::env::var(ENV_SIGNING_MODE).as_deref() {
            Ok("disabled") => SigningMode::Disabled,
            _ => SigningMode::Enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let (key, _pkcs8) = Ed25519Key::generate("test-key").unwrap();
        let msg = b"hello audit ledger";
        let sig = key.sign(msg);
        assert_eq!(sig.len(), 64);
        verify_ed25519(&key.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let (key, _pkcs8) = Ed25519Key::generate("test-key").unwrap();
        let msg = b"original message";
        let sig = key.sign(msg);
        let tampered = b"modified message";
        assert!(matches!(
            verify_ed25519(&key.public_key(), tampered, &sig),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let (key1, _) = Ed25519Key::generate("k1").unwrap();
        let (key2, _) = Ed25519Key::generate("k2").unwrap();
        let msg = b"a message";
        let sig = key1.sign(msg);
        assert!(matches!(
            verify_ed25519(&key2.public_key(), msg, &sig),
            Err(SigningError::VerificationFailed)
        ));
    }

    #[test]
    fn key_id_is_preserved() {
        let (key, _) = Ed25519Key::generate("my-key-001").unwrap();
        assert_eq!(key.key_id(), "my-key-001");
        assert_eq!(key.algorithm(), ALG_ED25519);
    }

    #[test]
    fn public_key_is_32_bytes() {
        let (key, _) = Ed25519Key::generate("k").unwrap();
        assert_eq!(key.public_key().len(), 32);
    }

    #[test]
    fn base64_round_trip_via_env_loader() {
        let (_key, pkcs8) = Ed25519Key::generate("original").unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pkcs8);
        // Simulate loading — bypass env for test isolation.
        let reloaded = Ed25519Key::from_pkcs8(
            "reloaded",
            &base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .unwrap(),
        )
        .unwrap();
        let msg = b"cross-process message";
        let sig = reloaded.sign(msg);
        verify_ed25519(&reloaded.public_key(), msg, &sig).unwrap();
    }
}
