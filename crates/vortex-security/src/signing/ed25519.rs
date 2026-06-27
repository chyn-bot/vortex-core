//! Ed25519 signing backend — loads a PKCS#8 DER private key from
//! the `VORTEX_AUDIT_SIGNING_KEY` environment variable (or a
//! provided byte slice) and signs via the `ring` crate.
//!
//! ## When to use this backend
//!
//! - Local dev: generate a throwaway key, stick it in the env,
//!   forget about it.
//! - CI: the same.
//! - Small non-regulated deployments where "private key on disk"
//!   is an acceptable trust model and the audit chain is a
//!   nice-to-have rather than a compliance requirement.
//!
//! ## When NOT to use this backend
//!
//! - Anywhere a regulator or auditor will review the deployment
//!   (banking, healthcare, critical infrastructure, public sector).
//!   The private key lives in the Vortex process heap where an
//!   attacker with local access or a debugger can extract it.
//!   Use [`crate::signing::pkcs11::Pkcs11SigningKey`] instead —
//!   it delegates every sign operation to an HSM and the private
//!   key never enters Vortex memory.

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::{SigningError, SigningKey, ALG_ED25519, ENV_SIGNING_KEY, ENV_SIGNING_KEY_ID};

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
    /// base64-encoded PKCS#8) and `VORTEX_AUDIT_SIGNING_KEY_ID`
    /// (optional, defaults to `"default"`).
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

    /// Generate a fresh in-memory Ed25519 key. Intended for tests
    /// and development; real deployments must load a persistent
    /// key via [`Self::from_env`] or use a hardware backend.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::verify::verify_ed25519;

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
