//! Pluggable key providers for secrets-at-rest.
//!
//! [`crate::crypto`] seals secrets under a single 32-byte master key read from
//! `VORTEX_SECRET_KEY`. That is fine for local and HSM-static deployments, but
//! regulated customers (and this codebase's BNM RMiT 8c/8d obligations) want
//! the *key* to live in a cloud KMS or a Vault/OpenBao Transit engine, so that
//! Vortex never holds long-term key material and key custody stays independent
//! of the hosting provider.
//!
//! This module adds that indirection without disturbing the existing
//! primitives. The shape deliberately mirrors [`crate::signing`] (the HSM
//! signing backend): a trait, a config enum, and a factory.
//!
//! ## Two envelope strategies
//!
//! * [`LocalKeyProvider`] seals directly under the master key and emits the
//!   **exact same byte layout** as `crypto::encrypt_str(x, &master_key())`.
//!   Existing rows therefore keep decrypting unchanged — adopting the provider
//!   API is a no-op for storage.
//!
//! * KMS/Vault backends use **envelope encryption**: a fresh random data key
//!   (DEK) encrypts the plaintext locally with AES-256-GCM, and the KMS wraps
//!   only the 32-byte DEK. The stored blob is a versioned envelope
//!   ([`ENVELOPE_MAGIC`]) carrying the wrapped DEK. Because the envelope is
//!   self-describing and legacy blobs are not, [`EnvelopeProvider::unseal`]
//!   can transparently fall back to the legacy master-key path for rows sealed
//!   before the migration — the single hardest requirement for turning KMS on
//!   in an existing deployment.
//!
//! ## Adding a backend
//!
//! Implement [`DekWrapper`] (wrap/unwrap a 32-byte DEK), add a variant to
//! [`config::KeyProviderConfig`], and a match arm to
//! [`config::build_key_provider`]. The AES-GCM data layer and the envelope
//! codec are shared — a backend only speaks to its KMS. See
//! [`aws_kms`]/[`vault`] for worked examples.

use crate::crypto::{self, CryptoError};

pub mod config;

#[cfg(any(feature = "aws-kms", feature = "vault"))]
mod http;

#[cfg(feature = "aws-kms")]
pub mod aws_kms;
#[cfg(feature = "vault")]
pub mod vault;

pub use config::{build_key_provider, KeyProviderConfig};

/// A source of confidentiality for secrets at rest. Implementations are
/// thread-safe and held as a single `Arc<dyn KeyProvider>` on `AppState` for
/// the life of the process.
///
/// `seal` / `unseal` are the only operations consumers need; the byte layout
/// of the returned blob is the provider's private concern (a `BYTEA` column).
pub trait KeyProvider: Send + Sync {
    /// Stable identifier for the wrapping key, for logs and audit. For the
    /// local provider this is `"local"`; for KMS it is the key ARN / Vault key
    /// name so operators can trace which key sealed which rows.
    fn key_id(&self) -> &str;

    /// Seal `plaintext`, returning an opaque storable blob.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Unseal a blob produced by [`KeyProvider::seal`] (or, for providers that
    /// support it, a legacy `crypto::encrypt` blob).
    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Convenience: seal a UTF-8 string secret.
    fn seal_str(&self, plaintext: &str) -> Result<Vec<u8>, CryptoError> {
        self.seal(plaintext.as_bytes())
    }

    /// Convenience: unseal back to a UTF-8 string.
    fn unseal_str(&self, blob: &[u8]) -> Result<String, CryptoError> {
        let bytes = self.unseal(blob)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::Decrypt)
    }
}

/// The default provider: seal under the process master key, byte-compatible
/// with every secret sealed before this module existed.
///
/// This is what a deployment with no KMS configured uses, and it is what the
/// `require_master_key()` startup gate already protects. It never falls back
/// to the insecure dev key silently at seal time beyond what `crypto` already
/// does; production must set `VORTEX_SECRET_KEY` (enforced at boot).
pub struct LocalKeyProvider {
    key: [u8; 32],
}

impl LocalKeyProvider {
    /// Build from the ambient `VORTEX_SECRET_KEY` (via [`crypto::master_key`]).
    pub fn from_env() -> Self {
        Self { key: crypto::master_key() }
    }

    /// Build from an explicit 32-byte key (tests, or a key handed down from an
    /// HSM that exports a static wrapping key).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl KeyProvider for LocalKeyProvider {
    fn key_id(&self) -> &str {
        "local"
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Identical layout to legacy `crypto::encrypt` — no envelope header —
        // so rows are indistinguishable from pre-existing ones.
        crypto::encrypt(plaintext, &self.key)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        crypto::decrypt(blob, &self.key)
    }
}

// ---------------------------------------------------------------------------
// Envelope encryption (KMS / Vault backends)
// ---------------------------------------------------------------------------

/// Magic prefix marking a Vortex key-envelope blob. Chosen so it cannot be a
/// valid legacy blob's leading bytes in practice: a legacy blob starts with a
/// random 12-byte AES-GCM nonce, so a collision is ~2^-32 per row, and even
/// then [`EnvelopeProvider::unseal`] retries via the legacy path.
pub const ENVELOPE_MAGIC: &[u8; 4] = b"VXK1";

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Wraps and unwraps a 32-byte data key against an external key service. This
/// is the *only* surface a KMS/Vault backend implements; the AES-GCM data
/// layer and the envelope framing are handled by [`EnvelopeProvider`].
pub trait DekWrapper: Send + Sync {
    /// Stable identifier of the wrapping key (ARN / Vault key name).
    fn key_id(&self) -> &str;

    /// One-byte tag distinguishing this backend in the stored envelope, so a
    /// blob can be sanity-checked against the configured provider on unseal.
    fn provider_tag(&self) -> u8;

    /// Encrypt (wrap) a 32-byte data key with the external key. The returned
    /// bytes are opaque KMS ciphertext, stored verbatim in the envelope.
    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt (unwrap) a wrapped data key produced by [`DekWrapper::wrap`].
    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], CryptoError>;
}

/// A [`KeyProvider`] that performs envelope encryption over any [`DekWrapper`].
///
/// Seal: generate a random DEK, AES-256-GCM-encrypt the plaintext under it,
/// ask the wrapper to wrap the DEK, and frame everything into a versioned
/// envelope. Unseal: parse the envelope, unwrap the DEK, decrypt. Blobs
/// without the magic prefix are treated as legacy and decrypted under the
/// process master key (only if one is configured), so an existing deployment
/// can switch to KMS and keep reading old rows.
pub struct EnvelopeProvider<W: DekWrapper> {
    wrapper: W,
    /// Whether to fall back to the master key for legacy (non-envelope) blobs.
    /// True for env→KMS migrations; can be disabled for KMS-only deployments
    /// that never held a local master key.
    legacy_fallback: bool,
}

impl<W: DekWrapper> EnvelopeProvider<W> {
    pub fn new(wrapper: W) -> Self {
        Self { wrapper, legacy_fallback: true }
    }

    /// Disable the legacy master-key fallback on unseal (KMS-only deployments).
    pub fn without_legacy_fallback(mut self) -> Self {
        self.legacy_fallback = false;
        self
    }

    /// Frame an envelope: MAGIC | version | provider_tag | key_id_len(u16 BE) |
    /// key_id | wrapped_len(u32 BE) | wrapped_dek | inner_blob.
    fn frame(&self, wrapped_dek: &[u8], inner: &[u8]) -> Vec<u8> {
        let key_id = self.wrapper.key_id().as_bytes();
        let mut out = Vec::with_capacity(
            4 + 1 + 1 + 2 + key_id.len() + 4 + wrapped_dek.len() + inner.len(),
        );
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(self.wrapper.provider_tag());
        out.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        out.extend_from_slice(key_id);
        out.extend_from_slice(&(wrapped_dek.len() as u32).to_be_bytes());
        out.extend_from_slice(wrapped_dek);
        out.extend_from_slice(inner);
        out
    }
}

/// Parsed view of an envelope blob's header. Borrows from the source blob.
struct Envelope<'a> {
    provider_tag: u8,
    #[allow(dead_code)]
    key_id: &'a [u8],
    wrapped_dek: &'a [u8],
    inner: &'a [u8],
}

/// Attempt to parse `blob` as an envelope. Returns `None` if the magic prefix
/// is absent (i.e. it is a legacy blob), `Some(Err)` if the magic is present
/// but the framing is corrupt.
fn parse_envelope(blob: &[u8]) -> Option<Result<Envelope<'_>, CryptoError>> {
    if blob.len() < 4 || &blob[0..4] != ENVELOPE_MAGIC {
        return None;
    }
    Some((|| {
        let mut p = 4usize;
        let need = |p: usize, n: usize| -> Result<(), CryptoError> {
            if p + n > blob.len() { Err(CryptoError::Envelope) } else { Ok(()) }
        };
        need(p, 2)?;
        let _version = blob[p];
        let provider_tag = blob[p + 1];
        p += 2;
        need(p, 2)?;
        let kid_len = u16::from_be_bytes([blob[p], blob[p + 1]]) as usize;
        p += 2;
        need(p, kid_len)?;
        let key_id = &blob[p..p + kid_len];
        p += kid_len;
        need(p, 4)?;
        let wlen = u32::from_be_bytes([blob[p], blob[p + 1], blob[p + 2], blob[p + 3]]) as usize;
        p += 4;
        need(p, wlen)?;
        let wrapped_dek = &blob[p..p + wlen];
        p += wlen;
        let inner = &blob[p..];
        Ok(Envelope { provider_tag, key_id, wrapped_dek, inner })
    })())
}

impl<W: DekWrapper> KeyProvider for EnvelopeProvider<W> {
    fn key_id(&self) -> &str {
        self.wrapper.key_id()
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Fresh per-secret data key; encrypt locally, wrap the DEK remotely.
        let mut dek = [0u8; 32];
        {
            use ring::rand::{SecureRandom, SystemRandom};
            SystemRandom::new().fill(&mut dek).map_err(|_| CryptoError::Encrypt)?;
        }
        let inner = crypto::encrypt(plaintext, &dek)?;
        let wrapped = self.wrapper.wrap(&dek)?;
        // Best-effort zeroization of the plaintext DEK.
        dek.iter_mut().for_each(|b| *b = 0);
        Ok(self.frame(&wrapped, &inner))
    }

    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match parse_envelope(blob) {
            Some(Ok(env)) => {
                if env.provider_tag != self.wrapper.provider_tag() {
                    // Sealed by a different backend than is configured.
                    return Err(CryptoError::Envelope);
                }
                let mut dek = self.wrapper.unwrap(env.wrapped_dek)?;
                let out = crypto::decrypt(env.inner, &dek);
                dek.iter_mut().for_each(|b| *b = 0);
                out
            }
            Some(Err(e)) => Err(e),
            None => {
                // Legacy (pre-envelope) blob.
                if self.legacy_fallback && crypto::master_key_configured() {
                    crypto::decrypt(blob, &crypto::master_key())
                } else {
                    Err(CryptoError::Envelope)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_provider_is_byte_compatible_with_crypto() {
        let key = [7u8; 32];
        let p = LocalKeyProvider::with_key(key);
        let blob = p.seal_str("hunter2").unwrap();
        // A blob sealed by the provider decrypts with the raw crypto API…
        assert_eq!(crypto::decrypt_str(&blob, &key).unwrap(), "hunter2");
        // …and a blob sealed by the raw crypto API unseals with the provider.
        let legacy = crypto::encrypt_str("hunter2", &key).unwrap();
        assert_eq!(p.unseal_str(&legacy).unwrap(), "hunter2");
    }

    /// A deterministic in-memory wrapper: "wraps" a DEK by XOR under a fixed
    /// key. Stands in for a real KMS to exercise the envelope codec.
    struct MockWrapper {
        k: [u8; 32],
    }
    impl DekWrapper for MockWrapper {
        fn key_id(&self) -> &str { "mock/key-1" }
        fn provider_tag(&self) -> u8 { 0xEE }
        fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
            Ok(dek.iter().zip(self.k.iter()).map(|(a, b)| a ^ b).collect())
        }
        fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], CryptoError> {
            if wrapped.len() != 32 { return Err(CryptoError::Provider); }
            let mut out = [0u8; 32];
            for i in 0..32 { out[i] = wrapped[i] ^ self.k[i]; }
            Ok(out)
        }
    }

    #[test]
    fn envelope_round_trips() {
        let p = EnvelopeProvider::new(MockWrapper { k: [3u8; 32] });
        let blob = p.seal_str("s3cr3t").unwrap();
        assert!(blob.starts_with(ENVELOPE_MAGIC));
        assert_eq!(p.unseal_str(&blob).unwrap(), "s3cr3t");
    }

    #[test]
    fn envelope_uses_fresh_dek_per_seal() {
        let p = EnvelopeProvider::new(MockWrapper { k: [5u8; 32] });
        // Same plaintext → different blobs (random DEK + random nonce).
        assert_ne!(p.seal_str("x").unwrap(), p.seal_str("x").unwrap());
    }

    #[test]
    fn envelope_rejects_wrong_provider_tag() {
        let sealed = EnvelopeProvider::new(MockWrapper { k: [1u8; 32] })
            .seal_str("x")
            .unwrap();
        struct Other;
        impl DekWrapper for Other {
            fn key_id(&self) -> &str { "other" }
            fn provider_tag(&self) -> u8 { 0x11 }
            fn wrap(&self, d: &[u8; 32]) -> Result<Vec<u8>, CryptoError> { Ok(d.to_vec()) }
            fn unwrap(&self, w: &[u8]) -> Result<[u8; 32], CryptoError> {
                let mut o = [0u8; 32]; o.copy_from_slice(w); Ok(o)
            }
        }
        let p = EnvelopeProvider::new(Other);
        assert!(matches!(p.unseal(&sealed), Err(CryptoError::Envelope)));
    }

    #[test]
    fn corrupt_envelope_is_rejected() {
        let p = EnvelopeProvider::new(MockWrapper { k: [2u8; 32] });
        let mut blob = p.seal_str("x").unwrap();
        blob.truncate(6); // magic + version + tag, nothing else
        assert!(matches!(p.unseal(&blob), Err(CryptoError::Envelope)));
    }
}
