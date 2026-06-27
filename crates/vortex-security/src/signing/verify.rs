//! Standalone signature verification helpers — live outside the
//! [`super::SigningKey`] trait because verification is a pure
//! function of `(public_key, message, signature)` with no need for
//! the holding backend. The audit chain verifier
//! ([`crate::audit::verify`]) and the plain unit tests share this
//! function; they don't need an HSM session just to confirm
//! historical entries.

use ring::signature::{UnparsedPublicKey, ED25519};

use super::SigningError;

/// Verify an Ed25519 signature against a known public key.
///
/// Returns `Ok(())` if the signature matches. Used by
/// `vortex audit verify` to validate historical entries against
/// the public keys recorded in `audit_signing_keys`. Works
/// regardless of which [`super::SigningKey`] backend produced the
/// signature — the signed bytes and the public key are the only
/// inputs.
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SigningError> {
    let parsed = UnparsedPublicKey::new(&ED25519, public_key);
    parsed
        .verify(message, signature)
        .map_err(|_| SigningError::VerificationFailed)
}
