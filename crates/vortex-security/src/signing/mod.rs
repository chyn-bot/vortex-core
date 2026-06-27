//! Cryptographic signing for the WORM audit ledger.
//!
//! Every entry in the audit chain is optionally signed by a private
//! key whose identifier is recorded alongside the signature so
//! verification can be performed later even after the key rotates.
//! The signed payload is the JCS canonical serialization of the
//! audit row (see [`crate::audit::canonical`]) concatenated with
//! the entry hash; signing after hashing lets verifiers recompute
//! the chain first and then verify signatures independently.
//!
//! # Backends
//!
//! The [`SigningKey`] trait is the seam. Vortex ships two backends
//! today and is designed so operators can drop in more without
//! touching core code:
//!
//! - [`ed25519::Ed25519Key`] — **dev and small-deployment only**.
//!   Private key loaded from the `VORTEX_AUDIT_SIGNING_KEY`
//!   environment variable (base64 PKCS#8 DER) and held in the
//!   running process's heap. This is how Phase 0.1 shipped.
//!   Regulated customers MUST use a hardware-backed backend.
//! - [`pkcs11::Pkcs11SigningKey`] — **production path for
//!   regulated customers**. Delegates every `sign()` call to an
//!   HSM via the OASIS PKCS#11 v3.0 standard API. Works with
//!   SoftHSM2 (for dev and CI, not FIPS-validated), YubiHSM 2,
//!   Thales Luna, Entrust nShield, Utimaco CryptoServer, and
//!   any other PKCS#11-compliant device. The private key material
//!   **never enters the Vortex process memory** — sign operations
//!   happen inside the HSM and only the signature bytes come back.
//!
//! # Adding a new backend
//!
//! Four steps, all local to this module:
//!
//! 1. Add a new submodule `signing/<backend>.rs` with a struct
//!    implementing [`SigningKey`]. Use [`pkcs11::Pkcs11SigningKey`]
//!    as a template for how a non-trivial backend opens resources,
//!    caches the public key, and handles errors.
//! 2. Add a variant to [`config::SigningBackendConfig`] with the
//!    config fields your backend needs.
//! 3. Add a match arm to [`config::build_signing_key`] that opens
//!    the backend from the config.
//! 4. Add the config parser path in
//!    `vortex-cli/src/commands/server.rs::parse_audit_signing_config`
//!    so operators can select it from `vortex.toml`.
//!
//! Backends that belong here (future work): HashiCorp Vault /
//! OpenBao via the Transit secrets engine, AWS KMS, Azure Key
//! Vault, Google Cloud KMS. All four are shaped the same way —
//! an HTTP/gRPC round-trip to a remote signing service — and can
//! reuse the exact same trait.
//!
//! # Why not a single "HSM" enum?
//!
//! Keeping backends as separate structs implementing one trait
//! means:
//!
//! - New backends add zero code to existing backends (no enum
//!   match to exhaust)
//! - Tests can construct a fake backend by implementing the trait
//!   (see the `Ed25519Key::generate` test helper)
//! - The `Arc<dyn SigningKey>` stored on [`PgAuditStorage`] is
//!   backend-neutral, so replacing the backend at deploy time is
//!   a config change, not a recompile

use thiserror::Error;

pub mod config;
pub mod ed25519;
pub mod pkcs11;
pub mod verify;

pub use config::{build_signing_key, Pkcs11Config, SigningBackendConfig};
pub use ed25519::Ed25519Key;
pub use pkcs11::Pkcs11SigningKey;
pub use verify::verify_ed25519;

/// Algorithm identifier stored alongside each signature. Must match the
/// `algorithm` column in `audit_signing_keys`.
pub const ALG_ED25519: &str = "ed25519";

/// Environment variable holding the base64-encoded PKCS#8 DER key
/// (dev backend only).
pub const ENV_SIGNING_KEY: &str = "VORTEX_AUDIT_SIGNING_KEY";

/// Environment variable holding the key ID (optional, defaults to `"default"`).
pub const ENV_SIGNING_KEY_ID: &str = "VORTEX_AUDIT_SIGNING_KEY_ID";

/// Environment variable toggling signing mode. Set to `disabled` to
/// skip signing entirely — the hash chain still guarantees tamper
/// evidence, but the ledger cannot prove *who* signed each entry.
/// Intended for local development only.
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
    #[error("PKCS#11 backend error: {0}")]
    Pkcs11(String),
    #[error("signing backend configuration invalid: {0}")]
    Config(String),
}

/// A signing key capable of producing detached signatures over
/// arbitrary byte sequences. Implementations are expected to be
/// thread-safe; the audit writer holds a single
/// [`std::sync::Arc<dyn SigningKey>`] for the lifetime of the
/// server.
///
/// Two implementations ship today: [`Ed25519Key`] (dev/small
/// deployments, private key in process memory) and
/// [`Pkcs11SigningKey`] (regulated deployments, private key inside
/// an HSM). See the module header for how to add more.
pub trait SigningKey: Send + Sync {
    /// Stable identifier for this key, used to look up the
    /// matching public key in the `audit_signing_keys` table
    /// during verification.
    fn key_id(&self) -> &str;

    /// Algorithm code (see [`ALG_ED25519`]). Matches the
    /// `algorithm` column in `audit_signing_keys` so the verifier
    /// knows which primitive to invoke for the stored signature.
    fn algorithm(&self) -> &'static str;

    /// Produce a signature over the given bytes.
    fn sign(&self, bytes: &[u8]) -> Vec<u8>;

    /// Return the raw public key bytes (32 bytes for Ed25519).
    /// Used at startup to populate `audit_signing_keys` so
    /// verifiers can find the right key after rotation.
    fn public_key(&self) -> Vec<u8>;
}

/// Resolved signing mode for the running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Every audit entry is signed. This is the default and the
    /// only mode acceptable for production.
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
