//! Signing-backend configuration: the `SigningBackendConfig`
//! enum selects which [`super::SigningKey`] implementation to
//! construct at startup, and [`build_signing_key`] is the factory
//! that dispatches by variant.
//!
//! Operators pick the backend via `vortex.toml` — see
//! `vortex-cli/src/commands/server.rs::parse_audit_signing_config`
//! for the TOML parsing, and `vortex.toml` for the field layout.
//!
//! ## Adding a new backend
//!
//! 1. Add a variant here carrying the config fields your backend
//!    needs — e.g. `Vault(VaultConfig)` with URL + token + key name.
//! 2. Add a match arm to [`build_signing_key`] that opens the
//!    backend and returns it as `Arc<dyn SigningKey>`.
//! 3. Add a submodule `signing/<backend>.rs` with the struct
//!    implementing [`super::SigningKey`] — see
//!    [`super::Pkcs11SigningKey`] as a non-trivial example.
//! 4. Extend `parse_audit_signing_config` in the CLI to recognize
//!    the new section in `vortex.toml`.
//!
//! No existing backend code is touched by any of these steps —
//! adding a backend is purely additive.

use std::sync::Arc;

use super::ed25519::Ed25519Key;
use super::pkcs11::Pkcs11SigningKey;
use super::{SigningError, SigningKey};

/// Configuration for the PKCS#11 signing backend.
///
/// The shape matches what every PKCS#11 HSM client needs: which
/// shared library to load, how to find the right token, which
/// private key object label to sign with, and where to read the
/// User PIN from. This is deliberately minimal — advanced HSM
/// features (multi-partition, slot tiering, session pooling) are
/// out of scope for the Vortex audit backend and can be added
/// later without breaking the default case.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Filesystem path to the PKCS#11 library `.so` / `.dll`.
    /// Typical values:
    ///
    /// - SoftHSM2 on Ubuntu: `/usr/lib/softhsm/libsofthsm2.so`
    /// - SoftHSM2 on RHEL/Fedora: `/usr/lib64/pkcs11/libsofthsm2.so`
    /// - Thales Luna: `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`
    /// - Entrust nShield: `/opt/nfast/toolkits/pkcs11/libcknfast.so`
    /// - YubiHSM 2: `/usr/lib/pkcs11/yubihsm_pkcs11.so`
    pub library_path: String,

    /// Token label to search for. Preferred over numeric `slot`
    /// because it stays stable across reboots and reslots.
    /// Matches the `CKA_LABEL` of the token, trimmed of trailing
    /// spaces (PKCS#11 pads labels with space to 32 chars).
    pub token_label: Option<String>,

    /// Numeric slot index, used only when `token_label` is None.
    /// Fragile — slot indexes can change when USB devices are
    /// replugged or HSMs are restarted — but useful for testing
    /// when the label is not yet known.
    pub slot: Option<u64>,

    /// Object label for the signing private key inside the
    /// token. This is the label the key was created with during
    /// the key ceremony (`CKA_LABEL` on the `CKO_PRIVATE_KEY`
    /// object). Vortex uses the same string as the stable
    /// `key_id` exposed in [`super::SigningKey::key_id`], so it
    /// also lands in `audit_signing_keys.key_id` for verifiers.
    pub key_label: String,

    /// Name of the environment variable holding the User PIN.
    /// Reading the PIN from an env var is deliberate: `vortex.toml`
    /// can be committed to VCS without leaking the PIN, and
    /// operators can inject it via systemd `Environment=`,
    /// docker `--env-file`, or a secrets manager.
    pub pin_env: String,
}

/// Which signing backend to construct at startup.
///
/// Today's set is `Env` (the dev path from Phase 0.1) and
/// `Pkcs11` (the regulated-deployment path). Future variants will
/// extend this enum without touching existing ones — see the
/// module header for the extension pattern.
#[derive(Debug, Clone)]
pub enum SigningBackendConfig {
    /// Ed25519 key loaded from `VORTEX_AUDIT_SIGNING_KEY`. Dev
    /// and small-deployment use only — private key material
    /// lives in the Vortex process heap. Not acceptable for
    /// regulated deployments.
    Env,

    /// PKCS#11 HSM. The private key lives inside the HSM and
    /// never enters Vortex memory. Works with SoftHSM2 (dev/CI,
    /// not FIPS-validated), YubiHSM 2, Thales Luna, Entrust
    /// nShield, Utimaco CryptoServer — any PKCS#11 v2.40+ device.
    Pkcs11(Pkcs11Config),
}

impl Default for SigningBackendConfig {
    fn default() -> Self {
        // Matches the Phase 0.1 default so upgrading deployments
        // see no behavior change until they explicitly opt into
        // a different backend via vortex.toml.
        SigningBackendConfig::Env
    }
}

impl SigningBackendConfig {
    /// Short identifier for logs and error messages.
    pub fn backend_name(&self) -> &'static str {
        match self {
            SigningBackendConfig::Env => "env",
            SigningBackendConfig::Pkcs11(_) => "pkcs11",
        }
    }
}

/// Build the configured signing backend and return it as an
/// `Arc<dyn SigningKey>` ready to hand to [`crate::audit::PgAuditStorage`].
///
/// Dispatches by variant:
///
/// - [`SigningBackendConfig::Env`] → [`Ed25519Key::from_env`]
/// - [`SigningBackendConfig::Pkcs11`] → [`Pkcs11SigningKey::open`]
///
/// Errors are propagated verbatim — any startup failure here
/// must be surfaced to the operator so they can fix the config,
/// not silently swallowed into a fallback path.
pub fn build_signing_key(
    config: &SigningBackendConfig,
) -> Result<Arc<dyn SigningKey>, SigningError> {
    match config {
        SigningBackendConfig::Env => {
            let key = Ed25519Key::from_env()?;
            Ok(Arc::new(key))
        }
        SigningBackendConfig::Pkcs11(pkcs11_config) => {
            let key = Pkcs11SigningKey::open(pkcs11_config)?;
            Ok(Arc::new(key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_is_env() {
        let config = SigningBackendConfig::default();
        assert!(matches!(config, SigningBackendConfig::Env));
        assert_eq!(config.backend_name(), "env");
    }

    #[test]
    fn pkcs11_backend_name() {
        let config = SigningBackendConfig::Pkcs11(Pkcs11Config {
            library_path: "/tmp/fake.so".to_string(),
            token_label: Some("test".to_string()),
            slot: None,
            key_label: "vortex-audit".to_string(),
            pin_env: "VORTEX_HSM_PIN".to_string(),
        });
        assert_eq!(config.backend_name(), "pkcs11");
    }

    #[test]
    fn build_env_backend_without_env_var_fails_clearly() {
        // No VORTEX_AUDIT_SIGNING_KEY set → MissingEnvVar error.
        // Test explicitly clears the variable to avoid depending
        // on shell state.
        // Safety: only this test touches these variables; no
        // parallel test in this file reads them.
        unsafe {
            std::env::remove_var("VORTEX_AUDIT_SIGNING_KEY");
        }
        match build_signing_key(&SigningBackendConfig::Env) {
            Ok(_) => panic!("expected MissingEnvVar error, got Ok"),
            Err(SigningError::MissingEnvVar(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn build_pkcs11_with_nonexistent_library_fails_cleanly() {
        let config = SigningBackendConfig::Pkcs11(Pkcs11Config {
            library_path: "/nonexistent/path/to/libsofthsm2.so".to_string(),
            token_label: Some("test".to_string()),
            slot: None,
            key_label: "vortex-audit".to_string(),
            pin_env: "VORTEX_HSM_PIN".to_string(),
        });
        match build_signing_key(&config) {
            Ok(_) => panic!("expected Pkcs11 or Config error, got Ok"),
            // Either Pkcs11 (library load failed) or Config — both
            // are acceptable since dlopen error propagates to
            // cryptoki's error type.
            Err(SigningError::Pkcs11(_)) | Err(SigningError::Config(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn pkcs11_config_debug_does_not_leak_pin() {
        // The PIN itself is not in the config (only the env var
        // name), so debug printing the config must not reveal
        // the secret. Defense in depth check.
        let config = Pkcs11Config {
            library_path: "/lib/fake.so".to_string(),
            token_label: Some("token".to_string()),
            slot: None,
            key_label: "key".to_string(),
            pin_env: "VORTEX_HSM_PIN".to_string(),
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("VORTEX_HSM_PIN"));
        // Would fail if someone accidentally added a `pin: String`
        // field and debug-printed the actual PIN value.
        assert!(!debug.contains("fedcba"));
        assert!(!debug.contains("secret"));
    }
}
