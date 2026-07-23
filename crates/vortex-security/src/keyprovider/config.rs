//! Key-provider selection: [`KeyProviderConfig`] picks which [`KeyProvider`]
//! to build at startup, and [`build_key_provider`] is the factory.
//!
//! Mirrors [`crate::signing::config`] exactly so operators and readers meet
//! one pattern for both crypto backends. Selection is runtime config, not a
//! cargo feature — but the KMS/Vault *code* is feature-gated so a deployment
//! that never uses them pays no dependency cost.

use std::sync::Arc;

use super::{KeyProvider, LocalKeyProvider};
use crate::crypto::CryptoError;

/// Configuration for the AWS KMS backend.
#[cfg(feature = "aws-kms")]
#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
    /// KMS key id or ARN used to wrap data keys.
    pub key_id: String,
    /// AWS region, e.g. `ap-southeast-1` (Malaysia-adjacent).
    pub region: String,
    /// Name of the env var holding the access key id.
    pub access_key_env: String,
    /// Name of the env var holding the secret access key.
    pub secret_key_env: String,
    /// Optional session-token env var (for STS/assumed roles).
    pub session_token_env: Option<String>,
}

/// Configuration for the HashiCorp Vault / OpenBao Transit backend.
#[cfg(feature = "vault")]
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Base address, e.g. `https://vault.internal:8200`.
    pub address: String,
    /// Transit key name to wrap/unwrap data keys with.
    pub key_name: String,
    /// Mount path of the transit engine (default `transit`).
    pub mount: String,
    /// Name of the env var holding the Vault token.
    pub token_env: String,
    /// Optional namespace header (Vault Enterprise / HCP).
    pub namespace: Option<String>,
}

/// Which key provider to construct at startup.
#[derive(Debug, Clone)]
pub enum KeyProviderConfig {
    /// Seal directly under `VORTEX_SECRET_KEY`. The default; byte-compatible
    /// with every previously sealed secret.
    Local,

    /// AWS KMS envelope encryption — the DEK is wrapped by a KMS key; Vortex
    /// never holds long-term key material.
    #[cfg(feature = "aws-kms")]
    AwsKms(AwsKmsConfig),

    /// Vault / OpenBao Transit envelope encryption.
    #[cfg(feature = "vault")]
    Vault(VaultConfig),
}

impl Default for KeyProviderConfig {
    fn default() -> Self {
        // No behaviour change for existing deployments until they opt in.
        KeyProviderConfig::Local
    }
}

impl KeyProviderConfig {
    /// Short identifier for logs and error messages.
    pub fn backend_name(&self) -> &'static str {
        match self {
            KeyProviderConfig::Local => "local",
            #[cfg(feature = "aws-kms")]
            KeyProviderConfig::AwsKms(_) => "aws-kms",
            #[cfg(feature = "vault")]
            KeyProviderConfig::Vault(_) => "vault",
        }
    }

    /// Whether this backend requires a local `VORTEX_SECRET_KEY` to seal new
    /// secrets. Only [`KeyProviderConfig::Local`] does; KMS/Vault deployments
    /// may run without one (though a master key is still useful for reading
    /// legacy rows during migration). Used by the startup gate so a KMS-only
    /// deployment is not forced to also set a master key.
    pub fn requires_master_key(&self) -> bool {
        matches!(self, KeyProviderConfig::Local)
    }
}

/// Build the configured provider as an `Arc<dyn KeyProvider>` for `AppState`.
///
/// Errors propagate — a misconfigured KMS must stop the boot, never fall back
/// to sealing secrets under the local key without the operator's knowledge.
pub fn build_key_provider(
    config: &KeyProviderConfig,
) -> Result<Arc<dyn KeyProvider>, CryptoError> {
    match config {
        KeyProviderConfig::Local => Ok(Arc::new(LocalKeyProvider::from_env())),

        #[cfg(feature = "aws-kms")]
        KeyProviderConfig::AwsKms(cfg) => {
            let wrapper = super::aws_kms::AwsKmsWrapper::from_config(cfg)?;
            Ok(Arc::new(super::EnvelopeProvider::new(wrapper)))
        }

        #[cfg(feature = "vault")]
        KeyProviderConfig::Vault(cfg) => {
            let wrapper = super::vault::VaultTransitWrapper::from_config(cfg)?;
            Ok(Arc::new(super::EnvelopeProvider::new(wrapper)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_local() {
        assert!(matches!(KeyProviderConfig::default(), KeyProviderConfig::Local));
        assert_eq!(KeyProviderConfig::default().backend_name(), "local");
        assert!(KeyProviderConfig::default().requires_master_key());
    }

    #[test]
    fn local_provider_builds() {
        let p = build_key_provider(&KeyProviderConfig::Local).unwrap();
        assert_eq!(p.key_id(), "local");
    }
}
