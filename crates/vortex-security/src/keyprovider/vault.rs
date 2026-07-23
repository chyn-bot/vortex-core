//! HashiCorp Vault / OpenBao **Transit** secrets-engine backend.
//!
//! The Transit engine performs "encryption as a service": Vortex sends the
//! 32-byte data key and Vault returns an opaque `vault:v1:…` ciphertext,
//! wrapping it under a key that never leaves Vault. This is the cheapest
//! correct way to satisfy BNM RMiT 8c (key custody independent of the hosting
//! provider) when the customer already runs Vault/OpenBao.
//!
//! API used:
//! * wrap  — `POST {addr}/v1/{mount}/encrypt/{key}`  body `{"plaintext": b64}`
//! * unwrap— `POST {addr}/v1/{mount}/decrypt/{key}`  body `{"ciphertext": …}`

use base64::Engine;
use serde::Deserialize;

use super::config::VaultConfig;
use super::http::post_json;
use super::DekWrapper;
use crate::crypto::CryptoError;

/// One-byte provider tag stored in the envelope header.
pub(crate) const PROVIDER_TAG: u8 = 0x02;

pub struct VaultTransitWrapper {
    encrypt_url: String,
    decrypt_url: String,
    token: String,
    namespace: Option<String>,
    key_id: String,
}

#[derive(Deserialize)]
struct EncryptResp {
    data: EncryptData,
}
#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}
#[derive(Deserialize)]
struct DecryptResp {
    data: DecryptData,
}
#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

impl VaultTransitWrapper {
    pub fn from_config(cfg: &VaultConfig) -> Result<Self, CryptoError> {
        let token = std::env::var(&cfg.token_env).map_err(|_| {
            tracing::error!("vault: token env {} not set", cfg.token_env);
            CryptoError::Provider
        })?;
        let addr = cfg.address.trim_end_matches('/');
        let mount = cfg.mount.trim_matches('/');
        Ok(Self {
            encrypt_url: format!("{addr}/v1/{mount}/encrypt/{}", cfg.key_name),
            decrypt_url: format!("{addr}/v1/{mount}/decrypt/{}", cfg.key_name),
            token,
            namespace: cfg.namespace.clone(),
            key_id: format!("vault:{}", cfg.key_name),
        })
    }

    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("content-type", "application/json".to_string()),
            ("x-vault-token", self.token.clone()),
        ];
        if let Some(ns) = &self.namespace {
            h.push(("x-vault-namespace", ns.clone()));
        }
        h
    }
}

impl DekWrapper for VaultTransitWrapper {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn provider_tag(&self) -> u8 {
        PROVIDER_TAG
    }

    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(dek);
        let body = serde_json::json!({ "plaintext": b64 }).to_string().into_bytes();
        let resp = post_json(&self.encrypt_url, self.headers(), body)?;
        let parsed: EncryptResp =
            serde_json::from_slice(&resp).map_err(|_| CryptoError::Provider)?;
        // Store the opaque `vault:v1:…` string verbatim.
        Ok(parsed.data.ciphertext.into_bytes())
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], CryptoError> {
        let ciphertext = std::str::from_utf8(wrapped).map_err(|_| CryptoError::Envelope)?;
        let body =
            serde_json::json!({ "ciphertext": ciphertext }).to_string().into_bytes();
        let resp = post_json(&self.decrypt_url, self.headers(), body)?;
        let parsed: DecryptResp =
            serde_json::from_slice(&resp).map_err(|_| CryptoError::Provider)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(parsed.data.plaintext.trim())
            .map_err(|_| CryptoError::Provider)?;
        if raw.len() != 32 {
            return Err(CryptoError::Provider);
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&raw);
        Ok(dek)
    }
}
