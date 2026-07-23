//! AWS KMS backend using envelope encryption.
//!
//! Vortex generates the data key locally and asks KMS only to **wrap** it
//! (`Encrypt`) and **unwrap** it (`Decrypt`) under a customer-managed key. The
//! long-term key never leaves KMS, satisfying BNM RMiT 8c/8d.
//!
//! Requests are signed with AWS Signature V4, hand-rolled on
//! [`crate::crypto::hmac_sha256`] (whose doc note already anticipates
//! "AWS SigV4-style derived-key schemes feed one tag in as the next key") plus
//! `ring` SHA-256 — no `aws-sdk-*` dependency, keeping the `cargo audit`
//! surface small per the workspace supply-chain rule, mirroring the existing
//! hand-rolled S3 SigV4 used for audit export.

use base64::Engine;
use ring::digest;
use serde::Deserialize;

use super::config::AwsKmsConfig;
use super::http::post_json;
use super::DekWrapper;
use crate::crypto::{hmac_sha256, CryptoError};

/// One-byte provider tag stored in the envelope header.
pub(crate) const PROVIDER_TAG: u8 = 0x01;

const SERVICE: &str = "kms";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

pub struct AwsKmsWrapper {
    key_id: String,
    region: String,
    host: String,
    endpoint: String,
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptResp {
    ciphertext_blob: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptResp {
    plaintext: String,
}

impl AwsKmsWrapper {
    pub fn from_config(cfg: &AwsKmsConfig) -> Result<Self, CryptoError> {
        let access_key = std::env::var(&cfg.access_key_env).map_err(|_| {
            tracing::error!("aws-kms: access key env {} not set", cfg.access_key_env);
            CryptoError::Provider
        })?;
        let secret_key = std::env::var(&cfg.secret_key_env).map_err(|_| {
            tracing::error!("aws-kms: secret key env {} not set", cfg.secret_key_env);
            CryptoError::Provider
        })?;
        let session_token = cfg
            .session_token_env
            .as_ref()
            .and_then(|e| std::env::var(e).ok());
        let host = format!("kms.{}.amazonaws.com", cfg.region);
        Ok(Self {
            key_id: cfg.key_id.clone(),
            region: cfg.region.clone(),
            endpoint: format!("https://{host}/"),
            host,
            access_key,
            secret_key,
            session_token,
        })
    }

    /// Perform one signed KMS call for the given `X-Amz-Target` and JSON body.
    fn call(&self, target: &str, body: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let (amz_date, date_stamp) = now_amz();
        let payload_hash = sha256_hex(&body);

        // 1. Canonical request. Headers must be sorted by lowercased name.
        let mut canonical_headers = format!(
            "content-type:application/x-amz-json-1.1\nhost:{}\nx-amz-date:{}\n",
            self.host, amz_date
        );
        let mut signed_headers = String::from("content-type;host;x-amz-date");
        if let Some(tok) = &self.session_token {
            // x-amz-security-token sorts after x-amz-date, before x-amz-target.
            canonical_headers.push_str(&format!("x-amz-security-token:{tok}\n"));
            signed_headers.push_str(";x-amz-security-token");
        }
        canonical_headers.push_str(&format!("x-amz-target:{target}\n"));
        signed_headers.push_str(";x-amz-target");

        let canonical_request = format!(
            "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        // 2. String to sign.
        let scope = format!("{date_stamp}/{}/{SERVICE}/aws4_request", self.region);
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        // 3. Derive the signing key and sign.
        let k_date = hmac_sha256(format!("AWS4{}", self.secret_key).as_bytes(), date_stamp.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        // 4. Authorization header.
        let authorization = format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );

        let mut headers = vec![
            ("authorization", authorization),
            ("x-amz-date", amz_date),
            ("x-amz-target", target.to_string()),
        ];
        if let Some(tok) = &self.session_token {
            headers.push(("x-amz-security-token", tok.clone()));
        }

        post_json_amz(&self.endpoint, headers, body)
    }
}

impl DekWrapper for AwsKmsWrapper {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn provider_tag(&self) -> u8 {
        PROVIDER_TAG
    }

    fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(dek);
        let body = serde_json::json!({ "KeyId": self.key_id, "Plaintext": b64 })
            .to_string()
            .into_bytes();
        let resp = self.call("TrentService.Encrypt", body)?;
        let parsed: EncryptResp =
            serde_json::from_slice(&resp).map_err(|_| CryptoError::Provider)?;
        Ok(parsed.ciphertext_blob.into_bytes())
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], CryptoError> {
        let blob = std::str::from_utf8(wrapped).map_err(|_| CryptoError::Envelope)?;
        let body = serde_json::json!({ "KeyId": self.key_id, "CiphertextBlob": blob })
            .to_string()
            .into_bytes();
        let resp = self.call("TrentService.Decrypt", body)?;
        let parsed: DecryptResp =
            serde_json::from_slice(&resp).map_err(|_| CryptoError::Provider)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(parsed.plaintext.trim())
            .map_err(|_| CryptoError::Provider)?;
        if raw.len() != 32 {
            return Err(CryptoError::Provider);
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&raw);
        Ok(dek)
    }
}

/// SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, data).as_ref())
}

/// Current UTC as (`YYYYMMDDTHHMMSSZ`, `YYYYMMDD`) for SigV4, computed from the
/// Unix epoch with a self-contained civil-date conversion (no date crate).
fn now_amz() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    (
        format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// Convert days-since-Unix-epoch to (year, month, day). Howard Hinnant's
/// well-known `civil_from_days` algorithm — exact, no leap-year edge cases.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Like [`post_json`] but sets the AWS-specific content-type. AWS SigV4 signed
/// `content-type:application/x-amz-json-1.1`, so the wire header must match
/// exactly or the signature is rejected.
fn post_json_amz(
    url: &str,
    mut headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    headers.push(("content-type", "application/x-amz-json-1.1".to_string()));
    // post_json only adds a default content-type when none is present, so our
    // explicit AWS content-type wins.
    post_json(url, headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-03-01 is 11017 days after epoch.
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        // 2020-02-29 (leap day) is 18321 days after epoch.
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    }

    #[test]
    fn sha256_hex_empty() {
        // Known SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
