//! Minimal blocking HTTP helper shared by the KMS/Vault backends.
//!
//! [`KeyProvider::seal`]/`unseal` are synchronous (like [`crate::signing`]),
//! but the backends make a network round-trip. Calling `reqwest::blocking`
//! directly from a Tokio worker panics ("cannot block the current thread from
//! within a runtime"), so every request runs on a dedicated std thread that
//! is joined immediately. Seals/unseals are rare (config save, mail send on
//! the job queue), so the per-call thread is not a hot path.

#![cfg(any(feature = "aws-kms", feature = "vault"))]

use std::time::Duration;

use crate::crypto::CryptoError;

/// POST `body` to `url` with the given headers, returning the response body on
/// a 2xx. Any transport error, timeout, or non-success status maps to the
/// opaque [`CryptoError::Provider`]; the concrete cause is logged, never
/// returned, so this cannot become an oracle.
pub(crate) fn post_json(
    url: &str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let url = url.to_string();
    std::thread::scope(|s| {
        s.spawn(move || -> Result<Vec<u8>, CryptoError> {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| {
                    tracing::error!("key provider: http client build failed: {e}");
                    CryptoError::Provider
                })?;
            // Callers supply their own content-type (Vault: application/json,
            // AWS KMS: application/x-amz-json-1.1) — reqwest's `.header()`
            // appends rather than replaces, so we must not set a default here
            // or two content-type headers would be sent and break SigV4.
            let mut req = client.post(&url).body(body);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            let resp = req.send().map_err(|e| {
                tracing::error!("key provider: request failed: {e}");
                CryptoError::Provider
            })?;
            let status = resp.status();
            let bytes = resp.bytes().map_err(|_| CryptoError::Provider)?.to_vec();
            if !status.is_success() {
                tracing::error!("key provider: HTTP {status}");
                return Err(CryptoError::Provider);
            }
            Ok(bytes)
        })
        .join()
        .map_err(|_| CryptoError::Provider)?
    })
}
