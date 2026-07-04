//! MyInvois REST client — OAuth token caching, batch submission,
//! status polling, cancellation. Trait-backed so the flow and jobs are
//! testable against canned LHDN responses.
//!
//! Endpoint mechanics ported from the proven Odoo implementation
//! (docs/MYINVOIS_NOTES.md): submission is HTTP 202 + async validation;
//! `documentHash` is the SHA-256 HEX of the raw document bytes and
//! `document` its base64 — hashing the wrong representation is the
//! classic LHDN rejection.

use vortex_plugin_sdk::prelude::async_trait;
use vortex_plugin_sdk::serde_json::{json, Value};

pub const SANDBOX_BASE: &str = "https://preprod-api.myinvois.hasil.gov.my";
pub const PRODUCTION_BASE: &str = "https://api.myinvois.hasil.gov.my";
pub const SANDBOX_PORTAL: &str = "https://preprod.myinvois.hasil.gov.my";
pub const PRODUCTION_PORTAL: &str = "https://myinvois.hasil.gov.my";

#[derive(Debug, Clone)]
pub struct SubmitDoc {
    /// Internal document number (LHDN `codeNumber`)
    pub code_number: String,
    /// Raw UBL XML bytes
    pub xml: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct SubmitResult {
    pub submission_uid: String,
    /// (code_number, lhdn_uuid) for accepted documents
    pub accepted: Vec<(String, String)>,
    /// (code_number, error json) for rejected documents
    pub rejected: Vec<(String, Value)>,
}

#[derive(Debug, Clone)]
pub struct DocStatus {
    pub lhdn_uuid: String,
    pub long_id: Option<String>,
    /// LHDN status: Submitted | InProgress | Valid | Invalid | Cancelled
    pub status: String,
    pub error: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct SubmissionStatus {
    /// InProgress | Valid | Invalid | Partial
    pub overall: String,
    pub documents: Vec<DocStatus>,
}

/// The API surface the flow depends on. `LhdnClient` is the real
/// implementation; tests provide canned ones.
#[async_trait]
pub trait MyInvoisApi: Send + Sync {
    async fn submit(&self, docs: Vec<SubmitDoc>) -> Result<SubmitResult, String>;
    async fn submission_status(&self, submission_uid: &str) -> Result<SubmissionStatus, String>;
    async fn document_details(&self, lhdn_uuid: &str) -> Result<Value, String>;
    /// Cancel within LHDN's 72-hour window.
    async fn cancel(&self, lhdn_uuid: &str, reason: &str) -> Result<(), String>;
}

pub struct LhdnClient {
    base: String,
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
    token: vortex_plugin_sdk::tokio::sync::Mutex<Option<(String, std::time::Instant)>>,
}

impl LhdnClient {
    pub fn new(production: bool, client_id: String, client_secret: String) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            base: if production { PRODUCTION_BASE } else { SANDBOX_BASE }.to_string(),
            client_id,
            client_secret,
            http,
            token: vortex_plugin_sdk::tokio::sync::Mutex::new(None),
        })
    }

    /// OAuth client-credentials token, cached for 55 minutes (LHDN
    /// tokens live 60).
    async fn bearer(&self) -> Result<String, String> {
        let mut guard = self.token.lock().await;
        if let Some((tok, at)) = guard.as_ref() {
            if at.elapsed() < std::time::Duration::from_secs(55 * 60) {
                return Ok(tok.clone());
            }
        }
        let resp = self
            .http
            .post(format!("{}/connect/token", self.base))
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("grant_type", "client_credentials"),
                ("scope", "InvoicingAPI"),
            ])
            .send()
            .await
            .map_err(|e| format!("token request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("token request failed: {}", resp.status()));
        }
        let body: Value = resp.json().await.map_err(|e| format!("token body: {e}"))?;
        let tok = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("token response missing access_token")?
            .to_string();
        *guard = Some((tok.clone(), std::time::Instant::now()));
        Ok(tok)
    }
}

#[async_trait]
impl MyInvoisApi for LhdnClient {
    async fn submit(&self, docs: Vec<SubmitDoc>) -> Result<SubmitResult, String> {
        use base64::Engine;
        let tok = self.bearer().await?;
        let documents: Vec<Value> = docs
            .iter()
            .map(|d| {
                json!({
                    "format": "XML",
                    "codeNumber": d.code_number,
                    "document": base64::engine::general_purpose::STANDARD.encode(&d.xml),
                    "documentHash": crate::einvois::sha256_hex(&d.xml),
                })
            })
            .collect();
        let resp = self
            .http
            .post(format!("{}/api/v1.0/documentsubmissions/", self.base))
            .bearer_auth(&tok)
            .header("Accept", "application/json")
            .header("Accept-Language", "en")
            .json(&json!({ "documents": documents }))
            .send()
            .await
            .map_err(|e| format!("submit request: {e}"))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status.as_u16() != 202 && !status.is_success() {
            return Err(format!("submit failed: {status} — {body}"));
        }
        // Casing varies across LHDN environments.
        let submission_uid = ["submissionUid", "submissionUID", "SubmissionUid"]
            .iter()
            .find_map(|k| body.get(*k).and_then(|v| v.as_str()))
            .unwrap_or_default()
            .to_string();
        let accepted = body
            .get("acceptedDocuments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| {
                        Some((
                            d.get("invoiceCodeNumber")?.as_str()?.to_string(),
                            d.get("uuid")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let rejected = body
            .get("rejectedDocuments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|d| {
                        (
                            d.get("invoiceCodeNumber")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string(),
                            d.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(SubmitResult { submission_uid, accepted, rejected })
    }

    async fn submission_status(&self, submission_uid: &str) -> Result<SubmissionStatus, String> {
        let tok = self.bearer().await?;
        let resp = self
            .http
            .get(format!("{}/api/v1.0/documentsubmissions/{submission_uid}", self.base))
            .bearer_auth(&tok)
            .send()
            .await
            .map_err(|e| format!("status request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("status failed: {}", resp.status()));
        }
        let body: Value = resp.json().await.map_err(|e| format!("status body: {e}"))?;
        let overall = body
            .get("overallStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("InProgress")
            .to_string();
        let documents = body
            .get("documentSummary")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| {
                        Some(DocStatus {
                            lhdn_uuid: d.get("uuid")?.as_str()?.to_string(),
                            long_id: d.get("longId").and_then(|v| v.as_str()).map(str::to_string),
                            status: d
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Submitted")
                                .to_string(),
                            error: d.get("error").filter(|e| !e.is_null()).cloned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(SubmissionStatus { overall, documents })
    }

    async fn document_details(&self, lhdn_uuid: &str) -> Result<Value, String> {
        let tok = self.bearer().await?;
        let resp = self
            .http
            .get(format!("{}/api/v1.0/documents/{lhdn_uuid}/details", self.base))
            .bearer_auth(&tok)
            .send()
            .await
            .map_err(|e| format!("details request: {e}"))?;
        resp.json().await.map_err(|e| format!("details body: {e}"))
    }

    async fn cancel(&self, lhdn_uuid: &str, reason: &str) -> Result<(), String> {
        let tok = self.bearer().await?;
        let resp = self
            .http
            .put(format!("{}/api/v1.0/documents/state/{lhdn_uuid}/state", self.base))
            .bearer_auth(&tok)
            .json(&json!({ "status": "cancelled", "reason": reason }))
            .send()
            .await
            .map_err(|e| format!("cancel request: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("cancel failed: {}", resp.status()))
        }
    }
}
