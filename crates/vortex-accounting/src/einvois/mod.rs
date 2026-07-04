//! LHDN MyInvois e-invoicing (document version 1.0, unsigned).
//!
//! - [`ubl`] — pure UBL 2.1 XML builder (golden-file tested)
//! - [`client`] — trait-backed REST client (OAuth, submit, poll, cancel)
//! - [`flow`] — payload assembly from the ledger + status lifecycle +
//!   FileStore evidence + webhook events
//! - [`jobs`] — durable submit/poll jobs + LHDN code-table sync
//!
//! Ported domain knowledge and endpoint mechanics:
//! `docs/MYINVOIS_NOTES.md`. Consolidated B2C submission is the
//! deliberate follow-up (partners marked `einvoice_optout` are skipped
//! by the individual flow and await the monthly consolidated
//! generator).

pub mod client;
pub mod flow;
pub mod jobs;
pub mod ubl;

/// SHA-256 hex of raw bytes — LHDN's `documentHash` (hash the RAW
/// document, not its base64).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
