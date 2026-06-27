//! WORM audit chain verification — the library verifier shared by
//! the `vortex audit verify` CLI and the scheduled background
//! integrity check.
//!
//! This is the single source of truth for what "the audit chain is
//! intact" means. Both callers consume byte-identical results; they
//! differ only in presentation — the CLI prints to stdout and exits
//! with a non-zero status on failure, the scheduled task writes the
//! result into the WORM ledger as a self-attestation event
//! ([`crate::audit::AuditAction::ChainVerificationPassed`] /
//! [`crate::audit::AuditAction::ChainVerificationFailed`]).
//!
//! ## What the verifier checks
//!
//! For every chained entry in scope (optionally filtered by company
//! and timestamp range), in ascending `chain_position` order, the
//! verifier confirms:
//!
//! 1. **Chain linkage** — the row's stored `prev_hash` matches the
//!    previous row's `entry_hash`. A break here means an entry was
//!    inserted, reordered, or tampered with at the chain level.
//! 2. **Entry hash integrity** — recompute the hash from the stored
//!    `canonical_payload` using the same `compute_entry_hash` the
//!    writer uses. Any mismatch means the canonical payload was
//!    edited after write.
//! 3. **Canonical stability** — re-canonicalize the JSON payload
//!    with JCS (RFC 8785) and compare to the stored bytes. Stored
//!    bytes that don't round-trip were either written non-canonically
//!    (bug) or mutated by a downstream process that stripped JSONB
//!    whitespace.
//! 4. **Signature validity** — for entries with an Ed25519 signature,
//!    verify against the public key stored in `audit_signing_keys`.
//!    Also flags signatures made by keys that were revoked before the
//!    entry's application timestamp.
//! 5. **Dual-clock skew** — compare the application timestamp
//!    (`timestamp`) and the database-assigned timestamp
//!    (`db_timestamp`). Drift larger than [`VerifyOptions::max_skew_seconds`]
//!    suggests NTP tampering, backdating, or a broken clock source.
//!
//! ## Why a library function, not an RPC
//!
//! The verifier runs directly against the Postgres pool. It does not
//! hold application state, does not take user input, and produces an
//! idempotent read-only result. Callers invoke it at their cadence
//! (cron, on-demand, CI pipeline). The scheduled-task consumer is
//! `vortex-cli`'s `SystemBuiltinPlugin`; the CLI consumer is
//! `vortex audit verify`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use vortex_common::{VortexError, VortexResult};

use crate::audit::canonical::canonicalize;
use crate::audit::pg::compute_entry_hash;
use crate::signing::verify_ed25519;

/// Default clock-skew tolerance, in seconds, between application and
/// database timestamps. Five seconds covers normal NTP drift;
/// anything larger is suspicious.
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 5;

/// Caller-supplied options for a verification run.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// If set, verify only this company's chain. If `None`, the
    /// verifier discovers every company with chained entries in
    /// `audit_log` and walks each one in turn.
    pub company: Option<Uuid>,
    /// Inclusive earliest entry timestamp to include. `None` for
    /// no lower bound.
    pub from: Option<DateTime<Utc>>,
    /// Inclusive latest entry timestamp to include. `None` for no
    /// upper bound.
    pub to: Option<DateTime<Utc>>,
    /// Maximum allowed skew between `timestamp` and `db_timestamp`
    /// before an entry is flagged.
    pub max_skew_seconds: i64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            company: None,
            from: None,
            to: None,
            max_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

/// Summary of a single verification run.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Number of company chains walked.
    pub companies_checked: usize,
    /// Total entries inspected across all companies.
    pub entries_verified: usize,
    /// Every integrity issue found, in discovery order.
    pub failures: Vec<VerifyFailure>,
    /// Wall-clock duration of the verification run.
    pub duration: Duration,
}

impl VerifyReport {
    /// The single bit callers care about: was the chain intact?
    ///
    /// Returns `true` iff no failures were recorded. Any failure —
    /// broken link, tampered hash, bad signature, excess clock skew —
    /// means the chain is not intact and the scheduled task writes a
    /// `ChainVerificationFailed` audit event.
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }

    /// Total number of failures across all kinds, for summary
    /// messaging in both the CLI and the self-attestation entry.
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }
}

/// A single integrity problem uncovered during verification.
#[derive(Debug, Clone)]
pub struct VerifyFailure {
    /// Which tenant's chain this failure is from.
    pub company_id: Uuid,
    /// Position inside that tenant's chain.
    pub chain_position: i64,
    /// `audit_log.id` for the offending entry.
    pub entry_id: Uuid,
    /// Classification of the failure mode.
    pub kind: VerifyFailureKind,
    /// Human-readable detail string, safe to include in
    /// log output and audit payloads.
    pub detail: String,
}

/// Classification of verification failures. Used for aggregation
/// and so the self-attestation audit event can carry a structured
/// breakdown instead of opaque text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyFailureKind {
    /// `prev_hash` does not match the previous entry's hash.
    BrokenChainLink,
    /// Recomputed entry hash does not match the stored hash.
    EntryHashMismatch,
    /// Stored canonical payload does not round-trip through JCS.
    CanonicalUnstable,
    /// Entry has a signature but it does not verify.
    SignatureInvalid,
    /// Entry references a `signing_key_id` that no longer exists.
    SignatureKeyUnknown,
    /// Entry was signed by a key after that key was revoked.
    SignatureKeyRevoked,
    /// `timestamp` and `db_timestamp` drift exceeds the tolerance.
    ClockSkewExceeded,
}

impl VerifyFailureKind {
    /// Stable lowercase code for inclusion in structured logs and
    /// audit payloads. Must not change for a given variant.
    pub fn code(&self) -> &'static str {
        match self {
            VerifyFailureKind::BrokenChainLink => "broken_chain_link",
            VerifyFailureKind::EntryHashMismatch => "entry_hash_mismatch",
            VerifyFailureKind::CanonicalUnstable => "canonical_unstable",
            VerifyFailureKind::SignatureInvalid => "signature_invalid",
            VerifyFailureKind::SignatureKeyUnknown => "signature_key_unknown",
            VerifyFailureKind::SignatureKeyRevoked => "signature_key_revoked",
            VerifyFailureKind::ClockSkewExceeded => "clock_skew_exceeded",
        }
    }
}

/// Cached signing key record used during verification to avoid a
/// database hit per signed entry.
struct KeyRecord {
    public_key: Vec<u8>,
    algorithm: String,
    valid_to: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Verify the audit chain according to `opts`.
///
/// Walks every entry in scope in strict `chain_position` order and
/// returns a structured [`VerifyReport`] summarising what was
/// checked and what failed. This function **never prints** and
/// **never exits** — callers decide how to surface the report.
///
/// The function is read-only: it makes no writes to `audit_log`.
/// The scheduled task that wraps it writes a self-attestation entry
/// **after** the call returns, so the attestation itself does not
/// participate in the check.
pub async fn verify_chain(pool: &PgPool, opts: &VerifyOptions) -> VortexResult<VerifyReport> {
    let started = Instant::now();

    // Discover the set of companies to verify.
    let companies: Vec<Uuid> = if let Some(c) = opts.company {
        vec![c]
    } else {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT DISTINCT company_id FROM audit_log \
             WHERE company_id IS NOT NULL AND chain_position IS NOT NULL \
             ORDER BY company_id",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("list companies: {e}")))?
    };

    // Preload the signing-key map so we can look up public keys by
    // key_id without re-hitting the DB for every signed entry.
    let key_rows = sqlx::query(
        "SELECT key_id, public_key, algorithm, valid_from, valid_to, revoked_at \
         FROM audit_signing_keys",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| VortexError::QueryExecution(format!("load signing keys: {e}")))?;

    let keys: HashMap<String, KeyRecord> = key_rows
        .into_iter()
        .map(|r| {
            let key_id: String = r.get("key_id");
            let rec = KeyRecord {
                public_key: r.get("public_key"),
                algorithm: r.get("algorithm"),
                valid_to: r.try_get("valid_to").ok(),
                revoked_at: r.try_get("revoked_at").ok(),
            };
            (key_id, rec)
        })
        .collect();

    let mut entries_verified = 0usize;
    let mut failures: Vec<VerifyFailure> = Vec::new();

    for cid in &companies {
        let mut sql = String::from(
            "SELECT id, chain_position, prev_hash, entry_hash, signature, \
             signing_key_id, canonical_payload, timestamp, db_timestamp \
             FROM audit_log \
             WHERE company_id = $1 AND chain_position IS NOT NULL",
        );
        let mut arg_idx = 1;
        if opts.from.is_some() {
            arg_idx += 1;
            sql.push_str(&format!(" AND timestamp >= ${arg_idx}"));
        }
        if opts.to.is_some() {
            arg_idx += 1;
            sql.push_str(&format!(" AND timestamp <= ${arg_idx}"));
        }
        sql.push_str(" ORDER BY chain_position ASC");

        let mut q = sqlx::query(&sql).bind(cid);
        if let Some(f) = opts.from {
            q = q.bind(f);
        }
        if let Some(t) = opts.to {
            q = q.bind(t);
        }
        let rows = q
            .fetch_all(pool)
            .await
            .map_err(|e| VortexError::QueryExecution(format!("fetch chain for {cid}: {e}")))?;

        let mut prev_expected_hash: Option<Vec<u8>> = None;
        for row in rows {
            entries_verified += 1;
            let entry_id: Uuid = row.get("id");
            let chain_position: i64 = row.get("chain_position");
            let stored_prev: Option<Vec<u8>> = row.try_get("prev_hash").ok();
            let stored_hash: Vec<u8> = row.get("entry_hash");
            let canonical: String = row.get("canonical_payload");
            let signature: Option<Vec<u8>> = row.try_get("signature").ok();
            let key_id: Option<String> = row.try_get("signing_key_id").ok();
            let app_ts: DateTime<Utc> = row.get("timestamp");
            let db_ts: DateTime<Utc> = row.get("db_timestamp");

            // 1. Chain linkage.
            match (&prev_expected_hash, &stored_prev) {
                (None, None) if chain_position == 0 => { /* valid genesis */ }
                (Some(a), Some(b)) if a == b => { /* valid link */ }
                (expected, actual) => {
                    failures.push(VerifyFailure {
                        company_id: *cid,
                        chain_position,
                        entry_id,
                        kind: VerifyFailureKind::BrokenChainLink,
                        detail: format!(
                            "broken chain link: expected prev_hash={:?}, stored={:?}",
                            expected.as_ref().map(hex::encode),
                            actual.as_ref().map(hex::encode)
                        ),
                    });
                    // Even on a broken link, keep walking — we want
                    // to surface every failure, not abort at the first.
                    prev_expected_hash = Some(stored_hash.clone());
                    continue;
                }
            }

            // 2. Recompute the entry hash from canonical_payload.
            let computed = compute_entry_hash(stored_prev.as_deref(), canonical.as_bytes());
            if computed.as_slice() != stored_hash.as_slice() {
                failures.push(VerifyFailure {
                    company_id: *cid,
                    chain_position,
                    entry_id,
                    kind: VerifyFailureKind::EntryHashMismatch,
                    detail: format!(
                        "entry_hash mismatch: canonical_payload tampered or chain computation drifted. \
                         computed={}, stored={}",
                        hex::encode(computed),
                        hex::encode(&stored_hash)
                    ),
                });
                prev_expected_hash = Some(stored_hash.clone());
                continue;
            }

            // 3. Canonical stability.
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&canonical) {
                match canonicalize(&parsed) {
                    Ok(re) if re == canonical => {}
                    Ok(_) => {
                        failures.push(VerifyFailure {
                            company_id: *cid,
                            chain_position,
                            entry_id,
                            kind: VerifyFailureKind::CanonicalUnstable,
                            detail: "canonical_payload is not stable under re-canonicalization"
                                .to_string(),
                        });
                    }
                    Err(e) => {
                        failures.push(VerifyFailure {
                            company_id: *cid,
                            chain_position,
                            entry_id,
                            kind: VerifyFailureKind::CanonicalUnstable,
                            detail: format!("canonical re-encode failed: {e}"),
                        });
                    }
                }
            }

            // 4. Signature verification.
            if let (Some(sig), Some(kid)) = (signature.as_ref(), key_id.as_ref()) {
                match keys.get(kid) {
                    Some(key) if key.algorithm == "ed25519" => {
                        // Key validity window.
                        if let Some(revoked) = key.revoked_at {
                            if app_ts >= revoked {
                                failures.push(VerifyFailure {
                                    company_id: *cid,
                                    chain_position,
                                    entry_id,
                                    kind: VerifyFailureKind::SignatureKeyRevoked,
                                    detail: format!(
                                        "entry signed by key '{kid}' AFTER its revocation at {revoked}"
                                    ),
                                });
                            }
                        }
                        if let Some(valid_to) = key.valid_to {
                            if app_ts > valid_to {
                                failures.push(VerifyFailure {
                                    company_id: *cid,
                                    chain_position,
                                    entry_id,
                                    kind: VerifyFailureKind::SignatureKeyRevoked,
                                    detail: format!(
                                        "entry signed by key '{kid}' AFTER its valid_to {valid_to}"
                                    ),
                                });
                            }
                        }
                        // Verify (entry_hash || canonical_bytes) — the exact
                        // message signed by PgAuditStorage.
                        let mut msg = Vec::with_capacity(32 + canonical.len());
                        msg.extend_from_slice(&stored_hash);
                        msg.extend_from_slice(canonical.as_bytes());
                        if let Err(e) = verify_ed25519(&key.public_key, &msg, sig) {
                            failures.push(VerifyFailure {
                                company_id: *cid,
                                chain_position,
                                entry_id,
                                kind: VerifyFailureKind::SignatureInvalid,
                                detail: format!("Ed25519 signature verification failed: {e}"),
                            });
                        }
                    }
                    Some(_) => {
                        failures.push(VerifyFailure {
                            company_id: *cid,
                            chain_position,
                            entry_id,
                            kind: VerifyFailureKind::SignatureKeyUnknown,
                            detail: format!("signing_key_id '{kid}' uses unknown algorithm"),
                        });
                    }
                    None => {
                        failures.push(VerifyFailure {
                            company_id: *cid,
                            chain_position,
                            entry_id,
                            kind: VerifyFailureKind::SignatureKeyUnknown,
                            detail: format!(
                                "signing_key_id '{kid}' not found in audit_signing_keys \
                                 (revoked and purged?)"
                            ),
                        });
                    }
                }
            }

            // 5. Dual-clock skew.
            let skew = (app_ts - db_ts).num_seconds().abs();
            if skew > opts.max_skew_seconds {
                failures.push(VerifyFailure {
                    company_id: *cid,
                    chain_position,
                    entry_id,
                    kind: VerifyFailureKind::ClockSkewExceeded,
                    detail: format!(
                        "clock skew {skew}s exceeds threshold {}s (app={app_ts}, db={db_ts}) — \
                         possible NTP tampering or backdating",
                        opts.max_skew_seconds
                    ),
                });
            }

            prev_expected_hash = Some(stored_hash);
        }
    }

    Ok(VerifyReport {
        companies_checked: companies.len(),
        entries_verified,
        failures,
        duration: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_have_standard_skew_tolerance() {
        let opts = VerifyOptions::default();
        assert_eq!(opts.max_skew_seconds, DEFAULT_CLOCK_SKEW_SECONDS);
        assert_eq!(opts.max_skew_seconds, 5);
        assert!(opts.company.is_none());
        assert!(opts.from.is_none());
        assert!(opts.to.is_none());
    }

    #[test]
    fn empty_report_is_ok() {
        let report = VerifyReport {
            companies_checked: 0,
            entries_verified: 0,
            failures: vec![],
            duration: Duration::ZERO,
        };
        assert!(report.ok());
        assert_eq!(report.failure_count(), 0);
    }

    #[test]
    fn report_with_failures_is_not_ok() {
        let report = VerifyReport {
            companies_checked: 1,
            entries_verified: 10,
            failures: vec![VerifyFailure {
                company_id: Uuid::nil(),
                chain_position: 3,
                entry_id: Uuid::nil(),
                kind: VerifyFailureKind::EntryHashMismatch,
                detail: "test".to_string(),
            }],
            duration: Duration::from_millis(42),
        };
        assert!(!report.ok());
        assert_eq!(report.failure_count(), 1);
    }

    #[test]
    fn failure_kind_codes_are_stable() {
        // These codes land in audit payloads and structured logs;
        // changing them is a breaking change.
        assert_eq!(VerifyFailureKind::BrokenChainLink.code(), "broken_chain_link");
        assert_eq!(VerifyFailureKind::EntryHashMismatch.code(), "entry_hash_mismatch");
        assert_eq!(VerifyFailureKind::CanonicalUnstable.code(), "canonical_unstable");
        assert_eq!(VerifyFailureKind::SignatureInvalid.code(), "signature_invalid");
        assert_eq!(VerifyFailureKind::SignatureKeyUnknown.code(), "signature_key_unknown");
        assert_eq!(VerifyFailureKind::SignatureKeyRevoked.code(), "signature_key_revoked");
        assert_eq!(VerifyFailureKind::ClockSkewExceeded.code(), "clock_skew_exceeded");
    }
}
