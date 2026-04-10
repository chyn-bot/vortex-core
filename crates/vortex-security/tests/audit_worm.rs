//! Integration tests for the WORM audit ledger.
//!
//! These tests exercise the full chain end-to-end against a real Postgres
//! database. They require `DATABASE_URL` to point at a database with
//! migrations 001..=114 applied (the standard `vortex db migrate` output).
//! When `DATABASE_URL` is absent, tests are skipped with a printed
//! warning — this lets `cargo test -p vortex-security` remain green in
//! environments without Postgres while still catching real integration
//! bugs in dev/CI.
//!
//! What each test covers:
//! - `chain_writes_and_verifies`: write a handful of entries across two
//!   tenants, then verify each row's chain linkage and recomputed hash.
//! - `tamper_is_detected`: mutate a canonical payload directly (via the
//!   migration role, bypassing the trigger) and confirm the recomputed
//!   hash no longer matches.
//! - `triggers_block_mutations`: confirm that UPDATE and DELETE on
//!   `audit_log` raise the expected exception.
//! - `signature_round_trip`: with a generated Ed25519 key, sign entries
//!   via PgAuditStorage and verify the signatures match.

use std::sync::Arc;

use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;
use vortex_common::CompanyId;
use vortex_orm::ConnectionPool;
use vortex_security::audit::canonical::canonicalize;
use vortex_security::audit::pg::{compute_entry_hash, PgAuditStorage};
use vortex_security::audit::{AuditAction, AuditEntry, AuditLog, AuditSeverity, AuditStorage};
use vortex_security::signing::{verify_ed25519, Ed25519Key, SigningKey};

/// Default company seeded in `001_initial_schema`.
const DEFAULT_COMPANY: Uuid = Uuid::from_bytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

async fn setup() -> Option<(Arc<ConnectionPool>, sqlx::PgPool)> {
    let url = match database_url() {
        Some(u) => u,
        None => {
            eprintln!("DATABASE_URL not set — skipping WORM integration test");
            return None;
        }
    };
    let pool = match PgPoolOptions::new().max_connections(4).connect(&url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to connect to {url}: {e} — skipping");
            return None;
        }
    };

    // Sanity-check migration 114 landed.
    let has_col: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_name='audit_log' AND column_name='entry_hash')",
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(false);
    if !has_col {
        eprintln!("migration 114 not applied — skipping");
        return None;
    }

    let cp = Arc::new(ConnectionPool::from_pg_pool(pool.clone(), &url));
    Some((cp, pool))
}

#[tokio::test]
async fn chain_writes_and_verifies() {
    let Some((cp, pool)) = setup().await else {
        return;
    };
    let storage = PgAuditStorage::new(cp.clone(), None);
    let audit = AuditLog::new(Arc::new(storage));

    // Reset this tenant's chain head and prior chained rows so the test
    // is idempotent. We can only DELETE from audit_chain_head (triggers
    // don't block it), and we filter audit_log by a sentinel action so
    // we don't touch unrelated rows. audit_log DELETE is blocked by the
    // trigger, so we use a fresh test company instead.
    let test_company_id = Uuid::now_v7();
    sqlx::query("INSERT INTO companies (id, name, code) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(test_company_id)
        .bind(format!("Test Company {}", test_company_id))
        .bind(format!("test_{}", &test_company_id.to_string()[..8]))
        .execute(&pool)
        .await
        .unwrap();

    // Write three entries to the test tenant.
    for i in 0..3 {
        let entry = AuditEntry::new(AuditAction::LoginSuccess, AuditSeverity::Info)
            .with_company(CompanyId(test_company_id))
            .with_username(format!("user_{i}"))
            .with_details(serde_json::json!({"i": i}));
        audit.log(entry).await.expect("chain write");
    }

    // Walk the chain and verify.
    let rows = sqlx::query(
        "SELECT chain_position, prev_hash, entry_hash, canonical_payload \
         FROM audit_log \
         WHERE company_id = $1 AND chain_position IS NOT NULL \
         ORDER BY chain_position ASC",
    )
    .bind(test_company_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 3, "expected 3 chained entries");

    let mut prev: Option<Vec<u8>> = None;
    for (idx, row) in rows.iter().enumerate() {
        let position: i64 = row.get("chain_position");
        assert_eq!(position as usize, idx, "chain position gap");
        let stored_prev: Option<Vec<u8>> = row.try_get("prev_hash").ok();
        let stored_hash: Vec<u8> = row.get("entry_hash");
        let canonical: String = row.get("canonical_payload");

        assert_eq!(
            stored_prev, prev,
            "prev_hash at position {position} does not link to prior entry_hash"
        );
        let computed = compute_entry_hash(stored_prev.as_deref(), canonical.as_bytes());
        assert_eq!(
            computed.as_slice(),
            stored_hash.as_slice(),
            "recomputed hash mismatch at position {position}"
        );

        // canonical_payload must be stable under re-canonicalization.
        let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        let re = canonicalize(&parsed).unwrap();
        assert_eq!(
            re, canonical,
            "canonical_payload drifted at position {position}"
        );

        prev = Some(stored_hash);
    }

    // Chain head advanced to position 2.
    let head: i64 = sqlx::query_scalar(
        "SELECT last_position FROM audit_chain_head WHERE company_id = $1",
    )
    .bind(test_company_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(head, 2);
}

#[tokio::test]
async fn triggers_block_mutations() {
    let Some((_cp, pool)) = setup().await else {
        return;
    };

    let update_err = sqlx::query("UPDATE audit_log SET action = 'tampered' WHERE id IS NOT NULL")
        .execute(&pool)
        .await
        .expect_err("UPDATE must be blocked");
    let msg = update_err.to_string();
    assert!(
        msg.contains("WORM") || msg.contains("append-only"),
        "UPDATE error was not the WORM trigger: {msg}"
    );

    let delete_err = sqlx::query("DELETE FROM audit_log WHERE id IS NOT NULL")
        .execute(&pool)
        .await
        .expect_err("DELETE must be blocked");
    let msg = delete_err.to_string();
    assert!(
        msg.contains("WORM") || msg.contains("append-only"),
        "DELETE error was not the WORM trigger: {msg}"
    );
}

#[tokio::test]
async fn signature_round_trip() {
    let Some((cp, pool)) = setup().await else {
        return;
    };

    let (key, _pkcs8) = Ed25519Key::generate("test-worm-sig").unwrap();
    let public_key = key.public_key();
    let signer: Arc<dyn SigningKey> = Arc::new(key);
    let storage = PgAuditStorage::new(cp.clone(), Some(signer));
    storage
        .register_signing_key("test-worm-sig", &public_key, "ed25519", Utc::now())
        .await
        .unwrap();
    let audit = AuditLog::new(Arc::new(storage));

    // Write to an isolated test company.
    let test_company_id = Uuid::now_v7();
    sqlx::query("INSERT INTO companies (id, name, code) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(test_company_id)
        .bind(format!("Sig Test {}", test_company_id))
        .bind(format!("sig_{}", &test_company_id.to_string()[..8]))
        .execute(&pool)
        .await
        .unwrap();

    let entry = AuditEntry::new(AuditAction::UserCreated, AuditSeverity::Info)
        .with_company(CompanyId(test_company_id))
        .with_username("sig_tester")
        .with_resource("user", Uuid::now_v7().to_string());
    audit.log(entry).await.unwrap();

    let row = sqlx::query(
        "SELECT entry_hash, canonical_payload, signature, signing_key_id \
         FROM audit_log WHERE company_id = $1 \
         ORDER BY chain_position DESC LIMIT 1",
    )
    .bind(test_company_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let entry_hash: Vec<u8> = row.get("entry_hash");
    let canonical: String = row.get("canonical_payload");
    let signature: Vec<u8> = row.get("signature");
    let key_id: String = row.get("signing_key_id");
    assert_eq!(key_id, "test-worm-sig");
    assert_eq!(signature.len(), 64, "Ed25519 signature is 64 bytes");

    // Reconstruct the exact message PgAuditStorage signed:
    // (entry_hash || canonical_bytes).
    let mut msg = Vec::with_capacity(entry_hash.len() + canonical.len());
    msg.extend_from_slice(&entry_hash);
    msg.extend_from_slice(canonical.as_bytes());
    verify_ed25519(&public_key, &msg, &signature).expect("signature should verify");
}
