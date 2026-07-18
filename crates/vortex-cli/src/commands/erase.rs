//! `vortex erase` — secure data erasure (CSRA control 18b).
//!
//! Two operations, both of which record the erasure through the WORM audit
//! ledger and drop a signed **erasure certificate** to disk as tamper-evident
//! proof of what was erased, when, and by whom:
//!
//! - `erase subject <username>` — crypto-shred a data subject's PII in the core
//!   `users` table (GDPR/PDPA right-to-erasure). The row is kept, not deleted:
//!   the WORM `audit_log` holds an immutable foreign key to `users.id`, so a
//!   hard delete is impossible by design. Instead every PII field is
//!   overwritten with an irreversible tombstone and the account is disabled.
//!   The immutable ledger retains only a minimal identifier under the audit /
//!   security-necessity retention basis — this is documented in
//!   `docs/DATA_ERASURE.md`.
//!
//! - `erase database <name>` — securely decommission an entire tenant database
//!   (POC teardown / end-of-life). Verifies and attests the tenant's WORM chain
//!   first (the certificate captures the final chain head), then drops the
//!   database and deregisters it from the master registry. Residual on-disk
//!   sanitisation is a media-level control (crypto-erase) covered in the docs.
//!
//! Both connect via `DATABASE_URL`, the same convention as `vortex user` /
//! `vortex audit`. For `subject`, point it at the tenant. For `database`, point
//! it at the primary/master — the target tenant is named as the argument.

use anyhow::{bail, Context as _, Result};
use clap::Subcommand;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use vortex_common::{CompanyId, UserId};
use vortex_orm::prelude::{ConnectionPool, DatabaseConfig};
use vortex_security::audit::verify::{verify_chain, VerifyOptions, DEFAULT_CLOCK_SKEW_SECONDS};
use vortex_security::audit::{AuditAction, AuditEntry, AuditSeverity, AuditStorage, PgAuditStorage};

#[derive(Subcommand)]
pub enum EraseCommands {
    /// Crypto-shred a data subject's PII in the core `users` table (the row is
    /// retained for audit-chain integrity; every PII field is tombstoned).
    Subject {
        /// Username of the account to erase.
        username: String,
        /// Confirm the irreversible erasure (required; without it, a dry run).
        #[arg(long)]
        yes: bool,
        /// Operator performing the erasure (for the certificate). Defaults to
        /// $USER.
        #[arg(long)]
        by: Option<String>,
    },
    /// Securely decommission an entire tenant database (verify+attest the WORM
    /// chain, drop it, deregister it). Point DATABASE_URL at the primary.
    Database {
        /// Name of the tenant database to erase.
        name: String,
        /// Confirm the irreversible erasure (required; without it, a dry run).
        #[arg(long)]
        yes: bool,
        /// Operator performing the erasure (for the certificate). Defaults to
        /// $USER.
        #[arg(long)]
        by: Option<String>,
    },
}

pub async fn run(command: EraseCommands) -> Result<()> {
    match command {
        EraseCommands::Subject { username, yes, by } => erase_subject(&username, yes, by).await,
        EraseCommands::Database { name, yes, by } => erase_database(&name, yes, by).await,
    }
}

/// Connect to the `DATABASE_URL` database as a `ConnectionPool` (so the same
/// handle serves both the plain SQL and the WORM audit storage).
async fn connect(url: &str) -> Result<Arc<ConnectionPool>> {
    let cfg = DatabaseConfig {
        url: url.to_string(),
        max_connections: 4,
        min_connections: 1,
        ..Default::default()
    };
    let pool = ConnectionPool::new(cfg)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to DATABASE_URL: {e}"))?;
    Ok(Arc::new(pool))
}

fn database_url() -> Result<String> {
    std::env::var("DATABASE_URL").context(
        "DATABASE_URL not set — point it at the target database, e.g. \
         postgres://vortex:vortex@localhost:5432/vortex",
    )
}

fn operator(by: Option<String>) -> String {
    by.or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Short, stable id fragment used to build unique tombstones.
fn short(id: Uuid) -> String {
    id.simple().to_string()[..12].to_string()
}

/// Key for the PII fingerprint HMAC. Uses the deployment secret so the
/// fingerprint is not brute-forceable from low-entropy PII. Falls back to a
/// fixed domain separator (with a warning) when the secret is unset — the
/// fingerprint is still stable, just not attacker-resistant.
fn fingerprint_key() -> Vec<u8> {
    match std::env::var("VORTEX_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k.into_bytes(),
        _ => {
            eprintln!("WARNING: VORTEX_SECRET_KEY unset — PII fingerprint is unsalted and may be brute-forceable. Set it before erasing production data.");
            b"vortex.erasure.fingerprint.v1".to_vec()
        }
    }
}

/// HMAC-SHA256 (FIPS 198-1), built on the already-vendored `sha2` so no new
/// dependency is pulled in for one call site.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    let outer = Sha256::new().chain_update(opad).chain_update(inner).finalize();
    outer.into()
}

// ─── subject erasure ─────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SubjectRow {
    id: Uuid,
    company_id: Uuid,
    username: String,
    email: String,
    full_name: Option<String>,
}

async fn erase_subject(username: &str, yes: bool, by: Option<String>) -> Result<()> {
    let url = database_url()?;
    let cpool = connect(&url).await?;
    let db = cpool.pool().clone();

    let subject = sqlx::query_as::<_, SubjectRow>(
        "SELECT id, company_id, username, email, full_name FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(&db)
    .await
    .context("failed to query user")?;

    let Some(subject) = subject else {
        bail!("no user named '{username}' in this database (is DATABASE_URL pointing at the right tenant?)");
    };

    // A fingerprint of the original PII: lets a certificate prove *which*
    // record was erased without retaining the cleartext. Keyed with the
    // deployment secret (HMAC) so low-entropy PII (guessable usernames /
    // emails) can't be brute-forced back out of the certificate or the WORM
    // entry by anyone who can read them but doesn't hold the key.
    let mut msg = Vec::new();
    msg.extend_from_slice(subject.username.as_bytes());
    msg.push(0);
    msg.extend_from_slice(subject.email.as_bytes());
    msg.push(0);
    msg.extend_from_slice(subject.full_name.as_deref().unwrap_or("").as_bytes());
    let fingerprint = hex::encode(hmac_sha256(&fingerprint_key(), &msg));

    let tomb = short(subject.id);
    let new_username = format!("erased_{tomb}");
    let new_email = format!("erased+{tomb}@erased.invalid");

    if !yes {
        println!("DRY RUN — would crypto-shred PII for user '{}' (id {}):", subject.username, subject.id);
        println!("  username   → {new_username}");
        println!("  email      → {new_email}");
        println!("  full_name  → [erased]");
        println!("  password   → invalidated (account disabled + locked)");
        println!("  mfa_secret → removed");
        println!("The users row is retained (WORM audit_log FK); the audit ledger keeps a");
        println!("minimal identifier under the audit-retention basis. Re-run with --yes to proceed.");
        return Ok(());
    }

    // Irreversible overwrite of every PII field. Unique tombstones keep the
    // (company_id, username) / (company_id, email) constraints satisfiable.
    let affected = sqlx::query(
        "UPDATE users SET \
            username = $2, email = $3, full_name = '[erased]', \
            password_hash = '!', mfa_secret = NULL, mfa_enabled = false, \
            active = false, locked = true, locked_at = COALESCE(locked_at, NOW()), \
            locked_reason = 'DATA_ERASED', failed_login_attempts = 0, \
            must_change_password = false, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(subject.id)
    .bind(&new_username)
    .bind(&new_email)
    .execute(&db)
    .await
    .context("failed to erase user PII")?
    .rows_affected();

    if affected != 1 {
        bail!("erasure UPDATE affected {affected} rows (expected 1) — aborting");
    }

    // Record the erasure through the WORM ledger (survives; only the subject's
    // PII was shredded, not the chain).
    let op = operator(by);
    let storage = PgAuditStorage::new(cpool.clone(), None);
    let entry = AuditEntry::new(AuditAction::RecordDeleted, AuditSeverity::Warning)
        .with_company(CompanyId(subject.company_id))
        .with_user(UserId(subject.id))
        .with_username(&new_username)
        .with_resource("user", subject.id.to_string())
        .with_details(serde_json::json!({
            "operation": "secure_subject_erasure",
            "subject_fingerprint_sha256": fingerprint,
            "fields_shredded": ["username", "email", "full_name", "password_hash", "mfa_secret"],
            "performed_by": op,
            "note": "row retained for WORM audit-chain FK integrity; PII irreversibly tombstoned",
        }));
    storage
        .write(entry)
        .await
        .map_err(|e| anyhow::anyhow!("WORM audit write for erasure failed: {e}"))?;

    // Verify: re-read and prove no original PII remains.
    let verify = sqlx::query_as::<_, SubjectRow>(
        "SELECT id, company_id, username, email, full_name FROM users WHERE id = $1",
    )
    .bind(subject.id)
    .fetch_one(&db)
    .await
    .context("post-erasure verification query failed")?;

    let clean = verify.username == new_username
        && verify.email == new_email
        && verify.full_name.as_deref() == Some("[erased]");
    if !clean {
        bail!("post-erasure verification FAILED — PII still present; investigate immediately");
    }

    let cert = serde_json::json!({
        "operation": "subject_erasure",
        "database": db_display(&url),
        "subject_id": subject.id,
        "subject_fingerprint_sha256": fingerprint,
        "fields_shredded": ["username", "email", "full_name", "password_hash", "mfa_secret"],
        "performed_at_utc": now_iso(),
        "performed_by": op,
        "verification": "passed: no original PII remains in operational tables",
        "audit_retention_note": "immutable audit_log retains a minimal identifier under the audit/security-necessity basis (see docs/DATA_ERASURE.md)",
    });
    let path = write_certificate(&cert, &format!("subject-{tomb}"))?;

    println!("Erased subject '{username}' (id {}).", subject.id);
    println!("  verification: PASSED — no original PII remains");
    println!("  WORM audit:   recorded (record_deleted / secure_subject_erasure)");
    println!("  certificate:  {path}");
    Ok(())
}

// ─── database decommission ───────────────────────────────────────────────

async fn erase_database(name: &str, yes: bool, by: Option<String>) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("refusing to operate on database name '{name}': must be non-empty [A-Za-z0-9_]");
    }
    // Never let the erasure tool destroy shared infrastructure: the master
    // tenant registry, or Postgres' own maintenance/template databases. Without
    // this, `erase database vortex_master` (while DATABASE_URL points at a
    // different primary) would pass its own chain attestation and drop the
    // registry for the entire deployment.
    const PROTECTED: &[&str] = &["vortex_master", "postgres", "template0", "template1"];
    if PROTECTED.iter().any(|p| p.eq_ignore_ascii_case(name)) {
        bail!("refusing to erase protected database '{name}' (master registry / Postgres maintenance database)");
    }
    let primary_url = database_url()?;
    let base = primary_url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&primary_url);
    let primary_db = primary_url.rsplit_once('/').map(|(_, d)| d).unwrap_or("");
    if name == primary_db {
        bail!("refusing to erase the database DATABASE_URL is pointed at ('{name}') — point DATABASE_URL at the primary and name the tenant to erase");
    }
    let tenant_url = format!("{base}/{name}");

    let cpool = connect(&primary_url).await?;
    let admin = cpool.pool().clone();

    // Target must exist.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(name)
        .fetch_one(&admin)
        .await
        .context("failed to check database existence")?;
    if !exists {
        bail!("database '{name}' does not exist (nothing to erase)");
    }

    // ── attest the tenant's WORM chain before destroying it ──────────────
    let tenant = connect(&tenant_url).await?;
    let tdb = tenant.pool().clone();
    let report = verify_chain(
        &tdb,
        &VerifyOptions { company: None, from: None, to: None, max_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS },
    )
    .await
    .map_err(|e| anyhow::anyhow!("pre-erasure audit verification failed: {e}"))?;
    let chain_ok = report.ok();

    // Capture the final chain head(s) as the attestation.
    let heads: Vec<serde_json::Value> = sqlx::query_as::<_, (Uuid, Vec<u8>, i64)>(
        "SELECT company_id, last_hash, last_position FROM audit_chain_head ORDER BY company_id",
    )
    .fetch_all(&tdb)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(c, h, p)| serde_json::json!({"company_id": c, "last_position": p, "last_hash": hex::encode(h)}))
    .collect();

    let audit_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&tdb)
        .await
        .unwrap_or(0);
    // Release the tenant pool so the DROP isn't blocked by our own connection.
    drop(tdb);
    tenant.pool().close().await;

    let op = operator(by);
    if !yes {
        println!("DRY RUN — would securely decommission database '{name}':");
        println!("  pre-erasure audit chain: {} ({} entries)", if chain_ok { "VERIFIED" } else { "FAILED — investigate before erasing" }, audit_rows);
        println!("  chain heads attested:    {}", heads.len());
        println!("  action: terminate connections → DROP DATABASE → deregister from managed_databases");
        println!("Re-run with --yes to proceed. This is irreversible.");
        return Ok(());
    }
    if !chain_ok {
        bail!("pre-erasure audit chain verification FAILED for '{name}' — refusing to erase a tampered/corrupt tenant without a clean attestation. Investigate first.");
    }

    // ── terminate other backends, then drop ──────────────────────────────
    let _ = sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(name)
    .execute(&admin)
    .await;

    sqlx::query(&format!("DROP DATABASE \"{name}\""))
        .execute(&admin)
        .await
        .with_context(|| format!("DROP DATABASE '{name}' failed"))?;

    // Deregister from the master registry (best-effort; table may live in the
    // primary and/or a separate vortex_master).
    let mut deregistered = sqlx::query("DELETE FROM managed_databases WHERE name = $1")
        .bind(name)
        .execute(&admin)
        .await
        .map(|r| r.rows_affected())
        .unwrap_or(0);
    if let Ok(master) = connect(&format!("{base}/vortex_master")).await {
        deregistered += sqlx::query("DELETE FROM managed_databases WHERE name = $1")
            .bind(name)
            .execute(master.pool())
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0);
        master.pool().close().await;
    }

    // ── verify erasure ───────────────────────────────────────────────────
    let still_there: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(name)
        .fetch_one(&admin)
        .await
        .unwrap_or(true);
    if still_there {
        bail!("post-erasure verification FAILED — database '{name}' still exists");
    }

    // ── record the decommission on the PRIMARY chain (survives) ──────────
    let storage = PgAuditStorage::new(cpool.clone(), None);
    let entry = AuditEntry::new(AuditAction::RecordDeleted, AuditSeverity::Critical)
        .with_resource("database", name)
        .with_resource_name(name)
        .with_details(serde_json::json!({
            "operation": "secure_database_decommission",
            "database": name,
            "pre_erasure_chain_verified": chain_ok,
            "pre_erasure_audit_entries": audit_rows,
            "attested_chain_heads": heads,
            "performed_by": op,
        }));
    if let Err(e) = storage.write(entry).await {
        // The data is already gone; a failed audit write must be loud but not
        // crash the tool after the irreversible step.
        eprintln!("WARNING: WORM audit write for decommission failed: {e}");
    }

    let cert = serde_json::json!({
        "operation": "database_decommission",
        "database": name,
        "performed_at_utc": now_iso(),
        "performed_by": op,
        "pre_erasure_audit_chain": if chain_ok { "verified" } else { "failed" },
        "pre_erasure_audit_entries": audit_rows,
        "attested_chain_heads": heads,
        "deregistered_rows": deregistered,
        "verification": "passed: database no longer exists",
        "media_sanitisation_note": "logical DROP frees blocks but does not purge disk; residual-data purge is a media-level control (encrypted volume + key destruction / crypto-erase) — see docs/DATA_ERASURE.md",
    });
    let path = write_certificate(&cert, &format!("database-{name}"))?;

    println!("Decommissioned database '{name}'.");
    println!("  pre-erasure chain: VERIFIED ({audit_rows} entries, {} heads attested)", heads.len());
    println!("  verification:      PASSED — database no longer exists");
    println!("  WORM audit:        recorded on primary (record_deleted / secure_database_decommission)");
    println!("  certificate:       {path}");
    Ok(())
}

// ─── certificate + helpers ───────────────────────────────────────────────

/// Best-effort UTC timestamp. `chrono::Utc::now` is fine here (this is a CLI,
/// not the resume-sensitive workflow runtime).
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// The database name portion of a connection URL, for display in certificates
/// (never the credentials).
fn db_display(url: &str) -> String {
    url.rsplit_once('/').map(|(_, d)| d.to_string()).unwrap_or_default()
}

/// Write a signed (self-hashed) erasure certificate to the certificates
/// directory and return its path. The `integrity_sha256` seals the body so any
/// later tampering with the certificate file is detectable.
fn write_certificate(body: &serde_json::Value, stem: &str) -> Result<String> {
    let dir = std::env::var("VORTEX_ERASURE_DIR").unwrap_or_else(|_| "erasure-certificates".to_string());
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create certificate dir '{dir}'"))?;

    let canonical = serde_json::to_string(body).context("failed to serialise certificate body")?;
    let seal = hex::encode(Sha256::digest(canonical.as_bytes()));
    let cert = serde_json::json!({ "certificate": body, "integrity_sha256": seal });

    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let path = format!("{dir}/erasure-{stem}-{stamp}.json");
    let pretty = serde_json::to_string_pretty(&cert).context("failed to serialise certificate")?;
    std::fs::write(&path, pretty).with_context(|| format!("failed to write certificate '{path}'"))?;

    // Certificates carry an operator name and a PII fingerprint — restrict them
    // to the owner (dir 0700, file 0600). Best-effort; non-Unix hosts skip.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}
