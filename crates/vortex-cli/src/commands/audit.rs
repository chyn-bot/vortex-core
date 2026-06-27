//! `vortex audit` — WORM ledger inspection and verification.
//!
//! Subcommands:
//! - `verify` — walk the per-tenant hash chain, recompute each entry's
//!   hash, verify Ed25519 signatures against the public keys stored in
//!   `audit_signing_keys`, and flag any integrity break or clock skew.
//!   Exit code 0 on success, 1 on any verification failure, 2 on infra
//!   errors. Writes a `chain_verification_passed` or
//!   `chain_verification_failed` audit entry at the end (self-attestation).
//! - `head` — print the current `(company_id, last_position, last_hash)`
//!   for each tenant, or for a specific tenant via `--company`.
//! - `export` — stream audit entries to stdout as JSONL, CEF, or LEEF for
//!   ingestion into external SIEMs.
//!
//! These commands connect to the database using `DATABASE_URL` and run
//! outside the server process — they can be scheduled by cron for
//! continuous integrity monitoring.

use anyhow::{bail, Context as _, Result};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use vortex_security::audit::verify::{
    verify_chain, VerifyOptions, DEFAULT_CLOCK_SKEW_SECONDS,
};

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Walk the audit chain and verify cryptographic integrity.
    Verify {
        /// Limit verification to a single company/tenant UUID.
        #[arg(long)]
        company: Option<Uuid>,
        /// Earliest entry timestamp to include (RFC 3339).
        #[arg(long)]
        from: Option<DateTime<Utc>>,
        /// Latest entry timestamp to include (RFC 3339).
        #[arg(long)]
        to: Option<DateTime<Utc>>,
        /// Maximum allowed clock skew in seconds between application and
        /// database timestamps before an entry is flagged.
        #[arg(long, default_value_t = DEFAULT_CLOCK_SKEW_SECONDS)]
        max_skew_seconds: i64,
    },
    /// Print the current chain head(s).
    Head {
        /// Limit to a single company.
        #[arg(long)]
        company: Option<Uuid>,
    },
    /// Stream audit entries in a SIEM-friendly format.
    Export {
        /// Limit to a single company.
        #[arg(long)]
        company: Option<Uuid>,
        /// Earliest entry timestamp to include (RFC 3339).
        #[arg(long)]
        from: Option<DateTime<Utc>>,
        /// Output format.
        #[arg(long, default_value = "jsonl")]
        format: ExportFormat,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ExportFormat {
    /// One JSON object per line.
    Jsonl,
    /// ArcSight Common Event Format.
    Cef,
    /// QRadar Log Event Extended Format.
    Leef,
}

pub async fn run(command: AuditCommands) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://remicle:remicle_dev_2026@localhost/remicle".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("failed to connect to DATABASE_URL for audit CLI")?;

    match command {
        AuditCommands::Verify {
            company,
            from,
            to,
            max_skew_seconds,
        } => verify_cmd(&pool, company, from, to, max_skew_seconds).await,
        AuditCommands::Head { company } => head_cmd(&pool, company).await,
        AuditCommands::Export {
            company,
            from,
            format,
        } => export_cmd(&pool, company, from, format).await,
    }
}

async fn verify_cmd(
    pool: &sqlx::PgPool,
    company: Option<Uuid>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    max_skew_seconds: i64,
) -> Result<()> {
    // The actual verification logic lives in the library so the
    // scheduled background check uses an identical code path. This
    // CLI adapter just renders the structured report and sets the
    // exit code.
    let report = verify_chain(
        pool,
        &VerifyOptions {
            company,
            from,
            to,
            max_skew_seconds,
        },
    )
    .await
    .context("audit chain verification failed")?;

    if report.companies_checked == 0 {
        println!("No chained audit entries found — nothing to verify.");
        return Ok(());
    }

    println!(
        "Verified {} entries across {} compan{}; {} failure{} ({}ms).",
        report.entries_verified,
        report.companies_checked,
        if report.companies_checked == 1 { "y" } else { "ies" },
        report.failure_count(),
        if report.failure_count() == 1 { "" } else { "s" },
        report.duration.as_millis()
    );

    if !report.ok() {
        println!();
        println!("Failures:");
        for f in &report.failures {
            println!(
                "  ✗ company {} position {} (id={}) [{}]: {}",
                f.company_id,
                f.chain_position,
                f.entry_id,
                f.kind.code(),
                f.detail
            );
        }
        std::process::exit(1);
    }

    Ok(())
}

async fn head_cmd(pool: &sqlx::PgPool, company: Option<Uuid>) -> Result<()> {
    let sql = match company {
        Some(_) => {
            "SELECT company_id, last_hash, last_position, updated_at \
             FROM audit_chain_head WHERE company_id = $1"
        }
        None => {
            "SELECT company_id, last_hash, last_position, updated_at \
             FROM audit_chain_head ORDER BY company_id"
        }
    };
    let mut q = sqlx::query(sql);
    if let Some(c) = company {
        q = q.bind(c);
    }
    let rows = q
        .fetch_all(pool)
        .await
        .context("failed to read audit_chain_head")?;

    if rows.is_empty() {
        println!("No chain heads found.");
        return Ok(());
    }

    println!("{:<38} {:>12}  last_hash                                                          updated_at", "company_id", "position");
    for row in rows {
        let cid: Uuid = row.get("company_id");
        let last_hash: Vec<u8> = row.get("last_hash");
        let last_position: i64 = row.get("last_position");
        let updated_at: DateTime<Utc> = row.get("updated_at");
        println!(
            "{cid:<38} {last_position:>12}  {}  {updated_at}",
            hex::encode(&last_hash)
        );
    }

    Ok(())
}

async fn export_cmd(
    pool: &sqlx::PgPool,
    company: Option<Uuid>,
    from: Option<DateTime<Utc>>,
    format: ExportFormat,
) -> Result<()> {
    let mut sql = String::from(
        "SELECT id, timestamp, company_id, user_id, username, action, \
         resource_type, resource_id, details, ip_address::text as ip_address, \
         user_agent, success, compliance_category, chain_position, entry_hash \
         FROM audit_log WHERE 1=1",
    );
    let mut arg_idx = 0;
    if company.is_some() {
        arg_idx += 1;
        sql.push_str(&format!(" AND company_id = ${arg_idx}"));
    }
    if from.is_some() {
        arg_idx += 1;
        sql.push_str(&format!(" AND timestamp >= ${arg_idx}"));
    }
    sql.push_str(" ORDER BY timestamp ASC");

    let mut q = sqlx::query(&sql);
    if let Some(c) = company {
        q = q.bind(c);
    }
    if let Some(f) = from {
        q = q.bind(f);
    }
    let rows = q.fetch_all(pool).await.context("audit_log scan")?;

    if rows.is_empty() {
        return Ok(());
    }

    for row in rows {
        let id: Uuid = row.get("id");
        let ts: DateTime<Utc> = row.get("timestamp");
        let company_id: Option<Uuid> = row.try_get("company_id").ok();
        let user_id: Option<Uuid> = row.try_get("user_id").ok();
        let username: Option<String> = row.try_get("username").ok();
        let action: String = row.get("action");
        let resource_type: Option<String> = row.try_get("resource_type").ok();
        let details: Option<serde_json::Value> = row.try_get("details").ok();
        let src_ip: Option<String> = row.try_get("ip_address").ok();
        let success: bool = row.try_get("success").unwrap_or(true);
        let chain_position: Option<i64> = row.try_get("chain_position").ok();

        match format {
            ExportFormat::Jsonl => {
                let obj = serde_json::json!({
                    "id": id.to_string(),
                    "timestamp": ts.to_rfc3339(),
                    "company_id": company_id.map(|u| u.to_string()),
                    "user_id": user_id.map(|u| u.to_string()),
                    "username": username,
                    "action": action,
                    "resource_type": resource_type,
                    "details": details,
                    "source_ip": src_ip,
                    "success": success,
                    "chain_position": chain_position,
                });
                println!("{}", serde_json::to_string(&obj).unwrap_or_default());
            }
            ExportFormat::Cef => {
                // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
                println!(
                    "CEF:0|Vortex|vortex|0.1|{}|{}|{}|suser={} src={} act={}",
                    action,
                    action,
                    if success { 3 } else { 7 },
                    username.as_deref().unwrap_or(""),
                    src_ip.as_deref().unwrap_or(""),
                    resource_type.as_deref().unwrap_or("")
                );
            }
            ExportFormat::Leef => {
                println!(
                    "LEEF:2.0|Vortex|vortex|0.1|{}|\t|devTime={}\tusrName={}\tsrc={}\tact={}\tsuccess={}",
                    action,
                    ts.to_rfc3339(),
                    username.as_deref().unwrap_or(""),
                    src_ip.as_deref().unwrap_or(""),
                    resource_type.as_deref().unwrap_or(""),
                    success
                );
            }
        }
    }

    Ok(())
}

/// Type alias used from main.rs so the subcommand enum is visible.
pub type Command = AuditCommands;

#[allow(unused)]
fn _stub_unused_warn() {
    // Keep anyhow::bail referenced without changing behaviour.
    fn _x() -> Result<()> {
        bail!("not used");
    }
}
