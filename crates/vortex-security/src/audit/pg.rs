//! Postgres-backed WORM audit storage.
//!
//! This is the production implementation of [`crate::audit::AuditStorage`].
//! It enforces the cryptographic hash chain, optional Ed25519 signing, and
//! the dual-clock (application + database) timestamp scheme.
//!
//! # Write path
//!
//! Every write takes the following steps inside a single transaction:
//!
//! 1. `SELECT last_hash, last_position FROM audit_chain_head WHERE company_id = $1 FOR UPDATE`
//!    — serializes all writes for a given tenant.
//! 2. If no head exists, this is the first entry for the tenant: `prev_hash`
//!    is `None` and `chain_position` is `0`. Otherwise `prev_hash` is the
//!    last head's hash and `chain_position = last_position + 1`.
//! 3. `SELECT NOW()` to obtain the database's view of the current time.
//!    This becomes `db_timestamp` and is included in the canonical payload
//!    alongside the caller-supplied `timestamp`, so verifiers can detect
//!    application-side clock tampering.
//! 4. Build an [`AuditDbRow`] from the [`crate::audit::AuditEntry`]. Serialize
//!    it via JCS (RFC 8785).
//! 5. Compute `entry_hash = SHA256(prev_hash_or_zeros || canonical_bytes)`.
//!    When `prev_hash` is `None`, a 32-byte zero prefix is used, so the
//!    hash domain is always `SHA256(32+N bytes)`. This is documented in
//!    [`chain_hash_input`] for verifiers to replay.
//! 6. If a signing key is configured, sign `entry_hash || canonical_bytes`
//!    with Ed25519. The `signing_key_id` is recorded alongside.
//! 7. `INSERT INTO audit_log (...)` with all chain + signing + dual-clock
//!    columns populated.
//! 8. `INSERT INTO audit_chain_head (...) ON CONFLICT (company_id) DO UPDATE`
//!    advances the head. The pattern is the atomic upsert used elsewhere
//!    (see `crates/vortex-eam/src/services/sequence.rs`).
//!
//! When `write` is called (no caller-owned transaction), a new transaction
//! is opened internally. When `write_tx` is called, the same steps run on
//! the caller's transaction so the audit write commits atomically with
//! whatever business mutation triggered it.
//!
//! # Concurrency
//!
//! Throughput is bounded by `FOR UPDATE` on the chain head row: for a
//! given tenant, audit writes serialize. For the current workload (utility
//! EAM, tens of tenants, moderate write rates) this is adequate. A
//! follow-up will add per-tenant `tokio::mpsc` batching for tenants that
//! exceed ~500 entries/second.

use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::postgres::PgRow;
use tracing::{debug, warn};
use uuid::Uuid;
use vortex_common::{CompanyId, UserId, VortexError, VortexResult};
use vortex_orm::pool_manager::DatabasePoolManager;
use vortex_orm::ConnectionPool;

use super::canonical::canonicalize;
use super::{AuditAction, AuditEntry, AuditFilter, AuditSeverity, AuditStorage};
use crate::signing::SigningKey;

/// Fallback company used when an audit entry arrives without tenant
/// context (e.g. a login failure for an unknown user). Matches the
/// default company seed in `001_initial_schema`.
const FALLBACK_COMPANY_ID: Uuid = Uuid::from_bytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// Domain-separation prefix for the chain-start hash: 32 zero bytes.
/// Used when an entry has no previous hash (genesis per-tenant entry).
const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Compute the chain hash input used for a given (`prev_hash`, `canonical`)
/// pair. Exposed so the CLI verifier can replay the exact byte sequence.
pub fn chain_hash_input(prev_hash: Option<&[u8]>, canonical: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + canonical.len());
    match prev_hash {
        Some(h) if h.len() == 32 => buf.extend_from_slice(h),
        Some(h) => {
            // Defensive: if someone fed us a non-32-byte hash, pad/truncate.
            let mut padded = [0u8; 32];
            let n = h.len().min(32);
            padded[..n].copy_from_slice(&h[..n]);
            buf.extend_from_slice(&padded);
        }
        None => buf.extend_from_slice(&GENESIS_PREV_HASH),
    }
    buf.extend_from_slice(canonical);
    buf
}

/// Compute the SHA-256 entry hash for an audit row.
pub fn compute_entry_hash(prev_hash: Option<&[u8]>, canonical: &[u8]) -> [u8; 32] {
    let input = chain_hash_input(prev_hash, canonical);
    let mut hasher = Sha256::new();
    hasher.update(&input);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Projection of [`AuditEntry`] into the exact shape that gets persisted
/// and canonicalized. Building this explicitly (rather than deriving
/// Serialize on `AuditEntry` directly) gives us strict control over which
/// fields enter the hash — adding a new field to `AuditEntry` should not
/// silently change historical hash values.
#[derive(Debug, Clone)]
pub struct AuditDbRow {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub db_timestamp: DateTime<Utc>,
    pub company_id: Uuid,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub action: String,
    pub severity: String,
    pub session_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub resource_name: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub details: Value,
    pub previous_state: Option<Value>,
    pub new_state: Option<Value>,
    pub cip_requirement: String,
    pub chain_position: i64,
    pub prev_hash: Option<[u8; 32]>,
}

impl AuditDbRow {
    /// Build the canonical JSON value that is serialized via JCS and
    /// hashed. Field names are lowercase_snake_case and keys are emitted
    /// in whatever order the `Map` holds — JCS sorts them for us.
    ///
    /// **Any change to this function's shape is a breaking change to the
    /// audit ledger's verification contract.** Old entries must remain
    /// verifiable forever, so fields can be added (they'll be absent in
    /// old entries and distinguishable by their default) but never
    /// renamed or removed.
    pub fn canonical_value(&self) -> Value {
        json!({
            "id": self.id.to_string(),
            "timestamp": fmt_ts(&self.timestamp),
            "db_timestamp": fmt_ts(&self.db_timestamp),
            "company_id": self.company_id.to_string(),
            "user_id": self.user_id.map(|u| u.to_string()),
            "username": self.username,
            "action": self.action,
            "severity": self.severity,
            "session_id": self.session_id.map(|u| u.to_string()),
            "request_id": self.request_id.map(|u| u.to_string()),
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id.map(|u| u.to_string()),
            "resource_name": self.resource_name,
            "success": self.success,
            "error_message": self.error_message,
            "details": self.details,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "cip_requirement": self.cip_requirement,
            "chain_position": self.chain_position,
            "prev_hash": self.prev_hash.map(|h| hex::encode(h)),
        })
    }
}

fn fmt_ts(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Postgres-backed WORM audit storage.
///
/// Holds an [`Arc<ConnectionPool>`] for read/write access and an optional
/// [`Arc<dyn SigningKey>`] for Ed25519 signing. Both are cheap to clone
/// since they are already reference-counted.
pub struct PgAuditStorage {
    pool: Arc<ConnectionPool>,
    signer: Option<Arc<dyn SigningKey>>,
    /// Multi-DB pool manager. When present AND an audit entry has
    /// `db_name` set, the write uses the tenant's pool instead of
    /// `self.pool`. This ensures each tenant's audit chain lives in
    /// its own database, satisfying the per-tenant isolation
    /// requirement for multi-DB deployments.
    pool_manager: Option<Arc<DatabasePoolManager>>,
}

impl PgAuditStorage {
    pub fn new(pool: Arc<ConnectionPool>, signer: Option<Arc<dyn SigningKey>>) -> Self {
        Self {
            pool,
            signer,
            pool_manager: None,
        }
    }

    /// Attach a pool manager for multi-DB audit scoping. When set,
    /// entries with `db_name` will be written to the tenant's
    /// database instead of the primary. Call during startup, after
    /// constructing the pool manager.
    pub fn with_pool_manager(mut self, pm: Arc<DatabasePoolManager>) -> Self {
        self.pool_manager = Some(pm);
        self
    }

    /// Resolve the connection pool for an audit entry. If the entry
    /// carries a `db_name` and we have a pool manager, try the
    /// tenant pool. Fall back to the primary on any lookup failure.
    async fn resolve_pool(&self, entry: &AuditEntry) -> Arc<ConnectionPool> {
        if let (Some(db_name), Some(pm)) = (&entry.db_name, &self.pool_manager) {
            match pm.get_pool(db_name).await {
                Ok(tenant_pool) => {
                    debug!(
                        db = %db_name,
                        "routing audit entry to tenant database"
                    );
                    return tenant_pool;
                }
                Err(e) => {
                    warn!(
                        db = %db_name,
                        error = %e,
                        "tenant pool not found for audit entry — falling back to primary"
                    );
                }
            }
        }
        self.pool.clone()
    }

    /// Returns the underlying connection pool, exposed for tests and the
    /// CLI `vortex audit verify` command.
    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }

    /// Returns the signer key ID if signing is enabled.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.signer.as_deref().map(|s| s.key_id())
    }

    /// Ensure the given signing key's public half is registered in the
    /// `audit_signing_keys` table with the given `valid_from` timestamp.
    /// Idempotent — safe to call on every startup.
    pub async fn register_signing_key(
        &self,
        key_id: &str,
        public_key: &[u8],
        algorithm: &str,
        valid_from: DateTime<Utc>,
    ) -> VortexResult<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_signing_keys (key_id, public_key, algorithm, valid_from)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (key_id) DO NOTHING
            "#,
        )
        .bind(key_id)
        .bind(public_key)
        .bind(algorithm)
        .bind(valid_from)
        .execute(self.pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(format!("register_signing_key: {e}")))?;
        Ok(())
    }

    /// Internal: perform a single chained + signed append on the given
    /// transaction. The transaction is NOT committed here — the caller is
    /// responsible for commit (or rollback on failure).
    async fn append_inner(
        &self,
        entry: &AuditEntry,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> VortexResult<()> {
        let company_uuid = entry
            .company_id
            .map(|c| c.0)
            .unwrap_or(FALLBACK_COMPANY_ID);

        // 1. Lock the chain head for this tenant and read its current state.
        let head: Option<(Vec<u8>, i64)> = sqlx::query(
            r#"
            SELECT last_hash, last_position
            FROM audit_chain_head
            WHERE company_id = $1
            FOR UPDATE
            "#,
        )
        .bind(company_uuid)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("chain_head select: {e}")))?
        .map(|row| (row.get::<Vec<u8>, _>(0), row.get::<i64, _>(1)));

        let (prev_hash_bytes, next_position) = match head {
            Some((h, pos)) => {
                let mut arr = [0u8; 32];
                let n = h.len().min(32);
                arr[..n].copy_from_slice(&h[..n]);
                (Some(arr), pos + 1)
            }
            None => (None, 0i64),
        };

        // 2. Fetch the database server's current time so the canonical
        //    payload contains a clock that the caller cannot tamper with.
        let db_ts: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| VortexError::QueryExecution(format!("db_ts fetch: {e}")))?;

        // 3. Project the caller's entry into the persisted row shape.
        let row = AuditDbRow {
            id: entry.id,
            timestamp: entry.timestamp,
            db_timestamp: db_ts,
            company_id: company_uuid,
            user_id: entry.user_id.map(|u| u.0),
            username: entry.username.clone(),
            action: entry.action.code(),
            severity: entry.severity.code().to_string(),
            session_id: entry.session_id,
            request_id: entry.request_id,
            source_ip: entry.source_ip.clone(),
            user_agent: entry.user_agent.clone(),
            resource_type: entry.resource.clone(),
            resource_id: entry.resource_id.as_ref().and_then(|s| Uuid::parse_str(s).ok()),
            resource_name: entry.resource_name.clone(),
            success: entry.success,
            error_message: entry.error_message.clone(),
            details: entry.details.clone(),
            previous_state: entry.previous_state.clone(),
            new_state: entry.new_state.clone(),
            cip_requirement: entry.cip_reference.clone(),
            chain_position: next_position,
            prev_hash: prev_hash_bytes,
        };

        // 4. JCS canonicalize + SHA-256 + optional Ed25519 sign.
        let canonical_value = row.canonical_value();
        let canonical_bytes = canonicalize(&canonical_value)
            .map_err(|e| VortexError::Internal(format!("audit canonicalize: {e}")))?;
        let entry_hash = compute_entry_hash(
            prev_hash_bytes.as_ref().map(|h| h.as_slice()),
            canonical_bytes.as_bytes(),
        );

        let (signature, key_id): (Option<Vec<u8>>, Option<String>) = match &self.signer {
            Some(signer) => {
                // Sign over (entry_hash || canonical_bytes). Signing only
                // over entry_hash would let an attacker swap canonical
                // payloads at will; signing over (hash || bytes) pins
                // both the chain position and the content.
                let mut msg = Vec::with_capacity(32 + canonical_bytes.len());
                msg.extend_from_slice(&entry_hash);
                msg.extend_from_slice(canonical_bytes.as_bytes());
                let sig = signer.sign(&msg);
                (Some(sig), Some(signer.key_id().to_string()))
            }
            None => (None, None),
        };

        // 5. Persist the row with all chain/signing fields populated.
        sqlx::query(
            r#"
            INSERT INTO audit_log (
                id, timestamp, company_id, user_id, username,
                action, resource_type, resource_id, resource_name,
                details, ip_address, user_agent, success, error_message,
                cip_requirement, security_level,
                prev_hash, entry_hash, chain_position, signature,
                signing_key_id, canonical_payload, db_timestamp
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11::inet, $12, $13, $14,
                $15, $16,
                $17, $18, $19, $20,
                $21, $22, $23
            )
            "#,
        )
        .bind(row.id)
        .bind(row.timestamp)
        .bind(row.company_id)
        .bind(row.user_id)
        .bind(&row.username)
        .bind(&row.action)
        .bind(&row.resource_type)
        .bind(row.resource_id)
        .bind(&row.resource_name)
        .bind(&row.details)
        .bind(row.source_ip.as_deref())
        .bind(row.user_agent.as_deref())
        .bind(row.success)
        .bind(row.error_message.as_deref())
        .bind(&row.cip_requirement)
        .bind(entry.severity.code())
        .bind(prev_hash_bytes.map(|h| h.to_vec()))
        .bind(entry_hash.to_vec())
        .bind(row.chain_position)
        .bind(signature.as_deref())
        .bind(key_id.as_deref())
        .bind(&canonical_bytes)
        .bind(row.db_timestamp)
        .execute(&mut **tx)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("audit_log insert: {e}")))?;

        // 6. Advance the chain head.
        sqlx::query(
            r#"
            INSERT INTO audit_chain_head (company_id, last_hash, last_position, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (company_id) DO UPDATE
            SET last_hash = EXCLUDED.last_hash,
                last_position = EXCLUDED.last_position,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(company_uuid)
        .bind(entry_hash.to_vec())
        .bind(row.chain_position)
        .execute(&mut **tx)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("chain_head upsert: {e}")))?;

        debug!(
            company_id = %company_uuid,
            chain_position = row.chain_position,
            action = %row.action,
            "audit entry chained"
        );

        Ok(())
    }
}

#[async_trait::async_trait]
impl AuditStorage for PgAuditStorage {
    async fn write(&self, entry: AuditEntry) -> VortexResult<()> {
        // Resolve the target pool: tenant-specific if the entry
        // carries a db_name and we have a pool manager, primary
        // otherwise. This is where multi-DB audit scoping happens.
        let target_pool = self.resolve_pool(&entry).await;
        let mut tx = target_pool
            .pool()
            .begin()
            .await
            .map_err(|e| VortexError::DatabaseConnection(format!("audit tx begin: {e}")))?;
        match self.append_inner(&entry, &mut tx).await {
            Ok(()) => tx
                .commit()
                .await
                .map_err(|e| VortexError::QueryExecution(format!("audit tx commit: {e}"))),
            Err(e) => {
                if let Err(rb) = tx.rollback().await {
                    warn!("audit tx rollback failed after error: {rb}");
                }
                Err(e)
            }
        }
    }

    async fn write_tx<'c>(
        &self,
        entry: AuditEntry,
        tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    ) -> VortexResult<()> {
        self.append_inner(&entry, tx).await
    }

    async fn query(&self, filter: AuditFilter) -> VortexResult<Vec<AuditEntry>> {
        // Simple reader for the CLI and UI. Does NOT verify the chain —
        // that is the job of `vortex audit verify`.
        let mut sql = String::from(
            "SELECT id, timestamp, company_id, user_id, username, action, \
             resource_type, resource_id, resource_name, details, ip_address::text, \
             user_agent, success, error_message, cip_requirement \
             FROM audit_log WHERE 1=1",
        );
        let mut args: Vec<QueryArg> = Vec::new();
        if let Some(uid) = filter.user_id {
            args.push(QueryArg::Uuid(uid.0));
            sql.push_str(&format!(" AND user_id = ${}", args.len()));
        }
        if let Some(cid) = filter.company_id {
            args.push(QueryArg::Uuid(cid.0));
            sql.push_str(&format!(" AND company_id = ${}", args.len()));
        }
        if let Some(start) = filter.start_time {
            args.push(QueryArg::Ts(start));
            sql.push_str(&format!(" AND timestamp >= ${}", args.len()));
        }
        if let Some(end) = filter.end_time {
            args.push(QueryArg::Ts(end));
            sql.push_str(&format!(" AND timestamp <= ${}", args.len()));
        }
        sql.push_str(" ORDER BY timestamp DESC");
        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {}", limit as i64));
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET {}", offset as i64));
        }

        let mut q = sqlx::query(&sql);
        for a in &args {
            q = match a {
                QueryArg::Uuid(u) => q.bind(u),
                QueryArg::Ts(t) => q.bind(t),
            };
        }
        let rows = q
            .fetch_all(self.pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(format!("audit query: {e}")))?;

        Ok(rows.into_iter().map(row_to_entry).collect())
    }

    async fn count(&self, filter: AuditFilter) -> VortexResult<u64> {
        let mut sql = String::from("SELECT COUNT(*) FROM audit_log WHERE 1=1");
        let mut args: Vec<QueryArg> = Vec::new();
        if let Some(uid) = filter.user_id {
            args.push(QueryArg::Uuid(uid.0));
            sql.push_str(&format!(" AND user_id = ${}", args.len()));
        }
        if let Some(cid) = filter.company_id {
            args.push(QueryArg::Uuid(cid.0));
            sql.push_str(&format!(" AND company_id = ${}", args.len()));
        }
        if let Some(start) = filter.start_time {
            args.push(QueryArg::Ts(start));
            sql.push_str(&format!(" AND timestamp >= ${}", args.len()));
        }
        if let Some(end) = filter.end_time {
            args.push(QueryArg::Ts(end));
            sql.push_str(&format!(" AND timestamp <= ${}", args.len()));
        }
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        for a in &args {
            q = match a {
                QueryArg::Uuid(u) => q.bind(u),
                QueryArg::Ts(t) => q.bind(t),
            };
        }
        let n: i64 = q
            .fetch_one(self.pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(format!("audit count: {e}")))?;
        Ok(n.max(0) as u64)
    }
}

enum QueryArg {
    Uuid(Uuid),
    Ts(DateTime<Utc>),
}

fn row_to_entry(row: PgRow) -> AuditEntry {
    let id: Uuid = row.try_get("id").unwrap_or_else(|_| Uuid::nil());
    let timestamp: DateTime<Utc> = row.try_get("timestamp").unwrap_or_else(|_| Utc::now());
    let company_id: Option<Uuid> = row.try_get("company_id").ok();
    let user_id: Option<Uuid> = row.try_get("user_id").ok();
    let username: Option<String> = row.try_get("username").ok();
    let action_code: String = row.try_get("action").unwrap_or_default();
    let resource_type: Option<String> = row.try_get("resource_type").ok();
    let resource_id: Option<Uuid> = row.try_get("resource_id").ok();
    let resource_name: Option<String> = row.try_get("resource_name").ok();
    let details: Option<Value> = row.try_get("details").ok();
    let source_ip: Option<String> = row.try_get("ip_address").ok();
    let user_agent: Option<String> = row.try_get("user_agent").ok();
    let success: bool = row.try_get("success").unwrap_or(true);
    let error_message: Option<String> = row.try_get("error_message").ok();
    let cip_requirement: String = row.try_get("cip_requirement").unwrap_or_default();

    AuditEntry {
        id,
        timestamp,
        action: action_code_to_action(&action_code),
        severity: if success { AuditSeverity::Info } else { AuditSeverity::Warning },
        user_id: user_id.map(UserId),
        username,
        company_id: company_id.map(CompanyId),
        session_id: None,
        request_id: None,
        source_ip,
        user_agent,
        resource: resource_type,
        resource_id: resource_id.map(|u| u.to_string()),
        resource_name,
        success,
        error_message,
        details: details.unwrap_or(Value::Null),
        previous_state: None,
        new_state: None,
        cip_reference: cip_requirement,
        db_name: None,
    }
}

/// Reverse the stable `AuditAction::code()` mapping. Unknown codes become
/// `Custom(code)`, which is the documented fallback — the reader never
/// loses data, only some strong typing.
fn action_code_to_action(code: &str) -> AuditAction {
    match code {
        "login_success" => AuditAction::LoginSuccess,
        "login_failure" => AuditAction::LoginFailure,
        "logout" => AuditAction::Logout,
        "session_timeout" => AuditAction::SessionTimeout,
        "password_change" => AuditAction::PasswordChange,
        "password_reset" => AuditAction::PasswordReset,
        "mfa_challenge" => AuditAction::MfaChallenge,
        "mfa_success" => AuditAction::MfaSuccess,
        "mfa_failure" => AuditAction::MfaFailure,
        "access_granted" => AuditAction::AccessGranted,
        "access_denied" => AuditAction::AccessDenied,
        "permission_change" => AuditAction::PermissionChange,
        "role_assigned" => AuditAction::RoleAssigned,
        "role_revoked" => AuditAction::RoleRevoked,
        "user_created" => AuditAction::UserCreated,
        "user_updated" => AuditAction::UserUpdated,
        "user_locked" => AuditAction::UserLocked,
        "user_unlocked" => AuditAction::UserUnlocked,
        "record_created" => AuditAction::RecordCreated,
        "record_updated" => AuditAction::RecordUpdated,
        "record_deleted" => AuditAction::RecordDeleted,
        "record_viewed" => AuditAction::RecordViewed,
        "bulk_export" => AuditAction::BulkExport,
        "config_changed" => AuditAction::ConfigChanged,
        "system_startup" => AuditAction::SystemStartup,
        "system_shutdown" => AuditAction::SystemShutdown,
        "module_loaded" => AuditAction::ModuleLoaded,
        "module_unloaded" => AuditAction::ModuleUnloaded,
        "security_alert" => AuditAction::SecurityAlert,
        "intrusion_attempt" => AuditAction::IntrusionAttempt,
        "rate_limit_exceeded" => AuditAction::RateLimitExceeded,
        "invalid_token" => AuditAction::InvalidToken,
        "genesis_created" => AuditAction::GenesisCreated,
        "chain_verification_passed" => AuditAction::ChainVerificationPassed,
        "chain_verification_failed" => AuditAction::ChainVerificationFailed,
        "key_rotated" => AuditAction::KeyRotated,
        "trigger_disabled" => AuditAction::TriggerDisabled,
        "workflow_transition" => AuditAction::WorkflowTransition,
        other => {
            if let Some(rest) = other.strip_prefix("custom:") {
                AuditAction::Custom(rest.to_string())
            } else {
                AuditAction::Custom(other.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_and_linked_hashes_differ() {
        let canon = b"{\"a\":1}";
        let h0 = compute_entry_hash(None, canon);
        let h1 = compute_entry_hash(Some(&h0), canon);
        assert_ne!(h0, h1);
    }

    #[test]
    fn hash_is_deterministic() {
        let canon = b"{\"x\":42}";
        let a = compute_entry_hash(None, canon);
        let b = compute_entry_hash(None, canon);
        assert_eq!(a, b);
    }

    #[test]
    fn action_code_round_trip() {
        let variants = [
            AuditAction::LoginSuccess,
            AuditAction::UserCreated,
            AuditAction::ChainVerificationFailed,
            AuditAction::Custom("sesb_custom".into()),
        ];
        for v in variants {
            let code = v.code();
            let back = action_code_to_action(&code);
            assert_eq!(v, back, "round-trip failed for {code}");
        }
    }

    #[test]
    fn chain_hash_input_pads_short_prev_hash() {
        // Even if a previous hash somehow has the wrong length, the
        // hashing function must not panic and must produce a deterministic
        // 32-byte domain.
        let canon = b"x";
        let short = [0xAA, 0xBB, 0xCC];
        let a = chain_hash_input(Some(&short), canon);
        assert_eq!(a.len(), 32 + 1);
    }
}
