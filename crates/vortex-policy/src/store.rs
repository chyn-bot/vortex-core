//! Policy storage: load Cedar policies from Postgres.
//!
//! Policies live in the `policy_rules` table (created by migration 115)
//! and are read at server startup. A future admin command or endpoint
//! can call [`PolicyStore::load_all`] at runtime to hot-reload without a
//! restart — the [`crate::service::PolicyService`] holds its policy set
//! behind an `RwLock` for exactly this reason.
//!
//! Each row in `policy_rules` has:
//! - `id` — UUID primary key, used as the Cedar `PolicyId`
//! - `name` — human-readable name for audit and logging
//! - `description` — free text for operators and auditors
//! - `policy_text` — the Cedar policy source
//! - `active` — soft-disable without deletion
//! - `priority` — ordering only; Cedar itself is unordered (forbid beats
//!   permit), but priority is used by tooling to display policies in a
//!   stable order and to help humans review conflicts
//! - `company_id` — optional tenant scope. `NULL` policies apply to all
//!   tenants; company-scoped policies apply only to that tenant.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::error::{PolicyError, PolicyResult};

/// A single row from `policy_rules`.
#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_text: String,
    pub active: bool,
    pub priority: i32,
    pub company_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Storage abstraction so `PolicyService` can be unit-tested without a
/// real database. The Postgres impl is [`PgPolicyStore`]; tests use the
/// [`InMemoryPolicyStore`] provided below.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Return every active policy, regardless of tenant. Called at
    /// startup and on reload.
    async fn load_all(&self) -> PolicyResult<Vec<PolicyRecord>>;
}

/// Postgres-backed store. Reads from `policy_rules` where `active = true`,
/// ordered by `priority` then `created_at`.
pub struct PgPolicyStore {
    pool: sqlx::PgPool,
}

impl PgPolicyStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn load_all(&self) -> PolicyResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, description, policy_text, active, priority,
                   company_id, created_at, updated_at
            FROM policy_rules
            WHERE active = true
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PolicyError::Store(format!("policy_rules select: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(PolicyRecord {
                id: row.try_get("id").map_err(|e| PolicyError::Store(e.to_string()))?,
                name: row
                    .try_get("name")
                    .map_err(|e| PolicyError::Store(e.to_string()))?,
                description: row.try_get("description").ok(),
                policy_text: row
                    .try_get("policy_text")
                    .map_err(|e| PolicyError::Store(e.to_string()))?,
                active: row
                    .try_get("active")
                    .map_err(|e| PolicyError::Store(e.to_string()))?,
                priority: row
                    .try_get("priority")
                    .map_err(|e| PolicyError::Store(e.to_string()))?,
                company_id: row.try_get("company_id").ok(),
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| PolicyError::Store(e.to_string()))?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|e| PolicyError::Store(e.to_string()))?,
            });
        }
        Ok(out)
    }
}

/// In-memory store for unit tests. Tests can construct a
/// `PolicyService::new(InMemoryPolicyStore::with(vec![...]))` without
/// touching Postgres.
#[cfg(test)]
pub struct InMemoryPolicyStore {
    records: Vec<PolicyRecord>,
}

#[cfg(test)]
impl InMemoryPolicyStore {
    pub fn with(records: Vec<PolicyRecord>) -> Self {
        Self { records }
    }
}

#[cfg(test)]
#[async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn load_all(&self) -> PolicyResult<Vec<PolicyRecord>> {
        Ok(self.records.clone())
    }
}

#[cfg(test)]
pub fn test_record(id: Uuid, name: &str, text: &str, priority: i32) -> PolicyRecord {
    PolicyRecord {
        id,
        name: name.into(),
        description: None,
        policy_text: text.into(),
        active: true,
        priority,
        company_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}
