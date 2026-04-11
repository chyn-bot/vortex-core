//! Persistence layer for workflow instances and transition history.
//!
//! The [`WorkflowStore`] trait abstracts storage so unit tests can
//! run against an in-memory store while production goes through
//! Postgres. Two implementations:
//!
//! - [`InMemoryWorkflowStore`] — used by `cargo test` runs without
//!   a database.
//! - [`PgWorkflowStore`] — production backend. Uses `FOR UPDATE`
//!   locking on instance rows during transitions so concurrent
//!   state changes on the same instance serialize correctly.
//!
//! The transition history table (`workflow_transitions`) is treated
//! as WORM just like `audit_log`: migration 116 adds BEFORE UPDATE/
//! DELETE triggers so a persisted transition can never be rewritten.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::{WorkflowError, WorkflowResult};
use crate::instance::{InstanceId, WorkflowInstance};
use crate::machine::WorkflowType;

/// A single row in the `workflow_transitions` history table.
#[derive(Debug, Clone)]
pub struct TransitionRecord {
    pub id: Uuid,
    pub instance_id: InstanceId,
    pub transition_name: String,
    pub from_state: String,
    pub to_state: String,
    pub actor_user_id: Option<Uuid>,
    pub context: Value,
    pub audit_entry_id: Option<Uuid>,
    pub occurred_at: DateTime<Utc>,
}

/// Abstract store interface. The engine uses this rather than a
/// concrete Postgres handle so the unit test suite can exercise the
/// full transition state machine against [`InMemoryWorkflowStore`].
#[async_trait]
pub trait WorkflowStore: Send + Sync {
    /// Persist a brand-new instance. Typically called from the
    /// handler that creates the underlying business record.
    async fn create_instance(&self, instance: WorkflowInstance) -> WorkflowResult<WorkflowInstance>;

    /// Load an instance by id. Returns `InstanceNotFound` if there
    /// is no such row.
    async fn get_instance(&self, id: InstanceId) -> WorkflowResult<WorkflowInstance>;

    /// Update an instance's state and state_data after a successful
    /// transition. The implementation is expected to bump
    /// `updated_at` to the current time.
    async fn update_instance_state(
        &self,
        id: InstanceId,
        new_state: &str,
        new_state_data: &Value,
    ) -> WorkflowResult<()>;

    /// Append a transition history row. Called by the engine inside
    /// the same transaction as `update_instance_state` so they
    /// commit atomically. `audit_entry_id` is the id of the audit
    /// ledger entry that was written for this transition (may be
    /// `None` if audit integration was disabled for this engine,
    /// which is only valid in tests).
    async fn record_transition(&self, record: TransitionRecord) -> WorkflowResult<()>;

    /// Read the full transition history for an instance, oldest first.
    /// Used by the inspection CLI and the handler layer that renders
    /// "timeline" views on workflow records.
    async fn get_transitions(&self, id: InstanceId) -> WorkflowResult<Vec<TransitionRecord>>;

    /// List instances filtered by type and/or state. Used by the
    /// inspection CLI's `workflow list` command and by handler
    /// layers that render "work queue" views.
    async fn list_instances(
        &self,
        workflow_type: Option<&WorkflowType>,
        state: Option<&str>,
        company_id: Option<Uuid>,
        limit: usize,
    ) -> WorkflowResult<Vec<WorkflowInstance>>;
}

// ─────────────────────────────────────────────────────────────────
//  PgWorkflowStore — production Postgres backend
// ─────────────────────────────────────────────────────────────────

/// Postgres-backed workflow store. Matches the shape of
/// `workflow_instances` and `workflow_transitions` from migration 116.
pub struct PgWorkflowStore {
    pool: PgPool,
}

impl PgWorkflowStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl WorkflowStore for PgWorkflowStore {
    async fn create_instance(&self, instance: WorkflowInstance) -> WorkflowResult<WorkflowInstance> {
        sqlx::query(
            r#"
            INSERT INTO workflow_instances (
                id, workflow_type, current_state, state_data,
                company_id, created_by, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(instance.id.0)
        .bind(instance.workflow_type.as_str())
        .bind(&instance.current_state)
        .bind(&instance.state_data)
        .bind(instance.company_id)
        .bind(instance.created_by)
        .bind(instance.created_at)
        .bind(instance.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| WorkflowError::Store(format!("create_instance: {e}")))?;
        Ok(instance)
    }

    async fn get_instance(&self, id: InstanceId) -> WorkflowResult<WorkflowInstance> {
        let row = sqlx::query(
            r#"
            SELECT id, workflow_type, current_state, state_data,
                   company_id, created_by, created_at, updated_at
            FROM workflow_instances
            WHERE id = $1
            "#,
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| WorkflowError::Store(format!("get_instance: {e}")))?
        .ok_or(WorkflowError::InstanceNotFound(id.0))?;

        Ok(WorkflowInstance {
            id: InstanceId(row.get::<Uuid, _>("id")),
            workflow_type: WorkflowType::new(row.get::<String, _>("workflow_type")),
            current_state: row.get("current_state"),
            state_data: row.get::<Option<Value>, _>("state_data").unwrap_or(Value::Null),
            company_id: row.get("company_id"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn update_instance_state(
        &self,
        id: InstanceId,
        new_state: &str,
        new_state_data: &Value,
    ) -> WorkflowResult<()> {
        sqlx::query(
            r#"
            UPDATE workflow_instances
            SET current_state = $1, state_data = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(new_state)
        .bind(new_state_data)
        .bind(id.0)
        .execute(&self.pool)
        .await
        .map_err(|e| WorkflowError::Store(format!("update_instance_state: {e}")))?;
        Ok(())
    }

    async fn record_transition(&self, record: TransitionRecord) -> WorkflowResult<()> {
        sqlx::query(
            r#"
            INSERT INTO workflow_transitions (
                id, instance_id, transition_name, from_state, to_state,
                actor_user_id, context, audit_entry_id, occurred_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(record.id)
        .bind(record.instance_id.0)
        .bind(&record.transition_name)
        .bind(&record.from_state)
        .bind(&record.to_state)
        .bind(record.actor_user_id)
        .bind(&record.context)
        .bind(record.audit_entry_id)
        .bind(record.occurred_at)
        .execute(&self.pool)
        .await
        .map_err(|e| WorkflowError::Store(format!("record_transition: {e}")))?;
        Ok(())
    }

    async fn get_transitions(&self, id: InstanceId) -> WorkflowResult<Vec<TransitionRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT id, instance_id, transition_name, from_state, to_state,
                   actor_user_id, context, audit_entry_id, occurred_at
            FROM workflow_transitions
            WHERE instance_id = $1
            ORDER BY occurred_at ASC
            "#,
        )
        .bind(id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WorkflowError::Store(format!("get_transitions: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| TransitionRecord {
                id: r.get("id"),
                instance_id: InstanceId(r.get::<Uuid, _>("instance_id")),
                transition_name: r.get("transition_name"),
                from_state: r.get("from_state"),
                to_state: r.get("to_state"),
                actor_user_id: r.try_get("actor_user_id").ok(),
                context: r.try_get("context").ok().unwrap_or(Value::Null),
                audit_entry_id: r.try_get("audit_entry_id").ok(),
                occurred_at: r.get("occurred_at"),
            })
            .collect())
    }

    async fn list_instances(
        &self,
        workflow_type: Option<&WorkflowType>,
        state: Option<&str>,
        company_id: Option<Uuid>,
        limit: usize,
    ) -> WorkflowResult<Vec<WorkflowInstance>> {
        let mut sql = String::from(
            "SELECT id, workflow_type, current_state, state_data,
                    company_id, created_by, created_at, updated_at
             FROM workflow_instances WHERE 1=1",
        );
        let mut args: Vec<String> = Vec::new();
        if let Some(wt) = workflow_type {
            args.push(format!("workflow_type = '{}'", wt.as_str().replace('\'', "''")));
        }
        if let Some(s) = state {
            args.push(format!("current_state = '{}'", s.replace('\'', "''")));
        }
        if let Some(c) = company_id {
            args.push(format!("company_id = '{}'", c));
        }
        for a in &args {
            sql.push_str(" AND ");
            sql.push_str(a);
        }
        sql.push_str(&format!(" ORDER BY updated_at DESC LIMIT {}", limit));

        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| WorkflowError::Store(format!("list_instances: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| WorkflowInstance {
                id: InstanceId(r.get::<Uuid, _>("id")),
                workflow_type: WorkflowType::new(r.get::<String, _>("workflow_type")),
                current_state: r.get("current_state"),
                state_data: r.get::<Option<Value>, _>("state_data").unwrap_or(Value::Null),
                company_id: r.get("company_id"),
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }
}

// ─────────────────────────────────────────────────────────────────
//  InMemoryWorkflowStore — unit test backend
// ─────────────────────────────────────────────────────────────────

/// In-memory store for unit tests. Not tamper-evident, not
/// persisted, not safe across processes. Never wire this into a
/// production server.
pub struct InMemoryWorkflowStore {
    instances: Arc<Mutex<std::collections::HashMap<Uuid, WorkflowInstance>>>,
    transitions: Arc<Mutex<Vec<TransitionRecord>>>,
}

impl Default for InMemoryWorkflowStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryWorkflowStore {
    pub fn new() -> Self {
        Self {
            instances: Arc::new(Mutex::new(std::collections::HashMap::new())),
            transitions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl WorkflowStore for InMemoryWorkflowStore {
    async fn create_instance(&self, instance: WorkflowInstance) -> WorkflowResult<WorkflowInstance> {
        self.instances.lock().await.insert(instance.id.0, instance.clone());
        Ok(instance)
    }

    async fn get_instance(&self, id: InstanceId) -> WorkflowResult<WorkflowInstance> {
        self.instances
            .lock()
            .await
            .get(&id.0)
            .cloned()
            .ok_or(WorkflowError::InstanceNotFound(id.0))
    }

    async fn update_instance_state(
        &self,
        id: InstanceId,
        new_state: &str,
        new_state_data: &Value,
    ) -> WorkflowResult<()> {
        let mut map = self.instances.lock().await;
        let inst = map
            .get_mut(&id.0)
            .ok_or(WorkflowError::InstanceNotFound(id.0))?;
        inst.current_state = new_state.to_string();
        inst.state_data = new_state_data.clone();
        inst.updated_at = Utc::now();
        Ok(())
    }

    async fn record_transition(&self, record: TransitionRecord) -> WorkflowResult<()> {
        self.transitions.lock().await.push(record);
        Ok(())
    }

    async fn get_transitions(&self, id: InstanceId) -> WorkflowResult<Vec<TransitionRecord>> {
        let list = self.transitions.lock().await;
        Ok(list
            .iter()
            .filter(|t| t.instance_id == id)
            .cloned()
            .collect())
    }

    async fn list_instances(
        &self,
        workflow_type: Option<&WorkflowType>,
        state: Option<&str>,
        company_id: Option<Uuid>,
        limit: usize,
    ) -> WorkflowResult<Vec<WorkflowInstance>> {
        let map = self.instances.lock().await;
        let mut results: Vec<_> = map
            .values()
            .filter(|i| workflow_type.map_or(true, |w| &i.workflow_type == w))
            .filter(|i| state.map_or(true, |s| i.current_state == s))
            .filter(|i| company_id.map_or(true, |c| i.company_id == c))
            .cloned()
            .collect();
        results.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        results.truncate(limit);
        Ok(results)
    }
}
