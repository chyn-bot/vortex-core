//! Chatter message model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use vortex_common::{Context, VortexError, VortexResult};
use vortex_orm::ConnectionPool;

/// Helper to map sqlx errors to VortexError
fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// A message or note posted on a record.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterMessage {
    pub id: Uuid,
    pub res_model: String,
    pub res_id: Uuid,
    pub message_type: String,
    pub subtype: Option<String>,
    pub subject: Option<String>,
    pub body: String,
    pub body_format: String,
    pub author_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub is_internal: bool,
    pub starred: bool,
    pub pinned: bool,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub active: bool,
}

impl ChatterMessage {
    /// Create a new message on a record.
    pub async fn create(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        body: &str,
        message_type: &str,
        is_internal: bool,
    ) -> VortexResult<Self> {
        let user_id = ctx.require_user()?;
        let company_id = ctx.require_company()?;
        let id = Uuid::now_v7();

        let message = sqlx::query_as::<_, ChatterMessage>(
            r#"
            INSERT INTO chatter_messages
                (id, res_model, res_id, message_type, body, body_format, author_id,
                 is_internal, company_id, created_by)
            VALUES ($1, $2, $3, $4, $5, 'html', $6, $7, $8, $6)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(res_model)
        .bind(res_id)
        .bind(message_type)
        .bind(body)
        .bind(user_id.0)
        .bind(is_internal)
        .bind(company_id.0)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(message)
    }

    /// Find messages for a specific record.
    pub async fn find_for_record(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        include_internal: bool,
        limit: u64,
        offset: u64,
    ) -> VortexResult<Vec<Self>> {
        let company_id = ctx.require_company()?;

        let messages = if include_internal {
            sqlx::query_as::<_, ChatterMessage>(
                r#"
                SELECT * FROM chatter_messages
                WHERE res_model = $1 AND res_id = $2 AND company_id = $3 AND active = true
                ORDER BY created_at DESC
                LIMIT $4 OFFSET $5
                "#,
            )
            .bind(res_model)
            .bind(res_id)
            .bind(company_id.0)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(pool.pool())
            .await.map_err(map_db_err)?
        } else {
            sqlx::query_as::<_, ChatterMessage>(
                r#"
                SELECT * FROM chatter_messages
                WHERE res_model = $1 AND res_id = $2 AND company_id = $3
                      AND active = true AND is_internal = false
                ORDER BY created_at DESC
                LIMIT $4 OFFSET $5
                "#,
            )
            .bind(res_model)
            .bind(res_id)
            .bind(company_id.0)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(pool.pool())
            .await.map_err(map_db_err)?
        };

        Ok(messages)
    }

    /// Find a message by ID.
    pub async fn find(pool: &ConnectionPool, id: Uuid) -> VortexResult<Option<Self>> {
        let message = sqlx::query_as::<_, ChatterMessage>(
            "SELECT * FROM chatter_messages WHERE id = $1 AND active = true",
        )
        .bind(id)
        .fetch_optional(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(message)
    }

    /// Soft delete a message.
    pub async fn delete(&self, pool: &ConnectionPool, ctx: &Context) -> VortexResult<()> {
        let user_id = ctx.require_user()?;

        sqlx::query(
            r#"
            UPDATE chatter_messages
            SET active = false, deleted_at = NOW(), deleted_by = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(user_id.0)
        .bind(self.id)
        .execute(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(())
    }

    /// Toggle starred status.
    pub async fn toggle_star(&mut self, pool: &ConnectionPool) -> VortexResult<()> {
        self.starred = !self.starred;

        sqlx::query("UPDATE chatter_messages SET starred = $1, updated_at = NOW() WHERE id = $2")
            .bind(self.starred)
            .bind(self.id)
            .execute(pool.pool())
            .await.map_err(map_db_err)?;

        Ok(())
    }

    /// Get reply count for this message.
    pub async fn reply_count(&self, pool: &ConnectionPool) -> VortexResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chatter_messages WHERE parent_id = $1 AND active = true",
        )
        .bind(self.id)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(row.0)
    }
}
