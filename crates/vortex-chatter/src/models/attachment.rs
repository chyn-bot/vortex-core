//! Chatter attachment model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use vortex_common::{Context, VortexError, VortexResult};
use vortex_orm::ConnectionPool;

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// A file attachment on a message or record.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterAttachment {
    pub id: Uuid,
    pub message_id: Option<Uuid>,
    pub res_model: Option<String>,
    pub res_id: Option<Uuid>,
    pub name: String,
    pub file_name: String,
    pub file_path: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub checksum: Option<String>,
    pub description: Option<String>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub active: bool,
}

impl ChatterAttachment {
    /// Create an attachment on a message.
    pub async fn create_for_message(
        pool: &ConnectionPool,
        ctx: &Context,
        message_id: Uuid,
        file_name: &str,
        file_path: &str,
        file_size: i64,
        mime_type: Option<&str>,
    ) -> VortexResult<Self> {
        let user_id = ctx.require_user()?;
        let company_id = ctx.require_company()?;
        let id = Uuid::now_v7();

        let attachment = sqlx::query_as::<_, ChatterAttachment>(
            r#"
            INSERT INTO chatter_attachments
                (id, message_id, name, file_name, file_path, file_size, mime_type, company_id, created_by)
            VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(message_id)
        .bind(file_name)
        .bind(file_path)
        .bind(file_size)
        .bind(mime_type)
        .bind(company_id.0)
        .bind(user_id.0)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(attachment)
    }

    /// Create an attachment directly on a record.
    pub async fn create_for_record(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        file_name: &str,
        file_path: &str,
        file_size: i64,
        mime_type: Option<&str>,
    ) -> VortexResult<Self> {
        let user_id = ctx.require_user()?;
        let company_id = ctx.require_company()?;
        let id = Uuid::now_v7();

        let attachment = sqlx::query_as::<_, ChatterAttachment>(
            r#"
            INSERT INTO chatter_attachments
                (id, res_model, res_id, name, file_name, file_path, file_size, mime_type, company_id, created_by)
            VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(res_model)
        .bind(res_id)
        .bind(file_name)
        .bind(file_path)
        .bind(file_size)
        .bind(mime_type)
        .bind(company_id.0)
        .bind(user_id.0)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(attachment)
    }

    /// Find attachments for a record (including those on messages).
    pub async fn find_for_record(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
    ) -> VortexResult<Vec<Self>> {
        let company_id = ctx.require_company()?;

        // Get direct attachments and attachments on messages for this record
        let attachments = sqlx::query_as::<_, ChatterAttachment>(
            r#"
            SELECT a.* FROM chatter_attachments a
            WHERE a.company_id = $1 AND a.active = true
              AND (
                  (a.res_model = $2 AND a.res_id = $3)
                  OR a.message_id IN (
                      SELECT id FROM chatter_messages
                      WHERE res_model = $2 AND res_id = $3 AND active = true
                  )
              )
            ORDER BY a.created_at DESC
            "#,
        )
        .bind(company_id.0)
        .bind(res_model)
        .bind(res_id)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(attachments)
    }

    /// Find attachments for a specific message.
    pub async fn find_for_message(pool: &ConnectionPool, message_id: Uuid) -> VortexResult<Vec<Self>> {
        let attachments = sqlx::query_as::<_, ChatterAttachment>(
            "SELECT * FROM chatter_attachments WHERE message_id = $1 AND active = true ORDER BY created_at",
        )
        .bind(message_id)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(attachments)
    }

    /// Soft delete an attachment.
    pub async fn delete(&self, pool: &ConnectionPool) -> VortexResult<()> {
        sqlx::query("UPDATE chatter_attachments SET active = false WHERE id = $1")
            .bind(self.id)
            .execute(pool.pool())
            .await.map_err(map_db_err)?;

        Ok(())
    }
}
