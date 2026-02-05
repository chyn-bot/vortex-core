//! Chatter notification model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use vortex_common::{VortexError, VortexResult};
use vortex_orm::ConnectionPool;

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// An in-app notification for a user.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterNotification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub message_id: Option<Uuid>,
    pub activity_id: Option<Uuid>,
    pub notification_type: String,
    pub title: String,
    pub body: Option<String>,
    pub res_model: String,
    pub res_id: Uuid,
    pub is_read: bool,
    pub read_at: Option<DateTime<Utc>>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

impl ChatterNotification {
    /// Create a notification.
    pub async fn create(
        pool: &ConnectionPool,
        user_id: Uuid,
        notification_type: &str,
        message_id: Option<Uuid>,
        activity_id: Option<Uuid>,
        res_model: &str,
        res_id: Uuid,
        title: &str,
        body: Option<&str>,
        company_id: Uuid,
    ) -> VortexResult<Self> {
        let id = Uuid::now_v7();

        let notification = sqlx::query_as::<_, ChatterNotification>(
            r#"
            INSERT INTO chatter_notifications
                (id, user_id, message_id, activity_id, notification_type, title, body,
                 res_model, res_id, company_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(message_id)
        .bind(activity_id)
        .bind(notification_type)
        .bind(title)
        .bind(body)
        .bind(res_model)
        .bind(res_id)
        .bind(company_id)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(notification)
    }

    /// Find unread notifications for a user.
    pub async fn find_unread(pool: &ConnectionPool, user_id: Uuid, limit: u64) -> VortexResult<Vec<Self>> {
        let notifications = sqlx::query_as::<_, ChatterNotification>(
            r#"
            SELECT * FROM chatter_notifications
            WHERE user_id = $1 AND is_read = false AND active = true
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit as i64)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(notifications)
    }

    /// Count unread notifications for a user.
    pub async fn count_unread(pool: &ConnectionPool, user_id: Uuid) -> VortexResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM chatter_notifications WHERE user_id = $1 AND is_read = false AND active = true",
        )
        .bind(user_id)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(row.0)
    }

    /// Mark notifications as read.
    pub async fn mark_read(pool: &ConnectionPool, notification_ids: &[Uuid]) -> VortexResult<()> {
        if notification_ids.is_empty() {
            return Ok(());
        }

        sqlx::query(
            r#"
            UPDATE chatter_notifications
            SET is_read = true, read_at = NOW()
            WHERE id = ANY($1)
            "#,
        )
        .bind(notification_ids)
        .execute(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(())
    }

    /// Mark all notifications as read for a user.
    pub async fn mark_all_read(pool: &ConnectionPool, user_id: Uuid) -> VortexResult<()> {
        sqlx::query(
            r#"
            UPDATE chatter_notifications
            SET is_read = true, read_at = NOW()
            WHERE user_id = $1 AND is_read = false
            "#,
        )
        .bind(user_id)
        .execute(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(())
    }

    /// Get all notifications for a user (paginated).
    pub async fn find_for_user(
        pool: &ConnectionPool,
        user_id: Uuid,
        limit: u64,
        offset: u64,
    ) -> VortexResult<Vec<Self>> {
        let notifications = sqlx::query_as::<_, ChatterNotification>(
            r#"
            SELECT * FROM chatter_notifications
            WHERE user_id = $1 AND active = true
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(notifications)
    }
}
