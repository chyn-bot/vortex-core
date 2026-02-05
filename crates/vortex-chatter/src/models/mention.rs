//! Chatter mention model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use vortex_common::{VortexError, VortexResult};
use vortex_orm::ConnectionPool;

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// A @mention linking a message to a user.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterMention {
    pub id: Uuid,
    pub message_id: Uuid,
    pub user_id: Uuid,
    pub notified: bool,
    pub notified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ChatterMention {
    /// Create a mention record.
    pub async fn create(pool: &ConnectionPool, message_id: Uuid, user_id: Uuid) -> VortexResult<Self> {
        let id = Uuid::now_v7();

        let mention = sqlx::query_as::<_, ChatterMention>(
            r#"
            INSERT INTO chatter_mentions (id, message_id, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (message_id, user_id) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(message_id)
        .bind(user_id)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(mention)
    }

    /// Find mentions for a message.
    pub async fn find_for_message(pool: &ConnectionPool, message_id: Uuid) -> VortexResult<Vec<Self>> {
        let mentions = sqlx::query_as::<_, ChatterMention>(
            "SELECT * FROM chatter_mentions WHERE message_id = $1 ORDER BY created_at",
        )
        .bind(message_id)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(mentions)
    }

    /// Mark mention as notified.
    pub async fn mark_notified(&mut self, pool: &ConnectionPool) -> VortexResult<()> {
        sqlx::query("UPDATE chatter_mentions SET notified = true, notified_at = NOW() WHERE id = $1")
            .bind(self.id)
            .execute(pool.pool())
            .await.map_err(map_db_err)?;

        self.notified = true;
        Ok(())
    }

    /// Get unnotified mentions for a user.
    pub async fn find_unnotified_for_user(pool: &ConnectionPool, user_id: Uuid) -> VortexResult<Vec<Self>> {
        let mentions = sqlx::query_as::<_, ChatterMention>(
            r#"
            SELECT * FROM chatter_mentions
            WHERE user_id = $1 AND notified = false
            ORDER BY created_at
            "#,
        )
        .bind(user_id)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(mentions)
    }
}
