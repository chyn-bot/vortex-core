//! Chatter follower model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use vortex_common::{Context, VortexError, VortexResult};
use vortex_orm::ConnectionPool;

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// A follower subscription to a record.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterFollower {
    pub id: Uuid,
    pub res_model: String,
    pub res_id: Uuid,
    pub user_id: Uuid,
    pub subtype_ids: serde_json::Value,
    pub reason: Option<String>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

impl ChatterFollower {
    /// Add a follower to a record.
    pub async fn add(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        user_id: Uuid,
        reason: Option<&str>,
    ) -> VortexResult<Self> {
        let company_id = ctx.require_company()?;
        let id = Uuid::now_v7();

        // Use ON CONFLICT to handle re-following
        let follower = sqlx::query_as::<_, ChatterFollower>(
            r#"
            INSERT INTO chatter_followers (id, res_model, res_id, user_id, reason, company_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (res_model, res_id, user_id)
            DO UPDATE SET active = true, reason = COALESCE($5, chatter_followers.reason)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(res_model)
        .bind(res_id)
        .bind(user_id)
        .bind(reason)
        .bind(company_id.0)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(follower)
    }

    /// Remove a follower from a record.
    pub async fn remove(
        pool: &ConnectionPool,
        res_model: &str,
        res_id: Uuid,
        user_id: Uuid,
    ) -> VortexResult<()> {
        sqlx::query(
            "UPDATE chatter_followers SET active = false WHERE res_model = $1 AND res_id = $2 AND user_id = $3",
        )
        .bind(res_model)
        .bind(res_id)
        .bind(user_id)
        .execute(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(())
    }

    /// Check if a user follows a record.
    pub async fn exists(
        pool: &ConnectionPool,
        res_model: &str,
        res_id: Uuid,
        user_id: Uuid,
    ) -> VortexResult<bool> {
        let row: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM chatter_followers
                WHERE res_model = $1 AND res_id = $2 AND user_id = $3 AND active = true
            )
            "#,
        )
        .bind(res_model)
        .bind(res_id)
        .bind(user_id)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(row.0)
    }

    /// Get all followers for a record.
    pub async fn find_for_record(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
    ) -> VortexResult<Vec<Self>> {
        let company_id = ctx.require_company()?;

        let followers = sqlx::query_as::<_, ChatterFollower>(
            r#"
            SELECT * FROM chatter_followers
            WHERE res_model = $1 AND res_id = $2 AND company_id = $3 AND active = true
            ORDER BY created_at
            "#,
        )
        .bind(res_model)
        .bind(res_id)
        .bind(company_id.0)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(followers)
    }

    /// Get all records a user follows.
    pub async fn find_for_user(
        pool: &ConnectionPool,
        ctx: &Context,
        user_id: Uuid,
    ) -> VortexResult<Vec<Self>> {
        let company_id = ctx.require_company()?;

        let followers = sqlx::query_as::<_, ChatterFollower>(
            r#"
            SELECT * FROM chatter_followers
            WHERE user_id = $1 AND company_id = $2 AND active = true
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(company_id.0)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(followers)
    }

    /// Count followers for a record.
    pub async fn count_for_record(
        pool: &ConnectionPool,
        res_model: &str,
        res_id: Uuid,
    ) -> VortexResult<i64> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM chatter_followers
            WHERE res_model = $1 AND res_id = $2 AND active = true
            "#,
        )
        .bind(res_model)
        .bind(res_id)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(row.0)
    }
}
