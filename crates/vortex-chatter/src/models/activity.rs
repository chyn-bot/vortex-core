//! Chatter activity models

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use vortex_common::{Context, VortexError, VortexResult};
use vortex_orm::ConnectionPool;

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// A scheduled activity/reminder on a record.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterActivity {
    pub id: Uuid,
    pub res_model: String,
    pub res_id: Uuid,
    pub activity_type_id: Uuid,
    pub summary: Option<String>,
    pub note: Option<String>,
    pub due_date: NaiveDate,
    pub due_time: Option<NaiveTime>,
    pub assigned_to_id: Uuid,
    pub assigned_by_id: Uuid,
    pub state: String,
    pub completed_at: Option<DateTime<Utc>>,
    pub completed_by: Option<Uuid>,
    pub feedback: Option<String>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub active: bool,
}

/// Activity type configuration.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChatterActivityType {
    pub id: Uuid,
    pub name: String,
    pub summary: Option<String>,
    pub icon: String,
    pub color: String,
    pub default_days: i32,
    pub res_model: Option<String>,
    pub sequence: i32,
    pub company_id: Option<Uuid>,
    pub active: bool,
}

impl ChatterActivity {
    /// Create a new activity.
    pub async fn create(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        activity_type_id: Uuid,
        summary: Option<&str>,
        note: Option<&str>,
        due_date: NaiveDate,
        assigned_to_id: Uuid,
    ) -> VortexResult<Self> {
        let user_id = ctx.require_user()?;
        let company_id = ctx.require_company()?;
        let id = Uuid::now_v7();

        let activity = sqlx::query_as::<_, ChatterActivity>(
            r#"
            INSERT INTO chatter_activities
                (id, res_model, res_id, activity_type_id, summary, note, due_date,
                 assigned_to_id, assigned_by_id, company_id, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(res_model)
        .bind(res_id)
        .bind(activity_type_id)
        .bind(summary)
        .bind(note)
        .bind(due_date)
        .bind(assigned_to_id)
        .bind(user_id.0)
        .bind(company_id.0)
        .fetch_one(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(activity)
    }

    /// Find activities for a specific record.
    pub async fn find_for_record(
        pool: &ConnectionPool,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        include_completed: bool,
    ) -> VortexResult<Vec<Self>> {
        let company_id = ctx.require_company()?;

        let activities = if include_completed {
            sqlx::query_as::<_, ChatterActivity>(
                r#"
                SELECT * FROM chatter_activities
                WHERE res_model = $1 AND res_id = $2 AND company_id = $3 AND active = true
                ORDER BY due_date ASC, created_at ASC
                "#,
            )
            .bind(res_model)
            .bind(res_id)
            .bind(company_id.0)
            .fetch_all(pool.pool())
            .await.map_err(map_db_err)?
        } else {
            sqlx::query_as::<_, ChatterActivity>(
                r#"
                SELECT * FROM chatter_activities
                WHERE res_model = $1 AND res_id = $2 AND company_id = $3
                      AND active = true AND state = 'pending'
                ORDER BY due_date ASC, created_at ASC
                "#,
            )
            .bind(res_model)
            .bind(res_id)
            .bind(company_id.0)
            .fetch_all(pool.pool())
            .await.map_err(map_db_err)?
        };

        Ok(activities)
    }

    /// Find activities assigned to a user.
    pub async fn find_for_user(
        pool: &ConnectionPool,
        ctx: &Context,
        user_id: Uuid,
        include_completed: bool,
    ) -> VortexResult<Vec<Self>> {
        let company_id = ctx.require_company()?;

        let activities = if include_completed {
            sqlx::query_as::<_, ChatterActivity>(
                r#"
                SELECT * FROM chatter_activities
                WHERE assigned_to_id = $1 AND company_id = $2 AND active = true
                ORDER BY due_date ASC, created_at ASC
                "#,
            )
            .bind(user_id)
            .bind(company_id.0)
            .fetch_all(pool.pool())
            .await.map_err(map_db_err)?
        } else {
            sqlx::query_as::<_, ChatterActivity>(
                r#"
                SELECT * FROM chatter_activities
                WHERE assigned_to_id = $1 AND company_id = $2
                      AND active = true AND state IN ('pending', 'overdue')
                ORDER BY due_date ASC, created_at ASC
                "#,
            )
            .bind(user_id)
            .bind(company_id.0)
            .fetch_all(pool.pool())
            .await.map_err(map_db_err)?
        };

        Ok(activities)
    }

    /// Find an activity by ID.
    pub async fn find(
        pool: &ConnectionPool,
        ctx: &Context,
        id: Uuid,
    ) -> VortexResult<Option<Self>> {
        let company_id = ctx.require_company()?;

        let activity = sqlx::query_as::<_, ChatterActivity>(
            "SELECT * FROM chatter_activities WHERE id = $1 AND company_id = $2 AND active = true",
        )
        .bind(id)
        .bind(company_id.0)
        .fetch_optional(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(activity)
    }

    /// Mark activity as completed.
    pub async fn complete(
        &mut self,
        pool: &ConnectionPool,
        ctx: &Context,
        feedback: Option<&str>,
    ) -> VortexResult<()> {
        let user_id = ctx.require_user()?;

        sqlx::query(
            r#"
            UPDATE chatter_activities
            SET state = 'completed', completed_at = NOW(), completed_by = $1,
                feedback = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(user_id.0)
        .bind(feedback)
        .bind(self.id)
        .execute(pool.pool())
        .await.map_err(map_db_err)?;

        self.state = "completed".to_string();
        self.completed_by = Some(user_id.0);
        self.feedback = feedback.map(String::from);

        Ok(())
    }

    /// Cancel an activity.
    pub async fn cancel(&mut self, pool: &ConnectionPool) -> VortexResult<()> {
        sqlx::query(
            "UPDATE chatter_activities SET state = 'cancelled', updated_at = NOW() WHERE id = $1",
        )
        .bind(self.id)
        .execute(pool.pool())
        .await.map_err(map_db_err)?;

        self.state = "cancelled".to_string();
        Ok(())
    }
}

impl ChatterActivityType {
    /// Get all active activity types.
    pub async fn all(pool: &ConnectionPool) -> VortexResult<Vec<Self>> {
        let types = sqlx::query_as::<_, ChatterActivityType>(
            "SELECT * FROM chatter_activity_types WHERE active = true ORDER BY sequence, name",
        )
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(types)
    }

    /// Get activity types for a specific model.
    pub async fn for_model(pool: &ConnectionPool, res_model: &str) -> VortexResult<Vec<Self>> {
        let types = sqlx::query_as::<_, ChatterActivityType>(
            r#"
            SELECT * FROM chatter_activity_types
            WHERE active = true AND (res_model IS NULL OR res_model = $1)
            ORDER BY sequence, name
            "#,
        )
        .bind(res_model)
        .fetch_all(pool.pool())
        .await.map_err(map_db_err)?;

        Ok(types)
    }
}
