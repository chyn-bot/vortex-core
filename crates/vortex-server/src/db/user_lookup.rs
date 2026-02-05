//! Database-backed user lookup implementation

use chrono::Utc;
use sqlx::Row;
use std::sync::Arc;
use vortex_common::{CompanyId, UserId, VortexError, VortexResult};
use vortex_orm::prelude::*;
use uuid::Uuid;
use vortex_security::auth::{UserAuth, UserLookup};

/// Database-backed user lookup
pub struct DbUserLookup {
    pool: Arc<ConnectionPool>,
}

impl DbUserLookup {
    /// Create a new database user lookup
    pub fn new(pool: Arc<ConnectionPool>) -> Self {
        Self { pool }
    }

    /// Get the dialect for SQL generation
    fn dialect(&self) -> &dyn SqlDialect {
        self.pool.dialect()
    }
}

#[async_trait::async_trait]
impl UserLookup for DbUserLookup {
    async fn find_by_username(&self, username: &str) -> VortexResult<Option<UserAuth>> {
        let dialect = self.dialect();

        // Build dialect-aware query for role aggregation
        let (roles_subquery, empty_array) = match dialect.backend() {
            DatabaseBackend::Postgres => (
                format!(
                    "(SELECT array_agg(r.name)
                     FROM user_roles ur
                     JOIN roles r ON r.id = ur.role_id
                     WHERE ur.user_id = u.id)"
                ),
                "ARRAY[]::text[]".to_string(),
            ),
            #[cfg(feature = "mssql")]
            DatabaseBackend::MsSql => (
                format!(
                    "(SELECT STRING_AGG(r.name, ',')
                     FROM user_roles ur
                     JOIN roles r ON r.id = ur.role_id
                     WHERE ur.user_id = u.id)"
                ),
                "''".to_string(),
            ),
        };

        let query = format!(
            r#"
            SELECT
                u.id,
                u.username,
                u.password_hash,
                u.password_changed_at,
                u.failed_login_attempts,
                u.locked_until,
                u.mfa_enabled,
                u.mfa_secret,
                u.active,
                u.company_id,
                COALESCE({}, {}) as roles
            FROM users u
            WHERE u.username = {}
            "#,
            roles_subquery,
            empty_array,
            dialect.param_placeholder(1)
        );

        // Execute based on backend
        match dialect.backend() {
            DatabaseBackend::Postgres => {
                let row = sqlx::query(&query)
                    .bind(username)
                    .fetch_optional(self.pool.pool())
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

                let Some(row) = row else {
                    return Ok(None);
                };

                let user_id: Uuid = row.get("id");
                let company_id: Option<Uuid> = row.get("company_id");

                Ok(Some(UserAuth {
                    user_id: UserId(user_id),
                    username: row.get("username"),
                    password_hash: row.get("password_hash"),
                    password_changed_at: row.get("password_changed_at"),
                    failed_attempts: row.get::<i32, _>("failed_login_attempts") as u32,
                    locked_until: row.get("locked_until"),
                    mfa_enabled: row.get("mfa_enabled"),
                    mfa_secret: row.get("mfa_secret"),
                    active: row.get("active"),
                    company_id: company_id.map(CompanyId),
                }))
            }
            #[cfg(feature = "mssql")]
            DatabaseBackend::MsSql => {
                let pool = self.pool.mssql_pool().ok_or_else(|| {
                    VortexError::QueryExecution("MSSQL pool not available".to_string())
                })?;

                let row = sqlx::query(&query)
                    .bind(username)
                    .fetch_optional(pool)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

                let Some(row) = row else {
                    return Ok(None);
                };

                let user_id: Uuid = row.get("id");
                let company_id: Option<Uuid> = row.get("company_id");

                Ok(Some(UserAuth {
                    user_id: UserId(user_id),
                    username: row.get("username"),
                    password_hash: row.get("password_hash"),
                    password_changed_at: row.get("password_changed_at"),
                    failed_attempts: row.get::<i32, _>("failed_login_attempts") as u32,
                    locked_until: row.get("locked_until"),
                    mfa_enabled: row.get("mfa_enabled"),
                    mfa_secret: row.get("mfa_secret"),
                    active: row.get("active"),
                    company_id: company_id.map(CompanyId),
                }))
            }
        }
    }

    async fn update_auth(&self, auth: &UserAuth) -> VortexResult<()> {
        let dialect = self.dialect();

        let query = format!(
            r#"
            UPDATE users
            SET
                failed_login_attempts = {},
                locked_until = {},
                password_changed_at = {}
            WHERE id = {}
            "#,
            dialect.param_placeholder(1),
            dialect.param_placeholder(2),
            dialect.param_placeholder(3),
            dialect.param_placeholder(4),
        );

        sqlx::query(&query)
            .bind(auth.failed_attempts as i32)
            .bind(auth.locked_until)
            .bind(auth.password_changed_at)
            .bind(auth.user_id.0)
            .execute(self.pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(())
    }

    async fn get_password_history(&self, user_id: UserId) -> VortexResult<Vec<String>> {
        let dialect = self.dialect();

        let query = format!(
            r#"
            SELECT password_hash
            FROM password_history
            WHERE user_id = {}
            ORDER BY created_at DESC
            {}
            "#,
            dialect.param_placeholder(1),
            dialect.pagination_sql(12, 0),
        );

        let rows = sqlx::query(&query)
            .bind(user_id.0)
            .fetch_all(self.pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows.iter().map(|r| r.get("password_hash")).collect())
    }

    async fn add_password_history(&self, user_id: UserId, hash: &str) -> VortexResult<()> {
        let dialect = self.dialect();

        let query = format!(
            r#"
            INSERT INTO password_history (id, user_id, password_hash, created_at)
            VALUES ({}, {}, {}, {})
            "#,
            dialect.param_placeholder(1),
            dialect.param_placeholder(2),
            dialect.param_placeholder(3),
            dialect.param_placeholder(4),
        );

        sqlx::query(&query)
            .bind(Uuid::now_v7())
            .bind(user_id.0)
            .bind(hash)
            .bind(Utc::now())
            .execute(self.pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(())
    }
}

/// Get user roles from the database
pub async fn get_user_roles(pool: &ConnectionPool, user_id: UserId) -> VortexResult<Vec<String>> {
    let dialect = pool.dialect();

    let query = format!(
        r#"
        SELECT r.name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = {}
        "#,
        dialect.param_placeholder(1),
    );

    let rows = sqlx::query(&query)
        .bind(user_id.0)
        .fetch_all(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(rows.iter().map(|r| r.get("name")).collect())
}

/// Get user display name from the database
pub async fn get_user_display_name(pool: &ConnectionPool, user_id: UserId) -> VortexResult<String> {
    let dialect = pool.dialect();

    let query = format!(
        r#"
        SELECT COALESCE(name, username) as display_name
        FROM users
        WHERE id = {}
        "#,
        dialect.param_placeholder(1),
    );

    let row = sqlx::query(&query)
        .bind(user_id.0)
        .fetch_optional(pool.pool())
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(row.map(|r| r.get("display_name")).unwrap_or_else(|| "Unknown User".to_string()))
}
