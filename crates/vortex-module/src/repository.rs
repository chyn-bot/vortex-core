//! Module repository for database persistence
//!
//! Provides database-backed storage for module installation state,
//! enabling Odoo-style per-database module management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, FromRow, PgPool, Row};
use uuid::Uuid;
use vortex_common::{VortexError, VortexResult};

use crate::manifest::ModuleState;

/// Database representation of an installed module
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct InstalledModule {
    pub id: Uuid,
    pub name: String,
    pub technical_name: String,
    pub version: String,
    pub state: String,
    pub category: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub website: Option<String>,
    pub license: Option<String>,
    pub is_core: bool,
    pub auto_install: bool,
    pub application: bool,
    pub installed_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub installed_by: Option<Uuid>,
    pub sequence: i32,
    pub icon: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Module dependency from database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ModuleDependencyRow {
    pub id: Uuid,
    pub module_id: Uuid,
    pub depends_on: String,
    pub version_constraint: Option<String>,
    pub optional: bool,
    pub auto_install_trigger: bool,
}

/// Module state as stored in database
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbModuleState {
    Uninstalled,
    ToInstall,
    Installed,
    ToUpgrade,
    ToRemove,
}

impl DbModuleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DbModuleState::Uninstalled => "uninstalled",
            DbModuleState::ToInstall => "to_install",
            DbModuleState::Installed => "installed",
            DbModuleState::ToUpgrade => "to_upgrade",
            DbModuleState::ToRemove => "to_remove",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "to_install" => DbModuleState::ToInstall,
            "installed" => DbModuleState::Installed,
            "to_upgrade" => DbModuleState::ToUpgrade,
            "to_remove" => DbModuleState::ToRemove,
            _ => DbModuleState::Uninstalled,
        }
    }
}

impl From<ModuleState> for DbModuleState {
    fn from(state: ModuleState) -> Self {
        match state {
            ModuleState::Uninstalled => DbModuleState::Uninstalled,
            ModuleState::Installing => DbModuleState::ToInstall,
            ModuleState::Installed => DbModuleState::Installed,
            ModuleState::Upgrading => DbModuleState::ToUpgrade,
            ModuleState::Uninstalling => DbModuleState::ToRemove,
            ModuleState::Failed => DbModuleState::Uninstalled,
            ModuleState::Disabled => DbModuleState::Uninstalled,
        }
    }
}

impl From<DbModuleState> for ModuleState {
    fn from(state: DbModuleState) -> Self {
        match state {
            DbModuleState::Uninstalled => ModuleState::Uninstalled,
            DbModuleState::ToInstall => ModuleState::Installing,
            DbModuleState::Installed => ModuleState::Installed,
            DbModuleState::ToUpgrade => ModuleState::Upgrading,
            DbModuleState::ToRemove => ModuleState::Uninstalling,
        }
    }
}

/// Repository for module database operations
pub struct ModuleRepository {
    pool: PgPool,
}

impl ModuleRepository {
    /// Create a new module repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get all modules (installed and available)
    pub async fn list_all(&self) -> VortexResult<Vec<InstalledModule>> {
        let modules = sqlx::query_as::<_, InstalledModule>(
            r#"
            SELECT id, name, technical_name, version, state, category, summary,
                   description, author, website, license, is_core, auto_install,
                   application, installed_at, updated_at, installed_by, sequence,
                   icon, created_at
            FROM installed_modules
            ORDER BY sequence, name
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(modules)
    }

    /// Get only installed modules
    pub async fn list_installed(&self) -> VortexResult<Vec<InstalledModule>> {
        let modules = sqlx::query_as::<_, InstalledModule>(
            r#"
            SELECT id, name, technical_name, version, state, category, summary,
                   description, author, website, license, is_core, auto_install,
                   application, installed_at, updated_at, installed_by, sequence,
                   icon, created_at
            FROM installed_modules
            WHERE state = 'installed'
            ORDER BY sequence, name
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(modules)
    }

    /// Get modules by state
    pub async fn list_by_state(&self, state: DbModuleState) -> VortexResult<Vec<InstalledModule>> {
        let modules = sqlx::query_as::<_, InstalledModule>(
            r#"
            SELECT id, name, technical_name, version, state, category, summary,
                   description, author, website, license, is_core, auto_install,
                   application, installed_at, updated_at, installed_by, sequence,
                   icon, created_at
            FROM installed_modules
            WHERE state = $1
            ORDER BY sequence, name
            "#
        )
        .bind(state.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(modules)
    }

    /// Get module by technical name
    pub async fn get_by_technical_name(&self, technical_name: &str) -> VortexResult<Option<InstalledModule>> {
        let module = sqlx::query_as::<_, InstalledModule>(
            r#"
            SELECT id, name, technical_name, version, state, category, summary,
                   description, author, website, license, is_core, auto_install,
                   application, installed_at, updated_at, installed_by, sequence,
                   icon, created_at
            FROM installed_modules
            WHERE technical_name = $1
            "#
        )
        .bind(technical_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(module)
    }

    /// Check if a module is installed
    pub async fn is_installed(&self, technical_name: &str) -> VortexResult<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM installed_modules WHERE technical_name = $1 AND state = 'installed'"
        )
        .bind(technical_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(row.is_some())
    }

    /// Update module state
    pub async fn update_state(
        &self,
        technical_name: &str,
        state: DbModuleState,
        user_id: Option<Uuid>,
    ) -> VortexResult<()> {
        let now = Utc::now();

        let (installed_at, updated_at) = match state {
            DbModuleState::Installed => (Some(now), Some(now)),
            _ => (None, Some(now)),
        };

        sqlx::query(
            r#"
            UPDATE installed_modules
            SET state = $1,
                installed_at = COALESCE($2, installed_at),
                updated_at = $3,
                installed_by = COALESCE($4, installed_by)
            WHERE technical_name = $5
            "#
        )
        .bind(state.as_str())
        .bind(installed_at)
        .bind(updated_at)
        .bind(user_id)
        .bind(technical_name)
        .execute(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(())
    }

    /// Register a new module (without installing it)
    pub async fn register_module(
        &self,
        technical_name: &str,
        name: &str,
        version: &str,
        category: Option<&str>,
        summary: Option<&str>,
        description: Option<&str>,
        is_core: bool,
        application: bool,
        dependencies: Vec<(&str, Option<&str>, bool)>, // (depends_on, version_constraint, optional)
    ) -> VortexResult<Uuid> {
        let module_id = Uuid::now_v7();

        // Insert module
        sqlx::query(
            r#"
            INSERT INTO installed_modules (
                id, technical_name, name, version, state, category, summary,
                description, is_core, application, sequence
            )
            VALUES ($1, $2, $3, $4, 'uninstalled', $5, $6, $7, $8, $9, 100)
            ON CONFLICT (technical_name) DO UPDATE
            SET name = $3, version = $4, category = $5, summary = $6,
                description = $7, is_core = $8, application = $9
            RETURNING id
            "#
        )
        .bind(module_id)
        .bind(technical_name)
        .bind(name)
        .bind(version)
        .bind(category)
        .bind(summary)
        .bind(description)
        .bind(is_core)
        .bind(application)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        // Get the actual module ID (in case of ON CONFLICT)
        let actual_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM installed_modules WHERE technical_name = $1"
        )
        .bind(technical_name)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        // Clear existing dependencies
        sqlx::query("DELETE FROM module_dependencies WHERE module_id = $1")
            .bind(actual_id)
            .execute(&self.pool)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        // Insert dependencies
        for (depends_on, version_constraint, optional) in dependencies {
            sqlx::query(
                r#"
                INSERT INTO module_dependencies (id, module_id, depends_on, version_constraint, optional)
                VALUES ($1, $2, $3, $4, $5)
                "#
            )
            .bind(Uuid::now_v7())
            .bind(actual_id)
            .bind(depends_on)
            .bind(version_constraint)
            .bind(optional)
            .execute(&self.pool)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        }

        Ok(actual_id)
    }

    /// Get module dependencies
    pub async fn get_dependencies(&self, technical_name: &str) -> VortexResult<Vec<ModuleDependencyRow>> {
        let deps = sqlx::query_as::<_, ModuleDependencyRow>(
            r#"
            SELECT md.id, md.module_id, md.depends_on, md.version_constraint,
                   md.optional, md.auto_install_trigger
            FROM module_dependencies md
            JOIN installed_modules im ON im.id = md.module_id
            WHERE im.technical_name = $1
            "#
        )
        .bind(technical_name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(deps)
    }

    /// Check if all dependencies are satisfied for a module
    pub async fn check_dependencies(&self, technical_name: &str) -> VortexResult<Vec<(String, bool)>> {
        let rows = sqlx::query(
            r#"
            SELECT
                md.depends_on,
                EXISTS (
                    SELECT 1 FROM installed_modules im2
                    WHERE im2.technical_name = md.depends_on
                    AND im2.state = 'installed'
                ) as is_satisfied
            FROM installed_modules im
            JOIN module_dependencies md ON md.module_id = im.id
            WHERE im.technical_name = $1 AND md.optional = false
            "#
        )
        .bind(technical_name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row: &PgRow| {
                (
                    row.get::<String, _>("depends_on"),
                    row.get::<bool, _>("is_satisfied"),
                )
            })
            .collect())
    }

    /// Get modules that depend on the given module
    pub async fn get_dependents(&self, technical_name: &str) -> VortexResult<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT im.technical_name
            FROM installed_modules im
            JOIN module_dependencies md ON md.module_id = im.id
            WHERE md.depends_on = $1
            AND im.state = 'installed'
            AND md.optional = false
            "#
        )
        .bind(technical_name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows.iter().map(|row: &PgRow| row.get("technical_name")).collect())
    }

    /// Get installation order for a module (topological sort of dependencies)
    pub async fn get_install_order(&self, technical_name: &str) -> VortexResult<Vec<String>> {
        // Use recursive CTE to get all dependencies in order
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE dep_tree AS (
                -- Base case: the module itself
                SELECT im.technical_name, 0 as depth
                FROM installed_modules im
                WHERE im.technical_name = $1

                UNION ALL

                -- Recursive case: dependencies
                SELECT im2.technical_name, dt.depth + 1
                FROM dep_tree dt
                JOIN installed_modules im ON im.technical_name = dt.technical_name
                JOIN module_dependencies md ON md.module_id = im.id
                JOIN installed_modules im2 ON im2.technical_name = md.depends_on
                WHERE md.optional = false
                AND im2.state != 'installed'
            )
            SELECT DISTINCT technical_name
            FROM dep_tree
            ORDER BY depth DESC
            "#
        )
        .bind(technical_name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows.iter().map(|row: &PgRow| row.get("technical_name")).collect())
    }

    /// Record module data for tracking (for clean uninstall)
    pub async fn record_module_data(
        &self,
        technical_name: &str,
        model_name: &str,
        record_id: Uuid,
        xml_id: Option<&str>,
    ) -> VortexResult<()> {
        let module = self.get_by_technical_name(technical_name).await?
            .ok_or_else(|| VortexError::ModuleNotFound(technical_name.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO module_data (id, module_id, model_name, record_id, xml_id)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (model_name, record_id) DO NOTHING
            "#
        )
        .bind(Uuid::now_v7())
        .bind(module.id)
        .bind(model_name)
        .bind(record_id)
        .bind(xml_id)
        .execute(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(())
    }

    /// Get all data records for a module (for uninstall)
    pub async fn get_module_data(&self, technical_name: &str) -> VortexResult<Vec<(String, Uuid)>> {
        let rows = sqlx::query(
            r#"
            SELECT md.model_name, md.record_id
            FROM module_data md
            JOIN installed_modules im ON im.id = md.module_id
            WHERE im.technical_name = $1
            ORDER BY md.created_at DESC
            "#
        )
        .bind(technical_name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row: &PgRow| {
                (
                    row.get::<String, _>("model_name"),
                    row.get::<Uuid, _>("record_id"),
                )
            })
            .collect())
    }

    /// Record a migration as applied for a module
    pub async fn record_migration(
        &self,
        technical_name: &str,
        migration_name: &str,
        version: Option<&str>,
        checksum: Option<&str>,
        execution_time_ms: Option<i32>,
    ) -> VortexResult<()> {
        let module = self.get_by_technical_name(technical_name).await?
            .ok_or_else(|| VortexError::ModuleNotFound(technical_name.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO module_migrations (id, module_id, migration_name, version, checksum, execution_time_ms)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (module_id, migration_name) DO NOTHING
            "#
        )
        .bind(Uuid::now_v7())
        .bind(module.id)
        .bind(migration_name)
        .bind(version)
        .bind(checksum)
        .bind(execution_time_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(())
    }

    /// Check if a migration has been applied for a module
    pub async fn is_migration_applied(
        &self,
        technical_name: &str,
        migration_name: &str,
    ) -> VortexResult<bool> {
        let row = sqlx::query(
            r#"
            SELECT 1
            FROM module_migrations mm
            JOIN installed_modules im ON im.id = mm.module_id
            WHERE im.technical_name = $1 AND mm.migration_name = $2
            "#
        )
        .bind(technical_name)
        .bind(migration_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(row.is_some())
    }

    /// Get list of installed module technical names
    pub async fn get_installed_module_names(&self) -> VortexResult<Vec<String>> {
        let rows = sqlx::query("SELECT technical_name FROM installed_modules WHERE state = 'installed'")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        Ok(rows.iter().map(|row: &PgRow| row.get("technical_name")).collect())
    }
}
