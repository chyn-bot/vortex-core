//! Migration loader for dialect-specific SQL files
//!
//! Supports a directory structure like:
//! ```text
//! migrations/
//!   001_initial_schema/
//!     postgres.sql
//!     mssql.sql
//!     metadata.toml
//!   002_add_assets/
//!     postgres.sql
//!     mssql.sql
//!     metadata.toml
//! ```

use crate::dialect::DatabaseBackend;
use crate::schema::Migration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use vortex_common::{VortexError, VortexResult};

/// Migration metadata from TOML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationMetadata {
    /// Migration name (defaults to directory name)
    pub name: Option<String>,
    /// Module this migration belongs to
    #[serde(default = "default_module")]
    pub module: String,
    /// Description of the migration
    pub description: Option<String>,
    /// Dependencies on other migrations
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Whether this migration is reversible
    #[serde(default)]
    pub reversible: bool,
}

fn default_module() -> String {
    "core".to_string()
}

impl Default for MigrationMetadata {
    fn default() -> Self {
        Self {
            name: None,
            module: default_module(),
            description: None,
            dependencies: Vec::new(),
            reversible: false,
        }
    }
}

/// Entry for a discovered migration
#[derive(Debug, Clone)]
pub struct MigrationEntry {
    /// Directory name (e.g., "001_initial_schema")
    pub dir_name: String,
    /// Migration metadata
    pub metadata: MigrationMetadata,
    /// Available SQL files by backend
    pub sql_files: HashMap<DatabaseBackend, PathBuf>,
    /// Down migration files if available
    pub down_files: HashMap<DatabaseBackend, PathBuf>,
}

impl MigrationEntry {
    /// Get the migration name
    pub fn name(&self) -> &str {
        self.metadata.name.as_deref().unwrap_or(&self.dir_name)
    }

    /// Check if this migration supports a specific backend
    pub fn supports_backend(&self, backend: DatabaseBackend) -> bool {
        self.sql_files.contains_key(&backend)
    }

    /// Load migration SQL for a specific backend
    pub fn load_for_backend(&self, backend: DatabaseBackend) -> VortexResult<Migration> {
        let sql_path = self.sql_files.get(&backend).ok_or_else(|| {
            VortexError::MigrationFailed(format!(
                "Migration '{}' does not support backend '{}'",
                self.name(),
                backend
            ))
        })?;

        let up_sql = std::fs::read_to_string(sql_path).map_err(|e| {
            VortexError::MigrationFailed(format!(
                "Failed to read migration file '{}': {}",
                sql_path.display(),
                e
            ))
        })?;

        let down_sql = if let Some(down_path) = self.down_files.get(&backend) {
            match std::fs::read_to_string(down_path) {
                Ok(sql) => Some(sql),
                Err(e) => {
                    warn!(
                        "Failed to read down migration '{}': {}",
                        down_path.display(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let mut migration =
            Migration::new(self.name(), &self.metadata.module, up_sql);

        if let Some(down) = down_sql {
            migration = migration.with_down(down);
        }

        if !self.metadata.dependencies.is_empty() {
            migration = migration.with_dependencies(self.metadata.dependencies.clone());
        }

        Ok(migration)
    }
}

/// Migration loader that discovers and loads dialect-specific migrations
pub struct MigrationLoader {
    /// Base directory for migrations
    base_dir: PathBuf,
    /// Discovered migrations
    migrations: Vec<MigrationEntry>,
}

impl MigrationLoader {
    /// Create a new migration loader for the given directory
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
            migrations: Vec::new(),
        }
    }

    /// Discover all migrations in the base directory
    pub fn discover(&mut self) -> VortexResult<&[MigrationEntry]> {
        self.migrations.clear();

        if !self.base_dir.exists() {
            warn!("Migrations directory does not exist: {}", self.base_dir.display());
            return Ok(&self.migrations);
        }

        let mut entries: Vec<_> = std::fs::read_dir(&self.base_dir)
            .map_err(|e| {
                VortexError::MigrationFailed(format!(
                    "Failed to read migrations directory: {}",
                    e
                ))
            })?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        // Sort by directory name for consistent ordering
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let dir_path = entry.path();
            let dir_name = entry.file_name().to_string_lossy().to_string();

            match self.load_migration_entry(&dir_path, &dir_name) {
                Ok(migration_entry) => {
                    debug!("Discovered migration: {}", migration_entry.name());
                    self.migrations.push(migration_entry);
                }
                Err(e) => {
                    warn!("Skipping invalid migration directory '{}': {}", dir_name, e);
                }
            }
        }

        info!("Discovered {} migrations", self.migrations.len());
        Ok(&self.migrations)
    }

    /// Load a migration entry from a directory
    fn load_migration_entry(
        &self,
        dir_path: &Path,
        dir_name: &str,
    ) -> VortexResult<MigrationEntry> {
        let metadata_path = dir_path.join("metadata.toml");
        let metadata = if metadata_path.exists() {
            let content = std::fs::read_to_string(&metadata_path).map_err(|e| {
                VortexError::MigrationFailed(format!(
                    "Failed to read metadata.toml: {}",
                    e
                ))
            })?;
            toml::from_str(&content).map_err(|e| {
                VortexError::MigrationFailed(format!(
                    "Failed to parse metadata.toml: {}",
                    e
                ))
            })?
        } else {
            MigrationMetadata::default()
        };

        let mut sql_files = HashMap::new();
        let mut down_files = HashMap::new();

        // Look for PostgreSQL migration
        let pg_path = dir_path.join("postgres.sql");
        if pg_path.exists() {
            sql_files.insert(DatabaseBackend::Postgres, pg_path);
        }
        let pg_down_path = dir_path.join("postgres_down.sql");
        if pg_down_path.exists() {
            down_files.insert(DatabaseBackend::Postgres, pg_down_path);
        }

        // Look for MSSQL migration
        #[cfg(feature = "mssql")]
        {
            let mssql_path = dir_path.join("mssql.sql");
            if mssql_path.exists() {
                sql_files.insert(DatabaseBackend::MsSql, mssql_path);
            }
            let mssql_down_path = dir_path.join("mssql_down.sql");
            if mssql_down_path.exists() {
                down_files.insert(DatabaseBackend::MsSql, mssql_down_path);
            }
        }

        if sql_files.is_empty() {
            return Err(VortexError::MigrationFailed(format!(
                "No SQL files found in migration directory: {}",
                dir_name
            )));
        }

        Ok(MigrationEntry {
            dir_name: dir_name.to_string(),
            metadata,
            sql_files,
            down_files,
        })
    }

    /// Get all discovered migrations
    pub fn migrations(&self) -> &[MigrationEntry] {
        &self.migrations
    }

    /// Get migrations that support a specific backend
    pub fn migrations_for_backend(&self, backend: DatabaseBackend) -> Vec<&MigrationEntry> {
        self.migrations
            .iter()
            .filter(|m| m.supports_backend(backend))
            .collect()
    }

    /// Load all migrations for a specific backend
    pub fn load_all_for_backend(&self, backend: DatabaseBackend) -> VortexResult<Vec<Migration>> {
        self.migrations_for_backend(backend)
            .into_iter()
            .map(|entry| entry.load_for_backend(backend))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_migrations() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create first migration
        let migration1 = dir.path().join("001_initial_schema");
        fs::create_dir(&migration1).unwrap();
        fs::write(
            migration1.join("postgres.sql"),
            "CREATE TABLE test (id UUID PRIMARY KEY);",
        )
        .unwrap();
        fs::write(
            migration1.join("metadata.toml"),
            r#"
            module = "core"
            description = "Initial schema"
            "#,
        )
        .unwrap();

        // Create second migration
        let migration2 = dir.path().join("002_add_users");
        fs::create_dir(&migration2).unwrap();
        fs::write(
            migration2.join("postgres.sql"),
            "CREATE TABLE users (id UUID PRIMARY KEY);",
        )
        .unwrap();
        fs::write(migration2.join("postgres_down.sql"), "DROP TABLE users;").unwrap();
        fs::write(
            migration2.join("metadata.toml"),
            r#"
            module = "core"
            dependencies = ["001_initial_schema"]
            reversible = true
            "#,
        )
        .unwrap();

        dir
    }

    #[test]
    fn test_discover_migrations() {
        let temp_dir = create_test_migrations();
        let mut loader = MigrationLoader::new(temp_dir.path());

        let migrations = loader.discover().unwrap();
        assert_eq!(migrations.len(), 2);
        assert_eq!(migrations[0].name(), "001_initial_schema");
        assert_eq!(migrations[1].name(), "002_add_users");
    }

    #[test]
    fn test_load_migration_for_backend() {
        let temp_dir = create_test_migrations();
        let mut loader = MigrationLoader::new(temp_dir.path());
        loader.discover().unwrap();

        let migration = loader.migrations()[0]
            .load_for_backend(DatabaseBackend::Postgres)
            .unwrap();

        assert_eq!(migration.name, "001_initial_schema");
        assert_eq!(migration.module, "core");
        assert!(migration.up_sql.contains("CREATE TABLE test"));
    }

    #[test]
    fn test_migration_with_dependencies() {
        let temp_dir = create_test_migrations();
        let mut loader = MigrationLoader::new(temp_dir.path());
        loader.discover().unwrap();

        let migration = loader.migrations()[1]
            .load_for_backend(DatabaseBackend::Postgres)
            .unwrap();

        assert_eq!(migration.dependencies, vec!["001_initial_schema"]);
        assert!(migration.down_sql.is_some());
    }
}
