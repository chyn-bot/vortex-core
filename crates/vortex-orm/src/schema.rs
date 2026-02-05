//! Database schema management and migrations

use crate::connection::ConnectionPool;
use crate::dialect::{PostgresDialect, SqlDialect};
use crate::field::{FieldType, OnDelete};
use crate::model::ModelMeta;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use vortex_common::{VortexError, VortexResult};

/// Schema manager for database migrations
pub struct SchemaManager {
    pool: ConnectionPool,
}

impl SchemaManager {
    /// Create a new schema manager
    pub fn new(pool: ConnectionPool) -> Self {
        Self { pool }
    }

    /// Get the SQL dialect for this schema manager
    pub fn dialect(&self) -> &dyn SqlDialect {
        self.pool.dialect()
    }

    /// Initialize the migration tracking table
    pub async fn init(&self) -> VortexResult<()> {
        let dialect = self.dialect();
        let uuid_type = dialect.field_type_to_sql(&FieldType::Uuid);
        let timestamp_type = dialect.field_type_to_sql(&FieldType::Timestamp);
        let now_fn = dialect.now_function();
        let uuid_fn = dialect.uuid_generate();

        let migrations_sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS vortex_migrations (
                id {} PRIMARY KEY DEFAULT {},
                name VARCHAR(255) NOT NULL UNIQUE,
                module VARCHAR(255) NOT NULL,
                applied_at {} NOT NULL DEFAULT {},
                checksum VARCHAR(64) NOT NULL,
                execution_time_ms INTEGER NOT NULL DEFAULT 0
            )
            "#,
            uuid_type, uuid_fn, timestamp_type, now_fn
        );

        self.pool.execute(&migrations_sql).await?;

        let version_sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS vortex_schema_version (
                id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
                version INTEGER NOT NULL DEFAULT 0,
                updated_at {} NOT NULL DEFAULT {}
            )
            "#,
            timestamp_type, now_fn
        );

        self.pool.execute(&version_sql).await?;

        // Insert default version row if not exists (PostgreSQL specific for now)
        // TODO: Make this dialect-aware for MERGE/UPSERT
        let upsert_sql = match self.pool.backend() {
            crate::dialect::DatabaseBackend::Postgres => {
                r#"
                INSERT INTO vortex_schema_version (id, version)
                VALUES (1, 0)
                ON CONFLICT (id) DO NOTHING
                "#
            }
            #[cfg(feature = "mssql")]
            crate::dialect::DatabaseBackend::MsSql => {
                r#"
                IF NOT EXISTS (SELECT 1 FROM vortex_schema_version WHERE id = 1)
                    INSERT INTO vortex_schema_version (id, version) VALUES (1, 0)
                "#
            }
        };

        self.pool.execute(upsert_sql).await?;

        info!("Migration tracking initialized");
        Ok(())
    }

    /// Generate CREATE TABLE SQL for a model using the connection's dialect
    pub fn generate_create_table(&self, meta: &ModelMeta) -> String {
        self.generate_create_table_with_dialect(meta, self.dialect())
    }

    /// Generate CREATE TABLE SQL for a model with specified dialect
    pub fn generate_create_table_with_dialect(
        &self,
        meta: &ModelMeta,
        dialect: &dyn SqlDialect,
    ) -> String {
        let mut sql = format!("CREATE TABLE IF NOT EXISTS {} (\n", meta.table);
        let mut columns = Vec::new();
        let mut constraints = Vec::new();

        for field in meta.fields_ordered() {
            let col_sql = self.field_to_column_def_with_dialect(field, dialect);
            if let Some(col) = col_sql {
                columns.push(col);
            }

            // Handle foreign keys
            if let FieldType::Reference { model, on_delete } = &field.field_type {
                constraints.push(format!(
                    "CONSTRAINT fk_{}_{} FOREIGN KEY ({}) REFERENCES {} (id) ON DELETE {}",
                    meta.table,
                    field.column_name(),
                    field.column_name(),
                    model,
                    self.on_delete_to_sql(on_delete)
                ));
            }
        }

        // Add standard audit columns if audited
        if meta.audited {
            let timestamp_type = dialect.field_type_to_sql(&FieldType::Timestamp);
            let uuid_type = dialect.field_type_to_sql(&FieldType::Uuid);
            let now_fn = dialect.now_function();

            columns.push(format!(
                "created_at {} NOT NULL DEFAULT {}",
                timestamp_type, now_fn
            ));
            columns.push(format!("created_by {} NOT NULL", uuid_type));
            columns.push(format!(
                "updated_at {} NOT NULL DEFAULT {}",
                timestamp_type, now_fn
            ));
            columns.push(format!("updated_by {} NOT NULL", uuid_type));
        }

        // Add company_id for multi-tenant models
        if meta.multi_tenant {
            let uuid_type = dialect.field_type_to_sql(&FieldType::Uuid);
            columns.push(format!("company_id {} NOT NULL", uuid_type));
            constraints.push(format!(
                "CONSTRAINT fk_{}_company FOREIGN KEY (company_id) REFERENCES companies (id)",
                meta.table
            ));
        }

        // Add soft delete column
        if meta.soft_delete {
            let bool_type = dialect.field_type_to_sql(&FieldType::Boolean);
            let default = dialect.bool_literal(true);
            columns.push(format!("active {} NOT NULL DEFAULT {}", bool_type, default));
        }

        // Combine columns and constraints
        let all_parts: Vec<String> = columns.into_iter().chain(constraints).collect();
        sql.push_str("    ");
        sql.push_str(&all_parts.join(",\n    "));
        sql.push_str("\n)");

        sql
    }

    /// Convert a field definition to a column definition with dialect
    fn field_to_column_def_with_dialect(
        &self,
        field: &crate::field::FieldDef,
        dialect: &dyn SqlDialect,
    ) -> Option<String> {
        // Skip computed fields
        if matches!(field.field_type, FieldType::Computed) {
            return None;
        }

        let col_name = field.column_name();
        let sql_type = dialect.field_type_to_sql(&field.field_type);

        let mut col_def = format!("{} {}", col_name, sql_type);

        if field.primary_key {
            col_def.push_str(" PRIMARY KEY");
        }
        if field.required && !field.primary_key {
            col_def.push_str(" NOT NULL");
        }
        if field.unique && !field.primary_key {
            col_def.push_str(" UNIQUE");
        }

        // Handle defaults
        if let Some(default) = &field.default {
            match default {
                crate::field::DefaultValue::Expression(expr) => {
                    // Map common expressions to dialect-specific versions
                    let dialect_expr = self.map_expression_to_dialect(expr, dialect);
                    col_def.push_str(&format!(" DEFAULT {}", dialect_expr));
                }
                crate::field::DefaultValue::Value(val) => {
                    col_def.push_str(&format!(" DEFAULT {}", self.value_to_sql_with_dialect(val, dialect)));
                }
                crate::field::DefaultValue::Function(_) => {
                    // Runtime computed, no SQL default
                }
            }
        }

        Some(col_def)
    }

    /// Map common SQL expressions to dialect-specific versions
    fn map_expression_to_dialect(&self, expr: &str, dialect: &dyn SqlDialect) -> String {
        let expr_lower = expr.to_lowercase();

        if expr_lower.contains("now()") {
            return expr_lower.replace("now()", dialect.now_function());
        }
        if expr_lower.contains("gen_random_uuid()") || expr_lower.contains("uuid_generate_v4()") {
            return dialect.uuid_generate().to_string();
        }

        expr.to_string()
    }

    /// Convert OnDelete to SQL
    fn on_delete_to_sql(&self, on_delete: &OnDelete) -> &'static str {
        match on_delete {
            OnDelete::Restrict => "RESTRICT",
            OnDelete::Cascade => "CASCADE",
            OnDelete::SetNull => "SET NULL",
            OnDelete::SetDefault => "SET DEFAULT",
            OnDelete::NoAction => "NO ACTION",
        }
    }

    /// Convert a FieldValue to SQL literal with dialect support
    fn value_to_sql_with_dialect(
        &self,
        value: &vortex_common::FieldValue,
        dialect: &dyn SqlDialect,
    ) -> String {
        use vortex_common::FieldValue;
        match value {
            FieldValue::Null => "NULL".to_string(),
            FieldValue::Bool(b) => dialect.bool_literal(*b).to_string(),
            FieldValue::Int(i) => i.to_string(),
            FieldValue::Float(f) => f.to_string(),
            FieldValue::String(s) => format!("'{}'", s.replace('\'', "''")),
            FieldValue::Uuid(u) => format!("'{}'", u),
            FieldValue::Timestamp(t) => format!("'{}'", t.to_rfc3339()),
            FieldValue::Json(j) => format!("'{}'", j.to_string().replace('\'', "''")),
            FieldValue::Binary(b) => {
                match dialect.backend() {
                    crate::dialect::DatabaseBackend::Postgres => {
                        format!("'\\x{}'", hex::encode(b))
                    }
                    #[cfg(feature = "mssql")]
                    crate::dialect::DatabaseBackend::MsSql => {
                        format!("0x{}", hex::encode(b))
                    }
                }
            }
            FieldValue::Array(arr) => {
                match dialect.backend() {
                    crate::dialect::DatabaseBackend::Postgres => {
                        let items: Vec<String> = arr
                            .iter()
                            .map(|v| self.value_to_sql_with_dialect(v, dialect))
                            .collect();
                        format!("ARRAY[{}]", items.join(", "))
                    }
                    #[cfg(feature = "mssql")]
                    crate::dialect::DatabaseBackend::MsSql => {
                        // SQL Server stores arrays as JSON strings
                        let json_arr: Vec<serde_json::Value> = arr
                            .iter()
                            .map(|v| match v {
                                FieldValue::String(s) => serde_json::Value::String(s.clone()),
                                FieldValue::Int(i) => serde_json::json!(*i),
                                FieldValue::Float(f) => serde_json::json!(*f),
                                FieldValue::Bool(b) => serde_json::json!(*b),
                                _ => serde_json::Value::Null,
                            })
                            .collect();
                        format!("'{}'", serde_json::to_string(&json_arr).unwrap_or_default())
                    }
                }
            }
        }
    }

    /// Convert a FieldValue to SQL literal (backward compatibility)
    fn value_to_sql(&self, value: &vortex_common::FieldValue) -> String {
        self.value_to_sql_with_dialect(value, &PostgresDialect)
    }

    /// Generate index creation SQL
    pub fn generate_create_index(&self, meta: &ModelMeta, index: &crate::model::IndexDef) -> String {
        self.generate_create_index_with_dialect(meta, index, self.dialect())
    }

    /// Generate index creation SQL with specified dialect
    pub fn generate_create_index_with_dialect(
        &self,
        meta: &ModelMeta,
        index: &crate::model::IndexDef,
        dialect: &dyn SqlDialect,
    ) -> String {
        let method_name = match index.method {
            crate::model::IndexMethod::BTree => "btree",
            crate::model::IndexMethod::Hash => "hash",
            crate::model::IndexMethod::Gin => "gin",
            crate::model::IndexMethod::Gist => "gist",
            crate::model::IndexMethod::Brin => "brin",
        };

        // Check if dialect supports this index method
        if !dialect.supports_index_method(method_name) {
            warn!(
                "Skipping unsupported index method '{}' for dialect '{}'",
                method_name,
                dialect.backend()
            );
            return String::new();
        }

        let unique = if index.unique { "UNIQUE " } else { "" };
        let method = match index.method {
            crate::model::IndexMethod::BTree => "",
            crate::model::IndexMethod::Hash => "USING hash ",
            crate::model::IndexMethod::Gin => "USING gin ",
            crate::model::IndexMethod::Gist => "USING gist ",
            crate::model::IndexMethod::Brin => "USING brin ",
        };

        let mut sql = format!(
            "CREATE {}INDEX IF NOT EXISTS {} {}ON {} ({})",
            unique,
            index.name,
            method,
            meta.table,
            index.columns.join(", ")
        );

        if let Some(where_clause) = &index.where_clause {
            sql.push_str(&format!(" WHERE {}", where_clause));
        }

        sql
    }

    /// Apply a migration
    pub async fn apply_migration(&self, migration: &Migration) -> VortexResult<()> {
        info!("Applying migration: {}", migration.name);

        let start = std::time::Instant::now();

        // Execute the migration
        self.pool.execute(&migration.up_sql).await?;

        let elapsed = start.elapsed().as_millis() as i32;

        // Record the migration
        let checksum = self.compute_checksum(&migration.up_sql);

        let insert_sql = match self.pool.backend() {
            crate::dialect::DatabaseBackend::Postgres => {
                format!(
                    r#"
                    INSERT INTO vortex_migrations (name, module, checksum, execution_time_ms)
                    VALUES ($1, $2, $3, $4)
                    "#
                )
            }
            #[cfg(feature = "mssql")]
            crate::dialect::DatabaseBackend::MsSql => {
                format!(
                    r#"
                    INSERT INTO vortex_migrations (name, module, checksum, execution_time_ms)
                    VALUES (@p1, @p2, @p3, @p4)
                    "#
                )
            }
        };

        sqlx::query(&insert_sql)
            .bind(&migration.name)
            .bind(&migration.module)
            .bind(&checksum)
            .bind(elapsed)
            .execute(self.pool.pool())
            .await
            .map_err(|e| VortexError::MigrationFailed(e.to_string()))?;

        info!("Migration applied in {}ms: {}", elapsed, migration.name);
        Ok(())
    }

    /// Check if a migration has been applied
    pub async fn is_migration_applied(&self, name: &str) -> VortexResult<bool> {
        let query = match self.pool.backend() {
            crate::dialect::DatabaseBackend::Postgres => {
                "SELECT 1 FROM vortex_migrations WHERE name = $1"
            }
            #[cfg(feature = "mssql")]
            crate::dialect::DatabaseBackend::MsSql => {
                "SELECT 1 FROM vortex_migrations WHERE name = @p1"
            }
        };

        let row = sqlx::query(query)
            .bind(name)
            .fetch_optional(self.pool.pool())
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        Ok(row.is_some())
    }

    /// Compute checksum of SQL
    fn compute_checksum(&self, sql: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        sql.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

/// Migration definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    /// Unique name for the migration
    pub name: String,
    /// Module this migration belongs to
    pub module: String,
    /// SQL to apply the migration
    pub up_sql: String,
    /// SQL to rollback the migration
    pub down_sql: Option<String>,
    /// Dependencies on other migrations
    pub dependencies: Vec<String>,
}

impl Migration {
    /// Create a new migration
    pub fn new(name: impl Into<String>, module: impl Into<String>, up_sql: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            module: module.into(),
            up_sql: up_sql.into(),
            down_sql: None,
            dependencies: Vec::new(),
        }
    }

    /// Add rollback SQL
    pub fn with_down(mut self, down_sql: impl Into<String>) -> Self {
        self.down_sql = Some(down_sql.into());
        self
    }

    /// Add dependencies
    pub fn with_dependencies(mut self, deps: Vec<String>) -> Self {
        self.dependencies = deps;
        self
    }
}
