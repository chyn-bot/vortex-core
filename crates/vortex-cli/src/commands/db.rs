//! Database commands

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::path::Path;
use std::sync::Arc;
use tracing::info;
use vortex_framework::{Plugin, PluginRegistry};

use crate::DbCommands;

/// Build a bare `PluginRegistry` suitable for migration-time work.
///
/// This is a lightweight version of the registry construction in
/// `commands/server.rs` — it registers every compiled-in plugin but
/// does NOT wire up the workflow engine, audit ledger, policy
/// service, or `AppState`. Migration commands only need the list
/// of plugins and their `migrations()` output, so the cheaper
/// registry is enough.
fn build_migration_registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    registry.register(Arc::new(vortex_contacts::ContactsPlugin::new()));
    registry.register(Arc::new(vortex_iwk::IwkPlugin::new()));
    registry.register(Arc::new(vortex_accounting::AccountingPlugin::new()));
    registry.register(Arc::new(vortex_inventory::InventoryPlugin::new()));
    registry.register(Arc::new(vortex_purchase::PurchasePlugin::new()));
    registry.register(Arc::new(vortex_sales::SalesPlugin::new()));
    registry.register(Arc::new(vortex_maintenance::MaintenancePlugin::new()));
    registry.register(Arc::new(vortex_sesb_eam::SesbEamPlugin::new()));
    #[cfg(feature = "cr")]
    registry.register(Arc::new(vortex_change::ChangeRequestPlugin::new()));
    registry
}

/// Project every compiled-in plugin's `#[derive(Model)]` metadata into a
/// database's `ir_model` / `ir_model_field` registry, making the derive the
/// single source of truth for the generic views and REST API. Idempotent; run
/// after the migration phase so the registry tables exist. Non-fatal on error
/// (a legacy DB may predate migration 122) — returns the number of models
/// synced.
async fn sync_model_registries(pool: &PgPool, registry: &PluginRegistry) -> usize {
    let metas: Vec<&'static vortex_orm::model::ModelMeta> = registry
        .plugins_iter()
        .flat_map(|p| p.models())
        .collect();
    if metas.is_empty() {
        return 0;
    }
    match vortex_orm::registry_sync::sync_model_registry(pool, &metas).await {
        Ok(n) => n,
        Err(e) => {
            println!("  Warning: model registry sync failed: {}", e);
            0
        }
    }
}

/// Composite identifier stored in `vortex_migrations.name` for
/// plugin migrations. Core migrations keep their raw directory name
/// (e.g. `116_workflow_engine`) for backwards compatibility; plugin
/// migrations are stored as `<module>:<name>` (e.g.
/// `change_request:001_change_requests`) so two plugins can ship
/// a migration with the same local name without colliding on the
/// `name UNIQUE` constraint.
fn plugin_migration_key(module: &str, name: &str) -> String {
    format!("{}:{}", module, name)
}

/// Get database connection
async fn get_db_pool() -> Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable not set")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;

    Ok(pool)
}

/// Ensure the vortex_migrations tracking table exists
async fn init_migrations_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vortex_migrations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL UNIQUE,
            module VARCHAR(255) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            checksum VARCHAR(64) NOT NULL,
            execution_time_ms INTEGER NOT NULL DEFAULT 0
        )
        "#
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Check if a migration has been applied
async fn is_migration_applied(pool: &PgPool, name: &str) -> Result<bool> {
    let result = sqlx::query("SELECT 1 FROM vortex_migrations WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;

    Ok(result.is_some())
}

/// Record a migration as applied
async fn record_migration(pool: &PgPool, name: &str, module: &str, execution_time_ms: i32) -> Result<()> {
    // Compute a simple checksum (in practice, this would be SHA256 of the SQL)
    let checksum = format!("{:x}", md5::compute(name.as_bytes()));

    sqlx::query(
        r#"
        INSERT INTO vortex_migrations (id, name, module, checksum, execution_time_ms)
        VALUES (gen_random_uuid(), $1, $2, $3, $4)
        "#
    )
    .bind(name)
    .bind(module)
    .bind(&checksum)
    .bind(execution_time_ms)
    .execute(pool)
    .await?;

    Ok(())
}

/// Result of applying one migration's SQL via [`apply_and_record_migration`].
enum MigApply {
    /// The whole file applied cleanly in one batch (elapsed ms).
    Applied(i32),
    /// The batch tripped an "already exists"; recovered by re-running
    /// statement-by-statement (`applied` new statements, `existed` skipped).
    Recovered { applied: usize, existed: usize },
}

/// Apply one migration's SQL and record it in `vortex_migrations`.
///
/// The primary path runs the whole file as a single batch. Postgres executes a
/// multi-statement simple query in one implicit transaction, so if *any*
/// statement fails the *entire* batch rolls back. The old code caught an
/// "already exists" here and simply marked the migration applied — which meant a
/// migration that (say) creates one existing table and adds one *new* column had
/// its `ALTER` silently rolled back and never retried: permanent, invisible
/// schema drift. Instead, on "already exists" we re-run the file
/// statement-by-statement, swallowing "already exists" per statement so the
/// genuinely-new statements DO apply. Any other error propagates loudly.
async fn apply_and_record_migration(
    pool: &PgPool,
    key: &str,
    module: &str,
    sql: &str,
) -> Result<MigApply> {
    let start = std::time::Instant::now();
    match sqlx::raw_sql(sql).execute(pool).await {
        Ok(_) => {
            let ms = start.elapsed().as_millis() as i32;
            record_migration(pool, key, module, ms).await?;
            Ok(MigApply::Applied(ms))
        }
        Err(e) if e.to_string().contains("already exists") => {
            let mut applied = 0usize;
            let mut existed = 0usize;
            for stmt in split_sql_statements(sql) {
                match sqlx::raw_sql(&stmt).execute(pool).await {
                    Ok(_) => applied += 1,
                    Err(se) if se.to_string().contains("already exists") => existed += 1,
                    Err(se) => {
                        return Err(se).with_context(|| {
                            format!(
                                "migration '{}': a statement failed while recovering from partial application",
                                key
                            )
                        })
                    }
                }
            }
            record_migration(pool, key, module, 0).await?;
            Ok(MigApply::Recovered { applied, existed })
        }
        Err(e) => Err(e).with_context(|| format!("Failed to apply migration '{}'", key)),
    }
}

/// Split a SQL script into individual statements on top-level semicolons,
/// ignoring semicolons inside single-quoted strings, dollar-quoted bodies
/// (`$$…$$` / `$tag$…$tag$`), and line/block comments. Used only by the
/// "already exists" recovery path in [`apply_and_record_migration`], so a
/// partially-applied migration's remaining statements can each be run alone.
pub(crate) fn split_sql_statements(sql: &str) -> Vec<String> {
    let b = sql.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    let mut start = 0usize;
    let mut out: Vec<String> = Vec::new();
    let mut push = |from: usize, to: usize| {
        let t = sql[from..to].trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
    };
    while i < n {
        match b[i] {
            b'\'' => {
                // single-quoted string; '' is an escaped quote
                i += 1;
                while i < n {
                    if b[i] == b'\'' {
                        if i + 1 < n && b[i + 1] == b'\'' {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'-' if i + 1 < n && b[i + 1] == b'-' => {
                i += 2;
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                i += 2;
                let mut depth = 1; // Postgres block comments nest
                while i < n && depth > 0 {
                    if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'$' => {
                if let Some(tag_end) = dollar_tag_end(b, i) {
                    let tag = &b[i..tag_end]; // "$$" or "$name$"
                    i = tag_end;
                    while i < n {
                        if b[i] == b'$' && i + tag.len() <= n && &b[i..i + tag.len()] == tag {
                            i += tag.len();
                            break;
                        }
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            b';' => {
                push(start, i);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    push(start, n);
    out
}

/// If `b[i]` (a `$`) begins a valid dollar-quote opening tag (`$$` or
/// `$ident$`), return the byte index just past its closing `$`; else `None`.
fn dollar_tag_end(b: &[u8], i: usize) -> Option<usize> {
    let n = b.len();
    let mut j = i + 1;
    if j < n && (b[j].is_ascii_alphabetic() || b[j] == b'_') {
        j += 1;
        while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
    }
    if j < n && b[j] == b'$' {
        Some(j + 1)
    } else {
        None
    }
}

pub async fn run(command: DbCommands) -> Result<()> {
    match command {
        DbCommands::Init { drop } => {
            if drop {
                println!("WARNING: This will drop all existing tables!");
            }
            println!("Initializing database...");
            let pool = get_db_pool().await?;
            init_migrations_table(&pool).await?;
            info!("Database initialization completed");
            println!("Database initialized successfully");
        }
        DbCommands::Migrate { target: _, all } => {
            if all {
                // Run migrations on all managed databases
                println!("Running migrations on all databases...");
                let database_url = std::env::var("DATABASE_URL")
                    .context("DATABASE_URL not set")?;
                let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);
                let admin_url = format!("{}/postgres", base_url);

                let admin_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                    .context("Failed to connect to postgres")?;

                let databases: Vec<(String,)> = sqlx::query_as(
                    "SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres') ORDER BY datname"
                )
                .fetch_all(&admin_pool)
                .await
                .context("Failed to list databases")?;

                for (db_name,) in &databases {
                    println!("\n--- Database: {} ---", db_name);
                    let db_url = format!("{}/{}", base_url, db_name);
                    match PgPoolOptions::new()
                        .max_connections(5)
                        .connect(&db_url)
                        .await
                    {
                        Ok(pool) => {
                            init_migrations_table(&pool).await?;
                            run_all_migrations(&pool).await?;
                            let (pa, ps) = run_plugin_migrations(&pool).await?;
                            if pa > 0 || ps > 0 {
                                println!(
                                    "  Plugin migrations: {} applied, {} skipped",
                                    pa, ps
                                );
                            }
                            // Sync this DB's apps list too.
                            let registry = build_migration_registry();
                            if let Ok((ins, upd)) = crate::commands::module_sync::sync_plugins_to_installed_modules(&pool, &registry).await {
                                if ins > 0 || upd > 0 {
                                    println!("  Apps list synced: {} new, {} refreshed", ins, upd);
                                }
                            }
                            // Project plugin `#[derive(Model)]` metadata into ir_model.
                            let synced = sync_model_registries(&pool, &registry).await;
                            if synced > 0 {
                                println!("  Model registry synced: {} model(s)", synced);
                            }
                        }
                        Err(e) => {
                            println!("  Warning: Could not connect to '{}': {}", db_name, e);
                        }
                    }
                }

                println!("\nAll databases migrated");
                return Ok(());
            }

            println!("Running migrations to latest...");
            let pool = get_db_pool().await?;

            // Ensure migrations table exists
            init_migrations_table(&pool).await?;

            // Find migrations directory
            let migrations_dir = Path::new("migrations");
            if !migrations_dir.exists() {
                println!("No migrations directory found.");
                return Ok(());
            }

            // Get list of migration directories sorted by name
            let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .collect();
            entries.sort_by_key(|e| e.file_name());

            let mut applied_count: usize = 0;
            let mut skipped_count: usize = 0;

            for entry in entries {
                let path = entry.path();
                let migration_name = path.file_name().unwrap().to_string_lossy().to_string();

                // Check if already applied
                if is_migration_applied(&pool, &migration_name).await? {
                    skipped_count += 1;
                    continue;
                }

                // Read metadata.toml
                let metadata_path = path.join("metadata.toml");
                let module = if metadata_path.exists() {
                    let content = std::fs::read_to_string(&metadata_path)?;
                    // Simple TOML parsing for module name
                    content
                        .lines()
                        .find(|line| line.starts_with("module"))
                        .and_then(|line| line.split('=').nth(1))
                        .map(|v| v.trim().trim_matches('"').to_string())
                        .unwrap_or_else(|| "core".to_string())
                } else {
                    "core".to_string()
                };

                // Read and execute postgres.sql
                let sql_path = path.join("postgres.sql");
                if !sql_path.exists() {
                    println!("  Skipping '{}' - no postgres.sql found", migration_name);
                    continue;
                }

                let sql = std::fs::read_to_string(&sql_path)?;

                println!("  Applying migration '{}'...", migration_name);
                match apply_and_record_migration(&pool, &migration_name, &module, &sql).await? {
                    MigApply::Applied(ms) => {
                        println!("  Applied '{}' ({}ms)", migration_name, ms);
                        applied_count += 1;
                    }
                    MigApply::Recovered { applied, existed } => {
                        println!(
                            "  Recovered '{}' — {} statement(s) applied, {} already present",
                            migration_name, applied, existed
                        );
                        if applied > 0 {
                            applied_count += 1;
                        } else {
                            skipped_count += 1;
                        }
                    }
                }
            }

            // ─── Plugin-declared migrations (Phase 0.6) ───────────
            // Walk every compiled-in plugin and apply any migrations
            // it embeds in its own crate. These live under
            // `crates/<plugin>/migrations/` and are registered via
            // `Plugin::migrations()` — no files in the host
            // `migrations/` directory.
            let (plugin_applied, plugin_skipped) = run_plugin_migrations(&pool).await?;
            applied_count += plugin_applied;
            skipped_count += plugin_skipped;

            // Register every compiled-in plugin in this DB's
            // `installed_modules` so new apps surface in Apps & Modules
            // (the CLI counterpart of the "Update Apps List" button).
            {
                let registry = build_migration_registry();
                match crate::commands::module_sync::sync_plugins_to_installed_modules(&pool, &registry).await {
                    Ok((ins, upd)) if ins > 0 || upd > 0 => {
                        println!("Apps list synced: {} new, {} refreshed", ins, upd)
                    }
                    Ok(_) => {}
                    Err(e) => println!("Warning: apps list sync failed: {}", e),
                }
                // Project plugin `#[derive(Model)]` metadata into ir_model /
                // ir_model_field so the generic views + REST API see it.
                let synced = sync_model_registries(&pool, &registry).await;
                if synced > 0 {
                    println!("Model registry synced: {} model(s)", synced);
                }
            }

            if applied_count > 0 {
                println!("\nApplied {} migration(s), skipped {} (already applied)", applied_count, skipped_count);
            } else if skipped_count > 0 {
                println!("All {} migrations already applied", skipped_count);
            } else {
                println!("No migrations to apply");
            }
            println!("Migrations completed");
        }
        DbCommands::Rollback { steps } => {
            println!("Rolling back {} migration(s)...", steps);
            let pool = get_db_pool().await?;

            // Get the last N applied migrations
            let migrations = sqlx::query(
                r#"
                SELECT name, module FROM vortex_migrations
                ORDER BY applied_at DESC
                LIMIT $1
                "#
            )
            .bind(steps as i32)
            .fetch_all(&pool)
            .await?;

            if migrations.is_empty() {
                println!("No migrations to rollback");
                return Ok(());
            }

            for row in migrations {
                let name: String = row.get("name");
                let module: String = row.get("module");

                // Check for down migration
                let down_path = Path::new("migrations")
                    .join(&name)
                    .join("postgres_down.sql");

                if down_path.exists() {
                    let sql = std::fs::read_to_string(&down_path)?;
                    println!("  Rolling back '{}'...", name);
                    sqlx::raw_sql(&sql).execute(&pool).await?;
                } else {
                    println!("  Warning: No rollback SQL for '{}' (module: {})", name, module);
                }

                // Remove from tracking
                sqlx::query("DELETE FROM vortex_migrations WHERE name = $1")
                    .bind(&name)
                    .execute(&pool)
                    .await?;

                println!("  Rolled back '{}'", name);
            }

            println!("Rollback completed");
        }
        DbCommands::Status => {
            let pool = get_db_pool().await?;

            // Check if migrations table exists
            let table_exists = sqlx::query(
                "SELECT 1 FROM information_schema.tables WHERE table_name = 'vortex_migrations'"
            )
            .fetch_optional(&pool)
            .await?
            .is_some();

            if !table_exists {
                println!("Migration Status: Not initialized");
                println!("Run 'vortex db init' first");
                return Ok(());
            }

            // Get applied migrations
            let applied = sqlx::query(
                r#"
                SELECT name, module, applied_at, execution_time_ms
                FROM vortex_migrations
                ORDER BY applied_at
                "#
            )
            .fetch_all(&pool)
            .await?;

            println!("\nMigration Status:");
            println!("─────────────────────────────────────────────────────────────────────────");
            println!("{:<30} {:<15} {:<25} {:<10}", "Migration", "Module", "Applied At", "Time (ms)");
            println!("─────────────────────────────────────────────────────────────────────────");

            if applied.is_empty() {
                println!("No migrations applied yet");
            } else {
                for row in &applied {
                    let name: String = row.get("name");
                    let module: String = row.get("module");
                    let applied_at: chrono::DateTime<chrono::Utc> = row.get("applied_at");
                    let time_ms: i32 = row.get("execution_time_ms");

                    println!(
                        "{:<30} {:<15} {:<25} {:<10}",
                        name,
                        module,
                        applied_at.format("%Y-%m-%d %H:%M:%S"),
                        time_ms
                    );
                }
            }

            // Check for pending migrations
            let migrations_dir = Path::new("migrations");
            if migrations_dir.exists() {
                let mut pending = Vec::new();
                for entry in std::fs::read_dir(migrations_dir)? {
                    let entry = entry?;
                    if entry.path().is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let is_applied = applied.iter().any(|r| r.get::<String, _>("name") == name);
                        if !is_applied {
                            pending.push(name);
                        }
                    }
                }

                if !pending.is_empty() {
                    pending.sort();
                    println!("\nPending migrations:");
                    for name in pending {
                        println!("  - {}", name);
                    }
                }
            }

            println!();
        }
        DbCommands::CreateMigration { name, module } => {
            // Find next migration number
            let migrations_dir = Path::new("migrations");
            let mut max_num = 0;

            if migrations_dir.exists() {
                for entry in std::fs::read_dir(migrations_dir)? {
                    let entry = entry?;
                    if entry.path().is_dir() {
                        let dir_name = entry.file_name().to_string_lossy().to_string();
                        if let Some(num_str) = dir_name.split('_').next() {
                            if let Ok(num) = num_str.parse::<u32>() {
                                max_num = max_num.max(num);
                            }
                        }
                    }
                }
            }

            let migration_num = max_num + 1;
            let migration_name = format!("{:03}_{}", migration_num, name);
            let migration_path = migrations_dir.join(&migration_name);

            // Create directory
            std::fs::create_dir_all(&migration_path)?;

            // Create metadata.toml
            let metadata = format!(
                r#"# Migration metadata for {}
module = "{}"
description = ""
reversible = true
dependencies = []
"#,
                migration_name, module
            );
            std::fs::write(migration_path.join("metadata.toml"), metadata)?;

            // Create postgres.sql template
            let sql_template = format!(
                r#"-- Migration: {}
-- Module: {}
-- Created: {}

-- Add your migration SQL here

"#,
                migration_name,
                module,
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            );
            std::fs::write(migration_path.join("postgres.sql"), sql_template)?;

            println!("Created migration: {}", migration_path.display());
            println!("  - postgres.sql: Add your migration SQL here");
            println!("  - metadata.toml: Edit description and dependencies");
        }

        DbCommands::Create { name, demo } => {
            println!("Creating database '{}'...", name);
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?;
            let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);
            let admin_url = format!("{}/postgres", base_url);

            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await
                .context("Failed to connect to postgres")?;

            let create_sql = format!("CREATE DATABASE \"{}\"", name);
            sqlx::query(&create_sql)
                .execute(&admin_pool)
                .await
                .context("Failed to create database")?;

            println!("Database '{}' created", name);

            // Run migrations on the new database
            let db_url = format!("{}/{}", base_url, name);
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&db_url)
                .await
                .context("Failed to connect to new database")?;

            init_migrations_table(&pool).await?;
            run_all_migrations(&pool).await?;

            if demo {
                println!("Demo data seeding not yet implemented");
            }

            println!("Database '{}' is ready", name);
        }

        DbCommands::List => {
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?;
            let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);
            let admin_url = format!("{}/postgres", base_url);

            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await
                .context("Failed to connect to postgres")?;

            let databases: Vec<(String,)> = sqlx::query_as(
                "SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres') ORDER BY datname"
            )
            .fetch_all(&admin_pool)
            .await
            .context("Failed to list databases")?;

            println!("\nDatabases:");
            println!("{:<30} {:<10}", "Name", "Status");
            println!("{}", "─".repeat(40));
            for (name,) in databases {
                println!("{:<30} {:<10}", name, "active");
            }
            println!();
        }

        DbCommands::Delete { name, force } => {
            if !force {
                println!("WARNING: This will permanently delete database '{}'!", name);
                println!("Use --force to skip this confirmation.");
                return Ok(());
            }

            println!("Deleting database '{}'...", name);
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?;
            let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);
            let admin_url = format!("{}/postgres", base_url);

            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await
                .context("Failed to connect to postgres")?;

            // Terminate connections
            let _ = sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid != pg_backend_pid()")
                .bind(&name)
                .execute(&admin_pool)
                .await;

            let drop_sql = format!("DROP DATABASE IF EXISTS \"{}\"", name);
            sqlx::query(&drop_sql)
                .execute(&admin_pool)
                .await
                .context("Failed to drop database")?;

            println!("Database '{}' deleted", name);
        }

        DbCommands::Backup { name, output } => {
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?;
            let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);
            let db_url = format!("{}/{}", base_url, name);

            let output_file = output.unwrap_or_else(|| {
                format!("{name}_{}.backup", chrono::Utc::now().format("%Y%m%d_%H%M%S"))
            });

            println!("Backing up database '{}' to '{}'...", name, output_file);

            let status = std::process::Command::new("pg_dump")
                .arg("--format=custom")
                .arg("--file")
                .arg(&output_file)
                .arg(&db_url)
                .status()
                .context("Failed to run pg_dump")?;

            if status.success() {
                println!("Backup saved to '{}'", output_file);
            } else {
                anyhow::bail!("pg_dump failed with exit code: {:?}", status.code());
            }
        }

        DbCommands::Restore { file, name } => {
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?;
            let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);

            let db_name = name.unwrap_or_else(|| {
                Path::new(&file)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.split('_').next())
                    .unwrap_or("restored")
                    .to_string()
            });

            println!("Restoring '{}' to database '{}'...", file, db_name);

            // Create the database
            let admin_url = format!("{}/postgres", base_url);
            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await
                .context("Failed to connect to postgres")?;

            let create_sql = format!("CREATE DATABASE \"{}\"", db_name);
            let _ = sqlx::query(&create_sql).execute(&admin_pool).await;

            // Restore
            let db_url = format!("{}/{}", base_url, db_name);
            let status = std::process::Command::new("pg_restore")
                .arg("--no-owner")
                .arg("--no-acl")
                .arg("-d")
                .arg(&db_url)
                .arg(&file)
                .status()
                .context("Failed to run pg_restore")?;

            if status.success() || status.code() == Some(1) {
                println!("Database '{}' restored from '{}'", db_name, file);
            } else {
                anyhow::bail!("pg_restore failed with exit code: {:?}", status.code());
            }
        }

        DbCommands::Duplicate { source, target } => {
            println!("Duplicating '{}' to '{}'...", source, target);
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?;
            let base_url = database_url.rsplitn(2, '/').nth(1).unwrap_or(&database_url);
            let admin_url = format!("{}/postgres", base_url);

            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await
                .context("Failed to connect to postgres")?;

            // Terminate connections to source
            let _ = sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid != pg_backend_pid()")
                .bind(&source)
                .execute(&admin_pool)
                .await;

            let dup_sql = format!("CREATE DATABASE \"{}\" WITH TEMPLATE \"{}\"", target, source);
            sqlx::query(&dup_sql)
                .execute(&admin_pool)
                .await
                .context("Failed to duplicate database")?;

            println!("Database '{}' duplicated to '{}'", source, target);
        }
    }
    Ok(())
}

/// Run all pending migrations from the migrations/ directory.
/// Apply every plugin-declared migration that has not yet been
/// recorded. Runs **after** the core filesystem migrations so that
/// a plugin's `requires_core_migration` dependency is guaranteed
/// to be present.
///
/// Uses the composite `<module>:<name>` key in `vortex_migrations`
/// so plugin migrations never collide with core or with each other.
/// Falls back to the "object already exists → record as applied"
/// path that the core filesystem runner uses, which is how a dev DB
/// that was populated by the old filesystem layout transitions to
/// the plugin-declared layout cleanly.
async fn run_plugin_migrations(pool: &PgPool) -> Result<(usize, usize)> {
    let registry = build_migration_registry();
    let mut applied = 0usize;
    let mut skipped = 0usize;

    for plugin in registry.plugins_iter() {
        let module = plugin.technical_name();
        let migrations = plugin.migrations();
        if migrations.is_empty() {
            continue;
        }

        // Don't re-provision a module the tenant has explicitly uninstalled —
        // a proper uninstall drops its schema and deletes its migration records,
        // so without this gate the next `migrate` would recreate everything it
        // removed. A module ABSENT from installed_modules (a brand-new DB, or a
        // plugin seen for the first time) still provisions, so initial tenant
        // provisioning is unchanged. Best-effort: on any query error, provision.
        let uninstalled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM installed_modules WHERE technical_name = $1 AND state = 'uninstalled')",
        )
        .bind(module)
        .fetch_one(pool)
        .await
        .unwrap_or(false);
        if uninstalled {
            println!("  Skipping '{}' — module is uninstalled in this database", module);
            continue;
        }

        // Verify each required core migration is present before we
        // run any of this plugin's SQL. Fail fast with a clear error
        // — otherwise we'd get a confusing `relation "..." does not
        // exist` deep inside the plugin's SQL.
        for mig in &migrations {
            if let Some(required) = mig.requires_core_migration {
                let ok: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vortex_migrations WHERE name = $1)")
                        .bind(required)
                        .fetch_one(pool)
                        .await?;
                if !ok {
                    anyhow::bail!(
                        "plugin '{}' migration '{}' requires core migration '{}' which has not been applied. Run `vortex db migrate` to apply core migrations first.",
                        module,
                        mig.name,
                        required
                    );
                }
            }
        }

        for mig in migrations {
            let key = plugin_migration_key(module, mig.name);

            if is_migration_applied(pool, &key).await? {
                skipped += 1;
                continue;
            }

            println!("  Applying plugin migration '{}'...", key);
            match apply_and_record_migration(pool, &key, module, mig.up_sql).await? {
                MigApply::Applied(ms) => {
                    println!("  Applied '{}' ({}ms)", key, ms);
                    applied += 1;
                }
                MigApply::Recovered { applied: a, existed } => {
                    println!("  Recovered '{}' — {} applied, {} already present", key, a, existed);
                    if a > 0 {
                        applied += 1;
                    } else {
                        skipped += 1;
                    }
                }
            }
        }
    }

    Ok((applied, skipped))
}

/// Provision a single plugin's schema into `pool` — a specific tenant
/// database. Ensures the migration-tracking table exists, then applies
/// that plugin's `Plugin::migrations()` idempotently and records each.
/// Returns `(applied, skipped)`. No-op (`(0, 0)`) when `technical_name`
/// is not a compiled-in plugin (e.g. a core module) or has no migrations.
///
/// This is what the Apps & Modules "Install" action calls so that
/// installing a module in a tenant DB actually creates its tables there,
/// rather than only flipping the `installed_modules` flag.
pub async fn install_plugin_schema(pool: &PgPool, technical_name: &str) -> Result<(usize, usize)> {
    init_migrations_table(pool).await?;

    let registry = build_migration_registry();
    let Some(plugin) = registry
        .plugins_iter()
        .find(|p| p.technical_name() == technical_name)
    else {
        return Ok((0, 0));
    };

    let migrations = plugin.migrations();
    if migrations.is_empty() {
        return Ok((0, 0));
    }

    // Fail fast if a required core migration is missing from this DB.
    for mig in &migrations {
        if let Some(required) = mig.requires_core_migration {
            let ok: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vortex_migrations WHERE name = $1)")
                    .bind(required)
                    .fetch_one(pool)
                    .await?;
            if !ok {
                anyhow::bail!(
                    "module '{}' requires core migration '{}', which is not applied to this database. Run `vortex db migrate` against it first.",
                    technical_name,
                    required
                );
            }
        }
    }

    let module = plugin.technical_name();
    let mut applied = 0usize;
    let mut skipped = 0usize;
    for mig in migrations {
        let key = plugin_migration_key(module, mig.name);
        if is_migration_applied(pool, &key).await? {
            skipped += 1;
            continue;
        }
        match apply_and_record_migration(pool, &key, module, mig.up_sql).await? {
            MigApply::Applied(_) => applied += 1,
            MigApply::Recovered { applied: a, .. } => {
                if a > 0 {
                    applied += 1;
                } else {
                    skipped += 1;
                }
            }
        }
    }

    // Project this plugin's `#[derive(Model)]` metadata into the registry so
    // installing a module also wires its generic views + REST API.
    let metas = plugin.models();
    if !metas.is_empty() {
        if let Err(e) = vortex_orm::registry_sync::sync_model_registry(pool, &metas).await {
            println!(
                "  Warning: model registry sync for '{}' failed: {}",
                technical_name, e
            );
        }
    }

    Ok((applied, skipped))
}

async fn run_all_migrations(pool: &PgPool) -> Result<()> {
    let migrations_dir = Path::new("migrations");
    if !migrations_dir.exists() {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let migration_name = path.file_name().unwrap().to_string_lossy().to_string();

        if is_migration_applied(pool, &migration_name).await? {
            continue;
        }

        let metadata_path = path.join("metadata.toml");
        let module = if metadata_path.exists() {
            let content = std::fs::read_to_string(&metadata_path)?;
            content
                .lines()
                .find(|line| line.starts_with("module"))
                .and_then(|line| line.split('=').nth(1))
                .map(|v| v.trim().trim_matches('"').to_string())
                .unwrap_or_else(|| "core".to_string())
        } else {
            "core".to_string()
        };

        let sql_path = path.join("postgres.sql");
        if !sql_path.exists() {
            continue;
        }

        let sql = std::fs::read_to_string(&sql_path)?;
        println!("  Applying migration '{}'...", migration_name);
        match apply_and_record_migration(pool, &migration_name, &module, &sql).await? {
            MigApply::Applied(ms) => println!("  Applied '{}' ({}ms)", migration_name, ms),
            MigApply::Recovered { applied, existed } => println!(
                "  Recovered '{}' — {} applied, {} already present",
                migration_name, applied, existed
            ),
        }
    }

    // Apply plugin-declared migrations after the core filesystem
    // ones. Same pattern as the single-DB path above.
    let _ = run_plugin_migrations(pool).await?;

    // Project plugin model metadata into ir_model / ir_model_field.
    let _ = sync_model_registries(pool, &build_migration_registry()).await;
    Ok(())
}

#[cfg(test)]
mod split_sql_tests {
    use super::split_sql_statements;

    #[test]
    fn plain_statements() {
        let s = split_sql_statements("CREATE TABLE a (id int); ALTER TABLE b ADD COLUMN c int;");
        assert_eq!(s, vec!["CREATE TABLE a (id int)", "ALTER TABLE b ADD COLUMN c int"]);
    }

    #[test]
    fn trailing_statement_without_semicolon() {
        let s = split_sql_statements("SELECT 1;\nSELECT 2");
        assert_eq!(s, vec!["SELECT 1", "SELECT 2"]);
    }

    #[test]
    fn semicolon_inside_single_quoted_string_is_ignored() {
        let s = split_sql_statements("INSERT INTO t VALUES ('a;b;c'); SELECT 1;");
        assert_eq!(s, vec!["INSERT INTO t VALUES ('a;b;c')", "SELECT 1"]);
    }

    #[test]
    fn escaped_quote_inside_string() {
        let s = split_sql_statements("INSERT INTO t VALUES ('O''Brien; Co'); SELECT 2;");
        assert_eq!(s, vec!["INSERT INTO t VALUES ('O''Brien; Co')", "SELECT 2"]);
    }

    #[test]
    fn dollar_quoted_body_with_semicolons() {
        let sql = "CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN a := 1; b := 2; RETURN NEW; END $$ LANGUAGE plpgsql; SELECT 9;";
        let s = split_sql_statements(sql);
        assert_eq!(s.len(), 2, "function body semicolons must not split: {:?}", s);
        assert!(s[0].contains("$$ BEGIN a := 1; b := 2;"));
        assert_eq!(s[1], "SELECT 9");
    }

    #[test]
    fn tagged_dollar_quote() {
        let sql = "DO $mig$ BEGIN PERFORM 1; PERFORM 2; END $mig$; CREATE INDEX i ON t (c);";
        let s = split_sql_statements(sql);
        assert_eq!(s.len(), 2);
        assert!(s[0].contains("$mig$"));
        assert_eq!(s[1], "CREATE INDEX i ON t (c)");
    }

    #[test]
    fn line_and_block_comments_with_semicolons() {
        let sql = "-- a; b; c\nSELECT 1; /* x; y */ SELECT 2;";
        let s = split_sql_statements(sql);
        assert_eq!(s.len(), 2);
        assert!(s[0].contains("SELECT 1"));
        assert!(s[1].contains("SELECT 2"));
    }

    #[test]
    fn empty_and_whitespace_only_statements_dropped() {
        let s = split_sql_statements(";\n  ;\nSELECT 1;;\n");
        assert_eq!(s, vec!["SELECT 1"]);
    }
}
