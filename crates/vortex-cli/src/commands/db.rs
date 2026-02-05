//! Database commands

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tracing::info;
use std::path::Path;

use crate::DbCommands;

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
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
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
        VALUES (uuid_generate_v4(), $1, $2, $3, $4)
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

            let mut applied_count = 0;
            let mut skipped_count = 0;

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
                let start = std::time::Instant::now();

                // Execute migration - use raw_sql for multiple statements
                let result = sqlx::raw_sql(&sql)
                    .execute(&pool)
                    .await;

                let elapsed = start.elapsed().as_millis() as i32;

                match result {
                    Ok(_) => {
                        // Record migration
                        record_migration(&pool, &migration_name, &module, elapsed).await?;
                        println!("  Applied '{}' ({}ms)", migration_name, elapsed);
                        applied_count += 1;
                    }
                    Err(e) => {
                        let err_msg = e.to_string();
                        // Check if error is "already exists" - mark as applied
                        if err_msg.contains("already exists") {
                            println!("  Migration '{}' objects already exist, marking as applied", migration_name);
                            record_migration(&pool, &migration_name, &module, 0).await?;
                            skipped_count += 1;
                        } else {
                            return Err(e).with_context(|| format!("Failed to apply migration '{}'", migration_name));
                        }
                    }
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
        let start = std::time::Instant::now();

        match sqlx::raw_sql(&sql).execute(pool).await {
            Ok(_) => {
                let elapsed = start.elapsed().as_millis() as i32;
                record_migration(pool, &migration_name, &module, elapsed).await?;
                println!("  Applied '{}' ({}ms)", migration_name, elapsed);
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("already exists") {
                    record_migration(pool, &migration_name, &module, 0).await?;
                } else {
                    return Err(e).with_context(|| format!("Failed to apply migration '{}'", migration_name));
                }
            }
        }
    }
    Ok(())
}
