//! Module management commands
//!
//! Implements Odoo-style per-database module installation.

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tracing::info;

use crate::ModuleCommands;

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

/// Check if module registry tables exist
async fn check_module_registry_exists(pool: &PgPool) -> Result<bool> {
    let result = sqlx::query(
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'installed_modules'"
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.is_some())
}

pub async fn run(command: ModuleCommands) -> Result<()> {
    let pool = get_db_pool().await?;

    // Check if module registry tables exist
    if !check_module_registry_exists(&pool).await? {
        eprintln!("Error: Module registry not initialized.");
        eprintln!("Run migrations first: vortex db migrate");
        return Ok(());
    }

    match command {
        ModuleCommands::List { installed } => {
            list_modules(&pool, installed).await?;
        }
        ModuleCommands::Install { module_id, no_deps } => {
            install_module(&pool, &module_id, no_deps).await?;
        }
        ModuleCommands::Uninstall { module_id } => {
            uninstall_module(&pool, &module_id).await?;
        }
        ModuleCommands::Upgrade { module_id } => {
            upgrade_module(&pool, &module_id).await?;
        }
        ModuleCommands::Info { module_id } => {
            show_module_info(&pool, &module_id).await?;
        }
    }

    Ok(())
}

/// List all modules or only installed ones
async fn list_modules(pool: &PgPool, installed_only: bool) -> Result<()> {
    let query = if installed_only {
        r#"
        SELECT technical_name, name, version, state, category, summary, is_core, application
        FROM installed_modules
        WHERE state = 'installed'
        ORDER BY sequence, name
        "#
    } else {
        r#"
        SELECT technical_name, name, version, state, category, summary, is_core, application
        FROM installed_modules
        ORDER BY sequence, name
        "#
    };

    let rows = sqlx::query(query).fetch_all(pool).await?;

    if installed_only {
        println!("\nInstalled Modules:");
    } else {
        println!("\nAll Modules:");
    }
    println!("─────────────────────────────────────────────────────────────────────────");
    println!("{:<20} {:<25} {:<10} {:<12} {:<10}", "ID", "Name", "Version", "State", "Category");
    println!("─────────────────────────────────────────────────────────────────────────");

    if rows.is_empty() {
        println!("No modules found.");
    } else {
        for row in &rows {
            let technical_name: String = row.get("technical_name");
            let name: String = row.get("name");
            let version: String = row.get("version");
            let state: String = row.get("state");
            let category: Option<String> = row.get("category");
            let is_core: bool = row.get("is_core");
            let application: bool = row.get("application");

            let state_display = match state.as_str() {
                "installed" => format!("\x1b[32m{}\x1b[0m", state),  // Green
                "uninstalled" => format!("\x1b[90m{}\x1b[0m", state), // Gray
                "to_install" => format!("\x1b[33m{}\x1b[0m", state),  // Yellow
                "to_upgrade" => format!("\x1b[33m{}\x1b[0m", state),  // Yellow
                "to_remove" => format!("\x1b[31m{}\x1b[0m", state),   // Red
                _ => state.clone(),
            };

            let name_display = if is_core {
                format!("{} [core]", name)
            } else if application {
                format!("{} [app]", name)
            } else {
                name
            };

            println!(
                "{:<20} {:<25} {:<10} {:<12} {:<10}",
                technical_name,
                name_display,
                version,
                state_display,
                category.unwrap_or_else(|| "-".to_string())
            );
        }
    }

    println!();
    Ok(())
}

/// Install a module
async fn install_module(pool: &PgPool, module_id: &str, skip_deps: bool) -> Result<()> {
    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state, is_core FROM installed_modules WHERE technical_name = $1"
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await?;

    let Some(module) = module else {
        eprintln!("Error: Module '{}' not found.", module_id);
        eprintln!("\nAvailable modules:");
        list_modules(pool, false).await?;
        return Ok(());
    };

    let state: String = module.get("state");
    let name: String = module.get("name");

    if state == "installed" {
        println!("Module '{}' ({}) is already installed.", module_id, name);
        return Ok(());
    }

    // Check dependencies
    if !skip_deps {
        let deps = sqlx::query(
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
        .bind(module_id)
        .fetch_all(pool)
        .await?;

        let mut missing_deps = Vec::new();
        for dep in &deps {
            let depends_on: String = dep.get("depends_on");
            let is_satisfied: bool = dep.get("is_satisfied");
            if !is_satisfied {
                missing_deps.push(depends_on);
            }
        }

        if !missing_deps.is_empty() {
            println!("Installing dependencies first: {}", missing_deps.join(", "));
            for dep in &missing_deps {
                // Recursively install dependencies
                Box::pin(install_module(pool, dep, false)).await?;
            }
        }
    }

    println!("Installing module '{}' ({})...", module_id, name);

    // Update state to 'to_install'
    sqlx::query("UPDATE installed_modules SET state = 'to_install' WHERE technical_name = $1")
        .bind(module_id)
        .execute(pool)
        .await?;

    // Run module migrations
    run_module_migrations(pool, module_id).await?;

    // Update state to 'installed'
    sqlx::query(
        r#"
        UPDATE installed_modules
        SET state = 'installed', installed_at = NOW(), updated_at = NOW()
        WHERE technical_name = $1
        "#
    )
    .bind(module_id)
    .execute(pool)
    .await?;

    info!("Module '{}' installed successfully", module_id);
    println!("\x1b[32mModule '{}' ({}) installed successfully.\x1b[0m", module_id, name);

    Ok(())
}

/// Run migrations for a specific module
async fn run_module_migrations(pool: &PgPool, module_id: &str) -> Result<()> {
    // Find migrations for this module
    let migrations_dir = std::path::Path::new("migrations");

    if !migrations_dir.exists() {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Read metadata.toml
        let metadata_path = path.join("metadata.toml");
        if !metadata_path.exists() {
            continue;
        }

        let metadata_content = std::fs::read_to_string(&metadata_path)?;

        // Simple TOML parsing for module name
        let mut migration_module = String::new();
        for line in metadata_content.lines() {
            if line.starts_with("module") {
                if let Some(value) = line.split('=').nth(1) {
                    migration_module = value.trim().trim_matches('"').to_string();
                    break;
                }
            }
        }

        if migration_module != module_id {
            continue;
        }

        let migration_name = path.file_name().unwrap().to_string_lossy().to_string();

        // Check if already applied
        let applied = sqlx::query(
            r#"
            SELECT 1 FROM module_migrations mm
            JOIN installed_modules im ON im.id = mm.module_id
            WHERE im.technical_name = $1 AND mm.migration_name = $2
            "#
        )
        .bind(module_id)
        .bind(&migration_name)
        .fetch_optional(pool)
        .await?;

        if applied.is_some() {
            println!("  Migration '{}' already applied", migration_name);
            continue;
        }

        // Read and execute migration
        let sql_path = path.join("postgres.sql");
        if !sql_path.exists() {
            println!("  Warning: No postgres.sql found for migration '{}'", migration_name);
            continue;
        }

        let sql = std::fs::read_to_string(&sql_path)?;
        println!("  Running migration '{}'...", migration_name);

        let start = std::time::Instant::now();
        let result = sqlx::raw_sql(&sql).execute(pool).await;
        let elapsed = start.elapsed().as_millis() as i32;

        // Handle result - if objects already exist, mark as applied anyway
        let should_record = match result {
            Ok(_) => {
                println!("  Migration '{}' completed ({}ms)", migration_name, elapsed);
                true
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("already exists") {
                    println!("  Migration '{}' objects already exist, marking as applied", migration_name);
                    true
                } else {
                    return Err(e.into());
                }
            }
        };

        if should_record {
            // Record migration
            let module_row = sqlx::query("SELECT id FROM installed_modules WHERE technical_name = $1")
                .bind(module_id)
                .fetch_one(pool)
                .await?;
            let module_uuid: uuid::Uuid = module_row.get("id");

            sqlx::query(
                r#"
                INSERT INTO module_migrations (id, module_id, migration_name, execution_time_ms)
                VALUES ($1, $2, $3, $4)
                "#
            )
            .bind(uuid::Uuid::now_v7())
            .bind(module_uuid)
            .bind(&migration_name)
            .bind(elapsed)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// Uninstall a module
async fn uninstall_module(pool: &PgPool, module_id: &str) -> Result<()> {
    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state, is_core FROM installed_modules WHERE technical_name = $1"
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await?;

    let Some(module) = module else {
        eprintln!("Error: Module '{}' not found.", module_id);
        return Ok(());
    };

    let state: String = module.get("state");
    let name: String = module.get("name");
    let is_core: bool = module.get("is_core");

    if state != "installed" {
        println!("Module '{}' ({}) is not installed.", module_id, name);
        return Ok(());
    }

    if is_core {
        eprintln!("Error: Cannot uninstall core module '{}'.", module_id);
        return Ok(());
    }

    // Check if any installed module depends on this one
    let dependents = sqlx::query(
        r#"
        SELECT im.technical_name, im.name
        FROM installed_modules im
        JOIN module_dependencies md ON md.module_id = im.id
        WHERE md.depends_on = $1
        AND im.state = 'installed'
        AND md.optional = false
        "#
    )
    .bind(module_id)
    .fetch_all(pool)
    .await?;

    if !dependents.is_empty() {
        eprintln!("Error: Cannot uninstall '{}'. The following modules depend on it:", module_id);
        for dep in &dependents {
            let tech_name: String = dep.get("technical_name");
            let dep_name: String = dep.get("name");
            eprintln!("  - {} ({})", tech_name, dep_name);
        }
        eprintln!("\nUninstall dependent modules first.");
        return Ok(());
    }

    println!("Uninstalling module '{}' ({})...", module_id, name);

    // Update state to 'to_remove'
    sqlx::query("UPDATE installed_modules SET state = 'to_remove' WHERE technical_name = $1")
        .bind(module_id)
        .execute(pool)
        .await?;

    // Note: In a full implementation, we would also:
    // 1. Remove module data (from module_data table)
    // 2. Drop module tables
    // 3. Remove module migrations
    // For now, we just mark it as uninstalled

    // Update state to 'uninstalled'
    sqlx::query(
        r#"
        UPDATE installed_modules
        SET state = 'uninstalled', updated_at = NOW()
        WHERE technical_name = $1
        "#
    )
    .bind(module_id)
    .execute(pool)
    .await?;

    info!("Module '{}' uninstalled", module_id);
    println!("\x1b[33mModule '{}' ({}) uninstalled.\x1b[0m", module_id, name);
    println!("Note: Database tables created by this module have NOT been removed.");
    println!("To fully remove, manually drop the tables and delete module migrations.");

    Ok(())
}

/// Upgrade a module
async fn upgrade_module(pool: &PgPool, module_id: &str) -> Result<()> {
    if module_id == "all" {
        println!("Upgrading all installed modules...");

        let modules = sqlx::query(
            "SELECT technical_name FROM installed_modules WHERE state = 'installed' ORDER BY sequence"
        )
        .fetch_all(pool)
        .await?;

        for module in modules {
            let tech_name: String = module.get("technical_name");
            upgrade_single_module(pool, &tech_name).await?;
        }

        println!("\nAll modules upgraded.");
    } else {
        upgrade_single_module(pool, module_id).await?;
    }

    Ok(())
}

async fn upgrade_single_module(pool: &PgPool, module_id: &str) -> Result<()> {
    // Check if module exists and is installed
    let module = sqlx::query(
        "SELECT technical_name, name, state, version FROM installed_modules WHERE technical_name = $1"
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await?;

    let Some(module) = module else {
        eprintln!("Error: Module '{}' not found.", module_id);
        return Ok(());
    };

    let state: String = module.get("state");
    let name: String = module.get("name");
    let version: String = module.get("version");

    if state != "installed" {
        println!("Module '{}' is not installed (state: {}). Skipping.", module_id, state);
        return Ok(());
    }

    println!("Upgrading module '{}' ({}) v{}...", module_id, name, version);

    // Update state to 'to_upgrade'
    sqlx::query("UPDATE installed_modules SET state = 'to_upgrade' WHERE technical_name = $1")
        .bind(module_id)
        .execute(pool)
        .await?;

    // Run any new migrations
    run_module_migrations(pool, module_id).await?;

    // Update state back to 'installed'
    sqlx::query(
        r#"
        UPDATE installed_modules
        SET state = 'installed', updated_at = NOW()
        WHERE technical_name = $1
        "#
    )
    .bind(module_id)
    .execute(pool)
    .await?;

    println!("Module '{}' upgraded.", module_id);
    Ok(())
}

/// Show module information
async fn show_module_info(pool: &PgPool, module_id: &str) -> Result<()> {
    let module = sqlx::query(
        r#"
        SELECT technical_name, name, version, state, category, summary, description,
               author, website, license, is_core, auto_install, application,
               installed_at, updated_at, sequence
        FROM installed_modules
        WHERE technical_name = $1
        "#
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await?;

    let Some(module) = module else {
        eprintln!("Error: Module '{}' not found.", module_id);
        return Ok(());
    };

    let technical_name: String = module.get("technical_name");
    let name: String = module.get("name");
    let version: String = module.get("version");
    let state: String = module.get("state");
    let category: Option<String> = module.get("category");
    let summary: Option<String> = module.get("summary");
    let description: Option<String> = module.get("description");
    let author: Option<String> = module.get("author");
    let website: Option<String> = module.get("website");
    let license: Option<String> = module.get("license");
    let is_core: bool = module.get("is_core");
    let auto_install: bool = module.get("auto_install");
    let application: bool = module.get("application");
    let installed_at: Option<chrono::DateTime<chrono::Utc>> = module.get("installed_at");

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║ Module: {:<54} ║", name);
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║ Technical Name: {:<46} ║", technical_name);
    println!("║ Version:        {:<46} ║", version);
    println!("║ State:          {:<46} ║", state);
    println!("║ Category:       {:<46} ║", category.unwrap_or("-".to_string()));
    println!("╠═══════════════════════════════════════════════════════════════╣");

    if let Some(s) = summary {
        println!("║ Summary: {:<53} ║", s);
    }

    println!("║ Core Module:    {:<46} ║", if is_core { "Yes" } else { "No" });
    println!("║ Application:    {:<46} ║", if application { "Yes" } else { "No" });
    println!("║ Auto Install:   {:<46} ║", if auto_install { "Yes" } else { "No" });

    if let Some(a) = author {
        println!("║ Author:         {:<46} ║", a);
    }
    if let Some(w) = website {
        println!("║ Website:        {:<46} ║", w);
    }
    if let Some(l) = license {
        println!("║ License:        {:<46} ║", l);
    }

    if let Some(installed) = installed_at {
        println!("║ Installed:      {:<46} ║", installed.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    println!("╠═══════════════════════════════════════════════════════════════╣");

    // Show dependencies
    let deps = sqlx::query(
        r#"
        SELECT md.depends_on, md.optional, md.version_constraint,
               COALESCE(im2.state, 'not_found') as dep_state
        FROM module_dependencies md
        JOIN installed_modules im ON im.id = md.module_id
        LEFT JOIN installed_modules im2 ON im2.technical_name = md.depends_on
        WHERE im.technical_name = $1
        "#
    )
    .bind(module_id)
    .fetch_all(pool)
    .await?;

    if !deps.is_empty() {
        println!("║ Dependencies:                                                 ║");
        for dep in &deps {
            let depends_on: String = dep.get("depends_on");
            let optional: bool = dep.get("optional");
            let dep_state: String = dep.get("dep_state");
            let status = if dep_state == "installed" {
                "\x1b[32m✓\x1b[0m"
            } else if dep_state == "not_found" {
                "\x1b[31m✗\x1b[0m"
            } else {
                "\x1b[33m○\x1b[0m"
            };
            let opt = if optional { " (optional)" } else { "" };
            println!("║   {} {:<56} ║", status, format!("{}{}", depends_on, opt));
        }
    } else {
        println!("║ Dependencies: None                                            ║");
    }

    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    if let Some(desc) = description {
        if !desc.is_empty() {
            println!("Description:");
            println!("{}", desc);
            println!();
        }
    }

    Ok(())
}
