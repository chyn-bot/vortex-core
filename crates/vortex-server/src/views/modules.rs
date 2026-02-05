//! Module manager views
//!
//! Web-based module/app installation manager similar to Odoo's Apps menu.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sqlx::Row;
use vortex_common::Context;

use super::common::generate_csrf_token;
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

/// Module data for display in the list
#[derive(Debug, Clone, Serialize)]
pub struct ModuleDisplay {
    pub id: String,
    pub technical_name: String,
    pub name: String,
    pub version: String,
    pub state: String,
    pub category: String,
    pub summary: String,
    pub description: String,
    pub author: String,
    pub is_core: bool,
    pub application: bool,
    pub icon: String,
    pub initial: String,
    pub installed_at: Option<String>,
    pub dependencies: Vec<ModuleDependency>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleDependency {
    pub name: String,
    pub is_satisfied: bool,
    pub optional: bool,
}

/// Module list page template
#[derive(Template)]
#[template(path = "pages/modules.html")]
pub struct ModulesListTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub modules: Vec<ModuleDisplay>,
    pub installed_count: usize,
    pub available_count: usize,
    pub filter: String,
}

/// API response for module operations
#[derive(Debug, Serialize)]
pub struct ModuleOperationResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// List all modules (web page)
pub async fn modules_list(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    modules_list_with_filter(State(state), axum::Extension(ctx), Path("all".to_string())).await
}

/// List modules with filter (all, installed, available)
pub async fn modules_list_with_filter(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(filter): Path<String>,
) -> Response {
    let current_user_id = match ctx.user_id {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Html("Unauthorized")).into_response(),
    };

    let current_user_name = crate::db::user_lookup::get_user_display_name(&state.db, current_user_id)
        .await
        .unwrap_or_else(|_| "User".to_string());

    let user_initials = current_user_name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();

    // Fetch all modules
    let all_modules = fetch_modules_list(&state).await;

    // Count installed and available
    let installed_count = all_modules.iter().filter(|m| m.state == "installed").count();
    let available_count = all_modules.iter().filter(|m| m.state != "installed").count();

    // Filter modules based on filter parameter
    let modules: Vec<ModuleDisplay> = match filter.as_str() {
        "installed" => all_modules.into_iter().filter(|m| m.state == "installed").collect(),
        "available" => all_modules.into_iter().filter(|m| m.state != "installed").collect(),
        _ => all_modules,
    };

    let template = ModulesListTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "modules".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        modules,
        installed_count,
        available_count,
        filter,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Install a module (API endpoint)
pub async fn module_install(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(module_id): Path<String>,
) -> Response {
    // Only admins can install modules
    if !is_system_admin(&ctx) {
        return Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can install modules".to_string()),
        }).into_response();
    }

    match do_install_module(state.db.pool(), &module_id).await {
        Ok(msg) => Json(ModuleOperationResponse {
            success: true,
            message: msg,
            error: None,
        }).into_response(),
        Err(e) => Json(ModuleOperationResponse {
            success: false,
            message: "Installation failed".to_string(),
            error: Some(e),
        }).into_response(),
    }
}

/// Uninstall a module (API endpoint)
pub async fn module_uninstall(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(module_id): Path<String>,
) -> Response {
    // Only admins can uninstall modules
    if !is_system_admin(&ctx) {
        return Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can uninstall modules".to_string()),
        }).into_response();
    }

    match do_uninstall_module(state.db.pool(), &module_id).await {
        Ok(msg) => Json(ModuleOperationResponse {
            success: true,
            message: msg,
            error: None,
        }).into_response(),
        Err(e) => Json(ModuleOperationResponse {
            success: false,
            message: "Uninstallation failed".to_string(),
            error: Some(e),
        }).into_response(),
    }
}

/// Upgrade a module (API endpoint)
pub async fn module_upgrade(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(module_id): Path<String>,
) -> Response {
    if !is_system_admin(&ctx) {
        return Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can upgrade modules".to_string()),
        }).into_response();
    }

    match do_upgrade_module(state.db.pool(), &module_id).await {
        Ok(msg) => Json(ModuleOperationResponse {
            success: true,
            message: msg,
            error: None,
        }).into_response(),
        Err(e) => Json(ModuleOperationResponse {
            success: false,
            message: "Upgrade failed".to_string(),
            error: Some(e),
        }).into_response(),
    }
}

/// Get module info (API endpoint)
pub async fn module_info(
    State(state): State<AppState>,
    Path(module_id): Path<String>,
) -> Response {
    let module = fetch_module_by_id(&state, &module_id).await;

    match module {
        Some(m) => Json(m).into_response(),
        None => (StatusCode::NOT_FOUND, Json(ModuleOperationResponse {
            success: false,
            message: "Module not found".to_string(),
            error: Some(format!("Module '{}' not found", module_id)),
        })).into_response(),
    }
}

/// Fetch modules list from database
async fn fetch_modules_list(state: &AppState) -> Vec<ModuleDisplay> {
    let rows = sqlx::query(
        r#"
        SELECT
            im.id, im.technical_name, im.name, im.version, im.state,
            COALESCE(im.category, 'Uncategorized') as category,
            COALESCE(im.summary, '') as summary,
            COALESCE(im.description, '') as description,
            COALESCE(im.author, '') as author,
            im.is_core, im.application,
            COALESCE(im.icon, '') as icon,
            im.installed_at
        FROM installed_modules im
        ORDER BY im.sequence, im.name
        "#
    )
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    let mut modules = Vec::new();

    for row in &rows {
        let technical_name: String = row.get("technical_name");

        // Fetch dependencies for this module
        let deps = fetch_module_dependencies(state, &technical_name).await;

        let installed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("installed_at");
        let name: String = row.get("name");
        let initial = name.chars().next().unwrap_or('M').to_string();

        modules.push(ModuleDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            technical_name: technical_name.clone(),
            name,
            version: row.get("version"),
            state: row.get("state"),
            category: row.get("category"),
            summary: row.get("summary"),
            description: row.get("description"),
            author: row.get("author"),
            is_core: row.get("is_core"),
            application: row.get("application"),
            icon: row.get("icon"),
            initial,
            installed_at: installed_at.map(|dt| dt.format("%Y-%m-%d %H:%M").to_string()),
            dependencies: deps,
        });
    }

    modules
}

/// Fetch a single module by ID
async fn fetch_module_by_id(state: &AppState, module_id: &str) -> Option<ModuleDisplay> {
    let row = sqlx::query(
        r#"
        SELECT
            im.id, im.technical_name, im.name, im.version, im.state,
            COALESCE(im.category, 'Uncategorized') as category,
            COALESCE(im.summary, '') as summary,
            COALESCE(im.description, '') as description,
            COALESCE(im.author, '') as author,
            im.is_core, im.application,
            COALESCE(im.icon, '') as icon,
            im.installed_at
        FROM installed_modules im
        WHERE im.technical_name = $1
        "#
    )
    .bind(module_id)
    .fetch_optional(state.db.pool())
    .await
    .ok()
    .flatten()?;

    let technical_name: String = row.get("technical_name");
    let deps = fetch_module_dependencies(state, &technical_name).await;
    let installed_at: Option<chrono::DateTime<chrono::Utc>> = row.get("installed_at");
    let name: String = row.get("name");
    let initial = name.chars().next().unwrap_or('M').to_string();

    Some(ModuleDisplay {
        id: row.get::<uuid::Uuid, _>("id").to_string(),
        technical_name,
        name,
        version: row.get("version"),
        state: row.get("state"),
        category: row.get("category"),
        summary: row.get("summary"),
        description: row.get("description"),
        author: row.get("author"),
        is_core: row.get("is_core"),
        application: row.get("application"),
        icon: row.get("icon"),
        initial,
        installed_at: installed_at.map(|dt| dt.format("%Y-%m-%d %H:%M").to_string()),
        dependencies: deps,
    })
}

/// Fetch dependencies for a module
async fn fetch_module_dependencies(state: &AppState, module_id: &str) -> Vec<ModuleDependency> {
    let rows = sqlx::query(
        r#"
        SELECT
            md.depends_on,
            md.optional,
            EXISTS (
                SELECT 1 FROM installed_modules im2
                WHERE im2.technical_name = md.depends_on
                AND im2.state = 'installed'
            ) as is_satisfied
        FROM installed_modules im
        JOIN module_dependencies md ON md.module_id = im.id
        WHERE im.technical_name = $1
        ORDER BY md.optional, md.depends_on
        "#
    )
    .bind(module_id)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    rows.iter()
        .map(|row| ModuleDependency {
            name: row.get("depends_on"),
            is_satisfied: row.get("is_satisfied"),
            optional: row.get("optional"),
        })
        .collect()
}

/// Install module with dependencies
async fn do_install_module(pool: &sqlx::PgPool, module_id: &str) -> Result<String, String> {
    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state, is_core FROM installed_modules WHERE technical_name = $1"
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let Some(module) = module else {
        return Err(format!("Module '{}' not found", module_id));
    };

    let state: String = module.get("state");
    let name: String = module.get("name");

    if state == "installed" {
        return Ok(format!("Module '{}' is already installed", name));
    }

    // Check and install dependencies first
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
    .await
    .map_err(|e| e.to_string())?;

    for dep in &deps {
        let depends_on: String = dep.get("depends_on");
        let is_satisfied: bool = dep.get("is_satisfied");
        if !is_satisfied {
            // Recursively install dependency
            Box::pin(do_install_module(pool, &depends_on)).await?;
        }
    }

    // Update state to 'to_install'
    sqlx::query("UPDATE installed_modules SET state = 'to_install' WHERE technical_name = $1")
        .bind(module_id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;

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
    .await
    .map_err(|e| e.to_string())?;

    Ok(format!("Module '{}' installed successfully", name))
}

/// Run migrations for a module
async fn run_module_migrations(pool: &sqlx::PgPool, module_id: &str) -> Result<(), String> {
    let migrations_dir = std::path::Path::new("migrations");

    if !migrations_dir.exists() {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let metadata_path = path.join("metadata.toml");
        if !metadata_path.exists() {
            continue;
        }

        let metadata_content = std::fs::read_to_string(&metadata_path)
            .map_err(|e| e.to_string())?;

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
        .await
        .map_err(|e| e.to_string())?;

        if applied.is_some() {
            continue;
        }

        // Read and execute migration
        let sql_path = path.join("postgres.sql");
        if !sql_path.exists() {
            continue;
        }

        let sql = std::fs::read_to_string(&sql_path)
            .map_err(|e| e.to_string())?;

        let start = std::time::Instant::now();
        let result = sqlx::raw_sql(&sql).execute(pool).await;
        let elapsed = start.elapsed().as_millis() as i32;

        let should_record = match result {
            Ok(_) => true,
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("already exists") {
                    true
                } else {
                    return Err(format!("Migration '{}' failed: {}", migration_name, e));
                }
            }
        };

        if should_record {
            let module_row = sqlx::query("SELECT id FROM installed_modules WHERE technical_name = $1")
                .bind(module_id)
                .fetch_one(pool)
                .await
                .map_err(|e| e.to_string())?;
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
            .await
            .map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

/// Uninstall a module
async fn do_uninstall_module(pool: &sqlx::PgPool, module_id: &str) -> Result<String, String> {
    let module = sqlx::query(
        "SELECT technical_name, name, state, is_core FROM installed_modules WHERE technical_name = $1"
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let Some(module) = module else {
        return Err(format!("Module '{}' not found", module_id));
    };

    let state: String = module.get("state");
    let name: String = module.get("name");
    let is_core: bool = module.get("is_core");

    if state != "installed" {
        return Err(format!("Module '{}' is not installed", name));
    }

    if is_core {
        return Err(format!("Cannot uninstall core module '{}'", name));
    }

    // Check for dependent modules
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
    .await
    .map_err(|e| e.to_string())?;

    if !dependents.is_empty() {
        let dep_names: Vec<String> = dependents
            .iter()
            .map(|d| d.get::<String, _>("name"))
            .collect();
        return Err(format!(
            "Cannot uninstall '{}'. The following modules depend on it: {}",
            name,
            dep_names.join(", ")
        ));
    }

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
    .await
    .map_err(|e| e.to_string())?;

    Ok(format!("Module '{}' uninstalled successfully", name))
}

/// Upgrade a module
async fn do_upgrade_module(pool: &sqlx::PgPool, module_id: &str) -> Result<String, String> {
    let module = sqlx::query(
        "SELECT technical_name, name, state, version FROM installed_modules WHERE technical_name = $1"
    )
    .bind(module_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let Some(module) = module else {
        return Err(format!("Module '{}' not found", module_id));
    };

    let state: String = module.get("state");
    let name: String = module.get("name");

    if state != "installed" {
        return Err(format!("Module '{}' is not installed", name));
    }

    // Update state to 'to_upgrade'
    sqlx::query("UPDATE installed_modules SET state = 'to_upgrade' WHERE technical_name = $1")
        .bind(module_id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;

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
    .await
    .map_err(|e| e.to_string())?;

    Ok(format!("Module '{}' upgraded successfully", name))
}
