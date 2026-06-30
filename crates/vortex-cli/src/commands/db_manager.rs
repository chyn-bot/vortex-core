//! Database Manager HTTP handlers
//!
//! Public routes (no auth required, master-password protected) for managing
//! databases: create, duplicate, delete, backup, restore, change password.

use std::sync::Arc;

use axum::{
    extract::{Multipart, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use tracing::{error, info, warn};

use vortex_framework::AppState;

/// Build the database manager routes (public, master-password protected).
pub fn db_manager_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(db_manager_page))
        .route("/list", post(db_manager_list))
        .route("/create", post(db_manager_create))
        .route("/duplicate", post(db_manager_duplicate))
        .route("/delete", post(db_manager_delete))
        .route("/backup", post(db_manager_backup))
        .route("/restore", post(db_manager_restore))
        .route("/change-password", post(db_manager_change_pwd))
}

// ============================================================================
// Helpers
// ============================================================================

fn verify_master_password(state: &AppState, password: &str) -> bool {
    if password.is_empty() {
        return false;
    }
    match &state.master_password_hash {
        Some(hash) => {
            // If hash starts with $argon2, verify via argon2
            if hash.starts_with("$argon2") {
                use argon2::{Argon2, PasswordHash, PasswordVerifier};
                match PasswordHash::new(hash) {
                    Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
                    Err(_) => false,
                }
            } else {
                // Plain text comparison (for development only)
                hash == password
            }
        }
        None => {
            // No master password configured — accept any non-empty password
            // (first-time setup scenario)
            true
        }
    }
}

fn html_message(class: &str, msg: &str) -> Html<String> {
    Html(format!(
        r#"<div class="alert alert-{class} mb-4 shadow-sm"><span>{msg}</span></div>"#
    ))
}

fn success_msg(msg: &str) -> Response {
    html_message("success", msg).into_response()
}

fn error_msg(msg: &str) -> Response {
    html_message("error", msg).into_response()
}

fn get_master_db(state: &AppState) -> Result<&PgPool, Response> {
    state.master_db.as_ref().ok_or_else(|| {
        error_msg("Multi-database mode is not enabled")
    })
}

// ============================================================================
// Handlers
// ============================================================================

async fn db_manager_page(State(state): State<Arc<AppState>>) -> Response {
    if !state.multi_db {
        return (StatusCode::NOT_FOUND, "Database manager is not enabled").into_response();
    }
    Html(include_str!("../../templates/db_manager.html")).into_response()
}

#[derive(Deserialize)]
struct MasterPasswordForm {
    master_password: String,
}

async fn db_manager_list(
    State(state): State<Arc<AppState>>,
    Form(form): Form<MasterPasswordForm>,
) -> Response {
    if !verify_master_password(&state, &form.master_password) {
        return Html(r#"<div class="alert alert-warning mb-2"><span>Invalid master password</span></div>"#.to_string()).into_response();
    }

    let master_db = match get_master_db(&state) {
        Ok(db) => db,
        Err(resp) => return resp,
    };

    let databases = sqlx::query(
        "SELECT name, display_name, state, demo_data, created_at, size_bytes FROM managed_databases ORDER BY name"
    )
    .fetch_all(master_db)
    .await;

    match databases {
        Ok(rows) => {
            let mut html = String::from(r#"<div class="overflow-x-auto"><table class="table table-sm"><thead><tr>
                <th>Name</th><th>State</th><th>Demo</th><th>Created</th><th>Actions</th>
            </tr></thead><tbody>"#);

            for row in &rows {
                let name: &str = row.get("name");
                let db_state: &str = row.get("state");
                let demo: bool = row.get("demo_data");
                let created: chrono::DateTime<chrono::Utc> = row.get("created_at");

                let state_badge = match db_state {
                    "active" => r#"<span class="badge badge-success badge-sm">active</span>"#,
                    "creating" => r#"<span class="badge badge-warning badge-sm">creating</span>"#,
                    "error" => r#"<span class="badge badge-error badge-sm">error</span>"#,
                    _ => r#"<span class="badge badge-ghost badge-sm">archived</span>"#,
                };

                let demo_str = if demo { "Yes" } else { "" };
                let created_str = created.format("%Y-%m-%d %H:%M").to_string();
                html.push_str("<tr>");
                html.push_str(&format!(r#"<td class="font-mono font-medium">{name}</td>"#));
                html.push_str(&format!("<td>{state_badge}</td>"));
                html.push_str(&format!(r#"<td>{demo_str}</td>"#));
                html.push_str(&format!(r#"<td class="text-xs text-base-content/60">{created_str}</td>"#));
                html.push_str(r#"<td class="flex gap-1">"#);
                // Backup button
                html.push_str(r#"<form hx-post="/web/database/manager/backup" hx-swap="none" class="inline">"#);
                html.push_str(&format!(r#"<input type="hidden" name="name" value="{name}">"#));
                html.push_str(r#"<input type="hidden" name="master_password" class="mp-field">"#);
                html.push_str(r#"<button class="btn btn-xs btn-ghost">Backup</button></form>"#);
                // Delete button
                html.push_str(r##"<form hx-post="/web/database/manager/delete" hx-target="#db-messages" hx-swap="innerHTML" "##);
                html.push_str(&format!(r#"hx-confirm="Delete database {name}? This cannot be undone!" class="inline" "#));
                html.push_str(r#"hx-on::after-request="if(event.detail.successful){htmx.trigger(document.body,'reloadList')}">"#);
                html.push_str(&format!(r#"<input type="hidden" name="name" value="{name}">"#));
                html.push_str(r#"<input type="hidden" name="master_password" class="mp-field">"#);
                html.push_str(r#"<button class="btn btn-xs btn-error btn-ghost">Delete</button></form>"#);
                html.push_str("</td></tr>");
            }

            html.push_str("</tbody></table></div>");

            if rows.is_empty() {
                html = r#"<div class="text-center py-4 text-base-content/50">No databases registered</div>"#.to_string();
            }

            Html(html).into_response()
        }
        Err(e) => {
            error!("Failed to list databases: {}", e);
            error_msg(&format!("Failed to list databases: {}", e))
        }
    }
}

#[derive(Deserialize)]
struct CreateForm {
    master_password: String,
    name: String,
    #[serde(default)]
    demo_data: Option<String>,
}

async fn db_manager_create(
    State(state): State<Arc<AppState>>,
    Form(form): Form<CreateForm>,
) -> Response {
    if !verify_master_password(&state, &form.master_password) {
        return error_msg("Invalid master password");
    }

    let master_db = match get_master_db(&state) {
        Ok(db) => db,
        Err(resp) => return resp,
    };

    let name = form.name.trim().to_lowercase();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return error_msg("Database name must be alphanumeric with underscores only");
    }

    let demo = form.demo_data.as_deref() == Some("true");

    info!("Creating database '{}'", name);

    // Register as 'creating' in master db
    if let Err(e) = sqlx::query(
        "INSERT INTO managed_databases (name, state, demo_data) VALUES ($1, 'creating', $2)"
    )
    .bind(&name)
    .bind(demo)
    .execute(master_db)
    .await {
        return error_msg(&format!("Failed to register database: {}", e));
    }

    // Create the PostgreSQL database
    let base_url = state.pool_manager.config().base_url.clone();
    let admin_url = format!("{}/postgres", base_url);

    let admin_pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await {
        Ok(p) => p,
        Err(e) => {
            let _ = sqlx::query("DELETE FROM managed_databases WHERE name = $1")
                .bind(&name).execute(master_db).await;
            return error_msg(&format!("Failed to connect to postgres: {}", e));
        }
    };

    let create_sql = format!("CREATE DATABASE \"{}\"", name);
    if let Err(e) = sqlx::query(&create_sql).execute(&admin_pool).await {
        let _ = sqlx::query("UPDATE managed_databases SET state = 'error' WHERE name = $1")
            .bind(&name).execute(master_db).await;
        return error_msg(&format!("Failed to create database: {}", e));
    }

    // Run migrations on the new database
    let db_url = format!("{}/{}", base_url, name);
    match sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&db_url)
        .await {
        Ok(db_pool) => {
            if let Err(e) = run_migrations_on_pool(&db_pool).await {
                let _ = sqlx::query("UPDATE managed_databases SET state = 'error' WHERE name = $1")
                    .bind(&name).execute(master_db).await;
                return error_msg(&format!("Database created but migrations failed: {}", e));
            }

            // Seed core roles
            super::server::seed_core_roles_on_db(&db_pool).await;
        }
        Err(e) => {
            let _ = sqlx::query("UPDATE managed_databases SET state = 'error' WHERE name = $1")
                .bind(&name).execute(master_db).await;
            return error_msg(&format!("Failed to connect to new database: {}", e));
        }
    }

    // Update state to active
    let _ = sqlx::query("UPDATE managed_databases SET state = 'active' WHERE name = $1")
        .bind(&name).execute(master_db).await;

    info!("Database '{}' created successfully", name);
    success_msg(&format!("Database '{}' created successfully", name))
}

#[derive(Deserialize)]
struct DuplicateForm {
    master_password: String,
    source: String,
    target: String,
}

async fn db_manager_duplicate(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DuplicateForm>,
) -> Response {
    if !verify_master_password(&state, &form.master_password) {
        return error_msg("Invalid master password");
    }

    let master_db = match get_master_db(&state) {
        Ok(db) => db,
        Err(resp) => return resp,
    };

    let source = form.source.trim().to_lowercase();
    let target = form.target.trim().to_lowercase();

    if target.is_empty() || !target.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return error_msg("Target name must be alphanumeric with underscores only");
    }

    info!("Duplicating database '{}' to '{}'", source, target);

    // Remove source pool to free exclusive access for template
    state.pool_manager.remove_pool(&source).await;

    // Connect to postgres db and duplicate
    let base_url = state.pool_manager.config().base_url.clone();
    let admin_url = format!("{}/postgres", base_url);

    let admin_pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await {
        Ok(p) => p,
        Err(e) => return error_msg(&format!("Failed to connect to postgres: {}", e)),
    };

    // Terminate connections to the source database
    let _ = sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid != pg_backend_pid()")
        .bind(&source)
        .execute(&admin_pool)
        .await;

    let dup_sql = format!("CREATE DATABASE \"{}\" WITH TEMPLATE \"{}\"", target, source);
    if let Err(e) = sqlx::query(&dup_sql).execute(&admin_pool).await {
        return error_msg(&format!("Failed to duplicate: {}", e));
    }

    // Register in master db
    let _ = sqlx::query(
        "INSERT INTO managed_databases (name, state) VALUES ($1, 'active') ON CONFLICT (name) DO UPDATE SET state = 'active'"
    )
    .bind(&target)
    .execute(master_db)
    .await;

    info!("Database '{}' duplicated to '{}'", source, target);
    success_msg(&format!("Database '{}' duplicated to '{}'", source, target))
}

#[derive(Deserialize)]
struct DeleteForm {
    master_password: String,
    name: String,
}

async fn db_manager_delete(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if !verify_master_password(&state, &form.master_password) {
        return error_msg("Invalid master password");
    }

    let master_db = match get_master_db(&state) {
        Ok(db) => db,
        Err(resp) => return resp,
    };

    let name = form.name.trim();

    // Prevent deletion of master database
    if name == state.default_db || Some(name.to_string()) == state.master_db.as_ref().map(|_| {
        // Get master db name from config
        let (_, master_name, _, _, _) = super::server::parse_db_manager_config();
        master_name
    }) {
        return error_msg("Cannot delete the default or master database");
    }

    info!("Deleting database '{}'", name);

    // Remove pool
    state.pool_manager.remove_pool(name).await;

    // Terminate all connections and drop
    let base_url = state.pool_manager.config().base_url.clone();
    let admin_url = format!("{}/postgres", base_url);

    let admin_pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await {
        Ok(p) => p,
        Err(e) => return error_msg(&format!("Failed to connect to postgres: {}", e)),
    };

    let _ = sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid != pg_backend_pid()")
        .bind(name)
        .execute(&admin_pool)
        .await;

    let drop_sql = format!("DROP DATABASE IF EXISTS \"{}\"", name);
    if let Err(e) = sqlx::query(&drop_sql).execute(&admin_pool).await {
        return error_msg(&format!("Failed to drop database: {}", e));
    }

    // Remove from registry
    let _ = sqlx::query("DELETE FROM managed_databases WHERE name = $1")
        .bind(name)
        .execute(master_db)
        .await;

    info!("Database '{}' deleted", name);
    success_msg(&format!("Database '{}' deleted", name))
}

#[derive(Deserialize)]
struct BackupForm {
    master_password: String,
    name: String,
}

async fn db_manager_backup(
    State(state): State<Arc<AppState>>,
    Form(form): Form<BackupForm>,
) -> Response {
    if !verify_master_password(&state, &form.master_password) {
        return error_msg("Invalid master password");
    }

    let name = form.name.trim();
    let base_url = state.pool_manager.config().base_url.clone();
    let db_url = format!("{}/{}", base_url, name);

    info!("Creating backup of database '{}'", name);

    // Run pg_dump
    let output = match tokio::process::Command::new("pg_dump")
        .arg("--format=custom")
        .arg(&db_url)
        .output()
        .await {
        Ok(o) => o,
        Err(e) => return error_msg(&format!("Failed to run pg_dump: {}", e)),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return error_msg(&format!("pg_dump failed: {}", stderr));
    }

    let filename = format!("{name}_{}.backup", chrono::Utc::now().format("%Y%m%d_%H%M%S"));

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename).parse().unwrap(),
    );

    (StatusCode::OK, headers, output.stdout).into_response()
}

async fn db_manager_restore(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    let mut master_password = String::new();
    let mut db_name = String::new();
    let mut backup_data: Vec<u8> = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "master_password" => {
                master_password = field.text().await.unwrap_or_default();
            }
            "name" => {
                db_name = field.text().await.unwrap_or_default();
            }
            "backup_file" => {
                backup_data = field.bytes().await.unwrap_or_default().to_vec();
            }
            _ => {}
        }
    }

    if !verify_master_password(&state, &master_password) {
        return error_msg("Invalid master password");
    }

    if db_name.is_empty() || backup_data.is_empty() {
        return error_msg("Database name and backup file are required");
    }

    let master_db = match get_master_db(&state) {
        Ok(db) => db,
        Err(resp) => return resp,
    };

    let db_name = db_name.trim().to_lowercase();
    info!("Restoring database '{}' from backup", db_name);

    // Create the database first
    let base_url = state.pool_manager.config().base_url.clone();
    let admin_url = format!("{}/postgres", base_url);

    let admin_pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await {
        Ok(p) => p,
        Err(e) => return error_msg(&format!("Failed to connect to postgres: {}", e)),
    };

    let create_sql = format!("CREATE DATABASE \"{}\"", db_name);
    if let Err(e) = sqlx::query(&create_sql).execute(&admin_pool).await {
        return error_msg(&format!("Failed to create database: {}", e));
    }

    // Write backup to temp file and restore with pg_restore
    let temp_path = format!("/tmp/vortex_restore_{}.backup", uuid::Uuid::new_v4());
    if let Err(e) = tokio::fs::write(&temp_path, &backup_data).await {
        return error_msg(&format!("Failed to write temp file: {}", e));
    }

    let db_url = format!("{}/{}", base_url, db_name);
    let output = tokio::process::Command::new("pg_restore")
        .arg("--no-owner")
        .arg("--no-acl")
        .arg("-d")
        .arg(&db_url)
        .arg(&temp_path)
        .output()
        .await;

    let _ = tokio::fs::remove_file(&temp_path).await;

    match output {
        Ok(o) if o.status.success() || o.status.code() == Some(1) => {
            // pg_restore exit code 1 = warnings (e.g. "errors ignored"), which is usually fine
            // Register in master db
            let _ = sqlx::query(
                "INSERT INTO managed_databases (name, state) VALUES ($1, 'active') ON CONFLICT (name) DO UPDATE SET state = 'active'"
            )
            .bind(&db_name)
            .execute(master_db)
            .await;

            info!("Database '{}' restored successfully", db_name);
            success_msg(&format!("Database '{}' restored successfully", db_name))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            error_msg(&format!("pg_restore failed: {}", stderr))
        }
        Err(e) => error_msg(&format!("Failed to run pg_restore: {}", e)),
    }
}

#[derive(Deserialize)]
struct ChangePasswordForm {
    master_password: String,
    new_password: String,
}

async fn db_manager_change_pwd(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    if !verify_master_password(&state, &form.master_password) {
        return error_msg("Invalid current master password");
    }

    let master_db = match get_master_db(&state) {
        Ok(db) => db,
        Err(resp) => return resp,
    };

    if form.new_password.len() < 8 {
        return error_msg("New password must be at least 8 characters");
    }

    // Hash the new password with Argon2
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = match Argon2::default().hash_password(form.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => return error_msg(&format!("Failed to hash password: {}", e)),
    };

    // Store in db_manager_config
    let _ = sqlx::query(
        "INSERT INTO db_manager_config (key, value) VALUES ('master_password', $1) ON CONFLICT (key) DO UPDATE SET value = $1"
    )
    .bind(&hash)
    .execute(master_db)
    .await;

    info!("Master password changed");
    success_msg("Master password changed successfully. Update vortex.toml to persist.")
}

/// Run all migrations from the migrations/ directory on a pool.
async fn run_migrations_on_pool(db: &PgPool) -> Result<(), String> {
    // Initialize migrations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vortex_migrations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL UNIQUE,
            module VARCHAR(255) NOT NULL DEFAULT 'core',
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            checksum VARCHAR(64) NOT NULL DEFAULT '',
            execution_time_ms INTEGER NOT NULL DEFAULT 0
        )
        "#
    )
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;

    // Read and apply migrations
    let mut migrations_dir = std::fs::read_dir("migrations")
        .map_err(|e| format!("Cannot read migrations/: {}", e))?
        .filter_map(|e| e.ok())
        .collect::<Vec<_>>();
    migrations_dir.sort_by_key(|e| e.file_name());

    for entry in migrations_dir {
        let name = entry.file_name().to_string_lossy().to_string();
        let sql_path = entry.path().join("postgres.sql");

        if !sql_path.exists() {
            continue;
        }

        // Check if already applied
        let already: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM vortex_migrations WHERE name = $1)"
        )
        .bind(&name)
        .fetch_one(db)
        .await
        .map_err(|e| e.to_string())?;

        if already {
            continue;
        }

        let sql = std::fs::read_to_string(&sql_path)
            .map_err(|e| format!("Cannot read {}: {}", sql_path.display(), e))?;

        sqlx::raw_sql(&sql)
            .execute(db)
            .await
            .map_err(|e| format!("Migration {} failed: {}", name, e))?;

        sqlx::query("INSERT INTO vortex_migrations (name) VALUES ($1)")
            .bind(&name)
            .execute(db)
            .await
            .map_err(|e| e.to_string())?;

        info!("Applied migration: {}", name);
    }

    Ok(())
}
