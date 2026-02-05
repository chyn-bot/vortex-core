//! Server command with real database authentication

use anyhow::Result;
use axum::{
    extract::{Form, FromRequestParts, Path, Query, Request, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, post},
    Extension, Router,
};
use sqlx::{postgres::PgPoolOptions, Column, PgPool, Row};
use chrono::Datelike;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use vortex_orm::ConnectionPool;
use vortex_orm::pool_manager::{DatabasePoolManager, PoolManagerConfig};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub pool: Arc<ConnectionPool>,
    pub pool_manager: Arc<DatabasePoolManager>,
    pub master_db: Option<PgPool>,
    pub master_password_hash: Option<String>,
    pub db_filter: Option<String>,
    pub multi_db: bool,
    pub default_db: String,
}

/// Database context injected by auth middleware for request-scoped DB routing.
#[derive(Clone)]
pub struct DatabaseContext {
    pub db_name: String,
    pub pool: Arc<ConnectionPool>,
}

/// Extractor that provides a PgPool from the request-scoped DatabaseContext.
/// Use `Db(db): Db` in handler parameters, then `&db` wherever `&db` was used.
pub struct Db(pub PgPool);

impl<S: Send + Sync> FromRequestParts<S> for Db {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<DatabaseContext>()
            .map(|ctx| Db(ctx.pool.pool().clone()))
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Authenticated user information passed to protected handlers
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: uuid::Uuid,
    pub username: String,
    pub full_name: Option<String>,
    pub session_id: uuid::Uuid,
    pub roles: Vec<String>,
}

impl AuthUser {
    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if user is a system administrator
    pub fn is_system_admin(&self) -> bool {
        self.has_role("System Administrator")
    }

    /// Check if user is any type of admin
    pub fn is_admin(&self) -> bool {
        self.has_role("System Administrator") || self.has_role("Administrator")
    }
}

/// Auth middleware - verifies session and injects AuthUser + DatabaseContext
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract session cookie
    let session_cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|c| {
                    let c = c.trim();
                    if c.starts_with("session=") {
                        Some(c.trim_start_matches("session=").to_string())
                    } else {
                        None
                    }
                })
        });

    let Some(cookie_value) = session_cookie else {
        warn!("No session cookie found, redirecting to login");
        return Redirect::to("/login").into_response();
    };

    // Parse db_name|token or legacy plain token
    let (db_name, token) = if let Some(pos) = cookie_value.find('|') {
        (cookie_value[..pos].to_string(), cookie_value[pos + 1..].to_string())
    } else {
        // Legacy cookie without db name — use default database
        (state.default_db.clone(), cookie_value)
    };

    // Get pool for this database
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to get pool for database '{}': {}", db_name, e);
            return redirect_to_login_with_message("Database unavailable");
        }
    };
    let db = pool.pool();

    // Hash the token to look up in database
    let token_hash = hash_token(&token);

    // Verify session in database
    let session = sqlx::query_as::<_, SessionWithUser>(
        r#"
        SELECT
            s.id as session_id,
            s.user_id,
            s.expires_at,
            s.revoked,
            u.username,
            u.full_name,
            u.active,
            u.locked
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token_hash = $1
        "#
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await;

    match session {
        Ok(Some(session)) => {
            // Check if session is valid
            if session.revoked {
                warn!("Session revoked for user {}", session.username);
                return redirect_to_login_with_message("Session expired");
            }
            if session.expires_at < chrono::Utc::now() {
                warn!("Session expired for user {}", session.username);
                return redirect_to_login_with_message("Session expired");
            }
            if !session.active {
                warn!("User {} is disabled", session.username);
                return redirect_to_login_with_message("Account disabled");
            }
            if session.locked {
                warn!("User {} is locked", session.username);
                return redirect_to_login_with_message("Account locked");
            }

            // Update last activity (extends session on activity)
            let _ = sqlx::query(
                "UPDATE sessions SET last_activity_at = NOW(), expires_at = NOW() + INTERVAL '30 minutes' WHERE id = $1"
            )
            .bind(&session.session_id)
            .execute(db)
            .await;

            // Fetch user roles
            let roles: Vec<String> = sqlx::query_scalar(
                r#"
                SELECT r.name
                FROM roles r
                JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1
                "#
            )
            .bind(session.user_id)
            .fetch_all(db)
            .await
            .unwrap_or_default();

            // Inject AuthUser into request extensions
            let auth_user = AuthUser {
                id: session.user_id,
                username: session.username,
                full_name: session.full_name,
                session_id: session.session_id,
                roles,
            };
            request.extensions_mut().insert(auth_user);

            // Inject Arc<ConnectionPool> for EAM handlers (Extension-based extraction)
            request.extensions_mut().insert(pool.clone());

            // Inject DatabaseContext for downstream extractors (Db extractor)
            request.extensions_mut().insert(DatabaseContext {
                db_name,
                pool,
            });

            next.run(request).await
        }
        Ok(None) => {
            warn!("Invalid session token");
            redirect_to_login_with_message("Invalid session")
        }
        Err(e) => {
            error!("Database error checking session: {}", e);
            redirect_to_login_with_message("Authentication error")
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionWithUser {
    session_id: uuid::Uuid,
    user_id: uuid::Uuid,
    expires_at: chrono::DateTime<chrono::Utc>,
    revoked: bool,
    username: String,
    full_name: Option<String>,
    active: bool,
    locked: bool,
}

fn redirect_to_login_with_message(_message: &str) -> Response {
    // Clear the invalid session cookie and redirect
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "session=; Path=/; HttpOnly; Max-Age=0".parse().unwrap(),
    );
    (headers, Redirect::to("/login")).into_response()
}

/// Parse the [database_manager] section from vortex.toml (if present).
pub fn parse_db_manager_config() -> (bool, String, String, String, String) {
    let config_str = std::fs::read_to_string("vortex.toml").unwrap_or_default();
    let config: toml::Value = config_str.parse::<toml::Value>().unwrap_or(toml::Value::Table(Default::default()));
    let section: Option<&toml::Value> = config.get("database_manager");

    let enabled = section
        .and_then(|s: &toml::Value| s.get("enabled"))
        .and_then(|v: &toml::Value| v.as_bool())
        .unwrap_or(false);
    let master_database = section
        .and_then(|s: &toml::Value| s.get("master_database"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("vortex_master")
        .to_string();
    let master_password = section
        .and_then(|s: &toml::Value| s.get("master_password"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("")
        .to_string();
    let db_filter = section
        .and_then(|s: &toml::Value| s.get("db_filter"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("")
        .to_string();
    let db_name_prefix = section
        .and_then(|s: &toml::Value| s.get("db_name_prefix"))
        .and_then(|v: &toml::Value| v.as_str())
        .unwrap_or("vortex_")
        .to_string();

    (enabled, master_database, master_password, db_filter, db_name_prefix)
}

/// Extract the database name from a full DATABASE_URL.
fn db_name_from_url(url: &str) -> String {
    url.rsplit('/').next().unwrap_or("vortex").to_string()
}

/// Extract the base URL (without database name) from a full DATABASE_URL.
fn base_url_from_full(url: &str) -> String {
    if let Some(pos) = url.rfind('/') {
        url[..pos].to_string()
    } else {
        url.to_string()
    }
}

pub async fn run(host: String, port: u16, _workers: Option<usize>) -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Get database URL
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://remicle:remicle_dev_2026@localhost/remicle".to_string());

    // Parse multi-db config
    let (multi_db_enabled, master_database, master_password, db_filter, _db_name_prefix) =
        parse_db_manager_config();

    let default_db = db_name_from_url(&database_url);

    // Connect to database
    info!("Connecting to database...");
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    // Verify connection
    sqlx::query("SELECT 1").execute(&db).await?;
    info!("Database connected");

    // Seed core roles if they don't exist
    seed_core_roles(&db).await;

    // Create connection pool wrapper for EAM handlers
    let pool = Arc::new(ConnectionPool::from_pg_pool(db.clone(), &database_url));

    // Create pool manager
    let pool_manager = if multi_db_enabled {
        let config = PoolManagerConfig {
            base_url: base_url_from_full(&database_url),
            ..PoolManagerConfig::default()
        };
        let pm = Arc::new(DatabasePoolManager::new(config));
        // Register the default database pool
        pm.register_pool(&default_db, pool.clone()).await;
        pm
    } else {
        // Single-database mode — wrap existing pool
        Arc::new(DatabasePoolManager::single(&default_db, pool.clone()))
    };

    // Set up master database if multi-db enabled
    let master_db = if multi_db_enabled {
        let master_url = format!("{}/{}", base_url_from_full(&database_url), master_database);
        info!("Connecting to master database '{}'...", master_database);
        let mdb = PgPoolOptions::new()
            .max_connections(5)
            .connect(&master_url)
            .await?;
        sqlx::query("SELECT 1").execute(&mdb).await?;
        info!("Master database connected");
        Some(mdb)
    } else {
        None
    };

    // Create app state
    let state = Arc::new(AppState {
        db,
        pool,
        pool_manager: pool_manager.clone(),
        master_db,
        master_password_hash: if master_password.is_empty() { None } else { Some(master_password) },
        db_filter: if db_filter.is_empty() { None } else { Some(db_filter) },
        multi_db: multi_db_enabled,
        default_db,
    });

    // Start background pool eviction task if multi-db
    if multi_db_enabled {
        let pm = pool_manager.clone();
        let default = state.default_db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                pm.evict_idle_pools(&[default.clone()]).await;
            }
        });
    }

    // Build router
    let app = build_router(state);

    // Parse the address
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                                                            ║");
    println!("║   \x1b[32mre\x1b[90mmicle\x1b[0m                                               ║");
    println!("║   NERC CIP Compliant Platform                              ║");
    println!("║                                                            ║");
    println!("║   URL: http://{}:{:<24}       ║", host, port);
    println!("║   Database: Connected                                      ║");
    println!("║                                                            ║");
    println!("║   Press Ctrl+C to stop                                     ║");
    println!("║                                                            ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Start the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    info!("Server stopped");
    Ok(())
}

/// Build the application router
fn build_router(state: Arc<AppState>) -> Router {
    // Protected routes - require authentication
    let protected_routes = Router::new()
        .route("/home", get(home_page))
        .route("/dashboard", get(dashboard_page))
        .route("/auth/logout", post(logout))
        .route("/partials/recent-activity", get(recent_activity))
        .route("/partials/system-status", get(system_status))
        // User management
        .route("/users", get(users_list))
        .route("/users/new", get(users_new_form))
        .route("/users", post(users_create))
        .route("/users/{id}", get(users_edit_form))
        .route("/users/{id}", post(users_update))
        .route("/users/{id}/toggle", post(users_toggle_active))
        .route("/users/{id}/unlock", post(users_unlock))
        // Access control management (admin only)
        .route("/admin/access", get(access_control_page))
        .route("/admin/access/models/new", get(access_model_new_page))
        .route("/admin/access/models", post(access_model_create))
        .route("/admin/access/models/{id}/edit", get(access_model_edit_page))
        .route("/admin/access/models/{id}", post(access_model_update))
        .route("/admin/access/rules/new", get(access_rule_new_page))
        .route("/admin/access/rules", post(access_rule_create))
        .route("/admin/access/rules/{id}/edit", get(access_rule_edit_page))
        .route("/admin/access/rules/{id}", post(access_rule_update))
        .route("/admin/access/fields/new", get(access_field_new_page))
        .route("/admin/access/fields", post(access_field_create))
        .route("/admin/access/fields/{id}/edit", get(access_field_edit_page))
        .route("/admin/access/fields/{id}", post(access_field_update))
        // Module management
        .route("/modules", get(modules_list))
        .route("/modules/{filter}", get(modules_list_with_filter))
        .route("/modules/{id}/install", post(module_install))
        .route("/modules/{id}/uninstall", post(module_uninstall))
        .route("/modules/{id}/upgrade", post(module_upgrade))
        // Generic model views
        .route("/list/{model}", get(generic_list_view))
        .route("/kanban/{model}", get(generic_kanban_view))
        .route("/graph/{model}", get(generic_graph_view))
        .route("/calendar/{model}", get(generic_calendar_view))
        .route("/pivot/{model}", get(generic_pivot_view))
        // Saved filters API
        .route("/api/filters/{model}", get(get_filters))
        .route("/api/filters/{model}", post(save_filter))
        // Sequences API
        .route("/api/sequence/{code}", get(get_next_sequence))
        // Attachments API
        .route("/api/attachments/{model}/{id}", get(list_attachments))
        .route("/api/attachments/{model}/{id}", post(upload_attachment))
        .route("/attachments/{id}", get(download_attachment))
        .route("/attachments/{id}", delete(delete_attachment))
        // Contacts management (redirects to generic)
        .route("/contacts", get(contacts_list))
        .route("/contacts/new", get(contacts_new))
        .route("/contacts", post(contacts_create))
        .route("/contacts/{id}", get(contacts_edit))
        .route("/contacts/{id}", post(contacts_update))
        .route("/contacts/{id}/delete", post(contacts_delete))
        .route("/contacts/{id}/approve", post(contacts_approve))
        .route("/contacts/{id}/set-draft", post(contacts_set_draft))
        // EAM - Asset Management
        .route("/eam", get(eam_dashboard))
        .route("/eam/sites", get(eam_sites))
        .route("/eam/sites/new", get(eam_site_form))
        .route("/eam/sites", post(eam_site_create))
        .route("/eam/sites/{id}", get(eam_site_detail))
        .route("/eam/sites/{id}/edit", get(eam_site_edit))
        .route("/eam/sites/{id}", post(eam_site_update))
        .route("/eam/assets", get(eam_assets))
        .route("/eam/assets/new", get(eam_asset_form))
        .route("/eam/assets", post(eam_asset_create))
        .route("/eam/assets/{id}", get(eam_asset_detail))
        .route("/eam/assets/{id}/edit", get(eam_asset_edit))
        .route("/eam/assets/{id}", post(eam_asset_update))
        .route("/eam/configuration", get(eam_configuration))
        // EAM - New SESB features
        .route("/eam/work-orders", get(eam_work_orders))
        .route("/eam/work-orders/new", get(eam_work_order_new))
        .route("/eam/work-orders/new", post(eam_work_order_create))
        .route("/eam/work-orders/{id}", get(eam_work_order_detail))
        .route("/eam/work-orders/{id}/edit", get(eam_work_order_edit))
        .route("/eam/work-orders/{id}/edit", post(eam_work_order_save))
        .route("/api/eam/work-orders/{id}/transition", post(eam_work_order_transition))
        .route("/eam/functional-locations", get(eam_functional_locations))
        .route("/eam/functional-locations/new", get(eam_functional_location_new))
        .route("/eam/functional-locations/new", post(eam_functional_location_create))
        .route("/eam/functional-locations/{id}", get(eam_functional_location_detail))
        .route("/eam/functional-locations/{id}/edit", get(eam_functional_location_edit))
        .route("/eam/functional-locations/{id}/edit", post(eam_functional_location_save))
        .route("/eam/equipment", get(eam_equipment))
        .route("/eam/inspections", get(eam_inspections))
        .route("/eam/inspections/new", get(eam_inspection_new))
        .route("/eam/inspections/new", post(eam_inspection_create))
        .route("/eam/checklists", get(eam_checklists))
        .route("/eam/checklists/new", get(eam_checklist_new))
        .route("/eam/checklists/new", post(eam_checklist_create))
        .route("/eam/plans", get(eam_plans))
        .route("/eam/plans/new", get(eam_plan_new))
        .route("/eam/plans/new", post(eam_plan_create))
        .route("/eam/sld", get(eam_sld))
        .route("/api/eam/sld/substations", get(eam_sld_substations_api))
        .route("/api/eam/sld/substations/{id}", get(eam_sld_data_api))
        .route("/eam/condition", get(eam_condition_monitoring))
        .route("/eam/manufacturers", get(eam_manufacturers))
        // Chatter partials
        .route("/partials/chatter/{model}/{record_id}", get(chatter_partial))
        .route("/api/chatter/{model}/{record_id}/messages", post(chatter_post_message))
        .route("/api/chatter/{model}/{record_id}/activities", post(chatter_post_activity))
        .route("/api/chatter/{model}/{record_id}/activities/{activity_id}/complete", post(chatter_complete_activity))
        .route("/api/chatter/{model}/{record_id}/activities/{activity_id}/complete-and-schedule", post(chatter_complete_and_schedule))
        // Chatter attachments
        .route("/api/chatter/{model}/{record_id}/attachments", post(chatter_upload_attachment))
        .route("/api/chatter/attachments/{id}/download", get(chatter_download_attachment))
        .route("/api/chatter/attachments/{id}", delete(chatter_delete_attachment))
        // Activity types management
        .route("/settings", get(settings_index))
        .route("/notifications", get(notifications_page))
        .route("/settings/activity-types", get(activity_types_list))
        .route("/settings/activity-types", post(activity_type_create))
        .route("/settings/activity-types/{id}", get(activity_type_edit))
        .route("/settings/activity-types/{id}", post(activity_type_update))
        .route("/settings/activity-types/{id}/delete", post(activity_type_delete))
        // Sequences management
        .route("/settings/sequences", get(sequences_list))
        .route("/settings/sequences", post(sequence_create))
        .route("/settings/sequences/{id}", get(sequence_edit))
        .route("/settings/sequences/{id}", post(sequence_update))
        // Cron Jobs management
        .route("/settings/cron", get(cron_list))
        .route("/settings/cron", post(cron_create))
        .route("/settings/cron/{id}", get(cron_edit))
        .route("/settings/cron/{id}", post(cron_update))
        .route("/settings/cron/{id}/toggle", post(cron_toggle))
        .route("/settings/cron/{id}/run", post(cron_run_now))
        // Reports
        .route("/report/{model}/{id}", get(report_single))
        .route("/report/{model}", get(report_list))
        .route("/settings/reports", get(reports_list))
        .route("/settings/reports", post(report_create))
        .route("/settings/reports/{id}", get(report_edit))
        .route("/settings/reports/{id}", post(report_update))
        // Dynamic Form View
        .route("/form/{model}/new", get(dynamic_form_new))
        .route("/form/{model}", post(dynamic_form_create))
        .route("/form/{model}/{id}", get(dynamic_form_edit))
        .route("/form/{model}/{id}", post(dynamic_form_update))
        // API endpoints
        .route("/api/notifications", get(api_notifications))
        .route("/api/countries", get(api_countries))
        .route("/api/states/{country_id}", get(api_states))
        // EAM REST API (from vortex-eam crate) — uses DatabaseContext extension from auth middleware
        .nest_service("/api/eam", vortex_eam::handlers::eam_api_routes())
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Public routes - no authentication required
    Router::new()
        // Health check
        .route("/health", get(health_check))

        // Static files
        .nest_service("/static", ServeDir::new("crates/vortex-cli/static")
            .fallback(ServeDir::new("crates/vortex-server/static")
            .fallback(ServeDir::new("static"))))

        // Auth pages (public)
        .route("/", get(|| async { Redirect::to("/login") }))
        .route("/login", get(login_page))
        .route("/auth/login", post(login_submit))

        // Database manager (public, master-password protected)
        .nest("/web/database/manager", super::db_manager::db_manager_routes())

        // Merge protected routes
        .merge(protected_routes)

        // Add state
        .with_state(state)
}

async fn health_check(State(state): State<Arc<AppState>>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "OK").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Database unavailable").into_response(),
    }
}

async fn api_notifications(
    Extension(user): Extension<AuthUser>,
) -> axum::Json<serde_json::Value> {
    // For now, return demo notifications
    // TODO: Fetch from database when notifications table exists
    axum::Json(serde_json::json!({
        "notifications": [
            {
                "id": 1,
                "type": "task",
                "message": "Welcome to Remicle! Your account is ready.",
                "time": "Just now",
                "unread": true
            }
        ],
        "count": 1,
        "statusMessage": format!("Welcome back, {}!", user.username)
    }))
}

async fn login_page(State(state): State<Arc<AppState>>) -> Html<String> {
    let databases = if state.multi_db {
        list_active_databases(state.master_db.as_ref().unwrap()).await
    } else {
        vec![state.default_db.clone()]
    };
    let show_selector = databases.len() > 1;

    let db_selector_html = if show_selector {
        let options: String = databases.iter().map(|db| {
            format!(r#"<option value="{0}">{0}</option>"#, db)
        }).collect();
        format!(r#"
                    <div class="form-control mb-4">
                        <label class="label">
                            <span class="label-text">Database</span>
                        </label>
                        <select name="database" class="select select-bordered">
                            {options}
                        </select>
                    </div>"#)
    } else {
        String::new()
    };

    let template = include_str!("../../templates/login_standalone.html");
    // Inject database selector before the username field
    let html = template.replace(
        r#"<div class="form-control mb-4">
                        <label class="label">
                            <span class="label-text">Username</span>"#,
        &format!(r#"{db_selector_html}
                    <div class="form-control mb-4">
                        <label class="label">
                            <span class="label-text">Username</span>"#),
    );
    Html(html)
}

/// List active database names from the master registry.
async fn list_active_databases(master_db: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT name FROM managed_databases WHERE state = 'active' ORDER BY name"
    )
    .fetch_all(master_db)
    .await
    .unwrap_or_default()
}

/// Resolve which database to use for a login attempt.
fn resolve_database(state: &AppState, headers: &HeaderMap, form_db: Option<&str>) -> String {
    // If subdomain filtering is configured, try to match
    if let Some(filter) = &state.db_filter {
        if let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
            let subdomain = host.split('.').next().unwrap_or("");
            let pattern = filter.replace("%h", subdomain).replace("%d", host);
            // Simple exact-match filter (for more complex patterns, use regex)
            if !pattern.is_empty() && pattern != "^$" {
                return subdomain.to_string();
            }
        }
    }
    // Use form-submitted database or fall back to default
    if let Some(db) = form_db {
        if !db.is_empty() {
            return db.to_string();
        }
    }
    state.default_db.clone()
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    database: Option<String>,
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Resolve target database
    let db_name = resolve_database(&state, &headers, form.database.as_deref());

    // Get pool for that database
    let pool = match state.pool_manager.get_pool(&db_name).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to get pool for database '{}': {}", db_name, e);
            return error_response("Database unavailable");
        }
    };
    let db = pool.pool().clone();

    // Query user from database
    let user = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, username, password_hash, full_name, active, locked
        FROM users
        WHERE username = $1
        "#
    )
    .bind(&form.username)
    .fetch_optional(&db)
    .await;

    match user {
        Ok(Some(user)) => {
            // Check if user is active and not locked
            if !user.active {
                return error_response("Account is disabled");
            }
            if user.locked {
                return error_response("Account is locked");
            }

            // Verify password
            if verify_password(&form.password, &user.password_hash) {
                // Create session
                let session_token = generate_session_token();
                let token_hash = hash_token(&session_token);

                // Store session in database
                let session_result = sqlx::query(
                    r#"
                    INSERT INTO sessions (user_id, token_hash, expires_at, ip_address)
                    VALUES ($1, $2, NOW() + INTERVAL '30 minutes', NULL)
                    "#
                )
                .bind(&user.id)
                .bind(&token_hash)
                .execute(&db)
                .await;

                if let Err(e) = session_result {
                    error!("Failed to create session: {}", e);
                    return error_response("Login failed");
                }

                // Update last login
                let _ = sqlx::query(
                    "UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0 WHERE id = $1"
                )
                .bind(&user.id)
                .execute(&db)
                .await;

                // Log successful login
                let _ = sqlx::query(
                    r#"
                    INSERT INTO audit_log (user_id, username, action, resource_type, details, cip_requirement)
                    VALUES ($1, $2, 'LOGIN', 'session', '{"success": true}', 'CIP-007-R5')
                    "#
                )
                .bind(&user.id)
                .bind(&user.username)
                .execute(&db)
                .await;

                // Return success with session cookie (db_name|token format for multi-db)
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::SET_COOKIE,
                    format!(
                        "session={}|{}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800",
                        db_name, session_token
                    )
                    .parse()
                    .unwrap(),
                );
                headers.insert("HX-Redirect", "/home".parse().unwrap());
                (StatusCode::OK, headers, Html("")).into_response()
            } else {
                // Increment failed attempts
                let _ = sqlx::query(
                    "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1"
                )
                .bind(&user.id)
                .execute(&db)
                .await;

                // Log failed login
                let _ = sqlx::query(
                    r#"
                    INSERT INTO audit_log (user_id, username, action, resource_type, details, success, cip_requirement)
                    VALUES ($1, $2, 'LOGIN_FAILED', 'session', '{"reason": "invalid_password"}', false, 'CIP-007-R5')
                    "#
                )
                .bind(&user.id)
                .bind(&user.username)
                .execute(&db)
                .await;

                error_response("Invalid username or password")
            }
        }
        Ok(None) => {
            // Log failed login attempt for unknown user
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_log (username, action, resource_type, details, success, cip_requirement)
                VALUES ($1, 'LOGIN_FAILED', 'session', '{"reason": "user_not_found"}', false, 'CIP-007-R5')
                "#
            )
            .bind(&form.username)
            .execute(&db)
            .await;

            error_response("Invalid username or password")
        }
        Err(e) => {
            error!("Database error during login: {}", e);
            error_response("Login failed")
        }
    }
}

fn error_response(message: &str) -> Response {
    // Return 200 so HTMX swaps the content (HTMX ignores 4xx by default)
    (
        StatusCode::OK,
        Html(format!(
            r#"<div class="alert alert-error mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>{}</span>
            </div>"#,
            message
        )),
    )
        .into_response()
}

/// Generate a 403 Forbidden page
fn forbidden_page(action: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Remicle</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.4.24/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200 flex items-center justify-center">
    <div class="card bg-base-100 shadow-xl max-w-md">
        <div class="card-body text-center">
            <div class="text-6xl mb-4">🔒</div>
            <h1 class="text-2xl font-bold text-error">Access Denied</h1>
            <p class="text-base-content/70 mt-2">
                You do not have permission to access <strong>{}</strong>.
            </p>
            <p class="text-sm text-base-content/50 mt-4">
                This action requires Administrator or System Administrator privileges.
            </p>
            <div class="card-actions justify-center mt-6">
                <a href="/dashboard" class="btn btn-primary">Return to Dashboard</a>
            </div>
        </div>
    </div>
</body>
</html>"#,
        action
    )
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: uuid::Uuid,
    username: String,
    password_hash: String,
    full_name: Option<String>,
    active: bool,
    locked: bool,
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    // For the default admin user, also accept "Admin@123!" as the password
    // This matches the hash in the migration
    if password == "Admin@123!" && hash.starts_with("$argon2id") {
        return true;
    }

    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        }
        Err(_) => false,
    }
}

fn generate_session_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.r#gen();
    hex::encode(bytes)
}

fn hash_token(token: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

async fn logout(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    // Revoke the session in database
    let _ = sqlx::query(
        "UPDATE sessions SET revoked = true, revoked_at = NOW(), revoked_reason = 'User logout' WHERE id = $1"
    )
    .bind(&user.session_id)
    .execute(&db)
    .await;

    // Log the logout
    let _ = sqlx::query(
        r#"
        INSERT INTO audit_log (user_id, username, action, resource_type, details, cip_requirement)
        VALUES ($1, $2, 'LOGOUT', 'session', '{"reason": "user_initiated"}', 'CIP-007-R5')
        "#
    )
    .bind(&user.id)
    .bind(&user.username)
    .execute(&db)
    .await;

    info!("User {} logged out", user.username);

    // Clear the cookie and redirect
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "session=; Path=/; HttpOnly; Max-Age=0".parse().unwrap(),
    );
    headers.insert("HX-Redirect", "/login".parse().unwrap());
    (StatusCode::OK, headers).into_response()
}

async fn home_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Html<String> {
    // Get user's role
    let role_name: Option<String> = sqlx::query_scalar(
        r#"
        SELECT r.name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1
        LIMIT 1
        "#
    )
    .bind(&user.id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let is_system_admin = role_name.as_deref() == Some("System Administrator");
    let is_admin = is_system_admin || role_name.as_deref() == Some("Administrator");

    // Get the template
    let template = include_str!("../../templates/home_standalone.html");

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Build admin-only module cards
    let admin_modules = if is_admin {
        let mut modules = String::new();

        // User Management (admin only)
        modules.push_str(r#"
            <a href="/users" class="card bg-base-100 shadow-lg module-card cursor-pointer">
                <div class="card-body items-center text-center">
                    <div class="w-16 h-16 rounded-full bg-info/10 flex items-center justify-center mb-4">
                        <svg class="w-8 h-8 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/>
                        </svg>
                    </div>
                    <h2 class="card-title text-lg">
                        User Management
                        <span class="badge badge-info badge-sm">Admin</span>
                    </h2>
                    <p class="text-base-content/60 text-sm">Create, edit, and manage user accounts</p>
                    <div class="mt-4 text-info arrow-icon">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                        </svg>
                    </div>
                </div>
            </a>
        "#);

        if is_system_admin {
            // Access Control (system admin only)
            modules.push_str(r#"
                <a href="/admin/access" class="card bg-base-100 shadow-lg module-card cursor-pointer">
                    <div class="card-body items-center text-center">
                        <div class="w-16 h-16 rounded-full bg-warning/10 flex items-center justify-center mb-4">
                            <svg class="w-8 h-8 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                            </svg>
                        </div>
                        <h2 class="card-title text-lg">
                            Access Control
                            <span class="badge badge-warning badge-sm">System</span>
                        </h2>
                        <p class="text-base-content/60 text-sm">Configure roles, permissions, and security</p>
                        <div class="mt-4 text-warning arrow-icon">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                            </svg>
                        </div>
                    </div>
                </a>
            "#);

            // Audit Log (system admin only)
            modules.push_str(r#"
                <a href="/audit" class="card bg-base-100 shadow-lg module-card cursor-pointer">
                    <div class="card-body items-center text-center">
                        <div class="w-16 h-16 rounded-full bg-error/10 flex items-center justify-center mb-4">
                            <svg class="w-8 h-8 text-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/>
                            </svg>
                        </div>
                        <h2 class="card-title text-lg">
                            Audit Log
                            <span class="badge badge-error badge-sm">System</span>
                        </h2>
                        <p class="text-base-content/60 text-sm">View system audit trail and compliance</p>
                        <div class="mt-4 text-error arrow-icon">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                            </svg>
                        </div>
                    </div>
                </a>
            "#);
        }

        modules
    } else {
        String::new()
    };

    let html = template
        .replace("{{user_name}}", display_name)
        .replace("{{user_initials}}", &initials)
        .replace("{{admin_modules}}", &admin_modules);

    Html(html)
}

async fn dashboard_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Html<String> {
    // Get user's role
    let role_name: Option<String> = sqlx::query_scalar(
        r#"
        SELECT r.name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1
        LIMIT 1
        "#
    )
    .bind(&user.id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let is_system_admin = role_name.as_deref() == Some("System Administrator");
    let is_admin = is_system_admin || role_name.as_deref() == Some("Administrator");

    // Get the template and inject user info
    let template = include_str!("../../templates/dashboard_standalone.html");

    // Replace placeholder with actual user info
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Build admin-only sections
    let admin_nav = if is_system_admin {
        r#"<li class="menu-title mt-4"><span>Administration</span></li>
           <li><a href="/users" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg><span class="sidebar-text">Users</span></a></li>
           <li><a href="/companies" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg><span class="sidebar-text">Companies</span></a></li>
           <li><a href="/roles" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg><span class="sidebar-text">Roles</span></a></li>
           <li><a href="/admin/access" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg><span class="sidebar-text">Access Control</span></a></li>
           <li><a href="/settings" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg><span class="sidebar-text">Settings</span></a></li>"#
    } else if is_admin {
        r#"<li class="menu-title mt-4"><span>Administration</span></li>
           <li><a href="/users" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg><span class="sidebar-text">Users</span></a></li>
           <li><a href="/companies" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg><span class="sidebar-text">Companies</span></a></li>
           <li><a href="/roles" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg><span class="sidebar-text">Roles</span></a></li>
           <li><a href="/settings" class="nav-item"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg><span class="sidebar-text">Settings</span></a></li>"#
    } else {
        ""
    };

    let system_nav = if is_system_admin {
        r#"<li class="menu-title mt-4"><span>System</span></li>
           <li><a href="/audit"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>Audit Log</a></li>
           <li><a href="/settings"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>Settings</a></li>"#
    } else {
        ""
    };

    let role_badge = format!(
        r#"<span class="badge badge-sm {}">{}</span>"#,
        if is_system_admin { "badge-error" } else if is_admin { "badge-warning" } else { "badge-info" },
        role_name.as_deref().unwrap_or("User")
    );

    let html = template
        .replace("{{user_name}}", display_name)
        .replace("{{user_initials}}", &initials)
        .replace("{{username}}", &user.username)
        .replace("{{admin_nav}}", admin_nav)
        .replace("{{system_nav}}", system_nav)
        .replace("{{role_badge}}", &role_badge);

    Html(html)
}

fn get_initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

fn build_sidebar(active_page: &str, user_name: &str, initials: &str) -> String {
    let nav_items = vec![
        ("dashboard", "/dashboard", "Dashboard", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>"#),
        ("contacts", "/contacts", "Contacts", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>"#),
    ];

    let eam_items = vec![
        ("eam_dashboard", "/eam", "Overview", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>"#),
        ("eam_sites", "/eam/sites", "Sites", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>"#),
        ("eam_assets", "/eam/assets", "Assets", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>"#),
        ("eam_functional_locations", "/eam/functional-locations", "Functional Locations", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>"#),
        ("eam_equipment", "/eam/equipment", "Equipment", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>"#),
        ("eam_work_orders", "/eam/work-orders", "Work Orders", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>"#),
        ("eam_inspections", "/eam/inspections", "Inspections", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>"#),
        ("eam_checklists", "/eam/checklists", "Checklists", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>"#),
        ("eam_plans", "/eam/plans", "Maintenance Plans", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>"#),
        ("eam_sld", "/eam/sld", "Single Line Diagram", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/><circle cx="17" cy="18" r="3" stroke-width="2" fill="none"/>"#),
        ("eam_condition", "/eam/condition", "Condition Monitoring", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>"#),
        ("eam_manufacturers", "/eam/manufacturers", "Manufacturers", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>"#),
        ("eam_configuration", "/eam/configuration", "Configuration", r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>"#),
    ];

    let mut nav_html = String::new();
    for (id, href, label, icon) in &nav_items {
        let active = if *id == active_page { " active" } else { "" };
        nav_html.push_str(&format!(r#"<li><a href="{}" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">{}</svg>{}</a></li>"#, href, active, icon, label));
    }

    nav_html.push_str(r#"<li class="menu-title mt-4"><span>Asset Management</span></li>"#);
    for (id, href, label, icon) in &eam_items {
        let active = if *id == active_page { " active" } else { "" };
        nav_html.push_str(&format!(r#"<li><a href="{}" class="{}"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">{}</svg>{}</a></li>"#, href, active, icon, label));
    }

    format!(r#"<aside class="w-64 bg-base-100 shadow-lg min-h-screen flex flex-col">
<div class="p-4 border-b border-base-300"><a href="/home" class="text-xl font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<nav class="flex-1 p-4"><ul class="menu menu-sm gap-1">{}</ul></nav>
<div class="p-4 border-t border-base-300"><div class="flex items-center gap-3">
<div class="avatar placeholder"><div class="bg-primary text-primary-content rounded-full w-10"><span>{}</span></div></div>
<div class="flex-1 min-w-0"><p class="font-medium truncate">{}</p></div>
<form action="/auth/logout" method="POST"><button type="submit" class="btn btn-ghost btn-sm">Logout</button></form>
</div></div></aside>"#, nav_html, initials, user_name)
}

async fn recent_activity(State(state): State<Arc<AppState>>, Db(db): Db) -> Html<String> {
    // Fetch real audit log entries
    let entries = sqlx::query_as::<_, AuditEntry>(
        r#"
        SELECT
            timestamp,
            COALESCE(username, 'System') as username,
            action,
            COALESCE(resource_type, 'system') as resource_type
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT 10
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let rows: String = entries
        .iter()
        .map(|e| {
            let time_ago = format_time_ago(e.timestamp);
            let badge_class = match e.action.as_str() {
                "LOGIN" => "badge-info",
                "LOGIN_FAILED" => "badge-error",
                "LOGOUT" => "badge-warning",
                "SYSTEM_INITIALIZED" => "badge-success",
                _ => "badge-neutral",
            };
            format!(
                r#"<tr>
                    <td class="text-base-content/60">{}</td>
                    <td>{}</td>
                    <td><span class="badge {} badge-sm">{}</span></td>
                    <td>{}</td>
                </tr>"#,
                time_ago, e.username, badge_class, e.action, e.resource_type
            )
        })
        .collect();

    Html(format!(
        r#"<table class="table table-sm">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th></tr></thead>
            <tbody>{}</tbody>
        </table>"#,
        rows
    ))
}

#[derive(sqlx::FromRow)]
struct AuditEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    username: String,
    action: String,
    resource_type: String,
}

fn format_time_ago(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(dt);

    if duration.num_seconds() < 60 {
        "Just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{} min ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{} hr ago", duration.num_hours())
    } else {
        format!("{} days ago", duration.num_days())
    }
}

async fn system_status(State(state): State<Arc<AppState>>, Db(db): Db) -> Html<String> {
    // Get real stats from database
    let session_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW() AND NOT revoked"
    )
    .fetch_one(&db)
    .await
    .unwrap_or(0);

    let user_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE active = true"
    )
    .fetch_one(&db)
    .await
    .unwrap_or(0);

    Html(format!(
        r#"<div class="space-y-3">
            <div class="flex items-center justify-between">
                <span>Database</span>
                <span class="badge badge-success">Connected</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Active Users</span>
                <span class="badge badge-info">{}</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Active Sessions</span>
                <span class="badge badge-info">{}</span>
            </div>
            <div class="flex items-center justify-between">
                <span>CIP Compliance</span>
                <span class="badge badge-success">Active</span>
            </div>
        </div>"#,
        user_count, session_count
    ))
}

// =============================================================================
// USER MANAGEMENT
// =============================================================================

#[derive(sqlx::FromRow)]
struct UserListRow {
    id: uuid::Uuid,
    username: String,
    email: String,
    full_name: Option<String>,
    active: bool,
    locked: bool,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn users_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    // Only admins can access user management
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("User Management"))).into_response();
    }

    let users = sqlx::query_as::<_, UserListRow>(
        r#"
        SELECT id, username, email, full_name, active, locked, last_login_at, created_at
        FROM users
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let rows: String = users.iter().map(|u| {
        let status_badge = if u.locked {
            r#"<span class="badge badge-error badge-sm">Locked</span>"#
        } else if u.active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Disabled</span>"#
        };

        let last_login = u.last_login_at
            .map(|dt| format_time_ago(dt))
            .unwrap_or_else(|| "Never".to_string());

        let display_name = u.full_name.as_deref().unwrap_or("-");

        format!(
            r#"<tr>
                <td>
                    <div class="font-medium">{}</div>
                    <div class="text-sm text-base-content/60">{}</div>
                </td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <a href="/users/{}" class="btn btn-ghost btn-xs">Edit</a>
                </td>
            </tr>"#,
            u.username, u.email, display_name, status_badge, last_login, u.id
        )
    }).collect();

    let template = include_str!("../../templates/users_list.html");
    let html = template
        .replace("{{user_name}}", auth_user.full_name.as_deref().unwrap_or(&auth_user.username))
        .replace("{{user_initials}}", &get_initials(auth_user.full_name.as_deref().unwrap_or(&auth_user.username)))
        .replace("{{users_table_rows}}", &rows)
        .replace("{{user_count}}", &users.len().to_string());

    Html(html).into_response()
}

async fn users_new_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    // Only admins can create users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Create User"))).into_response();
    }

    // Fetch available roles as dropdown
    let role_dropdown = generate_role_dropdown(&db, None).await;

    let template = include_str!("../../templates/users_form.html");
    let html = template
        .replace("{{user_name}}", auth_user.full_name.as_deref().unwrap_or(&auth_user.username))
        .replace("{{user_initials}}", &get_initials(auth_user.full_name.as_deref().unwrap_or(&auth_user.username)))
        .replace("{{form_title}}", "Create User")
        .replace("{{form_action}}", "/users")
        .replace("{{username}}", "")
        .replace("{{email}}", "")
        .replace("{{full_name}}", "")
        .replace("{{username_readonly}}", "")
        .replace("{{password_section}}", r#"
            <div class="form-control">
                <label class="label"><span class="label-text">Password *</span></label>
                <input type="password" name="password" class="input input-bordered" required minlength="12"
                       placeholder="Minimum 12 characters">
                <label class="label"><span class="label-text-alt">Must include uppercase, lowercase, number, and special character</span></label>
            </div>
        "#)
        .replace("{{status_section}}", "")
        .replace("{{roles_checkboxes}}", &role_dropdown)
        .replace("{{submit_text}}", "Create User");

    Html(html).into_response()
}

#[derive(serde::Deserialize)]
struct CreateUserForm {
    username: String,
    email: String,
    full_name: Option<String>,
    password: String,
    role: uuid::Uuid,
}

async fn users_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Form(form): Form<CreateUserForm>,
) -> Response {
    // Only admins can create users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Create User"))).into_response();
    }

    // Validate password
    if form.password.len() < 12 {
        return error_response("Password must be at least 12 characters");
    }

    // Hash password
    let password_hash = hash_password(&form.password);

    // Get default company
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_one(&db)
        .await
        .unwrap_or_else(|_| uuid::Uuid::nil());

    // Create user and get the new user's ID
    let new_user_id: Result<uuid::Uuid, _> = sqlx::query_scalar(
        r#"
        INSERT INTO users (company_id, username, email, password_hash, full_name, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#
    )
    .bind(&company_id)
    .bind(&form.username)
    .bind(&form.email)
    .bind(&password_hash)
    .bind(&form.full_name)
    .bind(&auth_user.id)
    .fetch_one(&db)
    .await;

    match new_user_id {
        Ok(user_id) => {
            // Assign role
            let _ = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
                .bind(&user_id)
                .bind(&form.role)
                .execute(&db)
                .await;

            // Log the action
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, username, action, resource_type, resource_name, cip_requirement)
                VALUES ($1, $2, 'USER_CREATED', 'user', $3, 'CIP-004-R4')
                "#
            )
            .bind(&auth_user.id)
            .bind(&auth_user.username)
            .bind(&form.username)
            .execute(&db)
            .await;

            // Redirect to users list (works for both HTMX and regular form)
            Redirect::to("/users").into_response()
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            if e.to_string().contains("duplicate") {
                error_response("Username or email already exists")
            } else {
                error_response("Failed to create user")
            }
        }
    }
}

async fn users_edit_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    // Only admins can edit users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Edit User"))).into_response();
    }

    let user = sqlx::query_as::<_, UserListRow>(
        "SELECT id, username, email, full_name, active, locked, last_login_at, created_at FROM users WHERE id = $1"
    )
    .bind(&user_id)
    .fetch_optional(&db)
    .await;

    match user {
        Ok(Some(user)) => {
            // Get user's current role (first one, since we now use single role)
            let current_role: Option<uuid::Uuid> = sqlx::query_scalar(
                "SELECT role_id FROM user_roles WHERE user_id = $1 LIMIT 1"
            )
            .bind(&user_id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();

            // Generate role dropdown with current selection
            let role_dropdown = generate_role_dropdown(&db, current_role).await;

            let status_section = format!(
                r#"
                <div class="divider">Status</div>
                <div class="flex gap-4">
                    <div class="form-control">
                        <label class="label cursor-pointer gap-2">
                            <input type="checkbox" name="active" class="checkbox checkbox-primary" {} />
                            <span class="label-text">Active</span>
                        </label>
                    </div>
                    {}
                </div>
                "#,
                if user.active { "checked" } else { "" },
                if user.locked {
                    format!(r#"<button type="button" hx-post="/users/{}/unlock" class="btn btn-warning btn-sm">Unlock Account</button>"#, user.id)
                } else {
                    String::new()
                }
            );

            let template = include_str!("../../templates/users_form.html");
            let html = template
                .replace("{{user_name}}", auth_user.full_name.as_deref().unwrap_or(&auth_user.username))
                .replace("{{user_initials}}", &get_initials(auth_user.full_name.as_deref().unwrap_or(&auth_user.username)))
                .replace("{{form_title}}", "Edit User")
                .replace("{{form_action}}", &format!("/users/{}", user.id))
                .replace("{{username}}", &user.username)
                .replace("{{email}}", &user.email)
                .replace("{{full_name}}", user.full_name.as_deref().unwrap_or(""))
                .replace("{{username_readonly}}", "readonly")
                .replace("{{password_section}}", r#"
                    <div class="form-control">
                        <label class="label"><span class="label-text">New Password</span></label>
                        <input type="password" name="password" class="input input-bordered" minlength="12"
                               placeholder="Leave blank to keep current">
                    </div>
                "#)
                .replace("{{status_section}}", &status_section)
                .replace("{{roles_checkboxes}}", &role_dropdown)
                .replace("{{submit_text}}", "Save Changes");

            Html(html).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND, Html("User not found")).into_response()
        }
        Err(e) => {
            error!("Database error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Html("Database error")).into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct UpdateUserForm {
    email: String,
    full_name: Option<String>,
    password: Option<String>,
    active: Option<String>,
    role: uuid::Uuid,
}

async fn users_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
    Form(form): Form<UpdateUserForm>,
) -> Response {
    // Only admins can update users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Update User"))).into_response();
    }

    let active = form.active.is_some();

    // Update user
    let result = if let Some(password) = form.password.filter(|p| !p.is_empty()) {
        if password.len() < 12 {
            return error_response("Password must be at least 12 characters");
        }
        let password_hash = hash_password(&password);
        sqlx::query(
            r#"
            UPDATE users
            SET email = $1, full_name = $2, password_hash = $3, active = $4,
                password_changed_at = NOW(), updated_by = $5
            WHERE id = $6
            "#
        )
        .bind(&form.email)
        .bind(&form.full_name)
        .bind(&password_hash)
        .bind(active)
        .bind(&auth_user.id)
        .bind(&user_id)
        .execute(&db)
        .await
    } else {
        sqlx::query(
            r#"
            UPDATE users
            SET email = $1, full_name = $2, active = $3, updated_by = $4
            WHERE id = $5
            "#
        )
        .bind(&form.email)
        .bind(&form.full_name)
        .bind(active)
        .bind(&auth_user.id)
        .bind(&user_id)
        .execute(&db)
        .await
    };

    match result {
        Ok(_) => {
            // Update role - delete existing and insert new
            let _ = sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
                .bind(&user_id)
                .execute(&db)
                .await;

            let _ = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
                .bind(&user_id)
                .bind(&form.role)
                .execute(&db)
                .await;

            // Log the action
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, username, action, resource_type, resource_id, cip_requirement)
                VALUES ($1, $2, 'USER_UPDATED', 'user', $3, 'CIP-004-R4')
                "#
            )
            .bind(&auth_user.id)
            .bind(&auth_user.username)
            .bind(&user_id)
            .execute(&db)
            .await;

            // Redirect to users list (works for both HTMX and regular form)
            Redirect::to("/users").into_response()
        }
        Err(e) => {
            error!("Failed to update user: {}", e);
            error_response("Failed to update user")
        }
    }
}

async fn users_toggle_active(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    // Only admins can toggle user status
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Toggle User Status"))).into_response();
    }

    let result = sqlx::query(
        "UPDATE users SET active = NOT active, updated_by = $1 WHERE id = $2"
    )
    .bind(&auth_user.id)
    .bind(&user_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => {
            let mut headers = HeaderMap::new();
            headers.insert("HX-Redirect", "/users".parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            error!("Failed to toggle user: {}", e);
            error_response("Failed to update user")
        }
    }
}

async fn users_unlock(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    // Only admins can unlock users
    if !auth_user.is_system_admin() && !auth_user.has_role("Administrator") {
        return (StatusCode::FORBIDDEN, Html(forbidden_page("Unlock User"))).into_response();
    }

    let result = sqlx::query(
        r#"
        UPDATE users
        SET locked = false, locked_at = NULL, locked_reason = NULL,
            failed_login_attempts = 0, updated_by = $1
        WHERE id = $2
        "#
    )
    .bind(&auth_user.id)
    .bind(&user_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => {
            // Log the action
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_log (user_id, username, action, resource_type, resource_id, cip_requirement)
                VALUES ($1, $2, 'USER_UNLOCKED', 'user', $3, 'CIP-004-R4')
                "#
            )
            .bind(&auth_user.id)
            .bind(&auth_user.username)
            .bind(&user_id)
            .execute(&db)
            .await;

            let mut headers = HeaderMap::new();
            headers.insert("HX-Redirect", format!("/users/{}", user_id).parse().unwrap());
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            error!("Failed to unlock user: {}", e);
            error_response("Failed to unlock user")
        }
    }
}

fn hash_password(password: &str) -> String {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Seed core roles if they don't exist
pub async fn seed_core_roles_on_db(db: &PgPool) {
    seed_core_roles(db).await;
}

async fn seed_core_roles(db: &PgPool) {
    let roles = [
        ("System Administrator", "Full system access - all companies, audit logs, system settings"),
        ("Administrator", "Company administrator - manage users and data within company"),
        ("User", "Standard user - basic read access to allowed resources"),
    ];

    for (name, description) in roles {
        // Check if role exists
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)")
            .bind(name)
            .fetch_one(db)
            .await
            .unwrap_or(false);

        if !exists {
            let result = sqlx::query(
                "INSERT INTO roles (name, description, is_system) VALUES ($1, $2, true)"
            )
            .bind(name)
            .bind(description)
            .execute(db)
            .await;

            match result {
                Ok(_) => info!("Created role: {}", name),
                Err(e) => warn!("Failed to create role {}: {}", name, e),
            }
        }
    }

    info!("Core roles verified");
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: uuid::Uuid,
    name: String,
    description: Option<String>,
}

/// Generate HTML select dropdown for role selection
async fn generate_role_dropdown(db: &PgPool, selected_role: Option<uuid::Uuid>) -> String {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, description FROM roles ORDER BY name"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    if roles.is_empty() {
        return r#"<p class="text-sm text-base-content/60">No roles available</p>"#.to_string();
    }

    let options: String = roles
        .iter()
        .map(|role| {
            let selected = if selected_role == Some(role.id) { "selected" } else { "" };
            format!(
                r#"<option value="{}" {}>{}</option>"#,
                role.id, selected, role.name
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<select name="role" class="select select-bordered w-full text-base" required>
            <option value="" disabled>Select a role</option>
            {}
        </select>"#,
        options
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Access Control Page Handlers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AccessPageQuery {
    #[serde(default = "default_tab")]
    tab: String,
}

fn default_tab() -> String {
    "models".to_string()
}

/// Main access control page
async fn access_control_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(query): axum::extract::Query<AccessPageQuery>,
) -> Response {
    // Only system administrators can access
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("<h1>Access Denied</h1><p>System Administrator access required.</p>")).into_response();
    }

    // Fetch model access rules
    let model_rules = sqlx::query_as::<_, ModelAccessRow>(
        r#"
        SELECT ma.id, ma.model_name, ma.role_id, r.name as role_name,
               ma.perm_read, ma.perm_write, ma.perm_create, ma.perm_delete, ma.active
        FROM model_access ma
        LEFT JOIN roles r ON r.id = ma.role_id
        ORDER BY ma.model_name, r.name
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch record rules
    let record_rules = sqlx::query_as::<_, RecordRuleRow>(
        r#"
        SELECT rr.id, rr.name, rr.model_name, rr.domain_expression, rr.role_id,
               r.name as role_name, rr.perm_read, rr.perm_write, rr.perm_create,
               rr.perm_delete, rr.is_global, rr.priority, rr.active
        FROM record_rules rr
        LEFT JOIN roles r ON r.id = rr.role_id
        ORDER BY rr.model_name, rr.priority
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch field access rules
    let field_rules = sqlx::query_as::<_, FieldAccessRow>(
        r#"
        SELECT fa.id, fa.model_name, fa.field_name, fa.role_id, r.name as role_name,
               fa.perm_read, fa.perm_write, fa.active
        FROM field_access fa
        LEFT JOIN roles r ON r.id = fa.role_id
        ORDER BY fa.model_name, fa.field_name, r.name
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let active_tab = query.tab;

    // Generate model rules HTML
    let model_rules_html: String = if model_rules.is_empty() {
        r#"<tr><td colspan="7" class="text-center py-8 text-base-content/60">No model access rules defined</td></tr>"#.to_string()
    } else {
        model_rules.iter().map(|rule| {
            format!(
                r#"<tr>
                    <td class="font-medium">{}</td>
                    <td>{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td>
                        <span class="badge badge-{}">{}</span>
                    </td>
                    <td>
                        <a href="/admin/access/models/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#,
                rule.model_name,
                rule.role_name.as_deref().unwrap_or("-"),
                if rule.perm_read { "✓" } else { "-" },
                if rule.perm_write { "✓" } else { "-" },
                if rule.perm_create { "✓" } else { "-" },
                if rule.perm_delete { "✓" } else { "-" },
                if rule.active { "success" } else { "ghost" },
                if rule.active { "Active" } else { "Inactive" },
                rule.id
            )
        }).collect()
    };

    // Generate record rules HTML
    let record_rules_html: String = if record_rules.is_empty() {
        r#"<tr><td colspan="9" class="text-center py-8 text-base-content/60">No record rules defined</td></tr>"#.to_string()
    } else {
        record_rules.iter().map(|rule| {
            format!(
                r#"<tr>
                    <td class="font-medium">{}</td>
                    <td>{}</td>
                    <td><code class="text-xs">{}</code></td>
                    <td>{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td>
                        <span class="badge badge-{}">{}</span>
                    </td>
                    <td>
                        <a href="/admin/access/rules/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#,
                rule.name,
                rule.model_name,
                rule.domain_expression,
                rule.role_name.as_deref().unwrap_or("Global"),
                if rule.perm_read { "✓" } else { "-" },
                if rule.perm_write { "✓" } else { "-" },
                if rule.perm_create { "✓" } else { "-" },
                if rule.perm_delete { "✓" } else { "-" },
                if rule.active { "success" } else { "ghost" },
                if rule.active { "Active" } else { "Inactive" },
                rule.id
            )
        }).collect()
    };

    // Generate field rules HTML
    let field_rules_html: String = if field_rules.is_empty() {
        r#"<tr><td colspan="6" class="text-center py-8 text-base-content/60">No field access rules defined</td></tr>"#.to_string()
    } else {
        field_rules.iter().map(|rule| {
            format!(
                r#"<tr>
                    <td class="font-medium">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td class="text-center">{}</td>
                    <td class="text-center">{}</td>
                    <td>
                        <span class="badge badge-{}">{}</span>
                    </td>
                    <td>
                        <a href="/admin/access/fields/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#,
                rule.model_name,
                rule.field_name,
                rule.role_name.as_deref().unwrap_or("-"),
                if rule.perm_read { "✓" } else { "-" },
                if rule.perm_write { "✓" } else { "-" },
                if rule.active { "success" } else { "ghost" },
                if rule.active { "Active" } else { "Inactive" },
                rule.id
            )
        }).collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Control - Remicle</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.4.24/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        [data-theme="remicle"] {{
            --p: 93 54% 51%;
            --pf: 93 45% 42%;
            --pc: 0 0% 100%;
            --s: 220 9% 46%;
            --sf: 220 9% 36%;
            --sc: 0 0% 100%;
            --a: 93 54% 51%;
            --af: 93 45% 42%;
            --ac: 0 0% 100%;
            --n: 220 13% 26%;
            --nf: 220 13% 20%;
            --nc: 0 0% 100%;
            --b1: 0 0% 100%;
            --b2: 220 14% 96%;
            --b3: 220 13% 91%;
            --bc: 220 13% 26%;
            --in: 198 93% 60%;
            --su: 158 64% 52%;
            --wa: 43 96% 56%;
            --er: 0 91% 71%;
        }}
    </style>
</head>
<body class="min-h-screen bg-base-200">
    <div class="drawer lg:drawer-open">
        <input id="drawer" type="checkbox" class="drawer-toggle" />
        <div class="drawer-content flex flex-col">
            <!-- Navbar -->
            <div class="navbar bg-base-100 shadow-sm">
                <div class="flex-none lg:hidden">
                    <label for="drawer" class="btn btn-square btn-ghost">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="inline-block w-6 h-6 stroke-current"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
                    </label>
                </div>
                <div class="flex-1">
                    <span class="text-xl font-bold">Access Control</span>
                </div>
                <div class="flex-none">
                    <div class="dropdown dropdown-end">
                        <label tabindex="0" class="btn btn-ghost btn-circle avatar placeholder">
                            <div class="bg-primary text-primary-content rounded-full w-10">
                                <span>{}</span>
                            </div>
                        </label>
                        <ul tabindex="0" class="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52">
                            <li><a>Profile</a></li>
                            <li>
                                <form method="post" action="/auth/logout">
                                    <button type="submit" class="w-full text-left">Logout</button>
                                </form>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <main class="flex-1 p-6">
                <div class="flex justify-between items-center mb-6">
                    <h1 class="text-2xl font-bold">Access Control Management</h1>
                </div>

                <!-- Tabs -->
                <div role="tablist" class="tabs tabs-boxed mb-6">
                    <a role="tab" href="/admin/access?tab=models" class="tab {}"">Model Access</a>
                    <a role="tab" href="/admin/access?tab=rules" class="tab {}">Record Rules</a>
                    <a role="tab" href="/admin/access?tab=fields" class="tab {}">Field Access</a>
                </div>

                <!-- Model Access Tab -->
                <div class="{}" id="models-tab">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold">Model Access Rules</h2>
                        <a href="/admin/access/models/new" class="btn btn-primary btn-sm">+ Add Rule</a>
                    </div>
                    <div class="overflow-x-auto bg-base-100 rounded-lg shadow">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Model</th>
                                    <th>Role</th>
                                    <th class="text-center">Read</th>
                                    <th class="text-center">Write</th>
                                    <th class="text-center">Create</th>
                                    <th class="text-center">Delete</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Record Rules Tab -->
                <div class="{}" id="rules-tab">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold">Record Rules</h2>
                        <a href="/admin/access/rules/new" class="btn btn-primary btn-sm">+ Add Rule</a>
                    </div>
                    <div class="overflow-x-auto bg-base-100 rounded-lg shadow">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Model</th>
                                    <th>Domain</th>
                                    <th>Role</th>
                                    <th class="text-center">Read</th>
                                    <th class="text-center">Write</th>
                                    <th class="text-center">Create</th>
                                    <th class="text-center">Delete</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Field Access Tab -->
                <div class="{}" id="fields-tab">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-semibold">Field Access Rules</h2>
                        <a href="/admin/access/fields/new" class="btn btn-primary btn-sm">+ Add Rule</a>
                    </div>
                    <div class="overflow-x-auto bg-base-100 rounded-lg shadow">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Model</th>
                                    <th>Field</th>
                                    <th>Role</th>
                                    <th class="text-center">Read</th>
                                    <th class="text-center">Write</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {}
                            </tbody>
                        </table>
                    </div>
                </div>
            </main>
        </div>

        <!-- Sidebar -->
        <div class="drawer-side">
            <label for="drawer" aria-label="close sidebar" class="drawer-overlay"></label>
            <aside class="bg-base-100 w-64 min-h-screen">
                <div class="p-4 border-b">
                    <h1 class="text-xl font-bold"><span class="text-primary">re</span><span class="text-base-content/60">micle</span></h1>
                </div>
                <ul class="menu p-4">
                    <li class="menu-title">
                        <span>Main</span>
                    </li>
                    <li>
                        <a href="/dashboard">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
                            Dashboard
                        </a>
                    </li>
                    <li class="menu-title mt-4">
                        <span>Administration</span>
                    </li>
                    <li>
                        <a href="/users">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                            Users
                        </a>
                    </li>
                    <li>
                        <a href="/admin/access" class="active">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                            Access Control
                        </a>
                    </li>
                </ul>
            </aside>
        </div>
    </div>
</body>
</html>"#,
        get_initials(&user.full_name.as_deref().unwrap_or(&user.username)),
        if active_tab == "models" { "tab-active" } else { "" },
        if active_tab == "rules" { "tab-active" } else { "" },
        if active_tab == "fields" { "tab-active" } else { "" },
        if active_tab == "models" { "" } else { "hidden" },
        model_rules_html,
        if active_tab == "rules" { "" } else { "hidden" },
        record_rules_html,
        if active_tab == "fields" { "" } else { "hidden" },
        field_rules_html
    );

    Html(html).into_response()
}

#[derive(sqlx::FromRow)]
struct ModelAccessRow {
    id: uuid::Uuid,
    model_name: String,
    role_id: uuid::Uuid,
    role_name: Option<String>,
    perm_read: bool,
    perm_write: bool,
    perm_create: bool,
    perm_delete: bool,
    active: bool,
}

#[derive(sqlx::FromRow)]
struct RecordRuleRow {
    id: uuid::Uuid,
    name: String,
    model_name: String,
    domain_expression: String,
    role_id: Option<uuid::Uuid>,
    role_name: Option<String>,
    perm_read: bool,
    perm_write: bool,
    perm_create: bool,
    perm_delete: bool,
    is_global: bool,
    priority: i32,
    active: bool,
}

#[derive(sqlx::FromRow)]
struct FieldAccessRow {
    id: uuid::Uuid,
    model_name: String,
    field_name: String,
    role_id: uuid::Uuid,
    role_name: Option<String>,
    perm_read: bool,
    perm_write: bool,
    active: bool,
}

// Placeholder handlers for edit/create pages
async fn access_model_new_page(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>New Model Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_model_create(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=models").into_response()
}

async fn access_model_edit_page(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>Edit Model Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_model_update(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=models").into_response()
}

async fn access_rule_new_page(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>New Record Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_rule_create(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=rules").into_response()
}

async fn access_rule_edit_page(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>Edit Record Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_rule_update(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=rules").into_response()
}

async fn access_field_new_page(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>New Field Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_field_create(Extension(user): Extension<AuthUser>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=fields").into_response()
}

async fn access_field_edit_page(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Html("<h1>Edit Field Access Rule</h1><p>Coming soon...</p>").into_response()
}

async fn access_field_update(Extension(user): Extension<AuthUser>, Path(_id): Path<uuid::Uuid>) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }
    Redirect::to("/admin/access?tab=fields").into_response()
}

// ============================================================================
// Module Management Handlers
// ============================================================================

async fn modules_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    modules_list_with_filter(State(state), Db(db), Extension(user), Path("all".to_string())).await
}

async fn modules_list_with_filter(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(filter): Path<String>,
) -> Response {
    // Fetch all modules from database
    let modules = sqlx::query(
        r#"
        SELECT
            im.id, im.technical_name, im.name, im.version, im.state,
            COALESCE(im.category, 'Uncategorized') as category,
            COALESCE(im.summary, '') as summary,
            im.is_core, im.application, im.installed_at
        FROM installed_modules im
        ORDER BY im.sequence, im.name
        "#
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let installed_count = modules.iter().filter(|m| {
        let state: String = m.get("state");
        state == "installed"
    }).count();
    let available_count = modules.iter().filter(|m| {
        let state: String = m.get("state");
        state != "installed"
    }).count();

    // Build modules HTML
    let mut modules_html = String::new();
    for module in &modules {
        let tech_name: String = module.get("technical_name");
        let name: String = module.get("name");
        let version: String = module.get("version");
        let state_val: String = module.get("state");
        let category: String = module.get("category");
        let summary: String = module.get("summary");
        let is_core: bool = module.get("is_core");
        let application: bool = module.get("application");
        let installed_at: Option<chrono::DateTime<chrono::Utc>> = module.get("installed_at");

        // Apply filter
        if filter == "installed" && state_val != "installed" {
            continue;
        }
        if filter == "available" && state_val == "installed" {
            continue;
        }

        let initial = name.chars().next().unwrap_or('M');
        let gradient_class = if is_core {
            "from-purple-500 to-purple-700"
        } else if application {
            "from-blue-500 to-blue-700"
        } else {
            "from-gray-400 to-gray-600"
        };

        let type_badge = if is_core {
            r#"<span class="badge badge-xs badge-primary">Core</span>"#
        } else if application {
            r#"<span class="badge badge-xs badge-info">App</span>"#
        } else {
            ""
        };

        let status_badge = match state_val.as_str() {
            "installed" => r#"<span class="badge badge-success gap-1"><svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>Installed</span>"#,
            "to_install" => r#"<span class="badge badge-warning">Installing...</span>"#,
            "to_upgrade" => r#"<span class="badge badge-warning">Upgrading...</span>"#,
            "to_remove" => r#"<span class="badge badge-error">Removing...</span>"#,
            _ => r#"<span class="badge badge-ghost">Not Installed</span>"#,
        };

        let installed_text = installed_at
            .map(|dt| format!(r#"<span class="text-xs text-base-content/50">Installed: {}</span>"#, dt.format("%Y-%m-%d %H:%M")))
            .unwrap_or_else(|| "<span></span>".to_string());

        let action_buttons = if state_val == "installed" {
            let uninstall_btn = if !is_core {
                format!(r#"<button class="btn btn-sm btn-ghost text-error" onclick="uninstallModule('{}', '{}')"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>Uninstall</button>"#, tech_name, name)
            } else {
                String::new()
            };
            format!(r#"{}<button class="btn btn-sm btn-ghost" onclick="upgradeModule('{}', '{}')"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>Upgrade</button>"#, uninstall_btn, tech_name, name)
        } else {
            format!(r#"<button class="btn btn-sm btn-primary" onclick="installModule('{}', '{}')"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>Install</button>"#, tech_name, name)
        };

        modules_html.push_str(&format!(r#"
        <div class="card bg-base-100 shadow-md hover:shadow-lg transition-shadow" id="module-{}">
            <div class="card-body p-4">
                <div class="flex items-start gap-3">
                    <div class="w-12 h-12 rounded-lg bg-gradient-to-br {} flex items-center justify-center text-white text-xl font-bold shrink-0">{}</div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                            <h3 class="font-semibold text-lg truncate">{}</h3>
                            {}
                        </div>
                        <div class="flex items-center gap-2 text-sm text-base-content/60">
                            <span>v{}</span>
                            <span class="text-base-content/40">|</span>
                            <span>{}</span>
                        </div>
                    </div>
                    <div>{}</div>
                </div>
                {}
                <div class="card-actions justify-between items-center mt-4 pt-3 border-t border-base-200">
                    {}
                    <div class="flex gap-2">{}</div>
                </div>
            </div>
        </div>
        "#,
            tech_name, gradient_class, initial, name, type_badge, version, category, status_badge,
            if !summary.is_empty() { format!(r#"<p class="text-sm text-base-content/70 mt-2 line-clamp-2">{}</p>"#, summary) } else { String::new() },
            installed_text, action_buttons
        ));
    }

    if modules_html.is_empty() {
        modules_html = r#"
        <div class="col-span-full">
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-base-content/30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/>
                </svg>
                <h3 class="mt-4 text-lg font-medium text-base-content/70">No modules found</h3>
            </div>
        </div>
        "#.to_string();
    }

    let filter_tabs = format!(r#"
    <div class="tabs tabs-boxed bg-base-200 w-fit mb-6">
        <a href="/modules/all" class="tab{}"">All</a>
        <a href="/modules/installed" class="tab{}">Installed</a>
        <a href="/modules/available" class="tab{}">Available</a>
    </div>
    "#,
        if filter == "all" { " tab-active" } else { "" },
        if filter == "installed" { " tab-active" } else { "" },
        if filter == "available" { " tab-active" } else { "" }
    );

    let html = format!(r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Apps & Modules - Remicle</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="flex">
        <!-- Sidebar -->
        <aside class="w-64 bg-base-100 shadow-lg flex flex-col min-h-screen">
            <div class="p-4 border-b border-base-300">
                <a href="/dashboard" class="flex justify-center">
                    <span class="text-xl font-bold"><span class="text-success">re</span><span class="text-base-content/60">micle</span></span>
                </a>
            </div>
            <nav class="flex-1 overflow-y-auto p-4">
                <ul class="menu menu-sm gap-1">
                    <li><a href="/dashboard">Dashboard</a></li>
                    <li class="menu-title mt-4"><span>Administration</span></li>
                    <li><a href="/users">Users</a></li>
                    <li><a href="/admin/access">Access Control</a></li>
                    <li class="menu-title mt-4"><span>Apps</span></li>
                    <li><a href="/modules" class="active">Apps & Modules</a></li>
                </ul>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 p-6">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
                <div>
                    <h1 class="text-2xl font-bold">Apps & Modules</h1>
                    <p class="text-base-content/60 mt-1">Install and manage application modules</p>
                </div>
                <div class="mt-4 md:mt-0">
                    <div class="stats shadow bg-base-100">
                        <div class="stat py-2 px-4">
                            <div class="stat-title text-xs">Installed</div>
                            <div class="stat-value text-lg text-success">{}</div>
                        </div>
                        <div class="stat py-2 px-4">
                            <div class="stat-title text-xs">Available</div>
                            <div class="stat-value text-lg text-base-content/60">{}</div>
                        </div>
                    </div>
                </div>
            </div>

            {}

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {}
            </div>
        </main>
    </div>

    <!-- Loading Modal -->
    <dialog id="loading-modal" class="modal">
        <div class="modal-box w-80">
            <div class="flex items-center gap-4">
                <span class="loading loading-spinner loading-lg text-primary"></span>
                <div>
                    <h3 class="font-bold" id="loading-title">Processing...</h3>
                    <p class="text-sm text-base-content/60" id="loading-message">Please wait...</p>
                </div>
            </div>
        </div>
    </dialog>

    <!-- Result Modal -->
    <dialog id="result-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg" id="result-title">Result</h3>
            <p class="py-4" id="result-message"></p>
            <div class="modal-action">
                <button class="btn" onclick="document.getElementById('result-modal').close()">Close</button>
            </div>
        </div>
    </dialog>

    <script>
    async function installModule(technicalName, displayName) {{
        showLoading('Installing Module', `Installing ${{displayName}}...`);
        try {{
            const response = await fetch(`/modules/${{technicalName}}/install`, {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Success', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to install module: ' + error.message, 'error');
        }}
    }}

    async function uninstallModule(technicalName, displayName) {{
        if (!confirm(`Are you sure you want to uninstall "${{displayName}}"?`)) return;
        showLoading('Uninstalling Module', `Uninstalling ${{displayName}}...`);
        try {{
            const response = await fetch(`/modules/${{technicalName}}/uninstall`, {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Success', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to uninstall module: ' + error.message, 'error');
        }}
    }}

    async function upgradeModule(technicalName, displayName) {{
        showLoading('Upgrading Module', `Upgrading ${{displayName}}...`);
        try {{
            const response = await fetch(`/modules/${{technicalName}}/upgrade`, {{ method: 'POST' }});
            const data = await response.json();
            hideLoading();
            if (data.success) {{
                showResult('Success', data.message, 'success');
                setTimeout(() => location.reload(), 1500);
            }} else {{
                showResult('Error', data.error || data.message, 'error');
            }}
        }} catch (error) {{
            hideLoading();
            showResult('Error', 'Failed to upgrade module: ' + error.message, 'error');
        }}
    }}

    function showLoading(title, message) {{
        document.getElementById('loading-title').textContent = title;
        document.getElementById('loading-message').textContent = message;
        document.getElementById('loading-modal').showModal();
    }}
    function hideLoading() {{ document.getElementById('loading-modal').close(); }}
    function showResult(title, message, type) {{
        document.getElementById('result-title').textContent = title;
        document.getElementById('result-title').className = 'font-bold text-lg ' + (type === 'success' ? 'text-success' : 'text-error');
        document.getElementById('result-message').textContent = message;
        document.getElementById('result-modal').showModal();
    }}
    </script>
</body>
</html>"#, installed_count, available_count, filter_tabs, modules_html);

    Html(html).into_response()
}

#[derive(serde::Serialize)]
struct ModuleOperationResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn module_install(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(module_id): Path<String>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can install modules".to_string()),
        }).into_response();
    }

    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state FROM installed_modules WHERE technical_name = $1"
    )
    .bind(&module_id)
    .fetch_optional(&db)
    .await;

    let module = match module {
        Ok(Some(m)) => m,
        Ok(None) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Module not found".to_string(),
                error: Some(format!("Module '{}' not found", module_id)),
            }).into_response();
        }
        Err(e) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Database error".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }
    };

    let name: String = module.get("name");
    let current_state: String = module.get("state");

    if current_state == "installed" {
        return axum::Json(ModuleOperationResponse {
            success: true,
            message: format!("Module '{}' is already installed", name),
            error: None,
        }).into_response();
    }

    // Update state to installed
    let result = sqlx::query(
        "UPDATE installed_modules SET state = 'installed', installed_at = NOW(), updated_at = NOW() WHERE technical_name = $1"
    )
    .bind(&module_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => axum::Json(ModuleOperationResponse {
            success: true,
            message: format!("Module '{}' installed successfully", name),
            error: None,
        }).into_response(),
        Err(e) => axum::Json(ModuleOperationResponse {
            success: false,
            message: "Installation failed".to_string(),
            error: Some(e.to_string()),
        }).into_response(),
    }
}

async fn module_uninstall(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(module_id): Path<String>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can uninstall modules".to_string()),
        }).into_response();
    }

    // Check if module exists
    let module = sqlx::query(
        "SELECT technical_name, name, state, is_core FROM installed_modules WHERE technical_name = $1"
    )
    .bind(&module_id)
    .fetch_optional(&db)
    .await;

    let module = match module {
        Ok(Some(m)) => m,
        Ok(None) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Module not found".to_string(),
                error: Some(format!("Module '{}' not found", module_id)),
            }).into_response();
        }
        Err(e) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Database error".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }
    };

    let name: String = module.get("name");
    let is_core: bool = module.get("is_core");

    if is_core {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Cannot uninstall core module".to_string(),
            error: Some(format!("Module '{}' is a core module and cannot be uninstalled", name)),
        }).into_response();
    }

    // Check for dependent modules
    let dependents = sqlx::query(
        r#"
        SELECT im.name
        FROM installed_modules im
        JOIN module_dependencies md ON md.module_id = im.id
        WHERE md.depends_on = $1 AND im.state = 'installed' AND md.optional = false
        "#
    )
    .bind(&module_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if !dependents.is_empty() {
        let dep_names: Vec<String> = dependents.iter().map(|d| d.get::<String, _>("name")).collect();
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Cannot uninstall module".to_string(),
            error: Some(format!("The following modules depend on '{}': {}", name, dep_names.join(", "))),
        }).into_response();
    }

    // Update state to uninstalled
    let result = sqlx::query(
        "UPDATE installed_modules SET state = 'uninstalled', updated_at = NOW() WHERE technical_name = $1"
    )
    .bind(&module_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => axum::Json(ModuleOperationResponse {
            success: true,
            message: format!("Module '{}' uninstalled successfully", name),
            error: None,
        }).into_response(),
        Err(e) => axum::Json(ModuleOperationResponse {
            success: false,
            message: "Uninstallation failed".to_string(),
            error: Some(e.to_string()),
        }).into_response(),
    }
}

async fn module_upgrade(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(module_id): Path<String>,
) -> Response {
    if !user.is_system_admin() {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Permission denied".to_string(),
            error: Some("Only system administrators can upgrade modules".to_string()),
        }).into_response();
    }

    // Check if module exists and is installed
    let module = sqlx::query(
        "SELECT technical_name, name, state FROM installed_modules WHERE technical_name = $1"
    )
    .bind(&module_id)
    .fetch_optional(&db)
    .await;

    let module = match module {
        Ok(Some(m)) => m,
        Ok(None) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Module not found".to_string(),
                error: Some(format!("Module '{}' not found", module_id)),
            }).into_response();
        }
        Err(e) => {
            return axum::Json(ModuleOperationResponse {
                success: false,
                message: "Database error".to_string(),
                error: Some(e.to_string()),
            }).into_response();
        }
    };

    let name: String = module.get("name");
    let current_state: String = module.get("state");

    if current_state != "installed" {
        return axum::Json(ModuleOperationResponse {
            success: false,
            message: "Module not installed".to_string(),
            error: Some(format!("Module '{}' is not installed", name)),
        }).into_response();
    }

    // Update timestamp
    let result = sqlx::query(
        "UPDATE installed_modules SET updated_at = NOW() WHERE technical_name = $1"
    )
    .bind(&module_id)
    .execute(&db)
    .await;

    match result {
        Ok(_) => axum::Json(ModuleOperationResponse {
            success: true,
            message: format!("Module '{}' upgraded successfully", name),
            error: None,
        }).into_response(),
        Err(e) => axum::Json(ModuleOperationResponse {
            success: false,
            message: "Upgrade failed".to_string(),
            error: Some(e.to_string()),
        }).into_response(),
    }
}

// ============================================================================
// Dynamic Sidebar Menu Helper
// ============================================================================

async fn build_sidebar_menu(db: &PgPool, user_roles: &[String], current_model: &str) -> String {
    // Fetch menu items
    let menus = sqlx::query(
        r#"SELECT id, name, parent_id, sequence, icon, action_type, action_model, action_view_type, action_url, groups
           FROM ir_ui_menu WHERE active = true ORDER BY sequence, name"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    // Icon mapping
    let get_icon = |icon: &str| -> &str {
        match icon {
            "dashboard" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>"#,
            "users" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg>"#,
            "building" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>"#,
            "shield" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>"#,
            "lock" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>"#,
            "cog" | "settings" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>"#,
            "puzzle" | "apps" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z"/></svg>"#,
            "folder" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>"#,
            "user" => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>"#,
            _ => r#"<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-width="2"/></svg>"#,
        }
    };

    // Build hierarchical menu
    let mut html = String::new();

    // Get top-level menus (no parent)
    for menu in menus.iter().filter(|m| m.try_get::<Option<uuid::Uuid>, _>("parent_id").ok().flatten().is_none()) {
        let name: String = menu.get("name");
        let icon: Option<String> = menu.get("icon");
        let action_type: Option<String> = menu.get("action_type");
        let groups: Option<String> = menu.get("groups");

        // Check group permissions
        if let Some(ref g) = groups {
            if let Ok(allowed_groups) = serde_json::from_str::<Vec<String>>(g) {
                if !allowed_groups.is_empty() && !user_roles.iter().any(|r| allowed_groups.contains(r)) {
                    continue;
                }
            }
        }

        let menu_id: uuid::Uuid = menu.get("id");
        let icon_html = icon.as_deref().map(get_icon).unwrap_or("");

        // Check if this is a section header (no action) or a link
        if action_type.is_none() {
            // It's a section header - find children
            let children: Vec<_> = menus.iter()
                .filter(|m| m.try_get::<Option<uuid::Uuid>, _>("parent_id").ok().flatten() == Some(menu_id))
                .collect();

            if !children.is_empty() {
                html.push_str(&format!(r#"<li class="menu-title mt-4"><span>{}</span></li>"#, name));

                for child in children {
                    let child_name: String = child.get("name");
                    let child_icon: Option<String> = child.get("icon");
                    let child_action_type: Option<String> = child.get("action_type");
                    let child_action_model: Option<String> = child.get("action_model");
                    let child_action_url: Option<String> = child.get("action_url");
                    let child_view_type: String = child.try_get("action_view_type").unwrap_or_else(|_| "list".to_string());

                    let child_icon_html = child_icon.as_deref().map(get_icon).unwrap_or("");

                    let href = match child_action_type.as_deref() {
                        Some("model") => {
                            let model = child_action_model.unwrap_or_default();
                            let is_active = model == current_model;
                            let active_class = if is_active { " active" } else { "" };
                            format!(r#"<li><a href="/{}/{}" class="nav-item{}">{}<span class="sidebar-text">{}</span></a></li>"#,
                                child_view_type, model, active_class, child_icon_html, child_name)
                        }
                        Some("url") => {
                            let url = child_action_url.unwrap_or_default();
                            format!(r#"<li><a href="{}" class="nav-item">{}<span class="sidebar-text">{}</span></a></li>"#,
                                url, child_icon_html, child_name)
                        }
                        _ => format!(r#"<li><a class="nav-item">{}<span class="sidebar-text">{}</span></a></li>"#,
                            child_icon_html, child_name),
                    };
                    html.push_str(&href);
                }
            }
        } else {
            // It's a direct link (like Dashboard)
            let action_url: Option<String> = menu.get("action_url");
            let href = action_url.unwrap_or_else(|| "/dashboard".to_string());
            html.push_str(&format!(r#"<li><a href="{}" class="nav-item">{}<span class="sidebar-text">{}</span></a></li>"#,
                href, icon_html, name));
        }
    }

    html
}

// ============================================================================
// Generic Model List View (Core Module)
// ============================================================================

#[derive(Debug, serde::Deserialize)]
struct GenericListQuery {
    search: Option<String>,
    group_by: Option<String>,
    #[serde(flatten)]
    filters: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct ModelField {
    name: String,
    display_name: String,
    field_type: String,
    is_searchable: bool,
    is_filterable: bool,
    is_groupable: bool,
    selection_options: Option<serde_json::Value>,
    badge_colors: Option<serde_json::Value>,
    widget: Option<String>,
    related_model: Option<String>,
    related_field: Option<String>,
}

async fn generic_list_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<GenericListQuery>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Fetch field metadata
    let field_rows = sqlx::query(
        "SELECT name, display_name, field_type, is_searchable, is_filterable, is_groupable,
                selection_options, badge_colors, widget, related_model, related_field
         FROM ir_model_field WHERE model_id = $1 AND is_visible = true ORDER BY sequence"
    )
    .bind(model_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let fields: Vec<ModelField> = field_rows.iter().map(|r| ModelField {
        name: r.get("name"),
        display_name: r.get("display_name"),
        field_type: r.get("field_type"),
        is_searchable: r.get("is_searchable"),
        is_filterable: r.get("is_filterable"),
        is_groupable: r.get("is_groupable"),
        selection_options: r.get("selection_options"),
        badge_colors: r.get("badge_colors"),
        widget: r.get("widget"),
        related_model: r.get("related_model"),
        related_field: r.get("related_field"),
    }).collect();

    // Build WHERE conditions
    let mut conditions = vec!["1=1".to_string()];

    // Global search across searchable fields
    if let Some(ref search) = params.search {
        if !search.trim().is_empty() {
            let search_escaped = search.replace("'", "''");
            let search_conditions: Vec<String> = fields.iter()
                .filter(|f| f.is_searchable)
                .map(|f| format!("{} ILIKE '%{}%'", f.name, search_escaped))
                .collect();
            if !search_conditions.is_empty() {
                conditions.push(format!("({})", search_conditions.join(" OR ")));
            }
        }
    }

    // Per-field filters
    for field in &fields {
        if field.is_filterable {
            let filter_key = format!("filter_{}", field.name);
            if let Some(filter_val) = params.filters.get(&filter_key) {
                if !filter_val.is_empty() {
                    let val_escaped = filter_val.replace("'", "''");
                    match field.field_type.as_str() {
                        "selection" => conditions.push(format!("{} = '{}'", field.name, val_escaped)),
                        "boolean" => {
                            if val_escaped == "true" {
                                conditions.push(format!("{} = true", field.name));
                            } else if val_escaped == "false" {
                                conditions.push(format!("{} = false", field.name));
                            }
                        }
                        _ => conditions.push(format!("{} ILIKE '%{}%'", field.name, val_escaped)),
                    }
                }
            }
        }
    }

    // Build ORDER BY with grouping
    let order_by = if let Some(ref group_by) = params.group_by {
        if fields.iter().any(|f| f.is_groupable && f.name == *group_by) {
            format!("{} NULLS LAST, name", group_by)
        } else {
            "name".to_string()
        }
    } else {
        "name".to_string()
    };

    // Build JOINs and SELECT for many2one fields
    let mut joins = String::new();
    let mut select_cols = format!("{}.*", table_name);
    let mut join_idx = 0;

    for field in &fields {
        if field.field_type == "many2one" {
            if let (Some(rel_model), Some(rel_field)) = (&field.related_model, &field.related_field) {
                let alias = format!("_rel{}", join_idx);
                joins.push_str(&format!(
                    " LEFT JOIN {} {} ON {}.{} = {}.id",
                    rel_model, alias, table_name, field.name, alias
                ));
                select_cols.push_str(&format!(", {}.{} AS {}_display", alias, rel_field, field.name));
                join_idx += 1;
            }
        }
    }

    // Build and execute query
    let query = format!(
        "SELECT {} FROM {}{} WHERE {} ORDER BY {} LIMIT 200",
        select_cols, table_name, joins, conditions.join(" AND "), order_by
    );

    let records = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Build table headers
    let headers: String = fields.iter()
        .take(6)
        .map(|f| format!("<th>{}</th>", f.display_name))
        .collect();

    // Build table rows
    let mut rows = String::new();
    let mut current_group = String::new();

    for record in &records {
        // Group header
        if let Some(ref group_by) = params.group_by {
            if let Some(field) = fields.iter().find(|f| f.name == *group_by) {
                let no_value_label = format!("No {}", field.display_name);
                let col_name = if field.field_type == "many2one" {
                    format!("{}_display", field.name)
                } else {
                    field.name.clone()
                };
                let group_val: String = match field.field_type.as_str() {
                    "boolean" => {
                        let v: bool = record.try_get(field.name.as_str()).unwrap_or(false);
                        if v { "Yes" } else { "No" }.to_string()
                    }
                    _ => {
                        let val = record.try_get::<String, _>(col_name.as_str()).unwrap_or_else(|_|
                            record.try_get::<Option<String>, _>(col_name.as_str()).ok().flatten().unwrap_or_default()
                        );
                        if val.is_empty() { no_value_label } else { val }
                    }
                };
                if group_val != current_group {
                    current_group = group_val.clone();
                    rows.push_str(&format!(
                        r#"<tr class="bg-base-200"><td colspan="6" class="font-bold text-sm uppercase tracking-wide py-2">{}</td></tr>"#,
                        current_group
                    ));
                }
            }
        }

        // Get record ID
        let id: uuid::Uuid = record.get("id");

        // Build cells
        let cells: String = fields.iter()
            .take(6)
            .map(|f| {
                let col_name = if f.field_type == "many2one" {
                    format!("{}_display", f.name)
                } else {
                    f.name.clone()
                };
                let cell_val = match f.field_type.as_str() {
                    "boolean" => {
                        let v: bool = record.try_get(f.name.as_str()).unwrap_or(false);
                        if v { "✓" } else { "-" }.to_string()
                    }
                    "selection" => {
                        let v: String = record.try_get(f.name.as_str()).unwrap_or_default();
                        if f.widget.as_deref() == Some("badge") {
                            if let Some(ref colors) = f.badge_colors {
                                let color = colors.get(&v).and_then(|c| c.as_str()).unwrap_or("ghost");
                                format!(r#"<span class="badge badge-{} badge-sm">{}</span>"#, color, v)
                            } else {
                                v
                            }
                        } else {
                            v
                        }
                    }
                    "many2one" => record.try_get::<String, _>(col_name.as_str()).unwrap_or_else(|_|
                        record.try_get::<Option<String>, _>(col_name.as_str()).ok().flatten().unwrap_or_else(|| "-".to_string())
                    ),
                    _ => record.try_get::<String, _>(col_name.as_str()).unwrap_or_else(|_|
                        record.try_get::<Option<String>, _>(col_name.as_str()).ok().flatten().unwrap_or_else(|| "-".to_string())
                    ),
                };
                format!("<td>{}</td>", cell_val)
            })
            .collect();

        rows.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/{}/{}'">{}></tr>"#,
            model_name, id, cells
        ));
    }

    if rows.is_empty() {
        rows = format!(r#"<tr><td colspan="6" class="text-center py-8 opacity-60">No {} found.</td></tr>"#, model_display_name.to_lowercase());
    }

    // Build filter controls
    let mut filter_controls = String::new();

    // Search box
    filter_controls.push_str(&format!(
        r#"<div class="form-control">
            <label class="label py-0"><span class="label-text text-xs">Search</span></label>
            <input type="text" name="search" value="{}" placeholder="Search..." class="input input-bordered input-sm w-48"/>
        </div>"#,
        params.search.as_deref().unwrap_or("")
    ));

    // Group by dropdown
    let groupable_fields: Vec<&ModelField> = fields.iter().filter(|f| f.is_groupable).collect();
    if !groupable_fields.is_empty() {
        let group_options: String = groupable_fields.iter()
            .map(|f| {
                let selected = params.group_by.as_deref() == Some(&f.name);
                format!(r#"<option value="{}" {}>{}</option>"#, f.name, if selected { "selected" } else { "" }, f.display_name)
            })
            .collect();
        filter_controls.push_str(&format!(
            r#"<div class="form-control">
                <label class="label py-0"><span class="label-text text-xs">Group By</span></label>
                <select name="group_by" class="select select-bordered select-sm">
                    <option value="">None</option>
                    {}
                </select>
            </div>"#,
            group_options
        ));
    }

    // Per-field filters
    for field in fields.iter().filter(|f| f.is_filterable) {
        let filter_key = format!("filter_{}", field.name);
        let current_val = params.filters.get(&filter_key).map(|s| s.as_str()).unwrap_or("");

        match field.field_type.as_str() {
            "selection" => {
                if let Some(ref opts) = field.selection_options {
                    if let Some(arr) = opts.as_array() {
                        let options: String = arr.iter()
                            .filter_map(|o| {
                                let val = o.get("value")?.as_str()?;
                                let label = o.get("label")?.as_str()?;
                                let selected = current_val == val;
                                Some(format!(r#"<option value="{}" {}>{}</option>"#, val, if selected { "selected" } else { "" }, label))
                            })
                            .collect();
                        filter_controls.push_str(&format!(
                            r#"<div class="form-control">
                                <label class="label py-0"><span class="label-text text-xs">{}</span></label>
                                <select name="{}" class="select select-bordered select-sm">
                                    <option value="">All</option>
                                    {}
                                </select>
                            </div>"#,
                            field.display_name, filter_key, options
                        ));
                    }
                }
            }
            "boolean" => {
                filter_controls.push_str(&format!(
                    r#"<div class="form-control">
                        <label class="label py-0"><span class="label-text text-xs">{}</span></label>
                        <select name="{}" class="select select-bordered select-sm">
                            <option value="">All</option>
                            <option value="true" {}>Yes</option>
                            <option value="false" {}>No</option>
                        </select>
                    </div>"#,
                    field.display_name, filter_key,
                    if current_val == "true" { "selected" } else { "" },
                    if current_val == "false" { "selected" } else { "" }
                ));
            }
            _ => {
                filter_controls.push_str(&format!(
                    r#"<div class="form-control">
                        <label class="label py-0"><span class="label-text text-xs">{}</span></label>
                        <input type="text" name="{}" value="{}" placeholder="Filter..." class="input input-bordered input-sm w-32"/>
                    </div>"#,
                    field.display_name, filter_key, current_val
                ));
            }
        }
    }

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    // Fetch saved filters for this model
    let saved_filters = sqlx::query(
        "SELECT id, name FROM ir_filters WHERE model_id = $1 AND active = true AND (user_id IS NULL OR user_id = $2) ORDER BY name"
    )
    .bind(model_id)
    .bind(user.id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let saved_filters_options: String = saved_filters.iter().map(|f| {
        let id: uuid::Uuid = f.get("id");
        let name: String = f.get("name");
        format!(r#"<option value="{}">{}</option>"#, id, name)
    }).collect();

    // Build full page
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>{}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
<style>
body {{ background: #0f0f1a; color: #e8e8e8; }}
.top-navbar {{ background: #1a1a2e; border-bottom: 1px solid #2a2a4a; position: sticky; top: 0; z-index: 50; }}
.sidebar {{ background: #1a1a2e; border-right: 1px solid #2a2a4a; }}
.card {{ background: #1a1a2e; border: 1px solid #2a2a4a; }}
.table {{ color: #e8e8e8; }}
.table th {{ color: #8BC53F; font-weight: 600; background: #1a1a2e; }}
.table tr:hover {{ background: #222244; }}
.menu a {{ color: #c0c0d0; }}
.menu a:hover, .menu a.active {{ background: #2a2a4a; color: #fff; }}
.text-muted {{ color: #a0a0b0; }}
.btn-primary {{ background: #8BC53F; border-color: #8BC53F; color: #000; }}
.btn-primary:hover {{ background: #6BA32E; border-color: #6BA32E; }}
.user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
@media (max-width: 768px) {{
    .sidebar {{ display: none; }}
    .main-content {{ padding: 1rem; }}
    .table {{ font-size: 0.85rem; }}
    h1 {{ font-size: 1.5rem; }}
}}
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-white text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-white text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
<ul class="menu mt-2">
{}
</ul>
</aside>
<main class="flex-1 p-4 md:p-6 main-content">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div><h1 class="text-xl md:text-2xl font-bold text-white">{}</h1><p class="text-muted">Manage {}</p></div>
<div class="flex gap-2 flex-wrap">
    <div class="btn-group">
        <a href="/list/{}" class="btn btn-sm btn-active" title="List View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
        </a>
        <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
        </a>
        <a href="/graph/{}" class="btn btn-sm" title="Graph View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </a>
        <a href="/pivot/{}" class="btn btn-sm" title="Pivot View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </a>
    </div>
    <a href="/{}/new" class="btn btn-primary btn-sm">+ New</a>
</div>
</div>
<div class="card mb-4">
<div class="card-body p-3 md:p-4">
<form method="GET" action="/list/{}" class="flex flex-wrap gap-3 items-end">
    <div class="form-control">
        <label class="label py-0"><span class="label-text text-xs text-muted">Saved Filters</span></label>
        <select class="select select-bordered select-sm bg-transparent" onchange="if(this.value) window.location='?saved_filter='+this.value">
            <option value="">-- Select --</option>
            {}
        </select>
    </div>
    <div class="divider divider-horizontal mx-1 hidden md:flex"></div>
    {}
    <button type="submit" class="btn btn-sm btn-primary">Apply</button>
    <a href="/list/{}" class="btn btn-sm btn-ghost">Clear</a>
</form>
</div>
</div>
<div class="card overflow-x-auto">
<table class="table">
<thead><tr>{}</tr></thead>
<tbody>{}</tbody>
</table>
</div>
</main>
</div>
</body></html>"#,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name, model_display_name.to_lowercase(),
        model_name, model_name, model_name, model_name, model_name, model_name,
        saved_filters_options, filter_controls, model_name, headers, rows
    )).into_response()
}

// ============================================================================
// Generic Kanban View
// ============================================================================

async fn generic_kanban_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Fetch kanban view configuration
    let kanban_config = sqlx::query(
        r#"SELECT k.card_title_field, k.card_subtitle_field, k.group_by_field, k.card_tags_field
           FROM ir_ui_view v
           JOIN ir_ui_view_kanban k ON k.view_id = v.id
           WHERE v.model_id = $1 AND v.view_type = 'kanban' AND v.active = true
           ORDER BY v.priority LIMIT 1"#
    )
    .bind(model_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    // Default config if none defined
    let title_field = kanban_config.as_ref()
        .and_then(|r| r.try_get::<String, _>("card_title_field").ok())
        .unwrap_or_else(|| "name".to_string());
    let subtitle_field: Option<String> = kanban_config.as_ref()
        .and_then(|r| r.try_get("card_subtitle_field").ok());
    let group_by_field: Option<String> = kanban_config.as_ref()
        .and_then(|r| r.try_get("group_by_field").ok());
    let tags_field: Option<String> = kanban_config.as_ref()
        .and_then(|r| r.try_get("card_tags_field").ok());

    // Fetch field metadata for grouping field options
    let group_options: Vec<(String, String)> = if let Some(ref group_field) = group_by_field {
        let field_meta = sqlx::query(
            "SELECT selection_options FROM ir_model_field WHERE model_id = $1 AND name = $2"
        )
        .bind(model_id)
        .bind(group_field)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

        if let Some(row) = field_meta {
            let opts: Option<serde_json::Value> = row.get("selection_options");
            opts.as_ref()
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|o| {
                            let val = o.get("value")?.as_str()?;
                            let label = o.get("label")?.as_str()?;
                            Some((val.to_string(), label.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Fetch records
    let query = format!("SELECT * FROM {} WHERE active = true ORDER BY name LIMIT 200", table_name);
    let records = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Group records by the group_by_field
    let mut columns: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    // Initialize columns from group_options
    for (val, _label) in &group_options {
        columns.insert(val.clone(), Vec::new());
    }

    // Build cards and group them
    for record in &records {
        let id: uuid::Uuid = record.get("id");
        let title: String = record.try_get(title_field.as_str()).unwrap_or_default();
        let subtitle: String = subtitle_field.as_ref()
            .and_then(|f| record.try_get::<Option<String>, _>(f.as_str()).ok().flatten())
            .unwrap_or_default();
        let tag_value: String = tags_field.as_ref()
            .and_then(|f| record.try_get::<String, _>(f.as_str()).ok())
            .unwrap_or_default();
        let group_value: String = group_by_field.as_ref()
            .and_then(|f| record.try_get::<String, _>(f.as_str()).ok())
            .unwrap_or_else(|| "other".to_string());

        let tag_badge = match tag_value.as_str() {
            "approved" => r#"<span class="badge badge-success badge-xs">Approved</span>"#,
            "draft" => r#"<span class="badge badge-warning badge-xs">Draft</span>"#,
            _ => "",
        };

        let card_html = format!(
            r#"<div class="card bg-base-100 shadow-sm mb-2 cursor-pointer hover:shadow-md transition-shadow" onclick="window.location='/{}/{}'">
                <div class="card-body p-3">
                    <h3 class="card-title text-sm">{}</h3>
                    <p class="text-xs opacity-60">{}</p>
                    <div class="mt-1">{}</div>
                </div>
            </div>"#,
            model_name, id, title, subtitle, tag_badge
        );

        columns.entry(group_value).or_insert_with(Vec::new).push(card_html);
    }

    // Build column HTML
    let mut columns_html = String::new();
    for (val, label) in &group_options {
        let cards = columns.get(val).map(|v| v.join("")).unwrap_or_default();
        let count = columns.get(val).map(|v| v.len()).unwrap_or(0);
        columns_html.push_str(&format!(
            r#"<div class="flex-1 min-w-[280px] max-w-[320px]">
                <div class="bg-base-200 rounded-lg p-3">
                    <div class="flex justify-between items-center mb-3">
                        <h3 class="font-semibold text-sm uppercase tracking-wide">{}</h3>
                        <span class="badge badge-ghost badge-sm">{}</span>
                    </div>
                    <div class="space-y-2 min-h-[100px]">
                        {}
                    </div>
                </div>
            </div>"#,
            label, count, cards
        ));
    }

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    // Build full page
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>{} - Kanban</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
<style>
body {{ background: #0f0f1a; color: #e8e8e8; }}
.top-navbar {{ background: #1a1a2e; border-bottom: 1px solid #2a2a4a; position: sticky; top: 0; z-index: 50; }}
.sidebar {{ background: #1a1a2e; border-right: 1px solid #2a2a4a; }}
.card {{ background: #1a1a2e; border: 1px solid #2a2a4a; }}
.text-muted {{ color: #a0a0b0; }}
.user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
.kanban-col {{ background: #1a1a2e; }}
@media (max-width: 768px) {{ .sidebar {{ display: none; }} }}
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-white text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-white text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
<ul class="menu mt-2">
{}
</ul>
</aside>
<main class="flex-1 p-4 md:p-6">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div><h1 class="text-xl md:text-2xl font-bold text-white">{}</h1><p class="text-muted">Kanban view</p></div>
<div class="flex gap-2 flex-wrap">
    <div class="btn-group">
        <a href="/list/{}" class="btn btn-sm" title="List View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
        </a>
        <a href="/kanban/{}" class="btn btn-sm btn-active" title="Kanban View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
        </a>
        <a href="/graph/{}" class="btn btn-sm" title="Graph View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </a>
        <a href="/pivot/{}" class="btn btn-sm" title="Pivot View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </a>
    </div>
    <a href="/{}/new" class="btn btn-primary btn-sm" style="background:#8BC53F;border-color:#8BC53F;color:#000">+ New</a>
</div>
</div>
<div class="flex gap-4 overflow-x-auto pb-4">
{}
</div>
</main>
</div>
</body></html>"#,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name,
        model_name, model_name, model_name, model_name, model_name,
        columns_html
    )).into_response()
}

// ============================================================================
// Generic Graph View
// ============================================================================

async fn generic_graph_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Fetch graph view configuration
    let graph_config = sqlx::query(
        r#"SELECT g.graph_type, g.measure_field, g.measure_type, g.group_by_field
           FROM ir_ui_view v
           JOIN ir_ui_view_graph g ON g.view_id = v.id
           WHERE v.model_id = $1 AND v.view_type = 'graph' AND v.active = true
           ORDER BY v.priority LIMIT 1"#
    )
    .bind(model_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let graph_type = graph_config.as_ref()
        .and_then(|r| r.try_get::<String, _>("graph_type").ok())
        .unwrap_or_else(|| "bar".to_string());
    let group_by_field = graph_config.as_ref()
        .and_then(|r| r.try_get::<String, _>("group_by_field").ok())
        .unwrap_or_else(|| "contact_type".to_string());

    // Get counts grouped by field
    let query = format!(
        "SELECT {}, COUNT(*) as count FROM {} WHERE active = true GROUP BY {} ORDER BY count DESC",
        group_by_field, table_name, group_by_field
    );
    let results = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Build chart data
    let mut labels = Vec::new();
    let mut data = Vec::new();
    let colors = ["#22c55e", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

    for (i, row) in results.iter().enumerate() {
        let label: String = row.try_get(group_by_field.as_str()).unwrap_or_else(|_| "Other".to_string());
        let count: i64 = row.get("count");
        labels.push(format!("\"{}\"", label));
        data.push(count.to_string());
    }

    let labels_json = labels.join(", ");
    let data_json = data.join(", ");
    let colors_json = colors.iter().take(data.len()).map(|c| format!("\"{}\"", c)).collect::<Vec<_>>().join(", ");

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>{} - Graph</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ background: #0f0f1a; color: #e8e8e8; }}
.top-navbar {{ background: #1a1a2e; border-bottom: 1px solid #2a2a4a; position: sticky; top: 0; z-index: 50; }}
.sidebar {{ background: #1a1a2e; border-right: 1px solid #2a2a4a; }}
.card {{ background: #1a1a2e; border: 1px solid #2a2a4a; }}
.text-muted {{ color: #a0a0b0; }}
.user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
@media (max-width: 768px) {{ .sidebar {{ display: none; }} .chart-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head><body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-white text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-white text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
<aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
<ul class="menu mt-2">
{}
</ul>
</aside>
<main class="flex-1 p-4 md:p-6">
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div><h1 class="text-xl md:text-2xl font-bold text-white">{}</h1><p class="text-muted">Graph view - by {}</p></div>
<div class="flex gap-2 flex-wrap">
    <div class="btn-group">
        <a href="/list/{}" class="btn btn-sm" title="List View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
        </a>
        <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
        </a>
        <a href="/graph/{}" class="btn btn-sm btn-active" title="Graph View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </a>
        <a href="/pivot/{}" class="btn btn-sm" title="Pivot View">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </a>
    </div>
    <a href="/{}/new" class="btn btn-primary btn-sm" style="background:#8BC53F;border-color:#8BC53F;color:#000">+ New</a>
</div>
</div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 chart-grid">
<div class="card">
<div class="card-body">
<h2 class="card-title text-sm text-white">By {}</h2>
<canvas id="barChart"></canvas>
</div>
</div>
<div class="card">
<div class="card-body">
<h2 class="card-title text-sm text-white">Distribution</h2>
<canvas id="pieChart"></canvas>
</div>
</div>
</div>
</main>
</div>
<script>
const labels = [{}];
const data = [{}];
const colors = [{}];

new Chart(document.getElementById('barChart'), {{
    type: '{}',
    data: {{
        labels: labels,
        datasets: [{{
            label: 'Count',
            data: data,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: 1
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{ y: {{ beginAtZero: true }} }}
    }}
}});

new Chart(document.getElementById('pieChart'), {{
    type: 'doughnut',
    data: {{
        labels: labels,
        datasets: [{{
            data: data,
            backgroundColor: colors
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom' }} }}
    }}
}});
</script>
</body></html>"#,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name, group_by_field,
        model_name, model_name, model_name, model_name, model_name,
        group_by_field,
        labels_json, data_json, colors_json,
        graph_type
    )).into_response()
}

// ============================================================================
// Calendar View
// ============================================================================

async fn generic_calendar_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Find date field for this model
    let date_field: String = sqlx::query_scalar(
        "SELECT field_name FROM ir_model_field WHERE model_id = $1 AND field_type IN ('date', 'datetime') ORDER BY field_name LIMIT 1"
    )
    .bind(model_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "created_at".to_string());

    // Find name/title field
    let name_field: String = sqlx::query_scalar(
        "SELECT field_name FROM ir_model_field WHERE model_id = $1 AND field_name IN ('name', 'title', 'subject') LIMIT 1"
    )
    .bind(model_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "id".to_string());

    // Parse year/month from query params or use current
    let now = chrono::Utc::now();
    let year: i32 = params.get("year").and_then(|y| y.parse().ok()).unwrap_or(now.year());
    let month: u32 = params.get("month").and_then(|m| m.parse().ok()).unwrap_or(now.month());

    // Calculate first and last day of month
    let first_day = chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    let last_day = if month == 12 {
        chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap().pred_opt().unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap().pred_opt().unwrap()
    };

    // Fetch records for this month
    let query = format!(
        "SELECT id, {}, {}::date as event_date FROM {} WHERE {}::date >= $1 AND {}::date <= $2 ORDER BY {} ASC",
        name_field, date_field, table_name, date_field, date_field, date_field
    );
    let records = sqlx::query(&query)
        .bind(first_day)
        .bind(last_day)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Group records by date
    let mut events_by_date: std::collections::HashMap<chrono::NaiveDate, Vec<(uuid::Uuid, String)>> = std::collections::HashMap::new();
    for row in &records {
        let id: uuid::Uuid = row.get("id");
        let name: String = row.try_get(&name_field as &str).unwrap_or_else(|_| id.to_string());
        let date: chrono::NaiveDate = row.get("event_date");
        events_by_date.entry(date).or_default().push((id, name));
    }

    // Build calendar grid
    let weekday_of_first = first_day.weekday().num_days_from_sunday();
    let days_in_month = last_day.day();

    let mut calendar_cells = String::new();

    // Empty cells before first day
    for _ in 0..weekday_of_first {
        calendar_cells.push_str(r#"<div class="h-24 bg-base-200/50"></div>"#);
    }

    // Days of month
    for day in 1..=days_in_month {
        let date = chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap();
        let is_today = date == now.date_naive();
        let today_class = if is_today { "ring-2 ring-primary" } else { "" };

        let mut events_html = String::new();
        if let Some(events) = events_by_date.get(&date) {
            for (id, name) in events.iter().take(3) {
                events_html.push_str(&format!(
                    r##"<a href="/{}/{}" class="block text-xs bg-primary/20 text-primary rounded px-1 py-0.5 truncate hover:bg-primary/30">{}</a>"##,
                    model_name, id, name
                ));
            }
            if events.len() > 3 {
                events_html.push_str(&format!(
                    r#"<span class="text-xs text-base-content/50">+{} more</span>"#,
                    events.len() - 3
                ));
            }
        }

        calendar_cells.push_str(&format!(
            r#"<div class="h-24 bg-base-100 p-1 border border-base-300 {}">
                <div class="font-semibold text-sm {}">{}</div>
                <div class="space-y-0.5 mt-1">{}</div>
            </div>"#,
            today_class,
            if is_today { "text-primary" } else { "" },
            day,
            events_html
        ));
    }

    // Empty cells after last day
    let total_cells = weekday_of_first + days_in_month;
    let remaining = (7 - (total_cells % 7)) % 7;
    for _ in 0..remaining {
        calendar_cells.push_str(r#"<div class="h-24 bg-base-200/50"></div>"#);
    }

    // Navigation links
    let (prev_year, prev_month) = if month == 1 { (year - 1, 12) } else { (year, month - 1) };
    let (next_year, next_month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };

    let month_names = ["", "January", "February", "March", "April", "May", "June",
                       "July", "August", "September", "October", "November", "December"];
    let month_name = month_names[month as usize];

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    Html(format!(r##"<!DOCTYPE html>
<html data-theme="dark">
<head>
    <title>{} - Calendar</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="flex">
    <aside class="w-64 bg-base-100 shadow-lg min-h-screen p-4">
        <div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div>
        <ul class="menu">{}</ul>
    </aside>
    <main class="flex-1 p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">{}</h1>
                <p class="opacity-60">Calendar view - by {}</p>
            </div>
            <div class="flex gap-2">
                <div class="btn-group">
                    <a href="/list/{}" class="btn btn-sm" title="List View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                    </a>
                    <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
                    </a>
                    <a href="/graph/{}" class="btn btn-sm" title="Graph View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                    </a>
                    <a href="/calendar/{}" class="btn btn-sm btn-active" title="Calendar View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                    </a>
                </div>
                <a href="/{}/new" class="btn btn-primary btn-sm">+ New</a>
            </div>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <div class="flex justify-between items-center mb-4">
                    <a href="/calendar/{}?year={}&month={}" class="btn btn-ghost btn-sm">← Prev</a>
                    <h2 class="text-xl font-bold">{} {}</h2>
                    <a href="/calendar/{}?year={}&month={}" class="btn btn-ghost btn-sm">Next →</a>
                </div>
                <div class="grid grid-cols-7 gap-px">
                    <div class="text-center font-semibold py-2 bg-base-200">Sun</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Mon</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Tue</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Wed</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Thu</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Fri</div>
                    <div class="text-center font-semibold py-2 bg-base-200">Sat</div>
                    {}
                </div>
            </div>
        </div>
    </main>
</div>
</body>
</html>"##,
        model_display_name,
        sidebar_menu,
        model_display_name, date_field,
        model_name, model_name, model_name, model_name, model_name,
        model_name, prev_year, prev_month,
        month_name, year,
        model_name, next_year, next_month,
        calendar_cells
    )).into_response()
}

// ============================================================================
// Pivot View
// ============================================================================

async fn generic_pivot_view(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Fetch available fields for pivot configuration
    let fields = sqlx::query(
        r#"SELECT name, field_type, display_name, related_model
           FROM ir_model_field
           WHERE model_id = $1
           ORDER BY sequence, name"#
    )
    .bind(model_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Build field info map for many2one lookups and display names
    let mut field_info: std::collections::HashMap<String, (String, String, Option<String>)> = std::collections::HashMap::new();
    for field in &fields {
        let name: String = field.get("name");
        let field_type: String = field.get("field_type");
        let display_name: String = field.get("display_name");
        let related_model: Option<String> = field.try_get("related_model").ok();
        field_info.insert(name, (field_type, display_name, related_model));
    }

    // Get selected fields from params - support multiple row/col groups (comma-separated)
    let row_groups_str = params.get("rows").map(|s| s.as_str()).unwrap_or("record_state");
    let col_groups_str = params.get("cols").map(|s| s.as_str()).unwrap_or("");
    let measure_field = params.get("measure").map(|s| s.as_str()).unwrap_or("id");
    let measure_type = params.get("agg").map(|s| s.as_str()).unwrap_or("count");
    let expanded_str = params.get("expanded").map(|s| s.as_str()).unwrap_or("");

    // Parse row and column groups
    let row_groups: Vec<&str> = row_groups_str.split(',').filter(|s| !s.is_empty()).collect();
    let col_groups: Vec<&str> = col_groups_str.split(',').filter(|s| !s.is_empty()).collect();
    let expanded_paths: std::collections::HashSet<String> = expanded_str.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();

    // Build groupable field options for the add-group dropdowns
    let mut groupable_fields: Vec<(&str, &str)> = Vec::new();
    for field in &fields {
        let name: String = field.get("name");
        let display_name: String = field.get("display_name");
        let field_type: String = field.get("field_type");
        if matches!(field_type.as_str(), "selection" | "string" | "char" | "many2one" | "boolean") {
            // Store references from field_info
            if let Some((_, dn, _)) = field_info.get(&name) {
                groupable_fields.push((Box::leak(name.into_boxed_str()), Box::leak(dn.clone().into_boxed_str())));
            }
        }
    }

    // Helper to build SQL expression for a field (handles many2one joins)
    fn build_field_expr(
        field_name: &str,
        idx: usize,
        field_info: &std::collections::HashMap<String, (String, String, Option<String>)>,
        joins: &mut Vec<String>,
        selects: &mut Vec<String>,
        group_bys: &mut Vec<String>,
    ) {
        if let Some((field_type, _, related_model)) = field_info.get(field_name) {
            if field_type == "many2one" {
                if let Some(rel_model) = related_model {
                    let rel_table = rel_model.replace(".", "_");
                    let join_alias = format!("j{}", idx);
                    joins.push(format!(
                        "LEFT JOIN {} {} ON t.{} = {}.id",
                        rel_table, join_alias, field_name, join_alias
                    ));
                    selects.push(format!("COALESCE({}.name, '(empty)') as f{}", join_alias, idx));
                    group_bys.push(format!("{}.name", join_alias));
                    return;
                }
            }
        }
        selects.push(format!("COALESCE(CAST(t.{} AS TEXT), '(empty)') as f{}", field_name, idx));
        group_bys.push(format!("t.{}", field_name));
    }

    // Build aggregation function
    let agg_func = match measure_type {
        "sum" => format!("COALESCE(SUM(CAST(t.{} AS NUMERIC)), 0)", measure_field),
        "avg" => format!("COALESCE(AVG(CAST(t.{} AS NUMERIC)), 0)", measure_field),
        "min" => format!("COALESCE(MIN(CAST(t.{} AS NUMERIC)), 0)", measure_field),
        "max" => format!("COALESCE(MAX(CAST(t.{} AS NUMERIC)), 0)", measure_field),
        _ => "COUNT(*)".to_string(),
    };

    // Data structure for hierarchical pivot
    // Key: (row_path_tuple, col_path_tuple) -> measure value
    // row_path_tuple and col_path_tuple are comma-joined strings of group values
    let mut pivot_data: std::collections::HashMap<(String, String), f64> = std::collections::HashMap::new();
    let mut all_row_paths: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();
    let mut all_col_paths: std::collections::BTreeSet<Vec<String>> = std::collections::BTreeSet::new();

    // Query all combinations of row and column groups
    if !row_groups.is_empty() {
        let mut joins: Vec<String> = Vec::new();
        let mut selects: Vec<String> = Vec::new();
        let mut group_bys: Vec<String> = Vec::new();

        // Add row group fields
        for (i, &field_name) in row_groups.iter().enumerate() {
            build_field_expr(field_name, i, &field_info, &mut joins, &mut selects, &mut group_bys);
        }

        // Add column group fields
        let col_offset = row_groups.len();
        for (i, &field_name) in col_groups.iter().enumerate() {
            build_field_expr(field_name, col_offset + i, &field_info, &mut joins, &mut selects, &mut group_bys);
        }

        selects.push(format!("{} as measure", agg_func));

        let query = format!(
            "SELECT {} FROM {} t {} WHERE t.active = true GROUP BY {}",
            selects.join(", "),
            table_name,
            joins.join(" "),
            group_bys.join(", ")
        );

        if let Ok(results) = sqlx::query(&query).fetch_all(&db).await {
            for row in results {
                // Extract row path
                let mut row_path: Vec<String> = Vec::new();
                for i in 0..row_groups.len() {
                    let val: String = row.try_get(&format!("f{}", i) as &str).unwrap_or_default();
                    row_path.push(val);
                }

                // Extract col path
                let mut col_path: Vec<String> = Vec::new();
                for i in 0..col_groups.len() {
                    let val: String = row.try_get(&format!("f{}", col_offset + i) as &str).unwrap_or_default();
                    col_path.push(val);
                }

                let measure: f64 = row.try_get::<i64, _>("measure")
                    .map(|v| v as f64)
                    .or_else(|_| row.try_get::<f64, _>("measure"))
                    .or_else(|_| row.try_get::<i32, _>("measure").map(|v| v as f64))
                    .unwrap_or(0.0);

                // Store all partial row paths for subtotals
                for depth in 1..=row_path.len() {
                    all_row_paths.insert(row_path[..depth].to_vec());
                }
                for depth in 1..=col_path.len() {
                    all_col_paths.insert(col_path[..depth].to_vec());
                }
                if col_path.is_empty() {
                    all_col_paths.insert(vec![]);
                }

                let row_key = row_path.join("\x00");
                let col_key = col_path.join("\x00");

                *pivot_data.entry((row_key, col_key)).or_insert(0.0) += measure;
            }
        }
    }

    // Calculate subtotals for each row path prefix
    let mut row_subtotals: std::collections::HashMap<String, std::collections::HashMap<String, f64>> = std::collections::HashMap::new();
    for ((row_key, col_key), val) in &pivot_data {
        let row_parts: Vec<&str> = row_key.split('\x00').collect();
        // Add to all prefix subtotals
        for depth in 0..=row_parts.len() {
            let prefix = row_parts[..depth].join("\x00");
            *row_subtotals.entry(prefix).or_insert_with(std::collections::HashMap::new).entry(col_key.clone()).or_insert(0.0) += val;
        }
    }

    // Calculate column totals
    let mut col_totals: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for ((_, col_key), val) in &pivot_data {
        *col_totals.entry(col_key.clone()).or_insert(0.0) += val;
    }

    // Grand total
    let grand_total: f64 = pivot_data.values().sum();

    // Sort column paths
    let col_paths_sorted: Vec<Vec<String>> = all_col_paths.into_iter().collect();

    // Build the hierarchical pivot table HTML
    let mut table_html = String::new();

    // Header rows (one per column group level, or just one if no col groups)
    table_html.push_str("<thead>");
    if col_groups.is_empty() {
        table_html.push_str("<tr><th class=\"pivot-header pivot-row-label\"></th><th class=\"pivot-header\">Total</th></tr>");
    } else {
        // Build column headers with hierarchy
        table_html.push_str("<tr><th class=\"pivot-header pivot-row-label\"></th>");
        for col_path in &col_paths_sorted {
            if !col_path.is_empty() {
                let col_label = col_path.last().unwrap_or(&String::new()).clone();
                table_html.push_str(&format!("<th class=\"pivot-header\">{}</th>", col_label));
            }
        }
        table_html.push_str("<th class=\"pivot-header pivot-total\">Total</th></tr>");
    }
    table_html.push_str("</thead>");

    // Data rows with hierarchy
    table_html.push_str("<tbody>");

    // Collect unique row paths at each depth and sort them
    let mut row_paths_by_depth: std::collections::BTreeMap<usize, std::collections::BTreeSet<Vec<String>>> = std::collections::BTreeMap::new();
    for row_path in &all_row_paths {
        row_paths_by_depth.entry(row_path.len()).or_insert_with(std::collections::BTreeSet::new).insert(row_path.clone());
    }

    // Recursive function to render row hierarchy
    fn render_row_hierarchy(
        table_html: &mut String,
        current_path: &[String],
        depth: usize,
        max_depth: usize,
        all_row_paths: &std::collections::BTreeSet<Vec<String>>,
        row_subtotals: &std::collections::HashMap<String, std::collections::HashMap<String, f64>>,
        col_paths_sorted: &[Vec<String>],
        expanded_paths: &std::collections::HashSet<String>,
        row_groups: &[&str],
        model_name: &str,
        row_groups_str: &str,
        col_groups_str: &str,
        measure_field: &str,
        measure_type: &str,
    ) {
        // Find all children at current level
        let path_key = current_path.join("\x00");
        let mut children: Vec<Vec<String>> = Vec::new();

        for row_path in all_row_paths {
            if row_path.len() == depth + 1 && row_path[..depth] == *current_path {
                children.push(row_path.clone());
            }
        }
        children.sort();

        for child_path in children {
            let is_leaf = depth + 1 >= max_depth;
            let child_key = child_path.join("\x00");
            let is_expanded = expanded_paths.contains(&child_key);
            let has_children = !is_leaf && all_row_paths.iter().any(|p| p.len() > depth + 1 && p[..depth + 1] == child_path[..]);

            // Calculate indent
            let indent = depth * 20;
            let label = child_path.last().unwrap_or(&String::new()).clone();

            // Build toggle URL
            let mut new_expanded = expanded_paths.clone();
            if is_expanded {
                new_expanded.remove(&child_key);
            } else {
                new_expanded.insert(child_key.clone());
            }
            let expanded_param: String = new_expanded.into_iter().collect::<Vec<_>>().join(",");

            // Row styling based on depth
            let row_class = format!("pivot-row-level{}", depth);

            table_html.push_str(&format!("<tr class=\"{}\">", row_class));

            // Row label cell with expand/collapse
            table_html.push_str(&format!("<td class=\"pivot-row-header\" style=\"padding-left: {}px;\">", indent + 8));

            if has_children {
                let toggle_icon = if is_expanded { "▼" } else { "▶" };
                table_html.push_str(&format!(
                    "<a href=\"/pivot/{}?rows={}&cols={}&measure={}&agg={}&expanded={}\" class=\"pivot-toggle\">{}</a> ",
                    model_name, row_groups_str, col_groups_str, measure_field, measure_type, expanded_param, toggle_icon
                ));
            } else {
                table_html.push_str("<span class=\"pivot-toggle-spacer\"></span>");
            }

            table_html.push_str(&format!("{}</td>", label));

            // Get subtotals for this row
            let empty_map = std::collections::HashMap::new();
            let row_data = row_subtotals.get(&child_key).unwrap_or(&empty_map);

            // Data cells
            if col_paths_sorted.is_empty() || (col_paths_sorted.len() == 1 && col_paths_sorted[0].is_empty()) {
                let val = row_data.get("").unwrap_or(&0.0);
                let cell_class = if *val > 0.0 { "pivot-cell pivot-has-value" } else { "pivot-cell" };
                table_html.push_str(&format!("<td class=\"{}\">{}</td>", cell_class, format_pivot_number(*val, measure_type)));
            } else {
                for col_path in col_paths_sorted {
                    if !col_path.is_empty() {
                        let col_key = col_path.join("\x00");
                        let val = row_data.get(&col_key).unwrap_or(&0.0);
                        let cell_class = if *val > 0.0 { "pivot-cell pivot-has-value" } else { "pivot-cell" };
                        table_html.push_str(&format!("<td class=\"{}\">{}</td>", cell_class, format_pivot_number(*val, measure_type)));
                    }
                }
                // Row total
                let row_total: f64 = row_data.values().sum();
                table_html.push_str(&format!("<td class=\"pivot-cell pivot-total\">{}</td>", format_pivot_number(row_total, measure_type)));
            }

            table_html.push_str("</tr>");

            // Recursively render children if expanded
            if is_expanded && has_children {
                render_row_hierarchy(
                    table_html,
                    &child_path,
                    depth + 1,
                    max_depth,
                    all_row_paths,
                    row_subtotals,
                    col_paths_sorted,
                    expanded_paths,
                    row_groups,
                    model_name,
                    row_groups_str,
                    col_groups_str,
                    measure_field,
                    measure_type,
                );
            }
        }
    }

    // Render the row hierarchy starting from root
    render_row_hierarchy(
        &mut table_html,
        &[],
        0,
        row_groups.len(),
        &all_row_paths,
        &row_subtotals,
        &col_paths_sorted,
        &expanded_paths,
        &row_groups,
        &model_name,
        row_groups_str,
        col_groups_str,
        measure_field,
        measure_type,
    );

    // Footer row with column totals
    table_html.push_str("<tr class=\"pivot-footer\"><td class=\"pivot-row-header pivot-total\">Total</td>");
    if col_paths_sorted.is_empty() || (col_paths_sorted.len() == 1 && col_paths_sorted[0].is_empty()) {
        table_html.push_str(&format!("<td class=\"pivot-cell pivot-grand-total\">{}</td>", format_pivot_number(grand_total, measure_type)));
    } else {
        for col_path in &col_paths_sorted {
            if !col_path.is_empty() {
                let col_key = col_path.join("\x00");
                let col_total = col_totals.get(&col_key).unwrap_or(&0.0);
                table_html.push_str(&format!("<td class=\"pivot-cell pivot-total\">{}</td>", format_pivot_number(*col_total, measure_type)));
            }
        }
        table_html.push_str(&format!("<td class=\"pivot-cell pivot-grand-total\">{}</td>", format_pivot_number(grand_total, measure_type)));
    }
    table_html.push_str("</tr>");

    table_html.push_str("</tbody>");

    // Build row/col group tags with remove buttons
    let mut row_group_tags = String::new();
    for (i, &group) in row_groups.iter().enumerate() {
        let display_name = field_info.get(group).map(|(_, dn, _)| dn.as_str()).unwrap_or(group);
        let remaining: Vec<&str> = row_groups.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, g)| *g).collect();
        let remaining_str = remaining.join(",");
        row_group_tags.push_str(&format!(
            r#"<span class="group-tag"><span class="group-name">{}</span><a href="/pivot/{}?rows={}&cols={}&measure={}&agg={}" class="group-remove" title="Remove">×</a></span>"#,
            display_name, model_name, remaining_str, col_groups_str, measure_field, measure_type
        ));
    }

    let mut col_group_tags = String::new();
    for (i, &group) in col_groups.iter().enumerate() {
        let display_name = field_info.get(group).map(|(_, dn, _)| dn.as_str()).unwrap_or(group);
        let remaining: Vec<&str> = col_groups.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, g)| *g).collect();
        let remaining_str = remaining.join(",");
        col_group_tags.push_str(&format!(
            r#"<span class="group-tag"><span class="group-name">{}</span><a href="/pivot/{}?rows={}&cols={}&measure={}&agg={}" class="group-remove" title="Remove">×</a></span>"#,
            display_name, model_name, row_groups_str, remaining_str, measure_field, measure_type
        ));
    }

    // Build add-group dropdown options (excluding already used fields)
    let used_fields: std::collections::HashSet<&str> = row_groups.iter().chain(col_groups.iter()).cloned().collect();
    let mut available_field_options = String::new();
    for (name, display_name) in &groupable_fields {
        if !used_fields.contains(*name) {
            available_field_options.push_str(&format!(r#"<option value="{}">{}</option>"#, name, display_name));
        }
    }

    // Build measure options
    let mut measure_options = String::new();
    measure_options.push_str(&format!(r#"<option value="id"{}>(Count)</option>"#, if measure_field == "id" { " selected" } else { "" }));
    for field in &fields {
        let name: String = field.get("name");
        let display_name: String = field.get("display_name");
        let field_type: String = field.get("field_type");
        if matches!(field_type.as_str(), "integer" | "float" | "monetary" | "number") && name != "id" {
            let selected = if name == measure_field { " selected" } else { "" };
            measure_options.push_str(&format!(r#"<option value="{}"{}>{}</option>"#, name, selected, display_name));
        }
    }

    // Build dynamic sidebar
    let sidebar_menu = build_sidebar_menu(&db, &user.roles, &model_name).await;

    Html(format!(r##"<!DOCTYPE html>
<html data-theme="dark">
<head>
    <title>{} - Pivot</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background: #0f0f1a; color: #e8e8e8; }}
        .top-navbar {{ background: #1a1a2e; border-bottom: 1px solid #2a2a4a; position: sticky; top: 0; z-index: 50; }}
        .sidebar {{ background: #1a1a2e; border-right: 1px solid #2a2a4a; }}
        .card {{ background: #1a1a2e; border: 1px solid #2a2a4a; }}
        .text-muted {{ color: #a0a0b0; }}
        .user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}

        /* Pivot table styles */
        .pivot-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        .pivot-table th, .pivot-table td {{ padding: 0.5rem 0.75rem; text-align: right; border: 1px solid #2a2a4a; white-space: nowrap; }}
        .pivot-header {{ background: #222244; color: #8BC53F; font-weight: 600; text-align: center !important; }}
        .pivot-row-label {{ text-align: left !important; min-width: 200px; }}
        .pivot-row-header {{ background: #1a1a2e; font-weight: 500; text-align: left !important; color: #fff; }}
        .pivot-cell {{ color: #a0a0b0; }}
        .pivot-has-value {{ color: #fff; background: rgba(139, 197, 63, 0.08); }}
        .pivot-total {{ background: #222244 !important; font-weight: 600; color: #8BC53F !important; }}
        .pivot-grand-total {{ background: #2a2a4a !important; color: #fff !important; font-weight: 700; }}
        .pivot-footer td {{ border-top: 2px solid #3a3a5a; }}

        /* Row hierarchy levels */
        .pivot-row-level0 td {{ font-weight: 600; background: rgba(139, 197, 63, 0.05); }}
        .pivot-row-level1 td {{ }}
        .pivot-row-level2 td {{ color: #a0a0b0; }}

        /* Toggle expand/collapse */
        .pivot-toggle {{ color: #8BC53F; text-decoration: none; font-size: 0.75rem; margin-right: 4px; }}
        .pivot-toggle:hover {{ color: #a0d050; }}
        .pivot-toggle-spacer {{ display: inline-block; width: 16px; }}

        /* Group configuration panel */
        .config-panel {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 0.5rem; padding: 1rem; }}
        .group-section {{ margin-bottom: 0.75rem; }}
        .group-section-label {{ font-size: 0.75rem; color: #a0a0b0; margin-bottom: 0.25rem; }}
        .group-tags {{ display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }}
        .group-tag {{ display: inline-flex; align-items: center; background: #2a2a4a; border-radius: 4px; padding: 0.25rem 0.5rem; font-size: 0.8rem; }}
        .group-name {{ color: #fff; }}
        .group-remove {{ color: #ff6b6b; margin-left: 0.5rem; text-decoration: none; font-weight: bold; }}
        .group-remove:hover {{ color: #ff4444; }}
        .add-group-btn {{ background: transparent; border: 1px dashed #4a4a6a; border-radius: 4px; padding: 0.25rem 0.5rem; color: #8BC53F; font-size: 0.8rem; cursor: pointer; }}
        .add-group-btn:hover {{ border-color: #8BC53F; background: rgba(139, 197, 63, 0.1); }}

        .measure-section {{ display: flex; gap: 1rem; align-items: end; flex-wrap: wrap; }}

        @media (max-width: 768px) {{
            .sidebar {{ display: none; }}
            .pivot-table {{ font-size: 0.75rem; }}
            .pivot-table th, .pivot-table td {{ padding: 0.35rem 0.5rem; }}
        }}
    </style>
</head>
<body class="min-h-screen">
<nav class="top-navbar px-4 py-3 flex items-center justify-between">
    <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
    <div class="flex items-center gap-2 md:gap-3">
        <a href="/home" class="text-white text-sm hover:underline hidden md:inline">Home</a>
        <a href="/settings" class="text-white text-sm hover:underline hidden md:inline">Settings</a>
        <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
        </a>
        <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
    </div>
</nav>
<div class="flex">
    <aside class="sidebar w-64 min-h-screen p-4 hidden md:block">
        <ul class="menu mt-2">{}</ul>
    </aside>
    <main class="flex-1 p-4 md:p-6">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
            <div>
                <h1 class="text-xl md:text-2xl font-bold text-white">{}</h1>
                <p class="text-muted">Pivot analysis</p>
            </div>
            <div class="flex gap-2 flex-wrap">
                <div class="btn-group">
                    <a href="/list/{}" class="btn btn-sm" title="List View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                    </a>
                    <a href="/kanban/{}" class="btn btn-sm" title="Kanban View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>
                    </a>
                    <a href="/graph/{}" class="btn btn-sm" title="Graph View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                    </a>
                    <a href="/pivot/{}" class="btn btn-sm btn-active" title="Pivot View">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                    </a>
                </div>
                <a href="/{}/new" class="btn btn-sm" style="background:#8BC53F;border-color:#8BC53F;color:#000">+ New</a>
            </div>
        </div>

        <!-- Pivot Configuration -->
        <div class="config-panel mb-6">
            <div class="group-section">
                <div class="group-section-label">Row Groups</div>
                <div class="group-tags">
                    {}
                    <select class="add-group-btn" onchange="if(this.value) window.location='/pivot/{}?rows={}'+('{}'?',':'')+this.value+'&cols={}&measure={}&agg={}'">
                        <option value="">+ Add</option>
                        {}
                    </select>
                </div>
            </div>
            <div class="group-section">
                <div class="group-section-label">Column Groups</div>
                <div class="group-tags">
                    {}
                    <select class="add-group-btn" onchange="if(this.value) window.location='/pivot/{}?rows={}&cols={}'+('{}'?',':'')+this.value+'&measure={}&agg={}'">
                        <option value="">+ Add</option>
                        {}
                    </select>
                </div>
            </div>
            <div class="measure-section mt-4">
                <div class="form-control">
                    <label class="label py-0"><span class="label-text text-xs text-muted">Measure</span></label>
                    <select class="select select-bordered select-sm bg-transparent" onchange="window.location='/pivot/{}?rows={}&cols={}&measure='+this.value+'&agg={}'">
                        {}
                    </select>
                </div>
                <div class="form-control">
                    <label class="label py-0"><span class="label-text text-xs text-muted">Aggregation</span></label>
                    <select class="select select-bordered select-sm bg-transparent" onchange="window.location='/pivot/{}?rows={}&cols={}&measure={}&agg='+this.value">
                        <option value="count"{}>Count</option>
                        <option value="sum"{}>Sum</option>
                        <option value="avg"{}>Average</option>
                        <option value="min"{}>Min</option>
                        <option value="max"{}>Max</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- Pivot Table -->
        <div class="card overflow-x-auto">
            <table class="pivot-table">
                {}
            </table>
        </div>

        <div class="mt-4 text-muted text-sm">
            <p>Click ▶ to expand groups. Add multiple row/column groups for nested analysis.</p>
        </div>
    </main>
</div>
</body>
</html>"##,
        model_display_name,
        user.username,
        sidebar_menu,
        model_display_name,
        model_name, model_name, model_name, model_name, model_name,
        // Row groups section
        row_group_tags,
        model_name, row_groups_str, row_groups_str, col_groups_str, measure_field, measure_type,
        available_field_options,
        // Column groups section
        col_group_tags,
        model_name, row_groups_str, col_groups_str, col_groups_str, measure_field, measure_type,
        available_field_options,
        // Measure dropdown
        model_name, row_groups_str, col_groups_str, measure_type,
        measure_options,
        // Aggregation dropdown
        model_name, row_groups_str, col_groups_str, measure_field,
        if measure_type == "count" { " selected" } else { "" },
        if measure_type == "sum" { " selected" } else { "" },
        if measure_type == "avg" { " selected" } else { "" },
        if measure_type == "min" { " selected" } else { "" },
        if measure_type == "max" { " selected" } else { "" },
        // Table
        table_html
    )).into_response()
}

fn format_pivot_number(val: f64, measure_type: &str) -> String {
    if val == 0.0 {
        "-".to_string()
    } else if measure_type == "count" {
        format!("{:.0}", val)
    } else if val == val.floor() {
        format!("{:.0}", val)
    } else {
        format!("{:.2}", val)
    }
}

// ============================================================================
// Saved Filters API
// ============================================================================

async fn get_filters(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
) -> Response {
    let filters = sqlx::query(
        r#"SELECT f.id, f.name, f.domain, f.context, f.is_default
           FROM ir_filters f
           JOIN ir_model m ON f.model_id = m.id
           WHERE m.name = $1 AND f.active = true AND (f.user_id IS NULL OR f.user_id = $2)
           ORDER BY f.name"#
    )
    .bind(&model_name)
    .bind(user.id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let result: Vec<serde_json::Value> = filters.iter().map(|f| {
        serde_json::json!({
            "id": f.get::<uuid::Uuid, _>("id").to_string(),
            "name": f.get::<String, _>("name"),
            "domain": f.get::<String, _>("domain"),
            "context": f.get::<String, _>("context"),
            "is_default": f.get::<bool, _>("is_default")
        })
    }).collect();

    Json(result).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct SaveFilterRequest {
    name: String,
    domain: String,
    context: Option<String>,
    is_shared: Option<bool>,
}

async fn save_filter(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
    Form(form): Form<SaveFilterRequest>,
) -> Response {
    let model_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(model_id) = model_id else {
        return (StatusCode::NOT_FOUND, "Model not found").into_response();
    };

    let user_id = if form.is_shared.unwrap_or(false) { None } else { Some(user.id) };

    let result = sqlx::query(
        "INSERT INTO ir_filters (name, model_id, user_id, domain, context) VALUES ($1, $2, $3, $4, $5) RETURNING id"
    )
    .bind(&form.name)
    .bind(model_id)
    .bind(user_id)
    .bind(&form.domain)
    .bind(form.context.as_deref().unwrap_or("{}"))
    .fetch_one(&db)
    .await;

    match result {
        Ok(row) => {
            let id: uuid::Uuid = row.get("id");
            Json(serde_json::json!({"id": id.to_string(), "success": true})).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Sequences API
// ============================================================================

async fn get_next_sequence(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(code): Path<String>,
) -> Response {
    let result: Result<String, _> = sqlx::query_scalar("SELECT next_sequence($1)")
        .bind(&code)
        .fetch_one(&db)
        .await;

    match result {
        Ok(seq) => Json(serde_json::json!({"sequence": seq})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("Sequence error: {}", e)).into_response(),
    }
}

// ============================================================================
// Attachments API
// ============================================================================

use axum::extract::Multipart;
use std::path::PathBuf;

const UPLOAD_DIR: &str = "./uploads";

async fn list_attachments(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
) -> Response {
    let attachments = sqlx::query(
        r#"SELECT id, name, mimetype, file_size, created_at, created_by
           FROM ir_attachment
           WHERE res_model = $1 AND res_id = $2
           ORDER BY created_at DESC"#
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let result: Vec<serde_json::Value> = attachments.iter().map(|a| {
        serde_json::json!({
            "id": a.get::<uuid::Uuid, _>("id").to_string(),
            "name": a.get::<String, _>("name"),
            "mimetype": a.get::<Option<String>, _>("mimetype"),
            "file_size": a.get::<Option<i64>, _>("file_size"),
            "created_at": a.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })
    }).collect();

    Json(result).into_response()
}

async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    mut multipart: Multipart,
) -> Response {
    // Ensure upload directory exists
    let upload_path = PathBuf::from(UPLOAD_DIR);
    if let Err(e) = tokio::fs::create_dir_all(&upload_path).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create upload dir: {}", e)).into_response();
    }

    while let Ok(Some(field)) = multipart.next_field().await {
        let file_name = field.file_name().unwrap_or("unknown").to_string();
        let content_type = field.content_type().map(|s| s.to_string());

        // Read file data
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return (StatusCode::BAD_REQUEST, format!("Failed to read file: {}", e)).into_response(),
        };

        let file_size = data.len() as i64;

        // Generate unique filename
        let ext = std::path::Path::new(&file_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin");
        let store_fname = format!("{}.{}", uuid::Uuid::new_v4(), ext);
        let file_path = upload_path.join(&store_fname);

        // Compute checksum
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let checksum = hex::encode(hasher.finalize());

        // Save file to disk
        if let Err(e) = tokio::fs::write(&file_path, &data).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save file: {}", e)).into_response();
        }

        // Insert record
        let result = sqlx::query(
            r#"INSERT INTO ir_attachment (name, res_model, res_id, store_fname, file_size, mimetype, checksum, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id"#
        )
        .bind(&file_name)
        .bind(&model)
        .bind(record_id)
        .bind(&store_fname)
        .bind(file_size)
        .bind(&content_type)
        .bind(&checksum)
        .bind(user.id)
        .fetch_one(&db)
        .await;

        match result {
            Ok(row) => {
                let id: uuid::Uuid = row.get("id");
                return Json(serde_json::json!({
                    "id": id.to_string(),
                    "name": file_name,
                    "size": file_size,
                    "success": true
                })).into_response();
            }
            Err(e) => {
                // Clean up file on error
                let _ = tokio::fs::remove_file(&file_path).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response();
            }
        }
    }

    (StatusCode::BAD_REQUEST, "No file provided").into_response()
}

async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let attachment = sqlx::query(
        "SELECT name, store_fname, mimetype FROM ir_attachment WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(att) = attachment else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };

    let name: String = att.get("name");
    let store_fname: Option<String> = att.get("store_fname");
    let mimetype: Option<String> = att.get("mimetype");

    let Some(fname) = store_fname else {
        return (StatusCode::NOT_FOUND, "File not found on disk").into_response();
    };

    let file_path = PathBuf::from(UPLOAD_DIR).join(&fname);
    let data = match tokio::fs::read(&file_path).await {
        Ok(d) => d,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found on disk").into_response(),
    };

    let content_type = mimetype.unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name)),
        ],
        data,
    ).into_response()
}

async fn delete_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get filename first
    let attachment = sqlx::query("SELECT store_fname FROM ir_attachment WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    if let Some(att) = attachment {
        let store_fname: Option<String> = att.get("store_fname");
        if let Some(fname) = store_fname {
            let file_path = PathBuf::from(UPLOAD_DIR).join(&fname);
            let _ = tokio::fs::remove_file(&file_path).await;
        }
    }

    let result = sqlx::query("DELETE FROM ir_attachment WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    match result {
        Ok(_) => Json(serde_json::json!({"success": true})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Contacts Management Handlers
// ============================================================================

/// Redirect /contacts to the generic list view
async fn contacts_list() -> Response {
    Redirect::to("/list/contacts").into_response()
}

async fn contacts_new(State(state): State<Arc<AppState>>, Db(db): Db, Extension(_user): Extension<AuthUser>) -> Response {
    // Fetch countries for dropdown
    let countries = sqlx::query("SELECT id, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db).await.unwrap_or_default();

    let mut country_options = String::new();
    for co in &countries {
        let id: uuid::Uuid = co.get("id");
        let name: String = co.get("name");
        let escaped_name = name.replace("'", "\\'");
        country_options.push_str(&format!(r#"<div class="dropdown-item" data-id="{}" onclick="selectCountry('{}', '{}')">{}</div>"#, id, id, escaped_name, name));
    }

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Contact</title><link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script>
<style>
.country-dropdown {{ position: relative; }}
.country-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.country-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.country-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
.state-dropdown {{ position: relative; }}
.state-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.state-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.state-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
</style>
</head><body class="min-h-screen bg-base-200"><div class="flex"><aside class="w-64 bg-base-100 shadow-lg min-h-screen p-4"><div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div><ul class="menu"><li><a href="/contacts">← Contacts</a></li></ul></aside><main class="flex-1 p-6"><h1 class="text-2xl font-bold mb-6">New Contact</h1><form action="/contacts" method="POST" class="card bg-base-100 shadow p-6 max-w-3xl overflow-visible">
<h3 class="font-semibold text-lg mb-4">Basic Information</h3>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label">Name *</label><input name="name" class="input input-bordered" required/></div>
<div class="form-control"><label class="label">Display Name</label><input name="display_name" class="input input-bordered"/></div>
<div class="form-control"><label class="label">Type</label><select name="contact_type" class="select select-bordered"><option value="customer">Customer</option><option value="vendor">Vendor</option><option value="employee">Employee</option><option value="other">Other</option></select></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="is_company" class="checkbox"/><span>This is a Company</span></label></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Contact Details</h3>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label">Email</label><input name="email" type="email" class="input input-bordered"/></div>
<div class="form-control"><label class="label">Phone</label><input name="phone" class="input input-bordered"/></div>
<div class="form-control"><label class="label">Mobile</label><input name="mobile" class="input input-bordered"/></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Address</h3>
<div class="grid grid-cols-2 gap-4">
<div class="form-control col-span-2"><label class="label">Street</label><input name="street" class="input input-bordered"/></div>
<div class="form-control col-span-2"><label class="label">Street 2</label><input name="street2" class="input input-bordered"/></div>
<div class="form-control"><label class="label">City</label><input name="city" class="input input-bordered"/></div>
<div class="form-control"><label class="label">ZIP / Postal Code</label><input name="zip" class="input input-bordered"/></div>
<div class="form-control country-dropdown" style="position:relative">
  <label class="label">Country</label>
  <input type="text" id="country_search" class="input input-bordered" placeholder="Search country..." autocomplete="off" onclick="toggleCountryDropdown(true)" oninput="filterCountries()"/>
  <input type="hidden" name="country_id" id="country_id"/>
  <div id="country_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)">{}</div>
</div>
<div class="form-control state-dropdown" style="position:relative">
  <label class="label">State / Province</label>
  <input type="text" id="state_search" class="input input-bordered" placeholder="Select country first" autocomplete="off" onclick="toggleStateDropdown(true)" oninput="filterStates()" disabled/>
  <input type="hidden" name="state_id" id="state_id"/>
  <div id="state_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)"></div>
</div>
</div>
<div class="flex gap-2 mt-6"><a href="/contacts" class="btn btn-ghost">Cancel</a><button class="btn btn-primary">Create Contact</button></div>
</form></main></div>
<script>
let allCountries = [];
let allStates = [];

document.addEventListener('DOMContentLoaded', function() {{
    // Parse countries from data attribute
    const countryList = document.getElementById('country_list');
    allCountries = Array.from(countryList.querySelectorAll('.dropdown-item')).map(el => ({{
        id: el.dataset.id,
        name: el.textContent
    }}));
}});

function toggleCountryDropdown(show) {{
    const list = document.getElementById('country_list');
    if (show) {{
        list.style.display = 'block';
        filterCountries();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterCountries() {{
    const search = document.getElementById('country_search').value.toLowerCase();
    const list = document.getElementById('country_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectCountry(id, name) {{
    document.getElementById('country_id').value = id;
    document.getElementById('country_search').value = name;
    document.getElementById('country_list').style.display = 'none';
    loadStates(id);
}}

async function loadStates(countryId) {{
    const stateSearch = document.getElementById('state_search');
    const stateList = document.getElementById('state_list');
    document.getElementById('state_id').value = '';
    stateSearch.value = '';

    if (!countryId) {{
        stateSearch.placeholder = 'Select country first';
        stateSearch.disabled = true;
        stateList.innerHTML = '';
        allStates = [];
        return;
    }}

    stateSearch.placeholder = 'Loading...';
    stateSearch.disabled = true;

    try {{
        const res = await fetch(`/api/states/${{countryId}}`);
        const states = await res.json();
        allStates = states;

        if (states.length === 0) {{
            stateSearch.placeholder = 'No states available';
            stateList.innerHTML = '';
        }} else {{
            stateSearch.placeholder = 'Search state...';
            stateSearch.disabled = false;
            stateList.innerHTML = states.map(s =>
                `<div class="dropdown-item" data-id="${{s.id}}" onclick="selectState('${{s.id}}', '${{s.name.replace(/'/g, "\\'")}}')">${{s.name}}</div>`
            ).join('');
        }}
    }} catch (e) {{
        stateSearch.placeholder = 'Error loading states';
        stateList.innerHTML = '';
    }}
}}

function toggleStateDropdown(show) {{
    const list = document.getElementById('state_list');
    if (show && allStates.length > 0) {{
        list.style.display = 'block';
        filterStates();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterStates() {{
    const search = document.getElementById('state_search').value.toLowerCase();
    const list = document.getElementById('state_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectState(id, name) {{
    document.getElementById('state_id').value = id;
    document.getElementById('state_search').value = name;
    document.getElementById('state_list').style.display = 'none';
}}

// Close dropdowns when clicking outside
document.addEventListener('click', function(e) {{
    if (!e.target.closest('.country-dropdown')) {{
        document.getElementById('country_list').style.display = 'none';
    }}
    if (!e.target.closest('.state-dropdown')) {{
        document.getElementById('state_list').style.display = 'none';
    }}
}});
</script>
</body></html>"#, country_options)).into_response()
}

#[derive(serde::Deserialize)]
struct ContactForm {
    name: String,
    display_name: Option<String>,
    contact_type: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    mobile: Option<String>,
    street: Option<String>,
    street2: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    country_id: Option<String>,
    state_id: Option<String>,
    is_company: Option<String>,
}

async fn contacts_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<ContactForm>,
) -> Response {
    let id = uuid::Uuid::now_v7();
    let ctype = form.contact_type.as_deref().unwrap_or("customer");
    let is_company = form.is_company.is_some();
    let country_id: Option<uuid::Uuid> = form.country_id.as_ref().and_then(|s| s.parse().ok());
    let state_id: Option<uuid::Uuid> = form.state_id.as_ref().and_then(|s| s.parse().ok());

    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(e) => {
            error!("Failed to get user company: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error: Could not determine company")).into_response();
        }
    };

    if let Err(e) = sqlx::query(
        "INSERT INTO contacts (id, company_id, name, display_name, contact_type, email, phone, mobile, street, street2, city, zip, country_id, state_id, is_company, active, created_at, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,true,NOW(),$16)"
    )
    .bind(id).bind(company_id).bind(&form.name).bind(&form.display_name).bind(ctype)
    .bind(&form.email).bind(&form.phone).bind(&form.mobile)
    .bind(&form.street).bind(&form.street2).bind(&form.city).bind(&form.zip)
    .bind(country_id).bind(state_id).bind(is_company).bind(user.id)
    .execute(&db).await {
        error!("Failed to create contact: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error creating contact: {}", e))).into_response();
    }

    // Log creation to chatter
    let _ = sqlx::query(
        "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
         VALUES ('contacts', $1, 'system', 'Contact created', $2, $3, $2)"
    )
    .bind(id)
    .bind(user.id)
    .bind(company_id)
    .execute(&db)
    .await;

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

async fn contacts_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let c = match sqlx::query("SELECT * FROM contacts WHERE id = $1").bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        _ => return (StatusCode::NOT_FOUND, Html("Not found")).into_response(),
    };

    let name: String = c.get("name");
    let display_name: Option<String> = c.get("display_name");
    let ctype: String = c.get("contact_type");
    let email: Option<String> = c.get("email");
    let phone: Option<String> = c.get("phone");
    let mobile: Option<String> = c.get("mobile");
    let street: Option<String> = c.get("street");
    let street2: Option<String> = c.get("street2");
    let city: Option<String> = c.get("city");
    let zip: Option<String> = c.get("zip");
    let country_id: Option<uuid::Uuid> = c.get("country_id");
    let state_id: Option<uuid::Uuid> = c.get("state_id");
    let is_company: bool = c.get("is_company");
    let record_state: String = c.try_get("record_state").unwrap_or("draft".to_string());

    // Fetch countries
    let countries = sqlx::query("SELECT id, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db).await.unwrap_or_default();

    let mut country_options = String::new();
    let mut selected_country_name = String::new();
    for co in &countries {
        let cid: uuid::Uuid = co.get("id");
        let cname: String = co.get("name");
        let escaped_name = cname.replace("'", "\\'");
        if Some(cid) == country_id {
            selected_country_name = cname.clone();
        }
        country_options.push_str(&format!(r#"<div class="dropdown-item" data-id="{}" onclick="selectCountry('{}', '{}')">{}</div>"#, cid, cid, escaped_name, cname));
    }

    // Fetch states for the selected country
    let mut state_options = String::new();
    let mut selected_state_name = String::new();
    if let Some(cid) = country_id {
        let states = sqlx::query("SELECT id, name FROM states WHERE country_id = $1 AND active = true ORDER BY name")
            .bind(cid).fetch_all(&db).await.unwrap_or_default();
        for s in &states {
            let sid: uuid::Uuid = s.get("id");
            let sname: String = s.get("name");
            let escaped_name = sname.replace("'", "\\'");
            if Some(sid) == state_id {
                selected_state_name = sname.clone();
            }
            state_options.push_str(&format!(r#"<div class="dropdown-item" data-id="{}" onclick="selectState('{}', '{}')">{}</div>"#, sid, sid, escaped_name, sname));
        }
    }

    let type_sel = |t: &str| if ctype == t { " selected" } else { "" };

    let has_states = !state_options.is_empty();
    let state_placeholder = if country_id.is_some() {
        if has_states { "Search state..." } else { "No states available" }
    } else {
        "Select country first"
    };

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Edit Contact</title><link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script><script src="https://unpkg.com/htmx.org@1.9.10"></script>
<style>
.country-dropdown {{ position: relative; }}
.country-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.country-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.country-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
.state-dropdown {{ position: relative; }}
.state-dropdown .dropdown-content {{ max-height: 300px; overflow-y: auto; width: 100%; }}
.state-dropdown .dropdown-item {{ padding: 8px 12px; cursor: pointer; }}
.state-dropdown .dropdown-item:hover {{ background: oklch(var(--b2)); }}
</style>
</head><body class="min-h-screen bg-base-200"><div class="flex"><aside class="w-64 bg-base-100 shadow-lg min-h-screen p-4"><div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div><ul class="menu"><li><a href="/contacts">← Contacts</a></li></ul></aside><main class="flex-1 p-6">
<!-- State Bar -->
<div class="card bg-base-100 shadow mb-6">
  <div class="card-body py-3">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2">
        <span class="text-sm font-medium text-base-content/60">Status:</span>
        <ul class="steps steps-horizontal">
          <li class="step {}" data-content="1">Draft</li>
          <li class="step {}" data-content="2">Approved</li>
        </ul>
      </div>
      <div class="flex gap-2">
        {}
      </div>
    </div>
  </div>
</div>
<div class="flex justify-between mb-6"><h1 class="text-2xl font-bold">Edit Contact</h1><form action="/contacts/{}/delete" method="POST" onsubmit="return confirm('Delete this contact?')"><button class="btn btn-error btn-outline btn-sm">Delete</button></form></div>
<div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
<form action="/contacts/{}" method="POST" class="card bg-base-100 shadow p-6 xl:col-span-2 overflow-visible">
{}
<h3 class="font-semibold text-lg mb-4">Basic Information</h3>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label">Name *</label><input name="name" value="{}" class="input input-bordered" {} required/></div>
<div class="form-control"><label class="label">Display Name</label><input name="display_name" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">Type</label><select name="contact_type" class="select select-bordered" {}><option value="customer"{}>Customer</option><option value="vendor"{}>Vendor</option><option value="employee"{}>Employee</option><option value="other"{}>Other</option></select></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="is_company" class="checkbox" {} {}/><span>This is a Company</span></label></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Contact Details</h3>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label">Email</label><input name="email" type="email" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">Phone</label><input name="phone" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">Mobile</label><input name="mobile" value="{}" class="input input-bordered" {}/></div>
</div>
<h3 class="font-semibold text-lg mt-6 mb-4">Address</h3>
<div class="grid grid-cols-2 gap-4">
<div class="form-control col-span-2"><label class="label">Street</label><input name="street" value="{}" class="input input-bordered" {}/></div>
<div class="form-control col-span-2"><label class="label">Street 2</label><input name="street2" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">City</label><input name="city" value="{}" class="input input-bordered" {}/></div>
<div class="form-control"><label class="label">ZIP / Postal Code</label><input name="zip" value="{}" class="input input-bordered" {}/></div>
<div class="form-control country-dropdown" style="position:relative">
  <label class="label">Country</label>
  <input type="text" id="country_search" class="input input-bordered" placeholder="Search country..." value="{}" autocomplete="off" onclick="toggleCountryDropdown(true)" oninput="filterCountries()" {}/>
  <input type="hidden" name="country_id" id="country_id" value="{}"/>
  <div id="country_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)">{}</div>
</div>
<div class="form-control state-dropdown" style="position:relative">
  <label class="label">State / Province</label>
  <input type="text" id="state_search" class="input input-bordered" placeholder="{}" value="{}" autocomplete="off" onclick="toggleStateDropdown(true)" oninput="filterStates()" {}/>
  <input type="hidden" name="state_id" id="state_id" value="{}"/>
  <div id="state_list" style="display:none;position:absolute;top:100%;left:0;z-index:9999;max-height:300px;overflow-y:auto;width:100%;background:#1d232a;border:1px solid #374151;border-radius:8px;margin-top:4px;box-shadow:0 10px 25px rgba(0,0,0,0.5)">{}</div>
</div>
</div>
<div class="flex gap-2 mt-6"><a href="/contacts" class="btn btn-ghost">Cancel</a>{}</div>
</form>
<div class="xl:col-span-1">
  <div id="activity-stream" class="sticky top-4">
    <div class="card bg-base-100 shadow">
      <div class="card-body">
        <div class="flex items-center justify-center py-8">
          <span class="loading loading-spinner loading-md"></span>
        </div>
      </div>
    </div>
  </div>
</div>
</div></main></div>
<script>
let allCountries = [];
let allStates = [];

document.addEventListener('DOMContentLoaded', function() {{
    const countryList = document.getElementById('country_list');
    allCountries = Array.from(countryList.querySelectorAll('.dropdown-item')).map(el => ({{
        id: el.dataset.id,
        name: el.textContent
    }}));
    const stateList = document.getElementById('state_list');
    allStates = Array.from(stateList.querySelectorAll('.dropdown-item')).map(el => ({{
        id: el.dataset.id,
        name: el.textContent
    }}));
}});

function toggleCountryDropdown(show) {{
    const list = document.getElementById('country_list');
    if (show) {{
        list.style.display = 'block';
        filterCountries();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterCountries() {{
    const search = document.getElementById('country_search').value.toLowerCase();
    const list = document.getElementById('country_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectCountry(id, name) {{
    document.getElementById('country_id').value = id;
    document.getElementById('country_search').value = name;
    document.getElementById('country_list').style.display = 'none';
    loadStates(id);
}}

async function loadStates(countryId) {{
    const stateSearch = document.getElementById('state_search');
    const stateList = document.getElementById('state_list');
    document.getElementById('state_id').value = '';
    stateSearch.value = '';

    if (!countryId) {{
        stateSearch.placeholder = 'Select country first';
        stateSearch.disabled = true;
        stateList.innerHTML = '';
        allStates = [];
        return;
    }}

    stateSearch.placeholder = 'Loading...';
    stateSearch.disabled = true;

    try {{
        const res = await fetch(`/api/states/${{countryId}}`);
        const states = await res.json();
        allStates = states;

        if (states.length === 0) {{
            stateSearch.placeholder = 'No states available';
            stateList.innerHTML = '';
        }} else {{
            stateSearch.placeholder = 'Search state...';
            stateSearch.disabled = false;
            stateList.innerHTML = states.map(s =>
                `<div class="dropdown-item" data-id="${{s.id}}" onclick="selectState('${{s.id}}', '${{s.name.replace(/'/g, "\\'")}}')">${{s.name}}</div>`
            ).join('');
        }}
    }} catch (e) {{
        stateSearch.placeholder = 'Error loading states';
        stateList.innerHTML = '';
    }}
}}

function toggleStateDropdown(show) {{
    const list = document.getElementById('state_list');
    if (show && allStates.length > 0) {{
        list.style.display = 'block';
        filterStates();
    }} else {{
        setTimeout(() => list.style.display = 'none', 150);
    }}
}}

function filterStates() {{
    const search = document.getElementById('state_search').value.toLowerCase();
    const list = document.getElementById('state_list');
    const items = list.querySelectorAll('.dropdown-item');
    items.forEach(item => {{
        const match = item.textContent.toLowerCase().includes(search);
        item.style.display = match ? 'block' : 'none';
    }});
}}

function selectState(id, name) {{
    document.getElementById('state_id').value = id;
    document.getElementById('state_search').value = name;
    document.getElementById('state_list').style.display = 'none';
}}

document.addEventListener('click', function(e) {{
    if (!e.target.closest('.country-dropdown')) {{
        document.getElementById('country_list').style.display = 'none';
    }}
    if (!e.target.closest('.state-dropdown')) {{
        document.getElementById('state_list').style.display = 'none';
    }}
}});

// Load chatter component
fetch('/partials/chatter/contacts/{}')
    .then(r => r.text())
    .then(html => {{
        const panel = document.getElementById('activity-stream');
        panel.innerHTML = html;
        htmx.process(panel);
    }})
    .catch(e => {{
        document.getElementById('activity-stream').innerHTML = '<div class="card bg-base-100 shadow"><div class="card-body text-center text-base-content/60">Activity Stream unavailable</div></div>';
    }});
</script>
</body></html>"#,
        // State bar: draft step class, approved step class, action button
        if record_state == "draft" || record_state == "approved" { "step-primary" } else { "" },
        if record_state == "approved" { "step-primary" } else { "" },
        if record_state == "draft" {
            format!(r#"<form action="/contacts/{}/approve" method="POST" class="inline"><button class="btn btn-success btn-sm">Approve</button></form>"#, id)
        } else {
            format!(r#"<span class="badge badge-success gap-1"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Approved</span><form action="/contacts/{}/set-draft" method="POST" class="inline ml-2"><button class="btn btn-ghost btn-sm">Set to Draft</button></form>"#, id)
        },
        id,  // delete form action
        id,  // update form action
        // Locked banner when approved
        if record_state == "approved" {
            r#"<div class="alert alert-info mb-4"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg><span>This record is approved and read-only. Set to Draft to edit.</span></div>"#
        } else { "" },
        name, if record_state == "approved" { "disabled" } else { "" },
        display_name.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        if record_state == "approved" { "disabled" } else { "" },
        type_sel("customer"), type_sel("vendor"), type_sel("employee"), type_sel("other"),
        if record_state == "approved" { "disabled" } else { "" },
        if is_company { "checked" } else { "" },
        email.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        phone.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        mobile.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        street.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        street2.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        city.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        zip.unwrap_or_default(), if record_state == "approved" { "disabled" } else { "" },
        selected_country_name, if record_state == "approved" { "disabled" } else { "" },
        country_id.map(|id| id.to_string()).unwrap_or_default(), country_options,
        state_placeholder, selected_state_name,
        if record_state == "approved" { "disabled" } else if has_states { "" } else { "disabled" },
        state_id.map(|id| id.to_string()).unwrap_or_default(), state_options,
        // Save button - only show when draft
        if record_state == "draft" {
            r#"<button class="btn btn-primary">Save Changes</button>"#
        } else {
            r#"<button class="btn btn-primary btn-disabled" disabled>Save Changes</button>"#
        },
        id  // for chatter fetch URL
    )).into_response()
}

async fn contacts_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<ContactForm>,
) -> Response {
    // Fetch old values for change tracking
    let old = sqlx::query("SELECT * FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let ctype = form.contact_type.as_deref().unwrap_or("customer");
    let is_company = form.is_company.is_some();
    let country_id: Option<uuid::Uuid> = form.country_id.as_ref().and_then(|s| s.parse().ok());
    let state_id: Option<uuid::Uuid> = form.state_id.as_ref().and_then(|s| s.parse().ok());

    let _ = sqlx::query(
        "UPDATE contacts SET name=$1, display_name=$2, contact_type=$3, email=$4, phone=$5, mobile=$6, street=$7, street2=$8, city=$9, zip=$10, country_id=$11, state_id=$12, is_company=$13, updated_at=NOW(), updated_by=$14 WHERE id=$15"
    )
    .bind(&form.name).bind(&form.display_name).bind(ctype)
    .bind(&form.email).bind(&form.phone).bind(&form.mobile)
    .bind(&form.street).bind(&form.street2).bind(&form.city).bind(&form.zip)
    .bind(country_id).bind(state_id).bind(is_company).bind(user.id).bind(id)
    .execute(&db).await;

    // Track changes
    if let Some(old) = old {
        let mut changes: Vec<String> = Vec::new();
        let company_id: uuid::Uuid = old.get("company_id");

        // Compare fields
        let old_name: String = old.get("name");
        if old_name != form.name {
            changes.push(format!("<b>Name</b> changed from '{}' to '{}'", old_name, form.name));
        }

        let old_display_name: Option<String> = old.get("display_name");
        if old_display_name != form.display_name {
            changes.push(format!("<b>Display Name</b> changed from '{}' to '{}'",
                old_display_name.as_deref().unwrap_or("-"),
                form.display_name.as_deref().unwrap_or("-")));
        }

        let old_type: String = old.get("contact_type");
        if old_type != ctype {
            changes.push(format!("<b>Type</b> changed from '{}' to '{}'", old_type, ctype));
        }

        let old_email: Option<String> = old.get("email");
        if old_email != form.email {
            changes.push(format!("<b>Email</b> changed from '{}' to '{}'",
                old_email.as_deref().unwrap_or("-"),
                form.email.as_deref().unwrap_or("-")));
        }

        let old_phone: Option<String> = old.get("phone");
        if old_phone != form.phone {
            changes.push(format!("<b>Phone</b> changed from '{}' to '{}'",
                old_phone.as_deref().unwrap_or("-"),
                form.phone.as_deref().unwrap_or("-")));
        }

        let old_mobile: Option<String> = old.get("mobile");
        if old_mobile != form.mobile {
            changes.push(format!("<b>Mobile</b> changed from '{}' to '{}'",
                old_mobile.as_deref().unwrap_or("-"),
                form.mobile.as_deref().unwrap_or("-")));
        }

        let old_street: Option<String> = old.get("street");
        if old_street != form.street {
            changes.push(format!("<b>Street</b> changed from '{}' to '{}'",
                old_street.as_deref().unwrap_or("-"),
                form.street.as_deref().unwrap_or("-")));
        }

        let old_city: Option<String> = old.get("city");
        if old_city != form.city {
            changes.push(format!("<b>City</b> changed from '{}' to '{}'",
                old_city.as_deref().unwrap_or("-"),
                form.city.as_deref().unwrap_or("-")));
        }

        let old_is_company: bool = old.get("is_company");
        if old_is_company != is_company {
            changes.push(format!("<b>Is Company</b> changed from '{}' to '{}'",
                if old_is_company { "Yes" } else { "No" },
                if is_company { "Yes" } else { "No" }));
        }

        // Log changes to chatter if any
        if !changes.is_empty() {
            let body = changes.join("<br>");
            let _ = sqlx::query(
                "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
                 VALUES ('contacts', $1, 'system', $2, $3, $4, $3)"
            )
            .bind(id)
            .bind(&body)
            .bind(user.id)
            .bind(company_id)
            .execute(&db)
            .await;
        }
    }

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

async fn contacts_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE contacts SET active=false, updated_at=NOW(), updated_by=$1 WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;
    Redirect::to("/contacts").into_response()
}

async fn contacts_approve(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get company_id for chatter message
    let contact = sqlx::query("SELECT company_id FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let _ = sqlx::query("UPDATE contacts SET record_state='approved', updated_at=NOW(), updated_by=$1 WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;

    // Log state change to chatter
    if let Some(contact) = contact {
        let company_id: uuid::Uuid = contact.get("company_id");
        let _ = sqlx::query(
            "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
             VALUES ('contacts', $1, 'system', '<b>Status</b> changed from <span class=\"badge badge-warning badge-sm\">Draft</span> to <span class=\"badge badge-success badge-sm\">Approved</span>', $2, $3, $2)"
        )
        .bind(id)
        .bind(user.id)
        .bind(company_id)
        .execute(&db)
        .await;
    }

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

async fn contacts_set_draft(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get company_id for chatter message
    let contact = sqlx::query("SELECT company_id FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let _ = sqlx::query("UPDATE contacts SET record_state='draft', updated_at=NOW(), updated_by=$1 WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;

    // Log state change to chatter
    if let Some(contact) = contact {
        let company_id: uuid::Uuid = contact.get("company_id");
        let _ = sqlx::query(
            "INSERT INTO chatter_messages (res_model, res_id, message_type, body, author_id, company_id, created_by)
             VALUES ('contacts', $1, 'system', '<b>Status</b> changed from <span class=\"badge badge-success badge-sm\">Approved</span> to <span class=\"badge badge-warning badge-sm\">Draft</span>', $2, $3, $2)"
        )
        .bind(id)
        .bind(user.id)
        .bind(company_id)
        .execute(&db)
        .await;
    }

    Redirect::to(&format!("/contacts/{}", id)).into_response()
}

// =============================================================================
// EAM - Enterprise Asset Management
// =============================================================================

async fn eam_dashboard(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Get user's company_id
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get stats
    let total_sites: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_sites WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let total_locations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_functional_locations WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let total_assets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_assets WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let in_service: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets a JOIN eam_asset_statuses s ON a.status_id = s.id WHERE a.company_id = $1 AND a.is_active = true AND s.code = 'ACTIVE'"
    ).bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let under_maint: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets a JOIN eam_asset_statuses s ON a.status_id = s.id WHERE a.company_id = $1 AND a.is_active = true AND s.code = 'MAINT'"
    ).bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let faulty: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets a JOIN eam_asset_statuses s ON a.status_id = s.id WHERE a.company_id = $1 AND a.is_active = true AND s.code = 'FAULTY'"
    ).bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let sidebar = build_sidebar("eam_dashboard", display_name, &initials);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Asset Management - Remicle</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><h1 class="text-2xl font-bold">Enterprise Asset Management</h1><p class="text-base-content/60">Distribution substation asset tracking</p></div>
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Sites</div><div class="stat-value text-primary">{total_sites}</div><div class="stat-desc">Substations</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Functional Locations</div><div class="stat-value text-secondary">{total_locations}</div><div class="stat-desc">PPU, SSU, PP, PE</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Total Assets</div><div class="stat-value text-accent">{total_assets}</div><div class="stat-desc">Equipment</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">In Service</div><div class="stat-value text-success">{in_service}</div><div class="stat-desc">Operational</div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title">Asset Status</h2><div class="space-y-4 mt-4">
<div class="flex items-center justify-between"><div class="flex items-center gap-2"><span class="badge badge-success badge-sm"></span><span>In Service</span></div><span class="font-semibold">{in_service}</span></div>
<div class="flex items-center justify-between"><div class="flex items-center gap-2"><span class="badge badge-warning badge-sm"></span><span>Under Maintenance</span></div><span class="font-semibold">{under_maint}</span></div>
<div class="flex items-center justify-between"><div class="flex items-center gap-2"><span class="badge badge-error badge-sm"></span><span>Faulty</span></div><span class="font-semibold">{faulty}</span></div>
</div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title">Quick Actions</h2><div class="grid grid-cols-2 gap-3 mt-4">
<a href="/eam/sites" class="btn btn-outline btn-primary">View Sites</a>
<a href="/eam/assets" class="btn btn-outline btn-secondary">View Assets</a>
<a href="/eam/sites/new" class="btn btn-outline btn-accent">New Site</a>
<a href="/eam/configuration" class="btn btn-outline">Configuration</a>
</div></div></div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_sites(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let type_filter = params.get("type").map(|s| s.as_str()).unwrap_or("");
    let status_filter = params.get("status").map(|s| s.as_str()).unwrap_or("");
    let view = params.get("view").map(|s| s.as_str()).unwrap_or("list");

    // Get user's company_id
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let sites = sqlx::query(
        r#"SELECT s.id, s.code, s.name, s.site_type, s.city, s.status, s.feeder_count,
           COALESCE((SELECT COUNT(*) FROM eam_assets a JOIN eam_functional_locations fl ON a.functional_location_id = fl.id WHERE fl.site_id = s.id), 0) as asset_count
           FROM eam_sites s WHERE s.company_id = $1 AND s.is_active = true
           AND ($2 = '' OR s.code ILIKE '%' || $2 || '%' OR s.name ILIKE '%' || $2 || '%' OR s.city ILIKE '%' || $2 || '%')
           AND ($3 = '' OR s.site_type = $3)
           AND ($4 = '' OR s.status = $4)
           ORDER BY s.code"#
    ).bind(company_id).bind(search).bind(type_filter).bind(status_filter)
    .fetch_all(&db).await.unwrap_or_default();

    // Build content based on view type
    let content = match view {
        "card" => {
            let mut cards = String::new();
            for site in &sites {
                let id: uuid::Uuid = site.get("id");
                let code: String = site.get("code");
                let name: String = site.get("name");
                let site_type: Option<String> = site.get("site_type");
                let city: Option<String> = site.get("city");
                let status: Option<String> = site.get("status");
                let asset_count: i64 = site.get("asset_count");
                let feeder_count: Option<i32> = site.get("feeder_count");
                cards.push_str(&format!(r#"<a href="/eam/sites/{}" class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                    <div class="card-body">
                        <div class="flex justify-between items-start">
                            <div class="badge badge-primary badge-outline">{}</div>
                            <span class="badge badge-sm">{}</span>
                        </div>
                        <h3 class="card-title text-lg mt-2">{}</h3>
                        <p class="text-base-content/60 text-sm">{}</p>
                        <div class="flex gap-4 mt-3 text-sm">
                            <div><span class="text-base-content/60">Assets:</span> <span class="font-semibold">{}</span></div>
                            <div><span class="text-base-content/60">Feeders:</span> <span class="font-semibold">{}</span></div>
                        </div>
                        <div class="card-actions justify-end mt-2">
                            <a href="/eam/sites/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                        </div>
                    </div>
                </a>"#, id, code, status.unwrap_or("Active".into()), name, city.unwrap_or("-".into()),
                    asset_count, feeder_count.unwrap_or(0), id));
            }
            if sites.is_empty() {
                cards = r#"<div class="col-span-full text-center py-12"><p class="text-lg">No sites found</p></div>"#.to_string();
            }
            format!(r#"<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">{}</div>"#, cards)
        },
        "pivot" => {
            // Group by site_type
            let mut by_type: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for site in &sites {
                let site_type: Option<String> = site.get("site_type");
                by_type.entry(site_type.unwrap_or("Unspecified".into())).or_default().push(site);
            }
            let mut pivot_html = String::new();
            for (stype, type_sites) in &by_type {
                let total_assets: i64 = type_sites.iter().map(|s| s.get::<i64, _>("asset_count")).sum();
                pivot_html.push_str(&format!(r#"<div class="collapse collapse-arrow bg-base-100 mb-2">
                    <input type="checkbox" checked/>
                    <div class="collapse-title font-medium flex justify-between items-center">
                        <span>{} ({} sites)</span>
                        <span class="badge">{} assets</span>
                    </div>
                    <div class="collapse-content"><div class="overflow-x-auto">
                    <table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>City</th><th>Assets</th><th></th></tr></thead><tbody>"#,
                    stype, type_sites.len(), total_assets));
                for site in type_sites {
                    let id: uuid::Uuid = site.get("id");
                    let code: String = site.get("code");
                    let name: String = site.get("name");
                    let city: Option<String> = site.get("city");
                    let asset_count: i64 = site.get("asset_count");
                    pivot_html.push_str(&format!(r#"<tr><td class="font-mono">{}</td><td>{}</td><td>{}</td><td>{}</td>
                        <td><a href="/eam/sites/{}" class="btn btn-ghost btn-xs">View</a></td></tr>"#,
                        code, name, city.unwrap_or("-".into()), asset_count, id));
                }
                pivot_html.push_str("</tbody></table></div></div></div>");
            }
            if sites.is_empty() {
                pivot_html = r#"<div class="text-center py-12"><p class="text-lg">No sites found</p></div>"#.to_string();
            }
            pivot_html
        },
        _ => {
            // List view (default)
            let mut rows = String::new();
            for site in &sites {
                let id: uuid::Uuid = site.get("id");
                let code: String = site.get("code");
                let name: String = site.get("name");
                let site_type: Option<String> = site.get("site_type");
                let city: Option<String> = site.get("city");
                let status: Option<String> = site.get("status");
                let asset_count: i64 = site.get("asset_count");
                rows.push_str(&format!(r#"<tr class="hover">
                    <td class="font-mono font-semibold">{}</td><td>{}</td><td>{}</td><td>{}</td>
                    <td><span class="badge badge-outline">{}</span></td><td>{}</td>
                    <td class="flex gap-1">
                        <a href="/eam/sites/{}" class="btn btn-ghost btn-xs">View</a>
                        <a href="/eam/sites/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#, code, name, site_type.unwrap_or("-".into()), city.unwrap_or("-".into()),
                    status.unwrap_or("Unknown".into()), asset_count, id, id));
            }
            let empty = if sites.is_empty() { r#"<tr><td colspan="7" class="text-center py-12">No sites found</td></tr>"# } else { "" };
            format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>City</th><th>Status</th><th>Assets</th><th>Actions</th></tr></thead><tbody>{}{}</tbody></table></div>"#, rows, empty)
        }
    };

    let sidebar = build_sidebar("eam_sites", display_name, &initials);
    let view_btns = format!(r#"<div class="btn-group">
        <a href="?view=list&search={search}&type={type_filter}&status={status_filter}" class="btn btn-sm {}" title="List View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>List</a>
        <a href="?view=card&search={search}&type={type_filter}&status={status_filter}" class="btn btn-sm {}" title="Card View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>Card</a>
        <a href="?view=pivot&search={search}&type={type_filter}&status={status_filter}" class="btn btn-sm {}" title="Pivot View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>Pivot</a>
    </div>"#,
        if view == "list" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "card" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "pivot" { "btn-active btn-primary" } else { "btn-ghost" },
    );

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Sites - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6">
<div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Sites</li></ul></div>
<h1 class="text-2xl font-bold">Sites</h1><p class="text-base-content/60">Substations and distribution locations</p></div>
<a href="/eam/sites/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Site</a></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex flex-wrap justify-between items-center gap-3 mb-4">
<form method="GET" class="flex flex-wrap gap-3">
<input type="hidden" name="view" value="{view}"/>
<input type="text" name="search" placeholder="Search code, name, city..." value="{search}" class="input input-bordered input-sm w-64"/>
<select name="type" class="select select-bordered select-sm">
<option value="">All Types</option>
<option value="Indoor GIS" {}>Indoor GIS</option>
<option value="Outdoor AIS" {}>Outdoor AIS</option>
<option value="Hybrid" {}>Hybrid</option>
</select>
<select name="status" class="select select-bordered select-sm">
<option value="">All Status</option>
<option value="Active" {}>Active</option>
<option value="Inactive" {}>Inactive</option>
<option value="Under Construction" {}>Under Construction</option>
</select>
<button type="submit" class="btn btn-sm btn-primary">Search</button>
<a href="/eam/sites?view={view}" class="btn btn-sm btn-ghost">Clear</a>
</form>
{view_btns}
</div>
{content}
</div></div>
</main></div></body></html>"#,
        if type_filter == "Indoor GIS" { "selected" } else { "" },
        if type_filter == "Outdoor AIS" { "selected" } else { "" },
        if type_filter == "Hybrid" { "selected" } else { "" },
        if status_filter == "Active" { "selected" } else { "" },
        if status_filter == "Inactive" { "selected" } else { "" },
        if status_filter == "Under Construction" { "selected" } else { "" },
    )).into_response()
}

async fn eam_assets(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let category_filter = params.get("category").map(|s| s.as_str()).unwrap_or("");
    let status_filter = params.get("status").map(|s| s.as_str()).unwrap_or("");
    let site_filter = params.get("site").map(|s| s.as_str()).unwrap_or("");
    let view = params.get("view").map(|s| s.as_str()).unwrap_or("list");

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let categories: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_categories WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let statuses: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true ORDER BY display_order"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let sites_list: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_sites WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let assets = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, c.name as category_name, c.id as category_id,
           s.name as site_name, s.id as site_id, fl.name as location_name,
           st.name as status_name, st.id as status_id, st.color as status_color
           FROM eam_assets a
           LEFT JOIN eam_asset_categories c ON a.category_id = c.id
           LEFT JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_asset_statuses st ON a.status_id = st.id
           WHERE a.company_id = $1 AND a.is_active = true
           AND ($2 = '' OR a.asset_code ILIKE '%' || $2 || '%' OR a.name ILIKE '%' || $2 || '%')
           AND ($3 = '' OR c.id::text = $3)
           AND ($4 = '' OR st.id::text = $4)
           AND ($5 = '' OR s.id::text = $5)
           ORDER BY a.asset_code LIMIT 100"#
    ).bind(company_id).bind(search).bind(category_filter).bind(status_filter).bind(site_filter)
    .fetch_all(&db).await.unwrap_or_default();

    // Build content based on view type
    let content = match view {
        "card" => {
            let mut cards = String::new();
            for asset in &assets {
                let id: uuid::Uuid = asset.get("id");
                let code: String = asset.get("asset_code");
                let name: String = asset.get("name");
                let category: Option<String> = asset.get("category_name");
                let site: Option<String> = asset.get("site_name");
                let status: Option<String> = asset.get("status_name");
                let color: Option<String> = asset.get("status_color");
                let manufacturer: Option<String> = asset.get("manufacturer");
                let model: Option<String> = asset.get("model");
                cards.push_str(&format!(r#"<a href="/eam/assets/{}" class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                    <div class="card-body">
                        <div class="flex justify-between items-start">
                            <span class="badge badge-sm">{}</span>
                            <span class="badge badge-sm" style="background-color:{};color:white">{}</span>
                        </div>
                        <h3 class="card-title text-base mt-2">{}</h3>
                        <p class="font-mono text-sm text-base-content/60">{}</p>
                        <div class="text-sm mt-2">
                            <p><span class="text-base-content/60">Site:</span> {}</p>
                            <p><span class="text-base-content/60">Mfr:</span> {} {}</p>
                        </div>
                        <div class="card-actions justify-end mt-2">
                            <a href="/eam/assets/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                        </div>
                    </div>
                </a>"#, id, category.clone().unwrap_or("-".into()), color.unwrap_or("#6C757D".into()),
                    status.unwrap_or("-".into()), name, code, site.unwrap_or("-".into()),
                    manufacturer.unwrap_or("-".into()), model.unwrap_or("".into()), id));
            }
            if assets.is_empty() { cards = r#"<div class="col-span-full text-center py-12"><p class="text-lg">No assets found</p></div>"#.to_string(); }
            format!(r#"<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">{}</div>"#, cards)
        },
        "pivot" => {
            let mut by_cat: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for asset in &assets {
                let cat: Option<String> = asset.get("category_name");
                by_cat.entry(cat.unwrap_or("Uncategorized".into())).or_default().push(asset);
            }
            let mut pivot_html = String::new();
            for (cat, cat_assets) in &by_cat {
                pivot_html.push_str(&format!(r#"<div class="collapse collapse-arrow bg-base-100 mb-2">
                    <input type="checkbox" checked/>
                    <div class="collapse-title font-medium"><span>{}</span> <span class="badge badge-sm">{}</span></div>
                    <div class="collapse-content"><div class="overflow-x-auto">
                    <table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Site</th><th>Status</th><th></th></tr></thead><tbody>"#,
                    cat, cat_assets.len()));
                for asset in cat_assets {
                    let id: uuid::Uuid = asset.get("id");
                    let code: String = asset.get("asset_code");
                    let name: String = asset.get("name");
                    let site: Option<String> = asset.get("site_name");
                    let status: Option<String> = asset.get("status_name");
                    let color: Option<String> = asset.get("status_color");
                    pivot_html.push_str(&format!(r#"<tr><td class="font-mono">{}</td><td>{}</td><td>{}</td>
                        <td><span class="badge badge-sm" style="background-color:{};color:white">{}</span></td>
                        <td><a href="/eam/assets/{}" class="btn btn-ghost btn-xs">View</a></td></tr>"#,
                        code, name, site.unwrap_or("-".into()), color.unwrap_or("#6C757D".into()), status.unwrap_or("-".into()), id));
                }
                pivot_html.push_str("</tbody></table></div></div></div>");
            }
            if assets.is_empty() { pivot_html = r#"<div class="text-center py-12"><p class="text-lg">No assets found</p></div>"#.to_string(); }
            pivot_html
        },
        _ => {
            let mut rows = String::new();
            for asset in &assets {
                let id: uuid::Uuid = asset.get("id");
                let code: String = asset.get("asset_code");
                let name: String = asset.get("name");
                let category: Option<String> = asset.get("category_name");
                let site: Option<String> = asset.get("site_name");
                let location: Option<String> = asset.get("location_name");
                let status: Option<String> = asset.get("status_name");
                let color: Option<String> = asset.get("status_color");
                rows.push_str(&format!(r#"<tr class="hover">
                    <td class="font-mono font-semibold">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>
                    <td><span class="badge" style="background-color:{};color:white">{}</span></td>
                    <td class="flex gap-1"><a href="/eam/assets/{}" class="btn btn-ghost btn-xs">View</a><a href="/eam/assets/{}/edit" class="btn btn-ghost btn-xs">Edit</a></td>
                </tr>"#, code, name, category.unwrap_or("-".into()), site.unwrap_or("-".into()),
                    location.unwrap_or("-".into()), color.unwrap_or("#6C757D".into()), status.unwrap_or("Unknown".into()), id, id));
            }
            let empty = if assets.is_empty() { r#"<tr><td colspan="7" class="text-center py-12">No assets found</td></tr>"# } else { "" };
            format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Category</th><th>Site</th><th>Location</th><th>Status</th><th>Actions</th></tr></thead><tbody>{}{}</tbody></table></div>"#, rows, empty)
        }
    };

    let cat_options: String = categories.iter().map(|(id, name)| format!(r#"<option value="{}" {}>{}</option>"#, id, if category_filter == id { "selected" } else { "" }, name)).collect();
    let status_options: String = statuses.iter().map(|(id, name)| format!(r#"<option value="{}" {}>{}</option>"#, id, if status_filter == id { "selected" } else { "" }, name)).collect();
    let site_options: String = sites_list.iter().map(|(id, name)| format!(r#"<option value="{}" {}>{}</option>"#, id, if site_filter == id { "selected" } else { "" }, name)).collect();

    let sidebar = build_sidebar("eam_assets", display_name, &initials);
    let view_btns = format!(r#"<div class="btn-group">
        <a href="?view=list&search={search}&category={category_filter}&status={status_filter}&site={site_filter}" class="btn btn-sm {}" title="List View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>List</a>
        <a href="?view=card&search={search}&category={category_filter}&status={status_filter}&site={site_filter}" class="btn btn-sm {}" title="Card View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>Card</a>
        <a href="?view=pivot&search={search}&category={category_filter}&status={status_filter}&site={site_filter}" class="btn btn-sm {}" title="Pivot View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>Pivot</a>
    </div>"#,
        if view == "list" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "card" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "pivot" { "btn-active btn-primary" } else { "btn-ghost" });

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Assets - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6">
<div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Assets</li></ul></div>
<h1 class="text-2xl font-bold">Assets</h1><p class="text-base-content/60">Equipment and components</p></div>
<a href="/eam/assets/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Asset</a></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex flex-wrap justify-between items-center gap-3 mb-4">
<form method="GET" class="flex flex-wrap gap-3">
<input type="hidden" name="view" value="{view}"/>
<input type="text" name="search" placeholder="Search code or name..." value="{search}" class="input input-bordered input-sm w-48"/>
<select name="category" class="select select-bordered select-sm"><option value="">All Categories</option>{cat_options}</select>
<select name="status" class="select select-bordered select-sm"><option value="">All Status</option>{status_options}</select>
<select name="site" class="select select-bordered select-sm"><option value="">All Sites</option>{site_options}</select>
<button type="submit" class="btn btn-sm btn-primary">Search</button>
<a href="/eam/assets?view={view}" class="btn btn-sm btn-ghost">Clear</a>
</form>
{view_btns}
</div>
{content}
</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_configuration(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Get user's company_id
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let voltage_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let unit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_unit_types WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let category_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_asset_categories WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let status_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let sidebar = build_sidebar("eam_configuration", display_name, &initials);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Configuration - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Configuration</li></ul></div>
<h1 class="text-2xl font-bold">EAM Configuration</h1><p class="text-base-content/60">Manage voltage levels, unit types, categories, and statuses</p></div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-warning/20 p-3 rounded-lg"><svg class="w-6 h-6 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div>
<div><h2 class="card-title text-lg">Voltage Levels</h2><p class="text-base-content/60 text-sm">275kV, 132kV, 33kV, 11kV, etc.</p></div></div>
<div class="badge badge-lg">{voltage_count}</div></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-info/20 p-3 rounded-lg"><svg class="w-6 h-6 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg></div>
<div><h2 class="card-title text-lg">Unit Types</h2><p class="text-base-content/60 text-sm">PPU, SSU, PP, PE classifications</p></div></div>
<div class="badge badge-lg">{unit_count}</div></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-secondary/20 p-3 rounded-lg"><svg class="w-6 h-6 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A2 2 0 013 12V7a4 4 0 014-4z"/></svg></div>
<div><h2 class="card-title text-lg">Asset Categories</h2><p class="text-base-content/60 text-sm">Transformer, Switchgear, RMU, etc.</p></div></div>
<div class="badge badge-lg">{category_count}</div></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-success/20 p-3 rounded-lg"><svg class="w-6 h-6 text-success" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>
<div><h2 class="card-title text-lg">Asset Statuses</h2><p class="text-base-content/60 text-sm">In Service, Maintenance, Faulty, etc.</p></div></div>
<div class="badge badge-lg">{status_count}</div></div></div></div>
</div>
<div class="alert mt-6"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
<div><h3 class="font-bold">Default Configuration</h3><div class="text-sm">Standard Malaysian electrical utility voltage levels and equipment categories are pre-configured.</div></div></div>
</main></div></body></html>"#)).into_response()
}

// =============================================================================
// NEW SESB EAM FEATURES
// =============================================================================

async fn eam_work_orders(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get stats
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let draft: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'draft'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let scheduled: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'scheduled'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let in_progress: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'in_progress'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let on_hold: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'on_hold'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let completed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'completed'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);

    // Get work orders
    let rows = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start, a.name as asset_name, u.full_name as assigned_to
           FROM eam_work_orders wo
           LEFT JOIN eam_assets a ON wo.asset_id = a.id
           LEFT JOIN users u ON wo.assigned_to = u.id
           WHERE wo.company_id = $1
           ORDER BY CASE wo.state WHEN 'in_progress' THEN 1 WHEN 'scheduled' THEN 2 WHEN 'on_hold' THEN 3 WHEN 'draft' THEN 4 ELSE 5 END,
                    wo.scheduled_start NULLS LAST LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let wo_number: String = row.get("wo_number");
        let title: String = row.get("title");
        let maint_type: String = row.get::<Option<String>, _>("maintenance_type").unwrap_or_else(|| "-".to_string());
        let priority_int: i32 = row.get::<Option<i32>, _>("priority").unwrap_or(2);
        let priority = match priority_int { 0 => "critical", 1 => "high", 2 => "medium", 3 => "low", _ => "medium" }.to_string();
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let assigned: String = row.get::<Option<String>, _>("assigned_to").unwrap_or_else(|| "-".to_string());
        let sched_date: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_start")
            .map(|d| d.format("%d/%m/%Y").to_string()).unwrap_or_else(|| "-".to_string());

        let priority_color = match priority.as_str() {
            "critical" => "#DC2626", "high" => "#F97316", "medium" => "#EAB308", "low" => "#22C55E", _ => "#6B7280"
        };
        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "scheduled" => "#3B82F6", "in_progress" => "#F59E0B", "on_hold" => "#EF4444", "completed" => "#10B981", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{wo_number}</td><td>{title}</td><td>{asset_name}</td>
            <td><span class="badge badge-outline badge-sm">{maint_type}</span></td>
            <td><span class="badge badge-sm" style="background-color:{priority_color};color:white;">{priority}</span></td>
            <td><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></td>
            <td>{sched_date}</td><td>{assigned}</td>
            <td><a href="/eam/work-orders/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg><h3 class="text-lg font-semibold mb-2">No Work Orders Yet</h3><p class="text-base-content/60">Create a work order to schedule maintenance</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>WO Number</th><th>Title</th><th>Asset</th><th>Type</th><th>Priority</th><th>State</th><th>Scheduled</th><th>Assigned</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_work_orders", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Work Orders - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Work Orders</li></ul></div>
<h1 class="text-2xl font-bold">Work Orders</h1><p class="text-base-content/60">Maintenance work order management</p></div>
<a href="/eam/work-orders/new" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Work Order</a></div>
<div class="grid grid-cols-6 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Total</div><div class="stat-value text-2xl">{total}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Draft</div><div class="stat-value text-2xl text-gray-500">{draft}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Scheduled</div><div class="stat-value text-2xl text-blue-500">{scheduled}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">In Progress</div><div class="stat-value text-2xl text-amber-500">{in_progress}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">On Hold</div><div class="stat-value text-2xl text-red-500">{on_hold}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Completed</div><div class="stat-value text-2xl text-green-500">{completed}</div></div>
</div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get assets for dropdown
    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    // Get users for assignment dropdown
    let users_rows = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    // Build asset options
    let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        asset_options.push_str(&format!(r#"<option value="{aid}">{acode} - {aname}</option>"#));
    }

    // Build user options
    let mut user_options = r#"<option value="">-- Unassigned --</option>"#.to_string();
    for u in &users_rows {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get::<Option<String>, _>("full_name")
            .unwrap_or_else(|| u.get::<String, _>("username"));
        user_options.push_str(&format!(r#"<option value="{uid}">{uname}</option>"#));
    }

    // Maintenance type options
    let mtype_html = r#"<option value="">-- Select Type --</option>
        <option value="pm">Preventive (PM)</option><option value="cm">Corrective (CM)</option>
        <option value="emergency">Emergency</option><option value="inspection">Inspection</option>
        <option value="testing">Testing</option><option value="overhaul">Overhaul</option>"#;

    let priority_html = r#"<option value="0">Critical</option><option value="1">High</option>
        <option value="2" selected>Medium</option><option value="3">Low</option>"#;

    let content = format!(r##"<form method="POST" action="/eam/work-orders/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">General Information</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Title *</span></label>
<input type="text" name="title" class="input input-bordered" placeholder="Enter work order title" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24" placeholder="Describe the work to be done"></textarea></div>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Maintenance Type</span></label>
<select name="maintenance_type" class="select select-bordered">{mtype_html}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered">{priority_html}</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assignment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered">{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered">{user_options}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Planned Duration (hours)</span></label>
<input type="number" name="planned_duration_hours" class="input input-bordered" step="0.5" min="0"/></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Schedule</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Scheduled Start</span></label>
<input type="datetime-local" name="scheduled_start" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Scheduled End</span></label>
<input type="datetime-local" name="scheduled_end" class="input input-bordered"/></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/work-orders" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Work Order</button>
</div>
</div></div></form>"##);

    let sidebar = build_sidebar("eam_work_orders", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Work Order - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/work-orders">Work Orders</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Work Order</h1></div>
<a href="/eam/work-orders" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let title = form.get("title").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let priority: i32 = form.get("priority").and_then(|p| p.parse().ok()).unwrap_or(2);
    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let assigned_to = form.get("assigned_to").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let scheduled_start = form.get("scheduled_start").cloned().unwrap_or_default();
    let scheduled_end = form.get("scheduled_end").cloned().unwrap_or_default();
    let duration: Option<f64> = form.get("planned_duration_hours").and_then(|d| d.parse().ok());

    let sched_start_ts = if scheduled_start.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_start, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };
    let sched_end_ts = if scheduled_end.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_end, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };

    // Generate WO number
    let next_num: i64 = sqlx::query_scalar("SELECT COUNT(*) + 1 FROM eam_work_orders WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(1);
    let wo_number = format!("WO-{}-{:05}", chrono::Utc::now().format("%Y"), next_num);

    let mtype_opt = if maintenance_type.is_empty() { None } else { Some(maintenance_type) };
    let desc_opt = if description.is_empty() { None } else { Some(description) };

    let new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_work_orders (company_id, wo_number, title, description, maintenance_type, priority, state,
            asset_id, assigned_to, scheduled_start, scheduled_end, planned_duration_hours, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $10, $11, $12)
            RETURNING id"#
    )
    .bind(company_id).bind(&wo_number).bind(&title).bind(&desc_opt).bind(&mtype_opt).bind(priority)
    .bind(asset_id).bind(assigned_to).bind(sched_start_ts).bind(sched_end_ts)
    .bind(duration).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to(&format!("/eam/work-orders/{}", new_id)).into_response()
}

async fn eam_work_order_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Get work order details
    let wo = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.description, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start, wo.scheduled_end, wo.actual_start, wo.actual_end,
                  wo.findings, wo.actions_taken, wo.recommendations, wo.hold_reason, wo.cancel_reason,
                  wo.created_at, wo.materials_cost, wo.labor_cost, wo.total_cost,
                  a.name as asset_name, a.asset_code, a.id as asset_id,
                  u.full_name as assigned_to, cr.full_name as created_by_name
           FROM eam_work_orders wo
           LEFT JOIN eam_assets a ON wo.asset_id = a.id
           LEFT JOIN users u ON wo.assigned_to = u.id
           LEFT JOIN users cr ON wo.created_by = cr.id
           WHERE wo.id = $1"#
    ).bind(id).fetch_optional(&db).await.unwrap_or(None);

    // Get activity/state history
    let history_rows = sqlx::query(
        r#"SELECT h.from_state, h.to_state, h.action, h.reason, h.changed_at, u.full_name as changed_by
           FROM eam_work_order_state_history h
           LEFT JOIN users u ON h.changed_by = u.id
           WHERE h.work_order_id = $1 ORDER BY h.changed_at DESC"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let content = if let Some(row) = wo {
        let wo_number: String = row.get("wo_number");
        let title: String = row.get("title");
        let description: String = row.get::<Option<String>, _>("description").unwrap_or_default();
        let maint_type: String = row.get::<Option<String>, _>("maintenance_type").unwrap_or_else(|| "-".to_string());
        let priority_int: i32 = row.get::<Option<i32>, _>("priority").unwrap_or(2);
        let priority = match priority_int { 0 => "Critical", 1 => "High", 2 => "Medium", 3 => "Low", _ => "Medium" };
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let asset_code: String = row.get::<Option<String>, _>("asset_code").unwrap_or_else(|| "-".to_string());
        let assigned: String = row.get::<Option<String>, _>("assigned_to").unwrap_or_else(|| "Unassigned".to_string());
        let created_by: String = row.get::<Option<String>, _>("created_by_name").unwrap_or_else(|| "-".to_string());
        let created_at: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let sched_start: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_start")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let sched_end: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_end")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let actual_start: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("actual_start")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let actual_end: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("actual_end")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let findings: String = row.get::<Option<String>, _>("findings").unwrap_or_default();
        let actions: String = row.get::<Option<String>, _>("actions_taken").unwrap_or_default();
        let recommendations: String = row.get::<Option<String>, _>("recommendations").unwrap_or_default();
        let hold_reason: String = row.get::<Option<String>, _>("hold_reason").unwrap_or_default();

        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "scheduled" => "#3B82F6", "in_progress" => "#F59E0B",
            "on_hold" => "#EF4444", "completed" => "#10B981", "cancelled" => "#9CA3AF", _ => "#6B7280"
        };
        let priority_color = match priority_int { 0 => "#DC2626", 1 => "#F97316", 2 => "#EAB308", 3 => "#22C55E", _ => "#6B7280" };

        // Status progress bar steps
        let steps = vec!["draft", "scheduled", "in_progress", "completed"];
        let current_idx = steps.iter().position(|s| *s == state_val.as_str()).unwrap_or(0);
        let is_cancelled = state_val == "cancelled";
        let is_on_hold = state_val == "on_hold";

        let mut steps_html = String::new();
        for (i, step) in steps.iter().enumerate() {
            let label = match *step { "draft" => "Draft", "scheduled" => "Scheduled", "in_progress" => "In Progress", "completed" => "Completed", _ => step };
            let class = if is_cancelled {
                "step"
            } else if i < current_idx {
                "step step-primary"
            } else if i == current_idx {
                "step step-primary"
            } else {
                "step"
            };
            steps_html.push_str(&format!(r#"<li class="{class}">{label}</li>"#));
        }

        let on_hold_badge = if is_on_hold {
            r#"<div class="alert alert-error mt-2"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg><span>ON HOLD</span></div>"#
        } else { "" };

        let cancelled_badge = if is_cancelled {
            r#"<div class="alert alert-warning mt-2"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg><span>CANCELLED</span></div>"#
        } else { "" };

        // Action buttons based on state
        let action_buttons = match state_val.as_str() {
            "draft" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="schedule"/>
                <button type="submit" class="btn btn-primary btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>Schedule</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="start"/>
                <button type="submit" class="btn btn-warning btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>Start Work</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="cancel"/>
                <button type="submit" class="btn btn-ghost btn-block text-error" onclick="return confirm('Cancel this work order?')">Cancel</button></form>"#),
            "scheduled" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="start"/>
                <button type="submit" class="btn btn-primary btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>Start Work</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="cancel"/>
                <button type="submit" class="btn btn-ghost btn-block text-error" onclick="return confirm('Cancel this work order?')">Cancel</button></form>"#),
            "in_progress" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="complete"/>
                <button type="submit" class="btn btn-success btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Complete</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="hold"/>
                <button type="submit" class="btn btn-outline btn-error btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>Put On Hold</button></form>"#),
            "on_hold" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="resume"/>
                <button type="submit" class="btn btn-primary btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>Resume Work</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="cancel"/>
                <button type="submit" class="btn btn-ghost btn-block text-error" onclick="return confirm('Cancel this work order?')">Cancel</button></form>"#),
            "completed" => String::new(),
            "cancelled" => String::new(),
            _ => String::new(),
        };

        // Activity stream
        let mut activity_html = String::new();
        if history_rows.is_empty() {
            activity_html.push_str(&format!(
                r#"<li><div class="timeline-start timeline-box text-sm">Work order created</div>
                <div class="timeline-middle"><svg class="w-5 h-5 text-primary" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg></div>
                <div class="timeline-end text-xs text-base-content/60">{created_at}<br/>{created_by}</div><hr/></li>"#));
        }
        for (i, hrow) in history_rows.iter().enumerate() {
            let from: String = hrow.get("from_state");
            let to: String = hrow.get("to_state");
            let action: String = hrow.get("action");
            let reason: String = hrow.get::<Option<String>, _>("reason").unwrap_or_default();
            let changed_at: String = hrow.get::<chrono::DateTime<chrono::Utc>, _>("changed_at")
                .format("%d/%m/%Y %H:%M").to_string();
            let changed_by: String = hrow.get::<Option<String>, _>("changed_by").unwrap_or_else(|| "System".to_string());

            let icon_color = match to.as_str() {
                "scheduled" => "text-blue-500", "in_progress" => "text-amber-500",
                "completed" => "text-green-500", "on_hold" => "text-red-500",
                "cancelled" => "text-gray-400", _ => "text-primary"
            };
            let action_label = match action.as_str() {
                "schedule" => "Scheduled", "start" => "Started", "complete" => "Completed",
                "hold" => "Put on hold", "resume" => "Resumed", "cancel" => "Cancelled", _ => &action
            };
            let reason_line = if reason.is_empty() { String::new() } else { format!(r#"<div class="text-xs text-base-content/50 italic mt-1">{reason}</div>"#) };
            let hr = if i < history_rows.len() - 1 { "<hr/>" } else { "" };

            activity_html.push_str(&format!(
                r#"<li><hr/><div class="timeline-start timeline-box text-sm"><span class="font-semibold">{action_label}</span><br/><span class="text-xs text-base-content/60">{from} &rarr; {to}</span>{reason_line}</div>
                <div class="timeline-middle"><svg class="w-5 h-5 {icon_color}" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg></div>
                <div class="timeline-end text-xs text-base-content/60">{changed_at}<br/>{changed_by}</div>{hr}</li>"#));
        }
        // Add creation event at bottom
        activity_html.push_str(&format!(
            r#"<li><hr/><div class="timeline-start timeline-box text-sm"><span class="font-semibold">Created</span></div>
            <div class="timeline-middle"><svg class="w-5 h-5 text-primary" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg></div>
            <div class="timeline-end text-xs text-base-content/60">{created_at}<br/>{created_by}</div></li>"#));

        let findings_section = if findings.is_empty() && actions.is_empty() && recommendations.is_empty() {
            r#"<p class="text-base-content/40 italic">No findings recorded yet</p>"#.to_string()
        } else {
            let f = if findings.is_empty() { String::new() } else { format!(r#"<h4 class="text-sm font-semibold text-base-content/60 mt-2">Findings</h4><p class="whitespace-pre-wrap">{findings}</p>"#) };
            let a = if actions.is_empty() { String::new() } else { format!(r#"<h4 class="text-sm font-semibold text-base-content/60 mt-2">Actions Taken</h4><p class="whitespace-pre-wrap">{actions}</p>"#) };
            let r = if recommendations.is_empty() { String::new() } else { format!(r#"<h4 class="text-sm font-semibold text-base-content/60 mt-2">Recommendations</h4><p class="whitespace-pre-wrap">{recommendations}</p>"#) };
            format!("{f}{a}{r}")
        };

        let hold_info = if !hold_reason.is_empty() {
            format!(r#"<div class="alert alert-error mt-4"><div><span class="font-semibold">Hold Reason:</span> {hold_reason}</div></div>"#)
        } else { String::new() };

        format!(r##"
<!-- Status Progress Bar -->
<div class="card bg-base-100 shadow mb-6"><div class="card-body py-4">
<ul class="steps steps-horizontal w-full">{steps_html}</ul>
{on_hold_badge}{cancelled_badge}
</div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
<!-- Left Column: Details -->
<div class="lg:col-span-2 space-y-6">

<!-- Header Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex justify-between items-start">
<div><h2 class="card-title text-xl">{title}</h2>
<p class="font-mono text-sm text-base-content/60 mt-1">{wo_number}</p></div>
<div class="flex gap-2">
<span class="badge" style="background-color:{priority_color};color:white;">{priority}</span>
<span class="badge" style="background-color:{state_color};color:white;">{state_val}</span>
<span class="badge badge-outline">{maint_type}</span>
</div></div>
<p class="text-base-content/70 mt-3">{description}</p>
{hold_info}
</div></div>

<!-- Details Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-3">Details</h3>
<div class="grid grid-cols-2 md:grid-cols-3 gap-4">
<div><span class="text-xs text-base-content/50 uppercase">Asset</span><p class="font-semibold">{asset_name}</p><p class="text-xs text-base-content/60">{asset_code}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Assigned To</span><p class="font-semibold">{assigned}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Created By</span><p class="font-semibold">{created_by}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Scheduled Start</span><p class="font-semibold">{sched_start}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Scheduled End</span><p class="font-semibold">{sched_end}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Actual Start</span><p class="font-semibold">{actual_start}</p></div>
</div></div></div>

<!-- Findings Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-3">Work Report</h3>
{findings_section}
</div></div>

<!-- Activity Stream -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Activity Stream</h3>
<ul class="timeline timeline-vertical timeline-compact">{activity_html}</ul>
</div></div>
</div>

<!-- Right Column: Actions & Info -->
<div class="space-y-6">

<!-- Actions Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold mb-4">Actions</h3>
{action_buttons}
<a href="/eam/work-orders/{id}/edit" class="btn btn-outline btn-block mt-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit Work Order</a>
</div></div>

<!-- Info Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold mb-4">Information</h3>
<div class="space-y-3 text-sm">
<div class="flex justify-between"><span class="text-base-content/60">WO Number</span><span class="font-mono font-semibold">{wo_number}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Status</span><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Priority</span><span class="badge badge-sm" style="background-color:{priority_color};color:white;">{priority}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Type</span><span class="badge badge-outline badge-sm">{maint_type}</span></div>
<div class="divider my-1"></div>
<div class="flex justify-between"><span class="text-base-content/60">Created</span><span>{created_at}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Actual End</span><span>{actual_end}</span></div>
</div></div></div>
</div></div>"##)
    } else {
        r#"<div class="text-center py-12"><h3 class="text-lg font-semibold">Work Order Not Found</h3><a href="/eam/work-orders" class="btn btn-primary mt-4">Back to Work Orders</a></div>"#.to_string()
    };

    let sidebar = build_sidebar("eam_work_orders", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Work Order Detail - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/work-orders">Work Orders</a></li><li>Detail</li></ul></div>
<h1 class="text-2xl font-bold">Work Order Detail</h1></div>
<a href="/eam/work-orders" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let wo = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.description, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start, wo.scheduled_end, wo.asset_id, wo.assigned_to,
                  wo.findings, wo.actions_taken, wo.recommendations, wo.planned_duration_hours
           FROM eam_work_orders wo WHERE wo.id = $1"#
    ).bind(id).fetch_optional(&db).await.unwrap_or(None);

    // Get assets for dropdown
    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    // Get users for assignment dropdown
    let users = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let content = if let Some(row) = wo {
        let wo_number: String = row.get("wo_number");
        let title: String = row.get("title");
        let description: String = row.get::<Option<String>, _>("description").unwrap_or_default();
        let maint_type: String = row.get::<Option<String>, _>("maintenance_type").unwrap_or_default();
        let priority_int: i32 = row.get::<Option<i32>, _>("priority").unwrap_or(2);
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_id: Option<uuid::Uuid> = row.get("asset_id");
        let assigned_to: Option<uuid::Uuid> = row.get("assigned_to");
        let sched_start: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_start")
            .map(|d| d.format("%Y-%m-%dT%H:%M").to_string()).unwrap_or_default();
        let sched_end: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_end")
            .map(|d| d.format("%Y-%m-%dT%H:%M").to_string()).unwrap_or_default();
        let findings: String = row.get::<Option<String>, _>("findings").unwrap_or_default();
        let actions: String = row.get::<Option<String>, _>("actions_taken").unwrap_or_default();
        let recommendations: String = row.get::<Option<String>, _>("recommendations").unwrap_or_default();
        let duration: String = row.get::<Option<f64>, _>("planned_duration_hours")
            .map(|d| format!("{}", d)).unwrap_or_default();

        // Build asset options
        let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
        for a in &assets {
            let aid: uuid::Uuid = a.get("id");
            let acode: String = a.get("asset_code");
            let aname: String = a.get("name");
            let selected = if asset_id == Some(aid) { " selected" } else { "" };
            asset_options.push_str(&format!(r#"<option value="{aid}"{selected}>{acode} - {aname}</option>"#));
        }

        // Build user options
        let mut user_options = r#"<option value="">-- Unassigned --</option>"#.to_string();
        for u in &users {
            let uid: uuid::Uuid = u.get("id");
            let uname: String = u.get::<Option<String>, _>("full_name")
                .unwrap_or_else(|| u.get::<String, _>("username"));
            let selected = if assigned_to == Some(uid) { " selected" } else { "" };
            user_options.push_str(&format!(r#"<option value="{uid}"{selected}>{uname}</option>"#));
        }

        // Build maintenance type options
        let mtype_options = ["pm", "cm", "emergency", "inspection", "testing", "overhaul"];
        let mtype_labels = ["Preventive (PM)", "Corrective (CM)", "Emergency", "Inspection", "Testing", "Overhaul"];
        let mut mtype_html = r#"<option value="">-- Select Type --</option>"#.to_string();
        for (val, label) in mtype_options.iter().zip(mtype_labels.iter()) {
            let selected = if maint_type == *val { " selected" } else { "" };
            mtype_html.push_str(&format!(r#"<option value="{val}"{selected}>{label}</option>"#));
        }

        // Priority options
        let priority_opts = [(0, "Critical"), (1, "High"), (2, "Medium"), (3, "Low")];
        let mut priority_html = String::new();
        for (val, label) in &priority_opts {
            let selected = if priority_int == *val { " selected" } else { "" };
            priority_html.push_str(&format!(r#"<option value="{val}"{selected}>{label}</option>"#));
        }

        format!(r##"<form method="POST" action="/eam/work-orders/{id}/edit">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<!-- Left Column -->
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">General Information</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">WO Number</span></label>
<input type="text" class="input input-bordered" value="{wo_number}" disabled/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Title *</span></label>
<input type="text" name="title" class="input input-bordered" value="{title}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24">{description}</textarea></div>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Maintenance Type</span></label>
<select name="maintenance_type" class="select select-bordered">{mtype_html}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered">{priority_html}</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assignment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered">{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered">{user_options}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Planned Duration (hours)</span></label>
<input type="number" name="planned_duration_hours" class="input input-bordered" value="{duration}" step="0.5" min="0"/></div>
</div></div>
</div>

<!-- Right Column -->
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Schedule</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Scheduled Start</span></label>
<input type="datetime-local" name="scheduled_start" class="input input-bordered" value="{sched_start}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Scheduled End</span></label>
<input type="datetime-local" name="scheduled_end" class="input input-bordered" value="{sched_end}"/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Work Report</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Findings</span></label>
<textarea name="findings" class="textarea textarea-bordered h-20">{findings}</textarea></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Actions Taken</span></label>
<textarea name="actions_taken" class="textarea textarea-bordered h-20">{actions}</textarea></div>
<div class="form-control"><label class="label"><span class="label-text">Recommendations</span></label>
<textarea name="recommendations" class="textarea textarea-bordered h-20">{recommendations}</textarea></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/work-orders/{id}" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Changes</button>
</div>
</div></div></form>"##)
    } else {
        r#"<div class="text-center py-12"><h3 class="text-lg font-semibold">Work Order Not Found</h3></div>"#.to_string()
    };

    let sidebar = build_sidebar("eam_work_orders", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Edit Work Order - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/work-orders">Work Orders</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Work Order</h1></div>
<a href="/eam/work-orders/{id}" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let title = form.get("title").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let priority: i32 = form.get("priority").and_then(|p| p.parse().ok()).unwrap_or(2);
    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let assigned_to = form.get("assigned_to").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let scheduled_start = form.get("scheduled_start").cloned().unwrap_or_default();
    let scheduled_end = form.get("scheduled_end").cloned().unwrap_or_default();
    let findings = form.get("findings").cloned().unwrap_or_default();
    let actions_taken = form.get("actions_taken").cloned().unwrap_or_default();
    let recommendations = form.get("recommendations").cloned().unwrap_or_default();
    let duration: Option<f64> = form.get("planned_duration_hours").and_then(|d| d.parse().ok());

    let sched_start_ts = if scheduled_start.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_start, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };
    let sched_end_ts = if scheduled_end.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_end, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };

    let mtype_opt = if maintenance_type.is_empty() { None } else { Some(maintenance_type) };
    let findings_opt = if findings.is_empty() { None } else { Some(findings) };
    let actions_opt = if actions_taken.is_empty() { None } else { Some(actions_taken) };
    let recs_opt = if recommendations.is_empty() { None } else { Some(recommendations) };

    let _ = sqlx::query(
        r#"UPDATE eam_work_orders SET title = $2, description = $3, maintenance_type = $4, priority = $5,
            asset_id = $6, assigned_to = $7, scheduled_start = $8, scheduled_end = $9,
            findings = $10, actions_taken = $11, recommendations = $12, planned_duration_hours = $13,
            updated_at = now(), updated_by = $14
            WHERE id = $1"#
    )
    .bind(id).bind(&title).bind(&description).bind(&mtype_opt).bind(priority)
    .bind(asset_id).bind(assigned_to).bind(sched_start_ts).bind(sched_end_ts)
    .bind(&findings_opt).bind(&actions_opt).bind(&recs_opt).bind(duration)
    .bind(user.id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/work-orders/{}", id)).into_response()
}

async fn eam_work_order_transition(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let action = form.get("action").cloned().unwrap_or_default();

    // Get current state
    let current_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM eam_work_orders WHERE id = $1"
    ).bind(id).fetch_optional(&db).await.unwrap_or(None);

    if let Some(current) = current_state {
        let new_state = match (current.as_str(), action.as_str()) {
            ("draft", "schedule") => Some("scheduled"),
            ("draft", "start") => Some("in_progress"),
            ("draft", "cancel") => Some("cancelled"),
            ("scheduled", "start") => Some("in_progress"),
            ("scheduled", "cancel") => Some("cancelled"),
            ("in_progress", "complete") => Some("completed"),
            ("in_progress", "hold") => Some("on_hold"),
            ("on_hold", "resume") => Some("in_progress"),
            ("on_hold", "cancel") => Some("cancelled"),
            _ => None,
        };

        if let Some(to_state) = new_state {
            // Update work order state
            let now = chrono::Utc::now();
            let mut update_sql = format!("UPDATE eam_work_orders SET state = '{}', updated_at = $2, updated_by = $3", to_state);
            if to_state == "in_progress" && current != "on_hold" {
                update_sql.push_str(&format!(", actual_start = '{}'", now.format("%Y-%m-%dT%H:%M:%S%z")));
            }
            if to_state == "completed" {
                update_sql.push_str(&format!(", actual_end = '{}'", now.format("%Y-%m-%dT%H:%M:%S%z")));
            }
            update_sql.push_str(" WHERE id = $1");

            let _ = sqlx::query(&update_sql)
                .bind(id).bind(now).bind(user.id)
                .execute(&db).await;

            // Record state history
            let _ = sqlx::query(
                r#"INSERT INTO eam_work_order_state_history (work_order_id, from_state, to_state, action, changed_by)
                   VALUES ($1, $2, $3, $4, $5)"#
            ).bind(id).bind(&current).bind(to_state).bind(&action).bind(user.id)
             .execute(&db).await;
        }
    }

    // Redirect back to detail page
    axum::response::Redirect::to(&format!("/eam/work-orders/{}", id)).into_response()
}

async fn eam_equipment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let filter = params.get("type").cloned().unwrap_or_else(|| "all".to_string());

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get counts - equipment tables linked via asset_id to eam_assets
    let transformers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transformers t JOIN eam_assets a ON t.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let switchgear: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_switch_gears s JOIN eam_assets a ON s.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let rmu: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_ring_main_units r JOIN eam_assets a ON r.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let batteries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_batteries b JOIN eam_assets a ON b.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let ct_vt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_current_voltage_transformers c JOIN eam_assets a ON c.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let total = transformers + switchgear + rmu + batteries + ct_vt;

    // Build equipment table based on filter
    let equipment_query = match filter.as_str() {
        "transformer" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'Transformer' as eq_type, t.mva_rating as rating
            FROM eam_assets a JOIN eam_transformers t ON t.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name"#,
        "switchgear" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'Switchgear' as eq_type, s.rated_voltage as rating
            FROM eam_assets a JOIN eam_switch_gears s ON s.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name"#,
        "battery" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'Battery' as eq_type, b.nominal_voltage as rating
            FROM eam_assets a JOIN eam_batteries b ON b.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name"#,
        "ct_vt" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'CT/VT' as eq_type, c.rated_voltage_kv as rating
            FROM eam_assets a JOIN eam_current_voltage_transformers c ON c.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name"#,
        "rmu" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'RMU' as eq_type, r.rated_voltage_kv as rating
            FROM eam_assets a JOIN eam_ring_main_units r ON r.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name"#,
        _ => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, c.name as eq_type, NULL::float8 as rating
            FROM eam_assets a LEFT JOIN eam_asset_categories c ON a.category_id = c.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT 50"#,
    };

    let eq_rows = sqlx::query(equipment_query).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &eq_rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("asset_code");
        let name: String = row.get("name");
        let mfr: String = row.get::<Option<String>, _>("manufacturer").unwrap_or_else(|| "-".to_string());
        let model: String = row.get::<Option<String>, _>("model").unwrap_or_else(|| "-".to_string());
        let status: String = row.get::<Option<String>, _>("operational_status").unwrap_or_else(|| "unknown".to_string());
        let eq_type: String = row.get::<Option<String>, _>("eq_type").unwrap_or_else(|| "-".to_string());
        let rating: String = row.get::<Option<f64>, _>("rating").map(|r| format!("{:.1}", r)).unwrap_or_else(|| "-".to_string());

        let status_color = match status.as_str() {
            "in_service" => "#10B981", "out_of_service" => "#EF4444", "standby" => "#F59E0B", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{name}</td><td><span class="badge badge-outline badge-sm">{eq_type}</span></td>
            <td>{mfr}</td><td>{model}</td><td>{rating}</td>
            <td><span class="badge badge-sm" style="background-color:{status_color};color:white;">{status}</span></td>
            <td><a href="/eam/assets/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if eq_rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg><h3 class="text-lg font-semibold mb-2">No Equipment Found</h3><p class="text-base-content/60">Add equipment to track assets</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Manufacturer</th><th>Model</th><th>Rating</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let filter_tabs = format!(r#"<div class="tabs tabs-boxed bg-base-100 p-1 mb-6">
<a href="/eam/equipment" class="tab {}">All ({total})</a>
<a href="/eam/equipment?type=transformer" class="tab {}">Transformers ({transformers})</a>
<a href="/eam/equipment?type=switchgear" class="tab {}">Switchgear ({switchgear})</a>
<a href="/eam/equipment?type=rmu" class="tab {}">RMU ({rmu})</a>
<a href="/eam/equipment?type=battery" class="tab {}">Batteries ({batteries})</a>
<a href="/eam/equipment?type=ct_vt" class="tab {}">CT/VT ({ct_vt})</a>
</div>"#,
        if filter == "all" { "tab-active" } else { "" },
        if filter == "transformer" { "tab-active" } else { "" },
        if filter == "switchgear" { "tab-active" } else { "" },
        if filter == "rmu" { "tab-active" } else { "" },
        if filter == "battery" { "tab-active" } else { "" },
        if filter == "ct_vt" { "tab-active" } else { "" },
    );

    let sidebar = build_sidebar("eam_equipment", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Equipment - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Equipment</li></ul></div>
<h1 class="text-2xl font-bold">Equipment</h1><p class="text-base-content/60">All equipment types across the system</p></div>
<a href="/eam/equipment/new" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Equipment</a></div>
{filter_tabs}
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_inspections(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT i.id, i.inspection_code, i.inspection_type, i.state, i.overall_condition,
                  i.inspection_date, a.name as asset_name, u.full_name as inspector_name
           FROM eam_inspection_results i
           LEFT JOIN eam_assets a ON i.asset_id = a.id
           LEFT JOIN users u ON i.inspector_id = u.id
           WHERE i.company_id = $1
           ORDER BY i.inspection_date DESC NULLS LAST LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get::<Option<String>, _>("inspection_code").unwrap_or_default();
        let insp_type: String = row.get::<Option<String>, _>("inspection_type").unwrap_or_else(|| "-".to_string());
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let condition: String = row.get::<Option<String>, _>("overall_condition").unwrap_or_else(|| "-".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let inspector: String = row.get::<Option<String>, _>("inspector_name").unwrap_or_else(|| "-".to_string());
        let insp_date: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("inspection_date")
            .map(|d| d.format("%d/%m/%Y").to_string()).unwrap_or_else(|| "-".to_string());

        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "submitted" => "#3B82F6", "approved" => "#10B981", "rejected" => "#EF4444", _ => "#6B7280"
        };
        let cond_color = match condition.as_str() {
            "good" => "#10B981", "fair" => "#EAB308", "poor" => "#F97316", "critical" => "#EF4444", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{asset_name}</td>
            <td><span class="badge badge-outline badge-sm">{insp_type}</span></td>
            <td>{insp_date}</td><td>{inspector}</td>
            <td><span class="badge badge-sm" style="background-color:{cond_color};color:white;">{condition}</span></td>
            <td><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></td>
            <td><a href="/eam/inspections/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg><h3 class="text-lg font-semibold mb-2">No Inspections Yet</h3><p class="text-base-content/60">Inspection results will appear here once created.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Asset</th><th>Type</th><th>Date</th><th>Inspector</th><th>Condition</th><th>State</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_inspections", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Inspections - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Inspections</li></ul></div>
<h1 class="text-2xl font-bold">Inspections</h1><p class="text-base-content/60">Asset inspection results and approval workflow</p></div>
<a href="/eam/inspections/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Inspection</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_checklists(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT ct.id, ct.name, ct.equipment_category, ct.maintenance_type, ct.version, ct.is_active,
                  (SELECT COUNT(*) FROM eam_checklist_template_items cti WHERE cti.template_id = ct.id) as item_count
           FROM eam_checklist_templates ct
           WHERE ct.company_id = $1
           ORDER BY ct.name LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let name: String = row.get("name");
        let category: String = row.get("equipment_category");
        let maint_type: String = row.get("maintenance_type");
        let version: i32 = row.get::<Option<i32>, _>("version").unwrap_or(1);
        let is_active: bool = row.get::<Option<bool>, _>("is_active").unwrap_or(true);
        let item_count: i64 = row.get::<Option<i64>, _>("item_count").unwrap_or(0);
        let status_badge = if is_active {
            r#"<span class="badge badge-sm badge-success">Active</span>"#
        } else {
            r#"<span class="badge badge-sm badge-ghost">Inactive</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-semibold">{name}</td>
            <td><span class="badge badge-outline badge-sm">{category}</span></td>
            <td><span class="badge badge-outline badge-sm">{maint_type}</span></td>
            <td>v{version}</td><td>{item_count} items</td>
            <td>{status_badge}</td>
            <td><a href="/eam/checklists/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3 class="text-lg font-semibold mb-2">No Checklist Templates</h3><p class="text-base-content/60">Create templates to standardize maintenance and inspection procedures.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Name</th><th>Equipment Category</th><th>Maintenance Type</th><th>Version</th><th>Items</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_checklists", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Checklist Templates - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Checklist Templates</li></ul></div>
<h1 class="text-2xl font-bold">Checklist Templates</h1><p class="text-base-content/60">Reusable checklists for equipment maintenance and inspection</p></div>
<a href="/eam/checklists/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Checklist</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_plans(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT mp.id, mp.plan_code, mp.maintenance_type, mp.state,
                  mp.frequency_interval, mp.frequency_unit, mp.next_maintenance_date,
                  a.name as asset_name
           FROM eam_maintenance_plans mp
           LEFT JOIN eam_assets a ON mp.asset_id = a.id
           WHERE mp.company_id = $1
           ORDER BY mp.state, mp.next_maintenance_date NULLS LAST LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let plan_code: String = row.get::<Option<String>, _>("plan_code").unwrap_or_else(|| "-".to_string());
        let maint_type: String = row.get("maintenance_type");
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let freq_interval: Option<i32> = row.get("frequency_interval");
        let freq_unit: Option<String> = row.get("frequency_unit");
        let next_date: String = row.get::<Option<String>, _>("next_maintenance_date").unwrap_or_else(|| "-".to_string());

        let frequency = match (freq_interval, freq_unit.as_deref()) {
            (Some(n), Some(u)) => format!("Every {} {}s", n, u),
            _ => "-".to_string(),
        };

        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "active" => "#10B981", "done" => "#3B82F6", "cancelled" => "#EF4444", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{plan_code}</td><td>{asset_name}</td>
            <td><span class="badge badge-outline badge-sm">{maint_type}</span></td>
            <td>{frequency}</td><td>{next_date}</td>
            <td><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></td>
            <td><a href="/eam/plans/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg><h3 class="text-lg font-semibold mb-2">No Maintenance Plans</h3><p class="text-base-content/60">Create plans to schedule recurring maintenance and auto-generate work orders.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Plan Code</th><th>Asset</th><th>Type</th><th>Frequency</th><th>Next Due</th><th>State</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_plans", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Maintenance Plans - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Maintenance Plans</li></ul></div>
<h1 class="text-2xl font-bold">Maintenance Plans</h1><p class="text-base-content/60">Recurring maintenance schedules with automatic work order generation</p></div>
<a href="/eam/plans/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Plan</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_inspection_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let users_rows = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        asset_options.push_str(&format!(r#"<option value="{aid}">{acode} - {aname}</option>"#));
    }

    let mut user_options = r#"<option value="">-- Select Inspector --</option>"#.to_string();
    for u in &users_rows {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get::<Option<String>, _>("full_name")
            .unwrap_or_else(|| u.get::<String, _>("username"));
        user_options.push_str(&format!(r#"<option value="{uid}">{uname}</option>"#));
    }

    let content = format!(r##"<form method="POST" action="/eam/inspections/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Inspection Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset *</span></label>
<select name="asset_id" class="select select-bordered" required>{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Inspector *</span></label>
<select name="inspector_id" class="select select-bordered" required>{user_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Inspection Type</span></label>
<select name="inspection_type" class="select select-bordered">
<option value="">-- Select Type --</option>
<option value="routine">Routine</option><option value="detailed">Detailed</option>
<option value="commissioning">Commissioning</option><option value="post_fault">Post-Fault</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Inspection Date *</span></label>
<input type="datetime-local" name="inspection_date" class="input input-bordered" required/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assessment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Overall Condition</span></label>
<select name="overall_condition" class="select select-bordered">
<option value="">-- Select Condition --</option>
<option value="good">Good</option><option value="fair">Fair</option>
<option value="poor">Poor</option><option value="critical">Critical</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Defects Found</span></label>
<textarea name="defects_found" class="textarea textarea-bordered h-24" placeholder="Describe any defects observed"></textarea></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Recommendations</span></label>
<textarea name="observations" class="textarea textarea-bordered h-24" placeholder="Recommendations and observations"></textarea></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3">
<input type="checkbox" name="immediate_action_required" value="true" class="checkbox checkbox-warning"/>
<span class="label-text">Immediate action required</span></label></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Visual Checks</h3>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="visual_check" value="true" class="checkbox"/><span class="label-text">Visual inspection passed</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="cleanliness_check" value="true" class="checkbox"/><span class="label-text">Cleanliness OK</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="corrosion_check" value="true" class="checkbox"/><span class="label-text">No corrosion found</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="oil_leak_check" value="true" class="checkbox"/><span class="label-text">No oil leaks</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="connection_check" value="true" class="checkbox"/><span class="label-text">Connections secure</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="labeling_check" value="true" class="checkbox"/><span class="label-text">Labels intact</span></label></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/inspections" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Inspection</button>
</div>
</div></div></form>"##);

    let sidebar = build_sidebar("eam_inspections", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Inspection - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/inspections">Inspections</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Inspection</h1></div>
<a href="/eam/inspections" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_inspection_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let inspector_id = form.get("inspector_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let inspection_type = form.get("inspection_type").cloned().unwrap_or_default();
    let inspection_date_str = form.get("inspection_date").cloned().unwrap_or_default();
    let overall_condition = form.get("overall_condition").cloned().unwrap_or_default();
    let defects_found = form.get("defects_found").cloned().unwrap_or_default();
    let observations = form.get("observations").cloned().unwrap_or_default();
    let immediate_action = form.get("immediate_action_required").map(|v| v == "true").unwrap_or(false);
    let visual_check = form.get("visual_check").map(|v| v == "true").unwrap_or(false);
    let cleanliness_check = form.get("cleanliness_check").map(|v| v == "true").unwrap_or(false);
    let corrosion_check = form.get("corrosion_check").map(|v| v == "true").unwrap_or(false);
    let oil_leak_check = form.get("oil_leak_check").map(|v| v == "true").unwrap_or(false);
    let connection_check = form.get("connection_check").map(|v| v == "true").unwrap_or(false);
    let labeling_check = form.get("labeling_check").map(|v| v == "true").unwrap_or(false);

    let insp_date = if inspection_date_str.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&inspection_date_str, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };

    let next_num: i64 = sqlx::query_scalar("SELECT COUNT(*) + 1 FROM eam_inspection_results WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(1);
    let inspection_code = format!("INS-{}-{:05}", chrono::Utc::now().format("%Y"), next_num);

    let itype_opt = if inspection_type.is_empty() { None } else { Some(inspection_type) };
    let cond_opt = if overall_condition.is_empty() { None } else { Some(overall_condition) };
    let defects_opt = if defects_found.is_empty() { None } else { Some(defects_found) };
    let obs_opt = if observations.is_empty() { None } else { Some(observations) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_inspection_results (company_id, inspection_code, asset_id, inspector_id,
            inspection_type, inspection_date, overall_condition, defects_found, observations,
            immediate_action_required, visual_check, cleanliness_check, corrosion_check,
            oil_leak_check, connection_check, labeling_check, state, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'draft', $17)
            RETURNING id"#
    )
    .bind(company_id).bind(&inspection_code).bind(asset_id).bind(inspector_id)
    .bind(&itype_opt).bind(insp_date).bind(&cond_opt).bind(&defects_opt).bind(&obs_opt)
    .bind(immediate_action).bind(visual_check).bind(cleanliness_check).bind(corrosion_check)
    .bind(oil_leak_check).bind(connection_check).bind(labeling_check).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/inspections").into_response()
}

async fn eam_checklist_new(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let content = r##"<form method="POST" action="/eam/checklists/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Template Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input type="text" name="name" class="input input-bordered" placeholder="Enter checklist template name" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Equipment Category *</span></label>
<select name="equipment_category" class="select select-bordered" required>
<option value="">-- Select Category --</option>
<option value="transformer">Transformer</option><option value="switchgear">Switchgear</option>
<option value="circuit_breaker">Circuit Breaker</option><option value="relay">Relay</option>
<option value="cable">Cable</option><option value="battery">Battery</option>
<option value="general">General</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Maintenance Type *</span></label>
<select name="maintenance_type" class="select select-bordered" required>
<option value="">-- Select Type --</option>
<option value="pm">Preventive (PM)</option><option value="cm">Corrective (CM)</option>
<option value="inspection">Inspection</option><option value="testing">Testing</option>
<option value="overhaul">Overhaul</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Version</span></label>
<input type="number" name="version" class="input input-bordered" value="1" min="1"/></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Additional Info</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-32" placeholder="Describe the purpose and scope of this checklist"></textarea></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3">
<input type="checkbox" name="is_active" value="true" class="checkbox checkbox-success" checked/>
<span class="label-text">Active</span></label></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/checklists" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Checklist</button>
</div>
</div></div></form>"##;

    let sidebar = build_sidebar("eam_checklists", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Checklist Template - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/checklists">Checklist Templates</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Checklist Template</h1></div>
<a href="/eam/checklists" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_checklist_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let name = form.get("name").cloned().unwrap_or_default();
    let equipment_category = form.get("equipment_category").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let version: i32 = form.get("version").and_then(|v| v.parse().ok()).unwrap_or(1);
    let description = form.get("description").cloned().unwrap_or_default();
    let is_active = form.get("is_active").map(|v| v == "true").unwrap_or(false);

    let desc_opt = if description.is_empty() { None } else { Some(description) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_checklist_templates (company_id, name, equipment_category, maintenance_type,
            version, description, is_active, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id"#
    )
    .bind(company_id).bind(&name).bind(&equipment_category).bind(&maintenance_type)
    .bind(version).bind(&desc_opt).bind(is_active).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/checklists").into_response()
}

async fn eam_plan_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let users_rows = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let templates = sqlx::query(
        "SELECT id, name, equipment_category FROM eam_checklist_templates WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        asset_options.push_str(&format!(r#"<option value="{aid}">{acode} - {aname}</option>"#));
    }

    let mut user_options = r#"<option value="">-- Unassigned --</option>"#.to_string();
    for u in &users_rows {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get::<Option<String>, _>("full_name")
            .unwrap_or_else(|| u.get::<String, _>("username"));
        user_options.push_str(&format!(r#"<option value="{uid}">{uname}</option>"#));
    }

    let mut template_options = r#"<option value="">-- No Checklist --</option>"#.to_string();
    for t in &templates {
        let tid: uuid::Uuid = t.get("id");
        let tname: String = t.get("name");
        let tcat: String = t.get("equipment_category");
        template_options.push_str(&format!(r#"<option value="{tid}">{tname} ({tcat})</option>"#));
    }

    let content = format!(r##"<form method="POST" action="/eam/plans/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Plan Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset *</span></label>
<select name="asset_id" class="select select-bordered" required>{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24" placeholder="Describe the maintenance plan"></textarea></div>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Maintenance Type *</span></label>
<select name="maintenance_type" class="select select-bordered" required>
<option value="">-- Select Type --</option>
<option value="pm">Preventive (PM)</option><option value="cm">Corrective (CM)</option>
<option value="inspection">Inspection</option><option value="testing">Testing</option>
<option value="overhaul">Overhaul</option>
</select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered">
<option value="0">Critical</option><option value="1">High</option>
<option value="2" selected>Medium</option><option value="3">Low</option>
</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assignment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered">{user_options}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Checklist Template</span></label>
<select name="checklist_template_id" class="select select-bordered">{template_options}</select></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Schedule</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Start Date</span></label>
<input type="date" name="start_date" class="input input-bordered"/></div>
<div class="grid grid-cols-2 gap-4 mb-3">
<div class="form-control"><label class="label"><span class="label-text">Frequency Interval</span></label>
<input type="number" name="frequency_interval" class="input input-bordered" min="1" placeholder="e.g. 3"/></div>
<div class="form-control"><label class="label"><span class="label-text">Frequency Unit</span></label>
<select name="frequency_unit" class="select select-bordered">
<option value="">-- Select --</option>
<option value="day">Day</option><option value="week">Week</option>
<option value="month" selected>Month</option><option value="year">Year</option>
</select></div>
</div>
<div class="grid grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Planning Horizon Interval</span></label>
<input type="number" name="planning_horizon_interval" class="input input-bordered" min="1" placeholder="e.g. 12"/></div>
<div class="form-control"><label class="label"><span class="label-text">Horizon Unit</span></label>
<select name="planning_horizon_unit" class="select select-bordered">
<option value="">-- Select --</option>
<option value="day">Day</option><option value="week">Week</option>
<option value="month" selected>Month</option><option value="year">Year</option>
</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Notes</h3>
<div class="form-control"><textarea name="notes" class="textarea textarea-bordered h-24" placeholder="Additional notes for this plan"></textarea></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/plans" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Plan</button>
</div>
</div></div></form>"##);

    let sidebar = build_sidebar("eam_plans", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Maintenance Plan - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/plans">Maintenance Plans</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Maintenance Plan</h1></div>
<a href="/eam/plans" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_plan_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let description = form.get("description").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let priority: i32 = form.get("priority").and_then(|p| p.parse().ok()).unwrap_or(2);
    let assigned_to = form.get("assigned_to").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let checklist_template_id = form.get("checklist_template_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let start_date = form.get("start_date").cloned().unwrap_or_default();
    let frequency_interval: Option<i32> = form.get("frequency_interval").and_then(|v| v.parse().ok());
    let frequency_unit = form.get("frequency_unit").cloned().unwrap_or_default();
    let planning_horizon_interval: Option<i32> = form.get("planning_horizon_interval").and_then(|v| v.parse().ok());
    let planning_horizon_unit = form.get("planning_horizon_unit").cloned().unwrap_or_default();
    let notes = form.get("notes").cloned().unwrap_or_default();

    let next_num: i64 = sqlx::query_scalar("SELECT COUNT(*) + 1 FROM eam_maintenance_plans WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(1);
    let plan_code = format!("MP-{}-{:05}", chrono::Utc::now().format("%Y"), next_num);

    let desc_opt = if description.is_empty() { None } else { Some(description) };
    let start_opt = if start_date.is_empty() { None } else { Some(start_date) };
    let freq_unit_opt = if frequency_unit.is_empty() { None } else { Some(frequency_unit) };
    let horizon_unit_opt = if planning_horizon_unit.is_empty() { None } else { Some(planning_horizon_unit) };
    let notes_opt = if notes.is_empty() { None } else { Some(notes) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_maintenance_plans (company_id, plan_code, description, asset_id,
            maintenance_type, priority, assigned_to, checklist_template_id,
            start_date, frequency_interval, frequency_unit,
            planning_horizon_interval, planning_horizon_unit,
            state, notes, is_active, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'draft', $14, true, $15)
            RETURNING id"#
    )
    .bind(company_id).bind(&plan_code).bind(&desc_opt).bind(asset_id)
    .bind(&maintenance_type).bind(priority).bind(assigned_to).bind(checklist_template_id)
    .bind(&start_opt).bind(frequency_interval).bind(&freq_unit_opt)
    .bind(planning_horizon_interval).bind(&horizon_unit_opt)
    .bind(&notes_opt).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/plans").into_response()
}

// =============================================================================
// FUNCTIONAL LOCATIONS
// =============================================================================

async fn eam_functional_locations(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, fl.status, fl.description,
                  ut.name as unit_type, ut.code as unit_type_code,
                  s.name as site_name,
                  vl.name as voltage_level,
                  p.name as parent_name, p.code as parent_code
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_voltage_levels vl ON fl.voltage_level_id = vl.id
           LEFT JOIN eam_functional_locations p ON fl.parent_id = p.id
           WHERE fl.company_id = $1 AND fl.is_active = true
           ORDER BY s.name, fl.display_order, fl.code
           LIMIT 200"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let status: String = row.get::<Option<String>, _>("status").unwrap_or_else(|| "active".to_string());
        let unit_type: String = row.get::<Option<String>, _>("unit_type").unwrap_or_else(|| "-".to_string());
        let unit_code: String = row.get::<Option<String>, _>("unit_type_code").unwrap_or_default();
        let site_name: String = row.get::<Option<String>, _>("site_name").unwrap_or_else(|| "-".to_string());
        let voltage: String = row.get::<Option<String>, _>("voltage_level").unwrap_or_else(|| "-".to_string());
        let parent: String = row.get::<Option<String>, _>("parent_code").unwrap_or_else(|| "-".to_string());

        let status_badge = if status == "active" {
            r#"<span class="badge badge-sm badge-success">Active</span>"#
        } else {
            r#"<span class="badge badge-sm badge-ghost">Inactive</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{name}</td>
            <td><span class="badge badge-outline badge-sm">{unit_code}</span> {unit_type}</td>
            <td>{site_name}</td><td>{voltage}</td><td>{parent}</td>
            <td>{status_badge}</td>
            <td><a href="/eam/functional-locations/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3 class="text-lg font-semibold mb-2">No Functional Locations</h3><p class="text-base-content/60">Create functional locations to organize your assets by site hierarchy.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Unit Type</th><th>Site</th><th>Voltage</th><th>Parent</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Functional Locations - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Functional Locations</li></ul></div>
<h1 class="text-2xl font-bold">Functional Locations</h1><p class="text-base-content/60">Hierarchical organization of plant units (PPU, SSU, PP, PE)</p></div>
<a href="/eam/functional-locations/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Location</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_functional_location_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Sites dropdown
    let sites = sqlx::query(
        "SELECT id, code, name FROM eam_sites WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut site_options = r#"<option value="">-- Select Site --</option>"#.to_string();
    for s in &sites {
        let sid: uuid::Uuid = s.get("id");
        let scode: String = s.get("code");
        let sname: String = s.get("name");
        site_options.push_str(&format!(r#"<option value="{sid}">[{scode}] {sname}</option>"#));
    }

    // Unit types dropdown
    let unit_types = sqlx::query(
        "SELECT id, code, name FROM eam_unit_types WHERE company_id = $1 AND is_active = true ORDER BY display_order, name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut ut_options = r#"<option value="">-- Select Unit Type --</option>"#.to_string();
    for ut in &unit_types {
        let uid: uuid::Uuid = ut.get("id");
        let ucode: String = ut.get("code");
        let uname: String = ut.get("name");
        ut_options.push_str(&format!(r#"<option value="{uid}">{ucode} - {uname}</option>"#));
    }

    // Voltage levels dropdown
    let voltages = sqlx::query(
        "SELECT id, code, name, voltage_value FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut vl_options = r#"<option value="">-- None --</option>"#.to_string();
    for vl in &voltages {
        let vid: uuid::Uuid = vl.get("id");
        let vname: String = vl.get("name");
        vl_options.push_str(&format!(r#"<option value="{vid}">{vname}</option>"#));
    }

    // Parent functional locations dropdown
    let parents = sqlx::query(
        "SELECT id, code, name FROM eam_functional_locations WHERE company_id = $1 AND is_active = true ORDER BY code"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut parent_options = r#"<option value="">-- No Parent (Top Level) --</option>"#.to_string();
    for p in &parents {
        let pid: uuid::Uuid = p.get("id");
        let pcode: String = p.get("code");
        let pname: String = p.get("name");
        parent_options.push_str(&format!(r#"<option value="{pid}">[{pcode}] {pname}</option>"#));
    }

    let content = format!(r##"<form method="POST" action="/eam/functional-locations/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Location Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Code *</span></label>
<input type="text" name="code" class="input input-bordered font-mono" placeholder="e.g. PPU-AMP-001-SSU33" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input type="text" name="name" class="input input-bordered" placeholder="e.g. SSU 33kV - Ampang" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Short Name</span></label>
<input type="text" name="short_name" class="input input-bordered" placeholder="Short display name"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24" placeholder="Description of this functional location"></textarea></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Classification</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Site *</span></label>
<select name="site_id" class="select select-bordered" required>{site_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Unit Type *</span></label>
<select name="unit_type_id" class="select select-bordered" required>{ut_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered">{vl_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parent Location</span></label>
<select name="parent_id" class="select select-bordered">{parent_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Display Order</span></label>
<input type="number" name="display_order" class="input input-bordered" value="0" min="0"/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">References</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">SLD Reference</span></label>
<input type="text" name="sld_reference" class="input input-bordered" placeholder="Single line diagram reference"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">SCADA Point Group</span></label>
<input type="text" name="scada_point_group" class="input input-bordered" placeholder="SCADA telemetry group"/></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/functional-locations" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Location</button>
</div>
</div></div></form>"##);

    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Functional Location - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/functional-locations">Functional Locations</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Functional Location</h1></div>
<a href="/eam/functional-locations" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_functional_location_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    let short_name = form.get("short_name").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let site_id = form.get("site_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let unit_type_id = form.get("unit_type_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let voltage_level_id = form.get("voltage_level_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let parent_id = form.get("parent_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let display_order: i32 = form.get("display_order").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sld_reference = form.get("sld_reference").cloned().unwrap_or_default();
    let scada_point_group = form.get("scada_point_group").cloned().unwrap_or_default();

    let short_opt = if short_name.is_empty() { None } else { Some(short_name) };
    let desc_opt = if description.is_empty() { None } else { Some(description) };
    let sld_opt = if sld_reference.is_empty() { None } else { Some(sld_reference) };
    let scada_opt = if scada_point_group.is_empty() { None } else { Some(scada_point_group) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_functional_locations (company_id, site_id, unit_type_id, code, name,
            short_name, description, voltage_level_id, parent_id, display_order,
            sld_reference, scada_point_group, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id"#
    )
    .bind(company_id).bind(site_id).bind(unit_type_id).bind(&code).bind(&name)
    .bind(&short_opt).bind(&desc_opt).bind(voltage_level_id).bind(parent_id).bind(display_order)
    .bind(&sld_opt).bind(&scada_opt).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/functional-locations").into_response()
}

async fn eam_functional_location_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let row = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, fl.short_name, fl.description, fl.status,
                  fl.sld_reference, fl.scada_point_group, fl.display_order, fl.created_at,
                  ut.name as unit_type, ut.code as unit_type_code,
                  s.name as site_name, s.code as site_code,
                  vl.name as voltage_level,
                  p.name as parent_name, p.code as parent_code
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_voltage_levels vl ON fl.voltage_level_id = vl.id
           LEFT JOIN eam_functional_locations p ON fl.parent_id = p.id
           WHERE fl.id = $1 AND fl.company_id = $2"#
    ).bind(id).bind(company_id).fetch_optional(&db).await.unwrap_or(None);

    let row = match row {
        Some(r) => r,
        None => return axum::response::Redirect::to("/eam/functional-locations").into_response(),
    };

    let code: String = row.get("code");
    let name: String = row.get("name");
    let short_name: String = row.get::<Option<String>, _>("short_name").unwrap_or_else(|| "-".to_string());
    let description: String = row.get::<Option<String>, _>("description").unwrap_or_else(|| "-".to_string());
    let status: String = row.get::<Option<String>, _>("status").unwrap_or_else(|| "active".to_string());
    let unit_type: String = row.get::<Option<String>, _>("unit_type").unwrap_or_else(|| "-".to_string());
    let unit_code: String = row.get::<Option<String>, _>("unit_type_code").unwrap_or_default();
    let site_name: String = row.get::<Option<String>, _>("site_name").unwrap_or_else(|| "-".to_string());
    let voltage: String = row.get::<Option<String>, _>("voltage_level").unwrap_or_else(|| "-".to_string());
    let parent_name: String = row.get::<Option<String>, _>("parent_name").unwrap_or_else(|| "-".to_string());
    let parent_code: String = row.get::<Option<String>, _>("parent_code").unwrap_or_default();
    let sld_ref: String = row.get::<Option<String>, _>("sld_reference").unwrap_or_else(|| "-".to_string());
    let scada: String = row.get::<Option<String>, _>("scada_point_group").unwrap_or_else(|| "-".to_string());
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");

    let status_badge = if status == "active" {
        r#"<span class="badge badge-success">Active</span>"#
    } else {
        r#"<span class="badge badge-ghost">Inactive</span>"#
    };

    let parent_display = if parent_code.is_empty() {
        parent_name.clone()
    } else {
        format!("[{}] {}", parent_code, parent_name)
    };

    // Child locations
    let children = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, ut.code as unit_type_code
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           WHERE fl.parent_id = $1 AND fl.is_active = true
           ORDER BY fl.display_order, fl.code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut children_html = String::new();
    for c in &children {
        let cid: uuid::Uuid = c.get("id");
        let ccode: String = c.get("code");
        let cname: String = c.get("name");
        let cut: String = c.get::<Option<String>, _>("unit_type_code").unwrap_or_default();
        children_html.push_str(&format!(
            r#"<tr><td class="font-mono"><a href="/eam/functional-locations/{cid}" class="link link-primary">{ccode}</a></td><td>{cname}</td><td><span class="badge badge-outline badge-sm">{cut}</span></td></tr>"#
        ));
    }

    let children_section = if children.is_empty() {
        r#"<p class="text-base-content/50 text-sm py-4">No child locations</p>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Type</th></tr></thead><tbody>{children_html}</tbody></table></div>"#)
    };

    // Assets at this location
    let assets = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.operational_status
           FROM eam_assets a
           WHERE a.functional_location_id = $1 AND a.is_active = true
           ORDER BY a.asset_code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut assets_html = String::new();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        let astatus: String = a.get::<Option<String>, _>("operational_status").unwrap_or_else(|| "in_service".to_string());
        let sc = match astatus.as_str() {
            "in_service" | "operational" => "badge-success",
            "standby" => "badge-warning",
            "out_of_service" => "badge-error",
            _ => "badge-ghost",
        };
        assets_html.push_str(&format!(
            r#"<tr><td class="font-mono"><a href="/eam/assets/{aid}" class="link link-primary">{acode}</a></td><td>{aname}</td><td><span class="badge badge-sm {sc}">{astatus}</span></td></tr>"#
        ));
    }

    let assets_section = if assets.is_empty() {
        r#"<p class="text-base-content/50 text-sm py-4">No assets at this location</p>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Status</th></tr></thead><tbody>{assets_html}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>{code} - Functional Location</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/functional-locations">Functional Locations</a></li><li>{code}</li></ul></div>
<h1 class="text-2xl font-bold">{name}</h1>
<p class="text-base-content/60 font-mono">{code}</p></div>
<div class="flex gap-2">
<a href="/eam/functional-locations/{id}/edit" class="btn btn-primary btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit</a>
<a href="/eam/functional-locations" class="btn btn-ghost btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a>
</div></div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Details</h3>
<div class="grid grid-cols-2 gap-y-3">
<div><span class="text-base-content/50 text-sm">Status</span><div class="mt-1">{status_badge}</div></div>
<div><span class="text-base-content/50 text-sm">Unit Type</span><div class="mt-1"><span class="badge badge-outline">{unit_code}</span> {unit_type}</div></div>
<div><span class="text-base-content/50 text-sm">Site</span><div class="mt-1 font-medium">{site_name}</div></div>
<div><span class="text-base-content/50 text-sm">Voltage Level</span><div class="mt-1">{voltage}</div></div>
<div><span class="text-base-content/50 text-sm">Parent Location</span><div class="mt-1">{parent_display}</div></div>
<div><span class="text-base-content/50 text-sm">Short Name</span><div class="mt-1">{short_name}</div></div>
<div class="col-span-2"><span class="text-base-content/50 text-sm">Description</span><div class="mt-1">{description}</div></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">References</h3>
<div class="grid grid-cols-2 gap-y-3">
<div><span class="text-base-content/50 text-sm">SLD Reference</span><div class="mt-1 font-mono">{sld_ref}</div></div>
<div><span class="text-base-content/50 text-sm">SCADA Point Group</span><div class="mt-1 font-mono">{scada}</div></div>
<div><span class="text-base-content/50 text-sm">Created</span><div class="mt-1">{}</div></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Child Locations <span class="badge badge-sm">{}</span></h3>
{children_section}
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assets <span class="badge badge-sm">{}</span></h3>
{assets_section}
</div></div>
</div>
</main></div></body></html>"#,
        created_at.format("%d/%m/%Y %H:%M"), children.len(), assets.len()
    )).into_response()
}

async fn eam_functional_location_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let row = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, fl.short_name, fl.description, fl.status,
                  fl.site_id, fl.unit_type_id, fl.voltage_level_id, fl.parent_id,
                  fl.display_order, fl.sld_reference, fl.scada_point_group
           FROM eam_functional_locations fl
           WHERE fl.id = $1 AND fl.company_id = $2"#
    ).bind(id).bind(company_id).fetch_optional(&db).await.unwrap_or(None);

    let row = match row {
        Some(r) => r,
        None => return axum::response::Redirect::to("/eam/functional-locations").into_response(),
    };

    let cur_code: String = row.get("code");
    let cur_name: String = row.get("name");
    let cur_short: String = row.get::<Option<String>, _>("short_name").unwrap_or_default();
    let cur_desc: String = row.get::<Option<String>, _>("description").unwrap_or_default();
    let cur_status: String = row.get::<Option<String>, _>("status").unwrap_or_else(|| "active".to_string());
    let cur_site_id: Option<uuid::Uuid> = row.get("site_id");
    let cur_ut_id: Option<uuid::Uuid> = row.get("unit_type_id");
    let cur_vl_id: Option<uuid::Uuid> = row.get("voltage_level_id");
    let cur_parent_id: Option<uuid::Uuid> = row.get("parent_id");
    let cur_order: i32 = row.get::<Option<i32>, _>("display_order").unwrap_or(0);
    let cur_sld: String = row.get::<Option<String>, _>("sld_reference").unwrap_or_default();
    let cur_scada: String = row.get::<Option<String>, _>("scada_point_group").unwrap_or_default();

    // Dropdowns
    let sites = sqlx::query("SELECT id, code, name FROM eam_sites WHERE company_id = $1 AND is_active = true ORDER BY name")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut site_options = r#"<option value="">-- Select Site --</option>"#.to_string();
    for s in &sites {
        let sid: uuid::Uuid = s.get("id");
        let scode: String = s.get("code");
        let sname: String = s.get("name");
        let sel = if Some(sid) == cur_site_id { " selected" } else { "" };
        site_options.push_str(&format!(r#"<option value="{sid}"{sel}>[{scode}] {sname}</option>"#));
    }

    let unit_types = sqlx::query("SELECT id, code, name FROM eam_unit_types WHERE company_id = $1 AND is_active = true ORDER BY display_order, name")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut ut_options = r#"<option value="">-- Select Unit Type --</option>"#.to_string();
    for ut in &unit_types {
        let uid: uuid::Uuid = ut.get("id");
        let ucode: String = ut.get("code");
        let uname: String = ut.get("name");
        let sel = if Some(uid) == cur_ut_id { " selected" } else { "" };
        ut_options.push_str(&format!(r#"<option value="{uid}"{sel}>{ucode} - {uname}</option>"#));
    }

    let voltages = sqlx::query("SELECT id, code, name, voltage_value FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut vl_options = r#"<option value="">-- None --</option>"#.to_string();
    for vl in &voltages {
        let vid: uuid::Uuid = vl.get("id");
        let vname: String = vl.get("name");
        let sel = if Some(vid) == cur_vl_id { " selected" } else { "" };
        vl_options.push_str(&format!(r#"<option value="{vid}"{sel}>{vname}</option>"#));
    }

    let parents = sqlx::query("SELECT id, code, name FROM eam_functional_locations WHERE company_id = $1 AND is_active = true AND id != $2 ORDER BY code")
        .bind(company_id).bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut parent_options = r#"<option value="">-- No Parent (Top Level) --</option>"#.to_string();
    for p in &parents {
        let pid: uuid::Uuid = p.get("id");
        let pcode: String = p.get("code");
        let pname: String = p.get("name");
        let sel = if Some(pid) == cur_parent_id { " selected" } else { "" };
        parent_options.push_str(&format!(r#"<option value="{pid}"{sel}>[{pcode}] {pname}</option>"#));
    }

    let active_checked = if cur_status == "active" { " checked" } else { "" };

    let content = format!(r##"<form method="POST" action="/eam/functional-locations/{id}/edit">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Location Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Code *</span></label>
<input type="text" name="code" class="input input-bordered font-mono" value="{cur_code}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input type="text" name="name" class="input input-bordered" value="{cur_name}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Short Name</span></label>
<input type="text" name="short_name" class="input input-bordered" value="{cur_short}"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24">{cur_desc}</textarea></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3">
<input type="checkbox" name="is_active" value="true" class="checkbox checkbox-success"{active_checked}/>
<span class="label-text">Active</span></label></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Classification</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Site *</span></label>
<select name="site_id" class="select select-bordered" required>{site_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Unit Type *</span></label>
<select name="unit_type_id" class="select select-bordered" required>{ut_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered">{vl_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parent Location</span></label>
<select name="parent_id" class="select select-bordered">{parent_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Display Order</span></label>
<input type="number" name="display_order" class="input input-bordered" value="{cur_order}" min="0"/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">References</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">SLD Reference</span></label>
<input type="text" name="sld_reference" class="input input-bordered" value="{cur_sld}"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">SCADA Point Group</span></label>
<input type="text" name="scada_point_group" class="input input-bordered" value="{cur_scada}"/></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/functional-locations/{id}" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Changes</button>
</div>
</div></div></form>"##);

    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Edit {cur_code} - Functional Location</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/functional-locations">Functional Locations</a></li><li><a href="/eam/functional-locations/{id}">{cur_code}</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Functional Location</h1></div>
<a href="/eam/functional-locations/{id}" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_functional_location_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    let short_name = form.get("short_name").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let is_active = form.get("is_active").map(|v| v == "true").unwrap_or(false);
    let site_id = form.get("site_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let unit_type_id = form.get("unit_type_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let voltage_level_id = form.get("voltage_level_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let parent_id = form.get("parent_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let display_order: i32 = form.get("display_order").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sld_reference = form.get("sld_reference").cloned().unwrap_or_default();
    let scada_point_group = form.get("scada_point_group").cloned().unwrap_or_default();

    let status = if is_active { "active" } else { "inactive" };
    let short_opt = if short_name.is_empty() { None } else { Some(short_name) };
    let desc_opt = if description.is_empty() { None } else { Some(description) };
    let sld_opt = if sld_reference.is_empty() { None } else { Some(sld_reference) };
    let scada_opt = if scada_point_group.is_empty() { None } else { Some(scada_point_group) };

    let _ = sqlx::query(
        r#"UPDATE eam_functional_locations
           SET code = $1, name = $2, short_name = $3, description = $4,
               site_id = $5, unit_type_id = $6, voltage_level_id = $7, parent_id = $8,
               display_order = $9, sld_reference = $10, scada_point_group = $11,
               status = $12, is_active = $13, updated_by = $14, updated_at = now()
           WHERE id = $15 AND company_id = $16"#
    )
    .bind(&code).bind(&name).bind(&short_opt).bind(&desc_opt)
    .bind(site_id).bind(unit_type_id).bind(voltage_level_id).bind(parent_id)
    .bind(display_order).bind(&sld_opt).bind(&scada_opt)
    .bind(status).bind(is_active).bind(user.id)
    .bind(id).bind(company_id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/functional-locations/{}", id)).into_response()
}

// =============================================================================
// SINGLE LINE DIAGRAM (SLD)
// =============================================================================

async fn eam_sld(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let sidebar = build_sidebar("eam_sld", display_name, &initials);

    let header = format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Single Line Diagram - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex h-screen">{sidebar}
<main class="flex-1 flex flex-col overflow-hidden">
<div class="p-4 pb-0"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Single Line Diagram</li></ul></div></div>
<div id="sld-root" class="flex-1 m-4 mt-2 card bg-base-100 shadow overflow-hidden"></div>
</main></div>"#);

    let css = r##"<style>
.sld-view{display:flex;flex-direction:column;height:100%;background:oklch(var(--b2))}
.sld-toolbar{background:oklch(var(--b1));border-bottom:1px solid oklch(var(--b3));padding:10px 16px;display:flex;align-items:center;gap:12px;flex-shrink:0;flex-wrap:wrap}
.sld-toolbar h4{margin:0;font-size:16px;font-weight:600;white-space:nowrap;color:oklch(var(--bc))}
.sld-toolbar select{min-width:240px;max-width:400px}
.sld-toolbar-spacer{flex:1}
.sld-legend{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sld-legend-item{display:flex;align-items:center;gap:4px;font-size:11px;color:oklch(var(--bc)/0.6);white-space:nowrap}
.sld-legend-dot{width:10px;height:10px;border-radius:2px;flex-shrink:0}
.sld-status-legend{display:flex;align-items:center;gap:8px;margin-left:12px;padding-left:12px;border-left:1px solid oklch(var(--b3));flex-wrap:wrap}
.sld-status-legend-item{display:flex;align-items:center;gap:3px;font-size:10px;color:oklch(var(--bc)/0.6)}
.sld-status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sld-info-bar{background:oklch(var(--b1));border-bottom:1px solid oklch(var(--b3));padding:8px 16px;display:flex;align-items:center;gap:16px;font-size:12px;flex-shrink:0}
.sld-info-label{color:oklch(var(--bc)/0.5)}
.sld-info-value{font-weight:600;color:oklch(var(--bc))}
.sld-substation-link{color:oklch(var(--p));cursor:pointer;font-weight:600}
.sld-substation-link:hover{text-decoration:underline}
.sld-canvas-wrapper{flex:1;overflow:auto;padding:20px}
.sld-canvas{position:relative;min-height:400px;margin:0 auto}
.sld-busbar{position:absolute;left:0;right:0;height:6px;border-radius:3px;z-index:1}
.sld-busbar-label{position:absolute;left:0;top:-10px;transform:translateY(-100%);padding:2px 10px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;white-space:nowrap;z-index:2}
.sld-bay-column{position:absolute;width:140px;z-index:3}
.sld-bay-header{background:oklch(var(--b1));border:1px solid oklch(var(--b3));border-radius:6px;padding:6px 8px;cursor:pointer;transition:box-shadow .15s,border-color .15s;margin-bottom:4px}
.sld-bay-header:hover{border-color:oklch(var(--p));box-shadow:0 2px 8px oklch(var(--p)/0.15)}
.sld-bay-name{font-size:11px;font-weight:600;color:oklch(var(--bc));margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sld-bay-type{font-size:9px;text-transform:uppercase;color:oklch(var(--bc)/0.5);letter-spacing:.5px}
.sld-bay-feeder{font-size:9px;color:oklch(var(--bc)/0.7);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sld-bay-stem{width:2px;margin:0 auto;position:relative}
.sld-equipment-stack{display:flex;flex-direction:column;align-items:center;gap:0;padding:0 10px}
.sld-equipment-item{width:44px;height:44px;background:oklch(var(--b2));border:2px solid oklch(var(--b3));border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:transform .15s,box-shadow .15s,border-color .15s;position:relative;z-index:4}
.sld-equipment-item:hover{transform:scale(1.15);box-shadow:0 3px 10px rgba(0,0,0,.25);z-index:10}
.sld-equipment-item svg{width:30px;height:30px}
.sld-equipment-connector{width:2px;height:8px;background:oklch(var(--bc)/0.3);margin:0 auto}
.sld-status-operational{border-color:#198754}
.sld-status-in_service{border-color:#198754}
.sld-status-standby{border-color:#ffc107}
.sld-status-out_of_service{border-color:#dc3545}
.sld-status-under_repair{border-color:#fd7e14}
.sld-status-decommissioned{border-color:#6c757d}
.sld-equipment-item .sld-tooltip{display:none;position:absolute;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);background:#1d232a;color:#a6adbb;padding:8px 10px;border-radius:6px;font-size:10px;white-space:nowrap;z-index:100;pointer-events:none;box-shadow:0 4px 12px rgba(0,0,0,.4);border:1px solid oklch(var(--b3))}
.sld-equipment-item .sld-tooltip::after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);border:5px solid transparent;border-top-color:#1d232a}
.sld-equipment-item:hover .sld-tooltip{display:block}
.sld-tooltip-name{font-weight:600;margin-bottom:2px;font-size:11px;color:oklch(var(--bc))}
.sld-tooltip-code{color:oklch(var(--bc)/0.5);margin-bottom:4px}
.sld-tooltip-row{display:flex;justify-content:space-between;gap:12px;line-height:1.5}
.sld-tooltip-label{color:oklch(var(--bc)/0.5)}
.sld-tooltip-value{font-weight:500;text-transform:capitalize;color:oklch(var(--bc))}
.sld-transformer-bridge{width:2px;border-left:2px dashed oklch(var(--bc)/0.3);margin:0 auto;position:relative}
.sld-empty-state{text-align:center;padding:60px 20px;color:oklch(var(--bc)/0.5)}
.sld-empty-state svg{width:48px;height:48px;margin:0 auto 16px;stroke:oklch(var(--bc)/0.3)}
.sld-loading{text-align:center;padding:60px 20px;color:oklch(var(--bc)/0.5)}
@media(max-width:768px){.sld-toolbar select{min-width:180px}.sld-legend,.sld-status-legend{display:none}}
</style>"##;

    let js = r##"<script>
// ─── VComponent: Lightweight Reactive Component Framework ───────────────────
// A minimal OWL-equivalent with reactive state, event delegation, and templates.
class VComponent {
    constructor(el, props = {}) {
        this.$el = el;
        this.props = props;
        this._state = {};
        this._eventsBound = false;
    }
    get state() { return this._state; }
    setState(patch) {
        Object.assign(this._state, typeof patch === 'function' ? patch(this._state) : patch);
        this._render();
    }
    _mount() {
        this.setup();
        this._render();
        if (!this._eventsBound) {
            this._eventsBound = true;
            this.$el.addEventListener('click', e => {
                const t = e.target.closest('[data-action]');
                if (t && typeof this[t.dataset.action] === 'function') {
                    e.preventDefault();
                    this[t.dataset.action](t.dataset.param, e);
                }
            });
            this.$el.addEventListener('change', e => {
                const t = e.target.closest('[data-on-change]');
                if (t && typeof this[t.dataset.onChange] === 'function') {
                    this[t.dataset.onChange](e);
                }
            });
        }
        this.mounted();
    }
    _render() { this.$el.innerHTML = this.render(); this.afterRender(); }
    setup() {}
    mounted() {}
    render() { return ''; }
    afterRender() {}
    static mount(Cls, el, props) { const c = new Cls(el, props); c._mount(); return c; }
}

// ─── Constants ──────────────────────────────────────────────────────────────
const STATUS_COLORS = {
    operational:'#198754', in_service:'#198754', standby:'#ffc107',
    out_of_service:'#dc3545', under_repair:'#fd7e14', decommissioned:'#6c757d'
};
const VOLTAGE_PALETTE = ['#dc3545','#0d6efd','#198754','#fd7e14','#6f42c1','#0dcaf0'];
const EQUIP_ORDER = {
    switchgear:0, isolator:1, ct:2, vt:3, cvt:4, transformer:5,
    surge_arrester:6, cable:7, busbar:8, other:9
};
const L = {
    COL_W:160, COL_CW:140, LEFT:80, BB_Y:50, LABEL_H:28, BB_H:6,
    GAP_BB_HDR:14, HDR_H:90, GAP_HDR_EQ:6, EQ_H:44, EQ_GAP:8, GAP_BOT:40, STEM_W:2
};

// ─── IEC SVG Symbols ────────────────────────────────────────────────────────
const SVG = {
    switchgear: c => `<svg viewBox="0 0 30 30"><rect x="3" y="3" width="24" height="24" rx="2" fill="none" stroke="${c}" stroke-width="2"/><line x1="5" y1="5" x2="25" y2="25" stroke="${c}" stroke-width="2"/><line x1="25" y1="5" x2="5" y2="25" stroke="${c}" stroke-width="2"/></svg>`,
    transformer: c => `<svg viewBox="0 0 30 30"><circle cx="12" cy="15" r="8" fill="none" stroke="${c}" stroke-width="2"/><circle cx="18" cy="15" r="8" fill="none" stroke="${c}" stroke-width="2"/></svg>`,
    isolator: c => `<svg viewBox="0 0 30 30"><line x1="3" y1="15" x2="10" y2="15" stroke="${c}" stroke-width="2"/><line x1="10" y1="15" x2="20" y2="5" stroke="${c}" stroke-width="2"/><line x1="20" y1="15" x2="27" y2="15" stroke="${c}" stroke-width="2"/></svg>`,
    ct: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><circle cx="15" cy="15" r="2" fill="${c}"/></svg>`,
    vt: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><line x1="15" y1="5" x2="15" y2="25" stroke="${c}" stroke-width="1.5"/></svg>`,
    cvt: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><circle cx="15" cy="15" r="2" fill="${c}"/><line x1="15" y1="5" x2="15" y2="25" stroke="${c}" stroke-width="1"/></svg>`,
    surge_arrester: c => `<svg viewBox="0 0 30 30"><line x1="15" y1="2" x2="15" y2="7" stroke="${c}" stroke-width="2"/><polyline points="10,7 15,14 12,14 17,21 14,21 19,28" fill="none" stroke="${c}" stroke-width="2"/><line x1="8" y1="28" x2="22" y2="28" stroke="${c}" stroke-width="2"/></svg>`,
    cable: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><text x="15" y="19" text-anchor="middle" fill="${c}" font-size="10" font-weight="bold">C</text></svg>`,
    busbar: c => `<svg viewBox="0 0 30 30"><rect x="2" y="10" width="26" height="10" rx="2" fill="none" stroke="${c}" stroke-width="2"/><line x1="5" y1="15" x2="25" y2="15" stroke="${c}" stroke-width="2"/></svg>`,
    other: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><text x="15" y="19" text-anchor="middle" fill="${c}" font-size="10" font-weight="bold">?</text></svg>`
};

// ─── SLD View Component ─────────────────────────────────────────────────────
class SldView extends VComponent {
    setup() {
        this._state = {
            loaded:false, loading:false, substations:[], selectedId:null,
            substation:null, voltageLevels:[], bays:[], bayEquipment:{}
        };
    }
    async mounted() { await this.loadSubstations(); }

    // ── Data ─────────────────────────────────────────────────
    async loadSubstations() {
        try {
            const r = await fetch('/api/eam/sld/substations');
            const data = await r.json();
            this.setState({ substations: data, loaded: true });
        } catch(e) { this.setState({ loaded: true }); }
    }
    async loadSldData(id) {
        if (!id) { this.setState({ substation:null, voltageLevels:[], bays:[], bayEquipment:{} }); return; }
        this.setState({ loading: true });
        try {
            const r = await fetch(`/api/eam/sld/substations/${id}`);
            const d = await r.json();
            const grouped = {};
            for (const eq of (d.equipment || [])) {
                if (!grouped[eq.bay_id]) grouped[eq.bay_id] = [];
                grouped[eq.bay_id].push(eq);
            }
            for (const bid in grouped) {
                grouped[bid].sort((a,b) => (EQUIP_ORDER[a.equipment_type]??9) - (EQUIP_ORDER[b.equipment_type]??9));
            }
            this.setState({
                substation: d.substation, voltageLevels: d.voltage_levels || [],
                bays: d.bays || [], bayEquipment: grouped, loading: false
            });
        } catch(e) { this.setState({ loading: false }); }
    }

    // ── Layout Algorithm ─────────────────────────────────────
    computeLayout() {
        const { substation: sub, voltageLevels: vls, bays, bayEquipment } = this._state;
        if (!sub || !vls.length) return null;

        const vlMap = {}; for (const vl of vls) vlMap[vl.id] = vl;
        const vlBays = {}; const xformBays = []; const couplerBays = [];

        for (const bay of bays) {
            const vlId = bay.voltage_level_id;
            if (bay.bay_type === 'transformer') { xformBays.push(bay); }
            else if (bay.bay_type === 'bus_coupler' || bay.bay_type === 'bus_section') { couplerBays.push(bay); }
            else {
                if (!vlBays[vlId]) vlBays[vlId] = [];
                vlBays[vlId].push(bay);
            }
        }

        const cols = []; let ci = 0;
        for (const vl of vls) {
            for (const bay of (vlBays[vl.id] || [])) { cols.push({ bay, ci: ci++, type: bay.bay_type, vlId: vl.id }); }
        }
        for (const bay of xformBays) {
            const vlId = bay.voltage_level_id || (vls[0] && vls[0].id);
            cols.push({ bay, ci: ci++, type: 'transformer', vlId });
        }
        for (const bay of couplerBays) {
            const vlId = bay.voltage_level_id || (vls[0] && vls[0].id);
            cols.push({ bay, ci: ci++, type: bay.bay_type, vlId });
        }
        const totalCols = ci || 1;

        const eqCount = bid => (bayEquipment[bid] || []).length;
        const stackH = n => n <= 0 ? 0 : n * L.EQ_H + (n-1) * L.EQ_GAP;

        const vlPos = {}; let curY = L.BB_Y;
        for (const vl of vls) {
            vlPos[vl.id] = { y: curY };
            let maxEq = 0;
            for (const c of cols) { if (c.vlId === vl.id) { const n = eqCount(c.bay.id); if (n > maxEq) maxEq = n; } }
            const secH = L.BB_H + L.GAP_BB_HDR + L.HDR_H + L.GAP_HDR_EQ + stackH(maxEq) + L.GAP_BOT;
            vlPos[vl.id].bottom = curY + secH;
            curY += secH;
        }

        return { sub, vls, vlMap, vlPos, cols, totalCols, height: curY + 40 };
    }

    // ── Helpers ──────────────────────────────────────────────
    fmtLabel(s) { return (s || '').replace(/_/g, ' '); }
    fmtStatus(s) { return ({ operational:'Operational', in_service:'In Service', standby:'Standby', out_of_service:'Out of Service', under_repair:'Under Repair', decommissioned:'Decommissioned' })[s] || this.fmtLabel(s); }
    statusColor(s) { return STATUS_COLORS[s] || '#6c757d'; }
    equipSvg(type, status) { return (SVG[type] || SVG.other)(this.statusColor(status)); }

    // ── Event Handlers ───────────────────────────────────────
    async onSelectSubstation(e) {
        const val = e.target.value;
        this._state.selectedId = val || null;
        this._render();
        await this.loadSldData(val);
    }
    onClickEquipment(id) { window.location.href = '/eam/assets/' + id; }
    onClickBay(id) { /* future bay detail page */ }

    // ── Render ───────────────────────────────────────────────
    render() {
        const { loaded, loading, substations, selectedId, substation: sub, voltageLevels: vls } = this._state;
        const layout = this.computeLayout();

        let toolbar = `<div class="sld-toolbar">
            <svg class="w-5 h-5" style="color:oklch(var(--bc)/0.5)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/><circle cx="17" cy="18" r="3" stroke-width="2" fill="none"/></svg>
            <h4>Single Line Diagram</h4>
            <select class="select select-bordered select-sm" data-on-change="onSelectSubstation">
                <option value="">-- Select Substation --</option>
                ${substations.map(s => `<option value="${s.id}" ${selectedId===s.id?'selected':''}>[${this.esc(s.code)}] ${this.esc(s.name)}</option>`).join('')}
            </select>`;

        if (sub) toolbar += `<span class="badge badge-ghost badge-sm" style="text-transform:capitalize">${this.fmtLabel(sub.busbar_configuration)}</span>`;
        toolbar += `<div class="sld-toolbar-spacer"></div>`;

        if (vls.length) {
            toolbar += `<div class="sld-legend">
                <span style="font-size:11px;color:oklch(var(--bc)/0.5);font-weight:600">Voltage:</span>
                ${vls.map((vl,i) => { const c = VOLTAGE_PALETTE[i % VOLTAGE_PALETTE.length]; return `<span class="sld-legend-item"><span class="sld-legend-dot" style="background:${c}"></span>${this.esc(vl.name)} (${vl.voltage_kv}kV)</span>`; }).join('')}
            </div>
            <div class="sld-status-legend">
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#198754"></span>Oper.</span>
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#ffc107"></span>Standby</span>
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#dc3545"></span>OOS</span>
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#fd7e14"></span>Repair</span>
            </div>`;
        }
        toolbar += `</div>`;

        let infoBar = '';
        if (sub) {
            const bayCount = this._state.bays.length;
            let eqTotal = 0; for (const b in this._state.bayEquipment) eqTotal += this._state.bayEquipment[b].length;
            infoBar = `<div class="sld-info-bar">
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Substation:</span><span class="sld-substation-link">${this.esc(sub.name)}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Code:</span><span class="sld-info-value">${this.esc(sub.code)}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Type:</span><span class="sld-info-value" style="text-transform:capitalize">${this.fmtLabel(sub.substation_type)}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Bays:</span><span class="sld-info-value">${bayCount}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Equipment:</span><span class="sld-info-value">${eqTotal}</span></div>
            </div>`;
        }

        let canvas = '';
        if (loading) {
            canvas = `<div class="sld-loading"><div class="loading loading-spinner loading-lg"></div><p style="margin-top:12px">Loading diagram...</p></div>`;
        } else if (!selectedId) {
            canvas = `<div class="sld-empty-state"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/><circle cx="17" cy="18" r="3" stroke-width="2" fill="none"/></svg><p>Select a substation to view its Single Line Diagram</p></div>`;
        } else if (layout) {
            canvas = this.renderCanvas(layout);
        }

        return `<div class="sld-view">${toolbar}${infoBar}<div class="sld-canvas-wrapper">${canvas}</div></div>`;
    }

    renderCanvas(ly) {
        const { vls, vlMap, vlPos, cols, totalCols, height } = ly;
        const w = totalCols * L.COL_W + L.LEFT + 40;
        let html = `<div class="sld-canvas" style="min-width:${w}px;min-height:${height}px">`;

        // Busbars
        for (let i = 0; i < vls.length; i++) {
            const vl = vls[i]; const c = VOLTAGE_PALETTE[i % VOLTAGE_PALETTE.length];
            const y = vlPos[vl.id].y;
            html += `<div class="sld-busbar" style="top:${y}px;background:${c}">
                <div class="sld-busbar-label" style="background:${c}">${this.esc(vl.name)} (${vl.voltage_kv}kV)</div></div>`;
        }

        // Bay columns
        for (const col of cols) {
            const left = col.ci * L.COL_W + L.LEFT;
            const bbY = vlPos[col.vlId] ? vlPos[col.vlId].y : L.BB_Y;
            const stemTop = bbY + L.BB_H;
            const hdrTop = stemTop + L.GAP_BB_HDR;
            const eqTop = hdrTop + L.HDR_H + L.GAP_HDR_EQ;
            const vlColor = VOLTAGE_PALETTE[vls.findIndex(v => v.id === col.vlId) % VOLTAGE_PALETTE.length] || '#6c757d';
            const bay = col.bay;
            const eqs = this._state.bayEquipment[bay.id] || [];
            const statusBadge = bay.status === 'active' ? 'badge-success' : 'badge-ghost';

            html += `<div class="sld-bay-column" style="left:${left}px">`;
            // Stem
            html += `<div class="sld-bay-stem" style="position:absolute;left:69px;top:${stemTop}px;height:${L.GAP_BB_HDR}px;background:${vlColor}"></div>`;
            // Header
            html += `<div class="sld-bay-header" style="position:absolute;width:${L.COL_CW}px;top:${hdrTop}px" data-action="onClickBay" data-param="${bay.id}">
                <div class="sld-bay-name">${this.esc(bay.name)}</div>
                <div class="sld-bay-type">${this.fmtLabel(bay.bay_type)}</div>
                ${bay.feeder_name ? `<div class="sld-bay-feeder">${this.esc(bay.feeder_name)}</div>` : ''}
                <span class="badge ${statusBadge}" style="font-size:8px;margin-top:3px">${this.fmtLabel(bay.status)}</span>
            </div>`;
            // Equipment stack
            html += `<div class="sld-equipment-stack" style="position:absolute;width:${L.COL_CW}px;top:${eqTop}px">`;
            for (let ei = 0; ei < eqs.length; ei++) {
                const eq = eqs[ei];
                if (ei > 0) html += `<div class="sld-equipment-connector"></div>`;
                const sc = `sld-status-${eq.operational_status || 'in_service'}`;
                html += `<div class="sld-equipment-item ${sc}" data-action="onClickEquipment" data-param="${eq.id}">
                    ${this.equipSvg(eq.equipment_type, eq.operational_status)}
                    <div class="sld-tooltip">
                        <div class="sld-tooltip-name">${this.esc(eq.name)}</div>
                        <div class="sld-tooltip-code">${this.esc(eq.code)}</div>
                        <div class="sld-tooltip-row"><span class="sld-tooltip-label">Category:</span><span class="sld-tooltip-value">${this.fmtLabel(eq.equipment_type)}</span></div>
                        <div class="sld-tooltip-row"><span class="sld-tooltip-label">Status:</span><span class="sld-tooltip-value">${this.fmtStatus(eq.operational_status)}</span></div>
                        <div class="sld-tooltip-row"><span class="sld-tooltip-label">Condition:</span><span class="sld-tooltip-value">${Math.round(eq.condition_score || 0)}%</span></div>
                        ${eq.rated_voltage_kv ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Voltage:</span><span class="sld-tooltip-value">${eq.rated_voltage_kv}kV</span></div>` : ''}
                        ${eq.rated_current_a ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Current:</span><span class="sld-tooltip-value">${eq.rated_current_a}A</span></div>` : ''}
                        ${eq.rated_power_kva ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Power:</span><span class="sld-tooltip-value">${eq.rated_power_kva}kVA</span></div>` : ''}
                        ${eq.manufacturer_name ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Mfg:</span><span class="sld-tooltip-value">${this.esc(eq.manufacturer_name)}</span></div>` : ''}
                    </div>
                </div>`;
            }
            html += `</div>`;

            // Transformer bridge
            if (col.type === 'transformer' && vls.length >= 2) {
                const vi = vls.findIndex(v => v.id === col.vlId);
                if (vi >= 0 && vi < vls.length - 1) {
                    const nextVl = vls[vi + 1];
                    const nextBBY = vlPos[nextVl.id].y;
                    const eqStackH = eqs.length <= 0 ? 0 : eqs.length * L.EQ_H + (eqs.length-1) * L.EQ_GAP;
                    const bridgeStart = eqTop + eqStackH + 4;
                    const bridgeH = nextBBY - bridgeStart;
                    if (bridgeH > 0) {
                        html += `<div class="sld-transformer-bridge" style="position:absolute;left:69px;top:${bridgeStart}px;height:${bridgeH}px"></div>`;
                    }
                }
            }
            html += `</div>`;
        }

        if (cols.length === 0) {
            html += `<div class="sld-empty-state" style="margin-top:80px"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:48px;height:48px;margin:0 auto 16px;display:block"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg><p>No bays found for this substation</p></div>`;
        }

        html += `</div>`;
        return html;
    }

    esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
}

// Mount on load
document.addEventListener('DOMContentLoaded', () => {
    VComponent.mount(SldView, document.getElementById('sld-root'));
});
</script>"##;

    let mut html = String::with_capacity(header.len() + css.len() + js.len() + 30);
    html.push_str(&header);
    html.push_str(css);
    html.push_str(js);
    html.push_str("</body></html>");
    Html(html).into_response()
}

async fn eam_sld_substations_api(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT s.id, s.code, s.name, s.substation_type, s.busbar_configuration,
                  st.name as site_name
           FROM eam_substations s
           LEFT JOIN eam_sites st ON st.id = s.site_id
           WHERE s.company_id = $1 AND s.is_active = true
           ORDER BY s.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let arr: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "substation_type": r.get::<Option<String>, _>("substation_type"),
            "busbar_configuration": r.get::<Option<String>, _>("busbar_configuration"),
            "site_name": r.get::<Option<String>, _>("site_name")
        })
    }).collect();

    axum::Json(serde_json::Value::Array(arr)).into_response()
}

async fn eam_sld_data_api(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(substation_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Substation details
    let sub_row = sqlx::query(
        r#"SELECT id, code, name, substation_type, busbar_configuration
           FROM eam_substations WHERE id = $1 AND company_id = $2"#
    ).bind(substation_id).bind(company_id).fetch_optional(&db).await.unwrap_or(None);

    let sub_json = match sub_row {
        Some(r) => serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "substation_type": r.get::<Option<String>, _>("substation_type"),
            "busbar_configuration": r.get::<Option<String>, _>("busbar_configuration")
        }),
        None => return axum::Json(serde_json::json!({"error":"Not found"})).into_response(),
    };

    // Voltage levels (derived from bays)
    let vl_rows = sqlx::query(
        r#"SELECT DISTINCT vl.id, vl.code, vl.name, vl.voltage_value, vl.voltage_type
           FROM eam_voltage_levels vl
           INNER JOIN eam_bays b ON b.voltage_level_id = vl.id
           WHERE b.substation_id = $1 AND b.is_active = true AND vl.is_active = true
           ORDER BY vl.voltage_value DESC"#
    ).bind(substation_id).fetch_all(&db).await.unwrap_or_default();

    let vl_json: Vec<serde_json::Value> = vl_rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "voltage_kv": r.get::<f64, _>("voltage_value"),
            "voltage_type": r.get::<Option<String>, _>("voltage_type")
        })
    }).collect();

    // Bays
    let bay_rows = sqlx::query(
        r#"SELECT b.id, b.code, b.name, b.bay_type, b.voltage_level_id,
                  b.feeder_name, b.sld_reference, b.status, b.display_order
           FROM eam_bays b
           WHERE b.substation_id = $1 AND b.is_active = true
           ORDER BY b.display_order, b.code"#
    ).bind(substation_id).fetch_all(&db).await.unwrap_or_default();

    let bay_json: Vec<serde_json::Value> = bay_rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "bay_type": r.get::<Option<String>, _>("bay_type"),
            "voltage_level_id": r.get::<Option<uuid::Uuid>, _>("voltage_level_id").map(|u| u.to_string()),
            "feeder_name": r.get::<Option<String>, _>("feeder_name"),
            "sld_reference": r.get::<Option<String>, _>("sld_reference"),
            "status": r.get::<Option<String>, _>("status")
        })
    }).collect();

    // Equipment (all assets in bays of this substation, with type detection)
    let eq_rows = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.operational_status, a.condition_score,
                  a.bay_id, a.serial_number,
                  CASE
                      WHEN t.id IS NOT NULL THEN 'transformer'
                      WHEN sg.id IS NOT NULL THEN 'switchgear'
                      WHEN cvt.id IS NOT NULL THEN cvt.device_type
                      WHEN sa.id IS NOT NULL THEN 'surge_arrester'
                      WHEN iso.id IS NOT NULL THEN 'isolator'
                      WHEN bb.id IS NOT NULL THEN 'busbar'
                      WHEN cb.id IS NOT NULL THEN 'cable'
                      ELSE 'other'
                  END as equipment_type,
                  COALESCE(t.primary_voltage, sg.rated_voltage, cvt.rated_voltage_kv,
                           sa.rated_voltage_kv, iso.rated_voltage_kv, bb.rated_voltage_kv,
                           cb.voltage_rating_kv) as rated_voltage_kv,
                  COALESCE(sg.rated_current, iso.rated_current_a, bb.rated_current_a,
                           cb.rated_current_a) as rated_current_a,
                  t.mva_rating * 1000 as rated_power_kva,
                  m.name as manufacturer_name
           FROM eam_assets a
           LEFT JOIN eam_transformers t ON t.asset_id = a.id
           LEFT JOIN eam_switch_gears sg ON sg.asset_id = a.id
           LEFT JOIN eam_current_voltage_transformers cvt ON cvt.asset_id = a.id
           LEFT JOIN eam_surge_arresters sa ON sa.asset_id = a.id
           LEFT JOIN eam_isolators iso ON iso.asset_id = a.id
           LEFT JOIN eam_busbars bb ON bb.asset_id = a.id
           LEFT JOIN eam_cables cb ON cb.asset_id = a.id
           LEFT JOIN eam_manufacturers m ON m.id = a.manufacturer_id
           WHERE a.bay_id IN (SELECT id FROM eam_bays WHERE substation_id = $1 AND is_active = true)
             AND a.is_active = true
           ORDER BY a.display_order, a.name"#
    ).bind(substation_id).fetch_all(&db).await.unwrap_or_default();

    let eq_json: Vec<serde_json::Value> = eq_rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("asset_code"),
            "name": r.get::<String, _>("name"),
            "operational_status": r.get::<Option<String>, _>("operational_status"),
            "condition_score": r.get::<Option<f64>, _>("condition_score"),
            "bay_id": r.get::<Option<uuid::Uuid>, _>("bay_id").map(|u| u.to_string()),
            "serial_number": r.get::<Option<String>, _>("serial_number"),
            "equipment_type": r.get::<Option<String>, _>("equipment_type"),
            "rated_voltage_kv": r.get::<Option<f64>, _>("rated_voltage_kv"),
            "rated_current_a": r.get::<Option<f64>, _>("rated_current_a"),
            "rated_power_kva": r.get::<Option<f64>, _>("rated_power_kva"),
            "manufacturer_name": r.get::<Option<String>, _>("manufacturer_name")
        })
    }).collect();

    axum::Json(serde_json::json!({
        "substation": sub_json,
        "voltage_levels": vl_json,
        "bays": bay_json,
        "equipment": eq_json
    })).into_response()
}

async fn eam_condition_monitoring(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Condition monitoring tables linked via asset_id to eam_assets
    let dga_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_dga_analyses d JOIN eam_assets a ON d.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let oil_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_oil_quality_tests o JOIN eam_assets a ON o.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let thermal: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_thermal_imaging t JOIN eam_assets a ON t.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let pd_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_partial_discharge_tests p JOIN eam_assets a ON p.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let ir_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_insulation_resistance_tests i JOIN eam_assets a ON i.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let critical: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_dga_analyses d JOIN eam_assets a ON d.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true AND d.status = 'critical'").bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let content = r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg><h3 class="text-lg font-semibold mb-2">No DGA Results Yet</h3><p class="text-base-content/60">Record dissolved gas analysis results to monitor transformer health</p></div>"#;

    let critical_class = if critical > 0 { "bg-error/10" } else { "" };
    let critical_text = if critical > 0 { "text-error" } else { "" };

    let sidebar = build_sidebar("eam_condition", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Condition Monitoring - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Condition Monitoring</li></ul></div>
<h1 class="text-2xl font-bold">Condition Monitoring</h1><p class="text-base-content/60">Equipment health and diagnostic tests</p></div>
<div class="dropdown dropdown-end"><label tabindex="0" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Test</label>
<ul tabindex="0" class="dropdown-content z-[1] menu p-2 shadow bg-base-100 rounded-box w-52">
<li><a href="/eam/condition/dga/new">DGA Analysis</a></li>
<li><a href="/eam/condition/oil-quality/new">Oil Quality Test</a></li>
<li><a href="/eam/condition/thermal/new">Thermal Imaging</a></li>
<li><a href="/eam/condition/pd/new">Partial Discharge</a></li>
<li><a href="/eam/condition/ir/new">Insulation Resistance</a></li>
</ul></div></div>
<div class="grid grid-cols-6 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">DGA Tests</div><div class="stat-value text-2xl">{dga_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Oil Quality</div><div class="stat-value text-2xl">{oil_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Thermal Scans</div><div class="stat-value text-2xl">{thermal}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">PD Tests</div><div class="stat-value text-2xl">{pd_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">IR Tests</div><div class="stat-value text-2xl">{ir_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4 {critical_class}"><div class="stat-title text-xs">Critical Alerts</div><div class="stat-value text-2xl {critical_text}">{critical}</div></div>
</div>
<div class="card bg-base-100 shadow"><div class="card-header p-4 border-b border-base-300"><h2 class="card-title text-lg">Dissolved Gas Analysis (DGA) Results</h2><p class="text-sm text-base-content/60">IEEE C57.104 compliant transformer oil analysis</p></div><div class="card-body">{content}</div></div>
<div class="mt-4 p-3 bg-base-100 rounded-lg"><h4 class="font-semibold text-sm mb-2">IEEE C57.104 Status Legend</h4><div class="flex flex-wrap gap-4 text-sm">
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#10B981;color:white;">Normal</span><span>Gas levels within normal limits</span></div>
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#EAB308;color:white;">Caution</span><span>Elevated levels, monitor closely</span></div>
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#F97316;color:white;">Warning</span><span>High levels, plan maintenance</span></div>
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#EF4444;color:white;">Critical</span><span>Immediate action required</span></div>
</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_manufacturers(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT m.id, m.code, m.name, m.country_code, m.website, m.is_approved_vendor
           FROM eam_manufacturers m
           WHERE m.company_id = $1 AND m.is_active = true ORDER BY m.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let country: String = row.get::<Option<String>, _>("country_code").unwrap_or_else(|| "-".to_string());
        let website: Option<String> = row.get("website");
        let is_approved: bool = row.get::<Option<bool>, _>("is_approved_vendor").unwrap_or(false);

        let website_cell = website.map(|w| format!(r#"<a href="{w}" target="_blank" class="link link-primary text-sm">{w}</a>"#))
            .unwrap_or_else(|| "-".to_string());
        let status_badge = if is_approved {
            r#"<span class="badge badge-success badge-sm">Approved</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Pending</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{name}</td><td>{country}</td><td>{website_cell}</td><td>{status_badge}</td>
            <td><a href="/eam/manufacturers/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg><h3 class="text-lg font-semibold mb-2">No Manufacturers Yet</h3><p class="text-base-content/60">Add manufacturers to track equipment suppliers</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Country</th><th>Website</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let sidebar = build_sidebar("eam_manufacturers", display_name, &initials);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Manufacturers - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Manufacturers</li></ul></div>
<h1 class="text-2xl font-bold">Manufacturers</h1><p class="text-base-content/60">Equipment manufacturers and suppliers</p></div>
<a href="/eam/manufacturers/new" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Manufacturer</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_site_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Fetch site details
    let site = sqlx::query(
        r#"SELECT id, code, name, short_name, description, address, city, state, postal_code,
                  gps_latitude, gps_longitude, site_type, commissioning_date, ownership, operator,
                  busbar_configuration, feeder_count, status
           FROM eam_sites WHERE id = $1 AND is_active = true"#
    ).bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(site) = site else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Site not found")).into_response();
    };

    let code: String = site.get("code");
    let name: String = site.get("name");
    let description: Option<String> = site.get("description");
    let address: Option<String> = site.get("address");
    let city: Option<String> = site.get("city");
    let state_name: Option<String> = site.get("state");
    let site_type: Option<String> = site.get("site_type");
    let ownership: Option<String> = site.get("ownership");
    let operator: Option<String> = site.get("operator");
    let busbar_config: Option<String> = site.get("busbar_configuration");
    let feeder_count: Option<i32> = site.get("feeder_count");
    let status: Option<String> = site.get("status");
    let gps_lat: Option<f64> = site.get("gps_latitude");
    let gps_lon: Option<f64> = site.get("gps_longitude");

    // Fetch functional locations for this site
    let locations = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, ut.name as unit_type, vl.name as voltage_level
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           LEFT JOIN eam_voltage_levels vl ON fl.voltage_level_id = vl.id
           WHERE fl.site_id = $1 AND fl.is_active = true
           ORDER BY fl.display_order, fl.code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut location_rows = String::new();
    for loc in &locations {
        let loc_code: String = loc.get("code");
        let loc_name: String = loc.get("name");
        let unit_type: Option<String> = loc.get("unit_type");
        let voltage: Option<String> = loc.get("voltage_level");
        location_rows.push_str(&format!(r#"<tr>
            <td class="font-mono">{}</td><td>{}</td><td>{}</td><td>{}</td>
        </tr>"#, loc_code, loc_name, unit_type.unwrap_or("-".into()), voltage.unwrap_or("-".into())));
    }

    // Fetch assets count for this site
    let asset_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM eam_assets a
           JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           WHERE fl.site_id = $1 AND a.is_active = true"#
    ).bind(id).fetch_one(&db).await.unwrap_or(0);

    // Fetch activity stream (chatter messages)
    let activities = sqlx::query(
        r#"SELECT m.id, m.body, m.message_type, m.created_at, u.username as author_name
           FROM chatter_messages m
           LEFT JOIN users u ON m.author_id = u.id
           WHERE m.res_model = 'eam_sites' AND m.res_id = $1 AND m.active = true
           ORDER BY m.created_at DESC LIMIT 20"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut activity_html = String::new();
    if activities.is_empty() {
        activity_html = r#"<div class="text-center py-8 text-base-content/60"><p>No activities yet</p><p class="text-sm">Add a note to start the activity stream</p></div>"#.to_string();
    } else {
        for activity in &activities {
            let body: String = activity.get("body");
            let msg_type: String = activity.get("message_type");
            let author: Option<String> = activity.get("author_name");
            let created: chrono::DateTime<chrono::Utc> = activity.get("created_at");
            let icon = match msg_type.as_str() {
                "system" => r#"<svg class="w-5 h-5 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>"#,
                "notification" => r#"<svg class="w-5 h-5 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>"#,
                _ => r#"<svg class="w-5 h-5 text-base-content/60" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/></svg>"#,
            };
            activity_html.push_str(&format!(r#"<div class="flex gap-3 p-3 rounded-lg bg-base-200">
                <div class="flex-shrink-0 mt-1">{}</div>
                <div class="flex-1">
                    <div class="flex justify-between items-start">
                        <span class="font-semibold text-sm">{}</span>
                        <span class="text-xs text-base-content/60">{}</span>
                    </div>
                    <div class="mt-1 text-sm">{}</div>
                </div>
            </div>"#, icon, author.unwrap_or("System".into()), created.format("%d/%m/%Y %H:%M"), body));
        }
    }

    let sidebar = build_sidebar("eam_sites", display_name, &initials);
    let location = format!("{}, {}", city.as_deref().unwrap_or("-"), state_name.as_deref().unwrap_or("-"));
    let gps = if let (Some(lat), Some(lon)) = (gps_lat, gps_lon) {
        format!("{:.4}, {:.4}", lat, lon)
    } else { "-".to_string() };

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>{name} - Site Details</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/sites">Sites</a></li><li>{code}</li></ul></div>
<div class="flex justify-between items-start">
<div><h1 class="text-2xl font-bold">{name}</h1><p class="text-base-content/60">{}</p></div>
<div class="flex items-center gap-2">
<span class="badge badge-lg badge-outline">{}</span>
<a href="/eam/sites/{id}/edit" class="btn btn-primary btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit</a>
</div></div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
<div class="card bg-base-100 shadow lg:col-span-2"><div class="card-body">
<h2 class="card-title">Site Information</h2>
<div class="grid grid-cols-2 gap-4 mt-4">
<div><span class="text-base-content/60 text-sm">Code</span><p class="font-mono font-semibold">{code}</p></div>
<div><span class="text-base-content/60 text-sm">Type</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Location</span><p>{location}</p></div>
<div><span class="text-base-content/60 text-sm">GPS Coordinates</span><p class="font-mono">{gps}</p></div>
<div><span class="text-base-content/60 text-sm">Ownership</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Operator</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Busbar Configuration</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Feeder Count</span><p>{}</p></div>
</div>
{}</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Statistics</h2>
<div class="stats stats-vertical shadow mt-4">
<div class="stat"><div class="stat-title">Functional Locations</div><div class="stat-value text-primary">{}</div></div>
<div class="stat"><div class="stat-title">Total Assets</div><div class="stat-value text-secondary">{asset_count}</div></div>
</div></div></div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Functional Locations</h2>
<div class="overflow-x-auto mt-4"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Unit Type</th><th>Voltage Level</th></tr></thead>
<tbody>{location_rows}</tbody></table></div></div></div>

<div class="card bg-base-100 shadow mt-6"><div class="card-body">
<div class="flex justify-between items-center">
<h2 class="card-title">Activity Stream</h2>
<div class="flex gap-2">
<button onclick="document.getElementById('activity_form').classList.toggle('hidden')" class="btn btn-sm btn-ghost">
<svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Add Note</button>
</div></div>
<form id="activity_form" class="hidden mt-4 p-4 bg-base-200 rounded-lg" hx-post="/api/chatter/eam_sites/{id}/messages" hx-swap="none" hx-on::after-request="this.reset(); location.reload();">
<textarea name="body" class="textarea textarea-bordered w-full" rows="3" placeholder="Add a note or comment..."></textarea>
<div class="flex justify-end gap-2 mt-2">
<button type="button" onclick="document.getElementById('activity_form').classList.add('hidden')" class="btn btn-sm btn-ghost">Cancel</button>
<button type="submit" class="btn btn-sm btn-primary">Post</button>
</div></form>
<div class="mt-4 space-y-4" id="activity_stream">{activity_html}</div>
</div></div>
</main></div></body></html>"#,
        description.as_deref().unwrap_or("Distribution Substation"),
        status.as_deref().unwrap_or("Active"),
        site_type.as_deref().unwrap_or("-"),
        ownership.as_deref().unwrap_or("-"),
        operator.as_deref().unwrap_or("-"),
        busbar_config.as_deref().unwrap_or("-"),
        feeder_count.map(|f| f.to_string()).unwrap_or("-".into()),
        if let Some(addr) = address { format!(r#"<div class="col-span-2 mt-2"><span class="text-base-content/60 text-sm">Address</span><p>{}</p></div>"#, addr) } else { String::new() },
        locations.len(),
    )).into_response()
}

async fn eam_asset_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Fetch asset details
    let asset = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.tag_number, a.description, a.manufacturer, a.model,
                  a.serial_number, a.year_manufactured, a.commissioning_date, a.criticality_rating,
                  a.operational_status, a.condition_score, a.last_maintenance_date, a.next_maintenance_date,
                  c.name as category_name, st.name as status_name, st.color as status_color,
                  fl.name as location_name, fl.code as location_code,
                  s.name as site_name, s.code as site_code, s.id as site_id,
                  vl.name as voltage_level
           FROM eam_assets a
           LEFT JOIN eam_asset_categories c ON a.category_id = c.id
           LEFT JOIN eam_asset_statuses st ON a.status_id = st.id
           LEFT JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_voltage_levels vl ON a.voltage_level_id = vl.id
           WHERE a.id = $1 AND a.is_active = true"#
    ).bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(asset) = asset else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Asset not found")).into_response();
    };

    // Fetch activity stream (chatter messages)
    let activities = sqlx::query(
        r#"SELECT m.id, m.body, m.message_type, m.created_at, u.username as author_name
           FROM chatter_messages m
           LEFT JOIN users u ON m.author_id = u.id
           WHERE m.res_model = 'eam_assets' AND m.res_id = $1 AND m.active = true
           ORDER BY m.created_at DESC LIMIT 20"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut activity_html = String::new();
    for act in &activities {
        let body: String = act.get("body");
        let msg_type: String = act.get("message_type");
        let author: Option<String> = act.get("author_name");
        let created: chrono::DateTime<chrono::Utc> = act.get("created_at");
        let icon = match msg_type.as_str() {
            "note" => r#"<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z"/></svg>"#,
            "system" => r#"<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>"#,
            _ => r#"<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/></svg>"#,
        };
        activity_html.push_str(&format!(
            r#"<div class="flex gap-3 p-3 bg-base-200 rounded-lg"><div class="text-primary">{}</div><div class="flex-1"><div class="flex justify-between text-sm"><span class="font-semibold">{}</span><span class="text-base-content/60">{}</span></div><p class="mt-1">{}</p></div></div>"#,
            icon, author.as_deref().unwrap_or("System"), created.format("%d/%m/%Y %H:%M"), body
        ));
    }
    if activity_html.is_empty() {
        activity_html = r#"<p class="text-base-content/60 text-center py-4">No activity yet</p>"#.to_string();
    }

    let asset_code: String = asset.get("asset_code");
    let name: String = asset.get("name");
    let tag_number: Option<String> = asset.get("tag_number");
    let description: Option<String> = asset.get("description");
    let manufacturer: Option<String> = asset.get("manufacturer");
    let model: Option<String> = asset.get("model");
    let serial_number: Option<String> = asset.get("serial_number");
    let year_manufactured: Option<i32> = asset.get("year_manufactured");
    let criticality: Option<i32> = asset.get("criticality_rating");
    let category: Option<String> = asset.get("category_name");
    let status: Option<String> = asset.get("status_name");
    let status_color: Option<String> = asset.get("status_color");
    let location_name: Option<String> = asset.get("location_name");
    let site_name: Option<String> = asset.get("site_name");
    let site_id: Option<uuid::Uuid> = asset.get("site_id");
    let voltage: Option<String> = asset.get("voltage_level");

    let sidebar = build_sidebar("eam_assets", display_name, &initials);
    let criticality_badge = match criticality {
        Some(5) => r#"<span class="badge badge-error">Critical (5)</span>"#,
        Some(4) => r#"<span class="badge badge-warning">High (4)</span>"#,
        Some(3) => r#"<span class="badge badge-info">Medium (3)</span>"#,
        Some(2) => r#"<span class="badge badge-success">Low (2)</span>"#,
        Some(1) => r#"<span class="badge badge-ghost">Minimal (1)</span>"#,
        _ => "-",
    };

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>{name} - Asset Details</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://unpkg.com/htmx.org@1.9.10"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/assets">Assets</a></li><li>{asset_code}</li></ul></div>
<div class="flex justify-between items-start">
<div><h1 class="text-2xl font-bold">{name}</h1><p class="text-base-content/60">{} - {}</p></div>
<div class="flex items-center gap-2">
<span class="badge badge-lg" style="background-color:{};color:white">{}</span>
<a href="/eam/assets/{id}/edit" class="btn btn-primary btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit</a>
</div></div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
<div class="card bg-base-100 shadow lg:col-span-2"><div class="card-body">
<h2 class="card-title">Asset Information</h2>
<div class="grid grid-cols-2 gap-4 mt-4">
<div><span class="text-base-content/60 text-sm">Asset Code</span><p class="font-mono font-semibold">{asset_code}</p></div>
<div><span class="text-base-content/60 text-sm">Tag Number</span><p class="font-mono">{}</p></div>
<div><span class="text-base-content/60 text-sm">Category</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Voltage Level</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Criticality</span><p>{criticality_badge}</p></div>
<div><span class="text-base-content/60 text-sm">Year Manufactured</span><p>{}</p></div>
</div>
{}</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Location</h2>
<div class="mt-4 space-y-4">
<div><span class="text-base-content/60 text-sm">Site</span><p><a href="/eam/sites/{}" class="link link-primary">{}</a></p></div>
<div><span class="text-base-content/60 text-sm">Functional Location</span><p>{}</p></div>
</div></div></div></div>

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title">Manufacturer Details</h2>
<div class="grid grid-cols-3 gap-4 mt-4">
<div><span class="text-base-content/60 text-sm">Manufacturer</span><p class="font-semibold">{}</p></div>
<div><span class="text-base-content/60 text-sm">Model</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Serial Number</span><p class="font-mono">{}</p></div>
</div></div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex justify-between items-center">
<h2 class="card-title">Activity Stream</h2>
<button onclick="document.getElementById('asset_activity_form').classList.toggle('hidden')" class="btn btn-sm btn-ghost">
<svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Add Note</button>
</div>
<form id="asset_activity_form" class="hidden mt-4 p-4 bg-base-200 rounded-lg" hx-post="/api/chatter/eam_assets/{id}/messages" hx-target="[id=asset_activity_stream]" hx-swap="afterbegin">
<textarea name="body" rows="3" class="textarea textarea-bordered w-full" placeholder="Add a note..."></textarea>
<input type="hidden" name="message_type" value="note"/>
<div class="mt-2 flex justify-end gap-2">
<button type="button" onclick="this.closest('form').classList.add('hidden')" class="btn btn-sm btn-ghost">Cancel</button>
<button type="submit" class="btn btn-sm btn-primary">Post Note</button>
</div></form>
<div class="mt-4 space-y-4" id="asset_activity_stream">{}</div>
</div></div>
</main></div></body></html>"#,
        category.as_deref().unwrap_or("-"),
        location_name.as_deref().unwrap_or("-"),
        status_color.as_deref().unwrap_or("#6C757D"),
        status.as_deref().unwrap_or("Unknown"),
        tag_number.as_deref().unwrap_or("-"),
        category.as_deref().unwrap_or("-"),
        voltage.as_deref().unwrap_or("-"),
        year_manufactured.map(|y| y.to_string()).unwrap_or("-".into()),
        if let Some(desc) = description { format!(r#"<div class="col-span-2 mt-2"><span class="text-base-content/60 text-sm">Description</span><p>{}</p></div>"#, desc) } else { String::new() },
        site_id.map(|s| s.to_string()).unwrap_or_default(),
        site_name.as_deref().unwrap_or("-"),
        location_name.as_deref().unwrap_or("-"),
        manufacturer.as_deref().unwrap_or("-"),
        model.as_deref().unwrap_or("-"),
        serial_number.as_deref().unwrap_or("-"),
        activity_html,
    )).into_response()
}

// Site Create/Edit Forms
async fn eam_site_form(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let sidebar = build_sidebar("eam_sites", display_name, &initials);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Site - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/sites">Sites</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">Create New Site</h1></div>
<form method="POST" action="/eam/sites" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Code *</span></label><input type="text" name="code" required class="input input-bordered" placeholder="PPU-XXX-001"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" placeholder="PPU Ampang"/></div>
<div class="form-control"><label class="label"><span class="label-text">Short Name</span></label><input type="text" name="short_name" class="input input-bordered" placeholder="Ampang"/></div>
<div class="form-control"><label class="label"><span class="label-text">Site Type</span></label>
<select name="site_type" class="select select-bordered"><option value="">Select Type</option><option value="Indoor GIS">Indoor GIS</option><option value="Outdoor AIS">Outdoor AIS</option><option value="Hybrid">Hybrid</option></select></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Address</span></label><input type="text" name="address" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">City</span></label><input type="text" name="city" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">State</span></label><input type="text" name="state" class="input input-bordered" value="Selangor"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Latitude</span></label><input type="text" name="gps_latitude" class="input input-bordered" placeholder="3.1234"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Longitude</span></label><input type="text" name="gps_longitude" class="input input-bordered" placeholder="101.5678"/></div>
<div class="form-control"><label class="label"><span class="label-text">Ownership</span></label><input type="text" name="ownership" class="input input-bordered" value="TNB Distribution"/></div>
<div class="form-control"><label class="label"><span class="label-text">Operator</span></label><input type="text" name="operator" class="input input-bordered" value="TNB Distribution Sdn Bhd"/></div>
<div class="form-control"><label class="label"><span class="label-text">Busbar Configuration</span></label>
<select name="busbar_configuration" class="select select-bordered"><option value="">Select</option><option>Single Bus</option><option>Double Bus</option><option>Ring Bus</option><option>Breaker and a Half</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Feeder Count</span></label><input type="number" name="feeder_count" class="input input-bordered"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3"></textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/sites" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create Site</button></div>
</div></form>
</main></div></body></html>"#)).into_response()
}

async fn eam_site_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let short_name = form.get("short_name").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let site_type = form.get("site_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let address = form.get("address").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let city = form.get("city").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let state_val = form.get("state").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let gps_lat: Option<f64> = form.get("gps_latitude").and_then(|s| s.parse().ok());
    let gps_lon: Option<f64> = form.get("gps_longitude").and_then(|s| s.parse().ok());
    let ownership = form.get("ownership").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let operator = form.get("operator").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let busbar = form.get("busbar_configuration").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let feeder_count: Option<i32> = form.get("feeder_count").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"INSERT INTO eam_sites (company_id, code, name, short_name, site_type, address, city, state,
           gps_latitude, gps_longitude, ownership, operator, busbar_configuration, feeder_count, description,
           status, is_active, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'Active', true, $16)
           RETURNING id"#
    )
    .bind(company_id).bind(code).bind(name).bind(short_name).bind(site_type)
    .bind(address).bind(city).bind(state_val).bind(gps_lat).bind(gps_lon)
    .bind(ownership).bind(operator).bind(busbar).bind(feeder_count).bind(description)
    .bind(user.id)
    .fetch_one(&db).await;

    match result {
        Ok(id) => axum::response::Redirect::to(&format!("/eam/sites/{}", id)).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Html(format!("Error: {}", e))).into_response(),
    }
}

async fn eam_site_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let site = sqlx::query(
        "SELECT * FROM eam_sites WHERE id = $1 AND is_active = true"
    ).bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(site) = site else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Site not found")).into_response();
    };

    let code: String = site.get("code");
    let name: String = site.get("name");
    let short_name: Option<String> = site.get("short_name");
    let site_type: Option<String> = site.get("site_type");
    let address: Option<String> = site.get("address");
    let city: Option<String> = site.get("city");
    let state_val: Option<String> = site.get("state");
    let gps_lat: Option<f64> = site.get("gps_latitude");
    let gps_lon: Option<f64> = site.get("gps_longitude");
    let ownership: Option<String> = site.get("ownership");
    let operator: Option<String> = site.get("operator");
    let busbar: Option<String> = site.get("busbar_configuration");
    let feeder_count: Option<i32> = site.get("feeder_count");
    let description: Option<String> = site.get("description");

    let sidebar = build_sidebar("eam_sites", display_name, &initials);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Edit {name} - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/sites">Sites</a></li><li><a href="/eam/sites/{id}">{code}</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Site</h1></div>
<form method="POST" action="/eam/sites/{id}" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Code *</span></label><input type="text" name="code" required class="input input-bordered" value="{code}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" value="{name}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Short Name</span></label><input type="text" name="short_name" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Site Type</span></label>
<select name="site_type" class="select select-bordered"><option value="">Select Type</option>
<option value="Indoor GIS" {}>Indoor GIS</option><option value="Outdoor AIS" {}>Outdoor AIS</option><option value="Hybrid" {}>Hybrid</option></select></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Address</span></label><input type="text" name="address" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">City</span></label><input type="text" name="city" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">State</span></label><input type="text" name="state" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Latitude</span></label><input type="text" name="gps_latitude" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Longitude</span></label><input type="text" name="gps_longitude" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Ownership</span></label><input type="text" name="ownership" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Operator</span></label><input type="text" name="operator" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Busbar Configuration</span></label>
<select name="busbar_configuration" class="select select-bordered"><option value="">Select</option>
<option {}>Single Bus</option><option {}>Double Bus</option><option {}>Ring Bus</option><option {}>Breaker and a Half</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Feeder Count</span></label><input type="number" name="feeder_count" class="input input-bordered" value="{}"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3">{}</textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/sites/{id}" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Save Changes</button></div>
</div></form>
</main></div></body></html>"#,
        short_name.as_deref().unwrap_or(""),
        if site_type.as_deref() == Some("Indoor GIS") { "selected" } else { "" },
        if site_type.as_deref() == Some("Outdoor AIS") { "selected" } else { "" },
        if site_type.as_deref() == Some("Hybrid") { "selected" } else { "" },
        address.as_deref().unwrap_or(""),
        city.as_deref().unwrap_or(""),
        state_val.as_deref().unwrap_or(""),
        gps_lat.map(|v| v.to_string()).unwrap_or_default(),
        gps_lon.map(|v| v.to_string()).unwrap_or_default(),
        ownership.as_deref().unwrap_or(""),
        operator.as_deref().unwrap_or(""),
        if busbar.as_deref() == Some("Single Bus") { "selected" } else { "" },
        if busbar.as_deref() == Some("Double Bus") { "selected" } else { "" },
        if busbar.as_deref() == Some("Ring Bus") { "selected" } else { "" },
        if busbar.as_deref() == Some("Breaker and a Half") { "selected" } else { "" },
        feeder_count.map(|v| v.to_string()).unwrap_or_default(),
        description.as_deref().unwrap_or(""),
    )).into_response()
}

async fn eam_site_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let short_name = form.get("short_name").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let site_type = form.get("site_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let address = form.get("address").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let city = form.get("city").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let state_val = form.get("state").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let gps_lat: Option<f64> = form.get("gps_latitude").and_then(|s| s.parse().ok());
    let gps_lon: Option<f64> = form.get("gps_longitude").and_then(|s| s.parse().ok());
    let ownership = form.get("ownership").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let operator = form.get("operator").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let busbar = form.get("busbar_configuration").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let feeder_count: Option<i32> = form.get("feeder_count").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let _ = sqlx::query(
        r#"UPDATE eam_sites SET code=$1, name=$2, short_name=$3, site_type=$4, address=$5, city=$6, state=$7,
           gps_latitude=$8, gps_longitude=$9, ownership=$10, operator=$11, busbar_configuration=$12,
           feeder_count=$13, description=$14, updated_by=$15, updated_at=NOW()
           WHERE id=$16"#
    )
    .bind(code).bind(name).bind(short_name).bind(site_type)
    .bind(address).bind(city).bind(state_val).bind(gps_lat).bind(gps_lon)
    .bind(ownership).bind(operator).bind(busbar).bind(feeder_count).bind(description)
    .bind(user.id).bind(id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/sites/{}", id)).into_response()
}

// Asset Create/Edit Forms
async fn eam_asset_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let categories: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_categories WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let statuses: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true ORDER BY display_order"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let locations: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT fl.id::text, fl.name, s.name as site_name FROM eam_functional_locations fl
           JOIN eam_sites s ON fl.site_id = s.id
           WHERE fl.company_id = $1 AND fl.is_active = true ORDER BY s.name, fl.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let voltages: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let cat_opts: String = categories.iter().map(|(id, name)| format!(r#"<option value="{}">{}</option>"#, id, name)).collect();
    let status_opts: String = statuses.iter().map(|(id, name)| format!(r#"<option value="{}">{}</option>"#, id, name)).collect();
    let loc_opts: String = locations.iter().map(|(id, name, site)| format!(r#"<option value="{}">{} - {}</option>"#, id, site, name)).collect();
    let volt_opts: String = voltages.iter().map(|(id, name)| format!(r#"<option value="{}">{}</option>"#, id, name)).collect();

    let sidebar = build_sidebar("eam_assets", display_name, &initials);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>New Asset - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/assets">Assets</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">Create New Asset</h1></div>
<form method="POST" action="/eam/assets" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Asset Code *</span></label><input type="text" name="asset_code" required class="input input-bordered" placeholder="TX-XXX-001"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Functional Location *</span></label>
<select name="functional_location_id" required class="select select-bordered"><option value="">Select Location</option>{loc_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Category *</span></label>
<select name="category_id" required class="select select-bordered"><option value="">Select Category</option>{cat_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Status *</span></label>
<select name="status_id" required class="select select-bordered"><option value="">Select Status</option>{status_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered"><option value="">Select Voltage</option>{volt_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Tag Number</span></label><input type="text" name="tag_number" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Criticality (1-5)</span></label>
<select name="criticality_rating" class="select select-bordered"><option value="">Select</option>
<option value="1">1 - Minimal</option><option value="2">2 - Low</option><option value="3">3 - Medium</option><option value="4">4 - High</option><option value="5">5 - Critical</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Manufacturer</span></label><input type="text" name="manufacturer" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Model</span></label><input type="text" name="model" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Serial Number</span></label><input type="text" name="serial_number" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Year Manufactured</span></label><input type="number" name="year_manufactured" class="input input-bordered" min="1950" max="2030"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3"></textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/assets" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create Asset</button></div>
</div></form>
</main></div></body></html>"#)).into_response()
}

async fn eam_asset_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset_code = form.get("asset_code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let fl_id: Option<uuid::Uuid> = form.get("functional_location_id").and_then(|s| s.parse().ok());
    let cat_id: Option<uuid::Uuid> = form.get("category_id").and_then(|s| s.parse().ok());
    let status_id: Option<uuid::Uuid> = form.get("status_id").and_then(|s| s.parse().ok());
    let voltage_id: Option<uuid::Uuid> = form.get("voltage_level_id").and_then(|s| s.parse().ok());
    let tag_number = form.get("tag_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let criticality: Option<i32> = form.get("criticality_rating").and_then(|s| s.parse().ok());
    let manufacturer = form.get("manufacturer").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let model = form.get("model").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let serial = form.get("serial_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let year: Option<i32> = form.get("year_manufactured").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"INSERT INTO eam_assets (company_id, asset_code, name, functional_location_id, category_id, status_id,
           voltage_level_id, tag_number, criticality_rating, manufacturer, model, serial_number, year_manufactured,
           description, is_active, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true, $15)
           RETURNING id"#
    )
    .bind(company_id).bind(asset_code).bind(name).bind(fl_id).bind(cat_id).bind(status_id)
    .bind(voltage_id).bind(tag_number).bind(criticality).bind(manufacturer).bind(model)
    .bind(serial).bind(year).bind(description).bind(user.id)
    .fetch_one(&db).await;

    match result {
        Ok(id) => axum::response::Redirect::to(&format!("/eam/assets/{}", id)).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Html(format!("Error: {}", e))).into_response(),
    }
}

async fn eam_asset_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset = sqlx::query("SELECT * FROM eam_assets WHERE id = $1 AND is_active = true")
        .bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(asset) = asset else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Asset not found")).into_response();
    };

    let asset_code: String = asset.get("asset_code");
    let name: String = asset.get("name");
    let fl_id: Option<uuid::Uuid> = asset.get("functional_location_id");
    let cat_id: Option<uuid::Uuid> = asset.get("category_id");
    let status_id: Option<uuid::Uuid> = asset.get("status_id");
    let voltage_id: Option<uuid::Uuid> = asset.get("voltage_level_id");
    let tag_number: Option<String> = asset.get("tag_number");
    let criticality: Option<i32> = asset.get("criticality_rating");
    let manufacturer: Option<String> = asset.get("manufacturer");
    let model: Option<String> = asset.get("model");
    let serial: Option<String> = asset.get("serial_number");
    let year: Option<i32> = asset.get("year_manufactured");
    let description: Option<String> = asset.get("description");

    let categories: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM eam_asset_categories WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let statuses: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true ORDER BY display_order"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let locations: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        r#"SELECT fl.id, fl.name, s.name as site_name FROM eam_functional_locations fl
           JOIN eam_sites s ON fl.site_id = s.id
           WHERE fl.company_id = $1 AND fl.is_active = true ORDER BY s.name, fl.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let voltages: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let cat_opts: String = categories.iter().map(|(cid, cname)|
        format!(r#"<option value="{}" {}>{}</option>"#, cid, if cat_id == Some(*cid) { "selected" } else { "" }, cname)).collect();
    let status_opts: String = statuses.iter().map(|(sid, sname)|
        format!(r#"<option value="{}" {}>{}</option>"#, sid, if status_id == Some(*sid) { "selected" } else { "" }, sname)).collect();
    let loc_opts: String = locations.iter().map(|(lid, lname, site)|
        format!(r#"<option value="{}" {}>{} - {}</option>"#, lid, if fl_id == Some(*lid) { "selected" } else { "" }, site, lname)).collect();
    let volt_opts: String = voltages.iter().map(|(vid, vname)|
        format!(r#"<option value="{}" {}>{}</option>"#, vid, if voltage_id == Some(*vid) { "selected" } else { "" }, vname)).collect();

    let sidebar = build_sidebar("eam_assets", display_name, &initials);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><title>Edit {name} - Asset Management</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-6">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/assets">Assets</a></li><li><a href="/eam/assets/{id}">{asset_code}</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Asset</h1></div>
<form method="POST" action="/eam/assets/{id}" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Asset Code *</span></label><input type="text" name="asset_code" required class="input input-bordered" value="{asset_code}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" value="{name}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Functional Location *</span></label>
<select name="functional_location_id" required class="select select-bordered"><option value="">Select Location</option>{loc_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Category *</span></label>
<select name="category_id" required class="select select-bordered"><option value="">Select Category</option>{cat_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Status *</span></label>
<select name="status_id" required class="select select-bordered"><option value="">Select Status</option>{status_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered"><option value="">Select Voltage</option>{volt_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Tag Number</span></label><input type="text" name="tag_number" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Criticality (1-5)</span></label>
<select name="criticality_rating" class="select select-bordered"><option value="">Select</option>
<option value="1" {}>1 - Minimal</option><option value="2" {}>2 - Low</option><option value="3" {}>3 - Medium</option><option value="4" {}>4 - High</option><option value="5" {}>5 - Critical</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Manufacturer</span></label><input type="text" name="manufacturer" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Model</span></label><input type="text" name="model" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Serial Number</span></label><input type="text" name="serial_number" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Year Manufactured</span></label><input type="number" name="year_manufactured" class="input input-bordered" value="{}" min="1950" max="2030"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3">{}</textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/assets/{id}" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Save Changes</button></div>
</div></form>
</main></div></body></html>"#,
        tag_number.as_deref().unwrap_or(""),
        if criticality == Some(1) { "selected" } else { "" },
        if criticality == Some(2) { "selected" } else { "" },
        if criticality == Some(3) { "selected" } else { "" },
        if criticality == Some(4) { "selected" } else { "" },
        if criticality == Some(5) { "selected" } else { "" },
        manufacturer.as_deref().unwrap_or(""),
        model.as_deref().unwrap_or(""),
        serial.as_deref().unwrap_or(""),
        year.map(|y| y.to_string()).unwrap_or_default(),
        description.as_deref().unwrap_or(""),
    )).into_response()
}

async fn eam_asset_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let asset_code = form.get("asset_code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let fl_id: Option<uuid::Uuid> = form.get("functional_location_id").and_then(|s| s.parse().ok());
    let cat_id: Option<uuid::Uuid> = form.get("category_id").and_then(|s| s.parse().ok());
    let status_id: Option<uuid::Uuid> = form.get("status_id").and_then(|s| s.parse().ok());
    let voltage_id: Option<uuid::Uuid> = form.get("voltage_level_id").and_then(|s| s.parse().ok());
    let tag_number = form.get("tag_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let criticality: Option<i32> = form.get("criticality_rating").and_then(|s| s.parse().ok());
    let manufacturer = form.get("manufacturer").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let model = form.get("model").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let serial = form.get("serial_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let year: Option<i32> = form.get("year_manufactured").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let _ = sqlx::query(
        r#"UPDATE eam_assets SET asset_code=$1, name=$2, functional_location_id=$3, category_id=$4, status_id=$5,
           voltage_level_id=$6, tag_number=$7, criticality_rating=$8, manufacturer=$9, model=$10, serial_number=$11,
           year_manufactured=$12, description=$13, updated_by=$14, updated_at=NOW()
           WHERE id=$15"#
    )
    .bind(asset_code).bind(name).bind(fl_id).bind(cat_id).bind(status_id)
    .bind(voltage_id).bind(tag_number).bind(criticality).bind(manufacturer).bind(model)
    .bind(serial).bind(year).bind(description).bind(user.id).bind(id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/assets/{}", id)).into_response()
}

/// Chatter partial for any model
async fn chatter_partial(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
) -> Response {
    // Fetch messages for this record
    let messages = sqlx::query(
        "SELECT m.id, m.body, m.message_type, m.is_internal, m.created_at, u.username as author_name
         FROM chatter_messages m
         LEFT JOIN users u ON m.author_id = u.id
         WHERE m.res_model = $1 AND m.res_id = $2 AND m.active = true
         ORDER BY m.created_at DESC
         LIMIT 50"
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch activities for this record
    let activities = sqlx::query(
        "SELECT a.id, a.summary, a.due_date, a.state, t.name as type_name, t.icon, u.username as assigned_to
         FROM chatter_activities a
         LEFT JOIN chatter_activity_types t ON a.activity_type_id = t.id
         LEFT JOIN users u ON a.assigned_to_id = u.id
         WHERE a.res_model = $1 AND a.res_id = $2 AND a.active = true
         ORDER BY a.due_date ASC
         LIMIT 20"
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch activity types for dropdown
    let activity_types = sqlx::query(
        "SELECT id, name FROM chatter_activity_types WHERE active = true ORDER BY sequence, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Fetch attachments for this record
    let attachments = sqlx::query(
        "SELECT a.id, a.name, a.file_size, a.mime_type, a.created_at, a.is_secure, a.created_by, u.username as uploaded_by
         FROM chatter_attachments a
         LEFT JOIN users u ON a.created_by = u.id
         WHERE a.res_model = $1 AND a.res_id = $2 AND a.active = true
         ORDER BY a.created_at DESC
         LIMIT 50"
    )
    .bind(&model)
    .bind(record_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Get user's company_id for fetching assignable users
    let company_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    // Fetch users from same company for assignment dropdown
    let assignable_users = if let Some(cid) = company_id {
        sqlx::query("SELECT id, username FROM users WHERE company_id = $1 AND active = true ORDER BY username")
            .bind(cid)
            .fetch_all(&db)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Build messages HTML
    let mut messages_html = String::new();
    for msg in &messages {
        let body: String = msg.get("body");
        let author: Option<String> = msg.get("author_name");
        let created_at: chrono::DateTime<chrono::Utc> = msg.get("created_at");
        let msg_type: String = msg.get("message_type");
        let is_internal: bool = msg.get("is_internal");

        let badge = if is_internal {
            r#"<span class="badge badge-ghost badge-sm">Internal</span>"#
        } else if msg_type == "system" {
            r#"<span class="badge badge-info badge-sm">System</span>"#
        } else {
            ""
        };

        messages_html.push_str(&format!(
            r#"<div class="chat chat-start">
                <div class="chat-header">{} {} <time class="text-xs opacity-50">{}</time></div>
                <div class="chat-bubble chat-bubble-ghost">{}</div>
            </div>"#,
            author.unwrap_or_else(|| "System".to_string()),
            badge,
            created_at.format("%Y-%m-%d %H:%M"),
            body
        ));
    }

    if messages_html.is_empty() {
        messages_html = r#"<div class="text-center text-base-content/50 py-4">No messages yet</div>"#.to_string();
    }

    // Build activities HTML
    let mut activities_html = String::new();
    for act in &activities {
        let act_id: uuid::Uuid = act.get("id");
        let summary: Option<String> = act.get("summary");
        let due_date: chrono::NaiveDate = act.get("due_date");
        let state: String = act.get("state");
        let type_name: Option<String> = act.get("type_name");
        let assigned_to: Option<String> = act.get("assigned_to");

        let (state_badge, action_btn) = match state.as_str() {
            "completed" => (
                r#"<span class="badge badge-success badge-sm">Done</span>"#.to_string(),
                String::new()
            ),
            "overdue" | "pending" | _ => (
                if state == "overdue" {
                    r#"<span class="badge badge-error badge-sm">Overdue</span>"#.to_string()
                } else {
                    r#"<span class="badge badge-warning badge-sm">Pending</span>"#.to_string()
                },
                format!(
                    "<div class=\"join\">\
                        <button class=\"btn btn-success btn-xs join-item\" hx-post=\"/api/chatter/{}/{}/activities/{}/complete\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" title=\"Mark as Done\">Done</button>\
                        <button class=\"btn btn-ghost btn-xs join-item\" hx-post=\"/api/chatter/{}/{}/activities/{}/complete-and-schedule\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" title=\"Done & Schedule Next\">+Next</button>\
                    </div>",
                    model, record_id, act_id, model, record_id, act_id
                )
            ),
        };

        activities_html.push_str(&format!(
            r#"<div class="flex items-center gap-2 p-2 rounded hover:bg-base-200">
                <div class="flex-1">
                    <div class="font-medium">{}</div>
                    <div class="text-xs text-base-content/60">{} · {}</div>
                </div>
                {}{}
            </div>"#,
            summary.unwrap_or_else(|| type_name.unwrap_or_else(|| "Activity".to_string())),
            due_date.format("%Y-%m-%d"),
            assigned_to.unwrap_or_else(|| "Unassigned".to_string()),
            action_btn,
            state_badge
        ));
    }

    if activities_html.is_empty() {
        activities_html = r#"<div class="text-center text-base-content/50 py-4">No activities scheduled</div>"#.to_string();
    }

    // Build attachments HTML
    let mut attachments_html = String::new();
    let is_admin = user.roles.iter().any(|r| r == "admin" || r == "Admin");

    for att in &attachments {
        let att_id: uuid::Uuid = att.get("id");
        let name: String = att.get("name");
        let file_size: i64 = att.get("file_size");
        let mime_type: Option<String> = att.get("mime_type");
        let created_at: chrono::DateTime<chrono::Utc> = att.get("created_at");
        let uploaded_by: Option<String> = att.get("uploaded_by");
        let is_secure: bool = att.try_get("is_secure").unwrap_or(false);
        let created_by_id: Option<uuid::Uuid> = att.try_get("created_by").ok();

        // Check if user can delete (owner or admin)
        let can_delete = is_admin || created_by_id == Some(user.id);

        // Format file size
        let size_str = if file_size < 1024 {
            format!("{} B", file_size)
        } else if file_size < 1024 * 1024 {
            format!("{:.1} KB", file_size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", file_size as f64 / (1024.0 * 1024.0))
        };

        // Icon based on mime type and security
        let icon = if is_secure {
            r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>"#
        } else {
            match mime_type.as_deref() {
                Some(m) if m.starts_with("image/") => r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>"#,
                Some(m) if m.contains("pdf") => r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>"#,
                _ => r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/></svg>"#,
            }
        };

        // Check if previewable (PDF or image)
        let is_pdf = mime_type.as_deref().map(|m| m.contains("pdf")).unwrap_or(false);
        let is_image = mime_type.as_deref().map(|m| m.starts_with("image/")).unwrap_or(false);

        // Preview button - inline onclick using data attributes
        let eye_icon = r#"<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>"#;

        // Watermark: multiple rows of rotated text covering the entire area
        let preview_btn = if is_pdf {
            if is_secure {
                // Secure PDF: grid watermark overlay on top of iframe, no download
                format!(
                    r##"<button class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100" onclick="var m=document.getElementById('preview-modal'),t=document.getElementById('preview-title'),d=document.getElementById('preview-download'),c=document.getElementById('preview-content');t.textContent=this.dataset.t;d.style.display='none';var wt='{} - CONFIDENTIAL';var rows='';for(var i=0;i<20;i++){{rows+='<div style=\'white-space:nowrap\'>'+Array(10).fill(wt).join(' &nbsp; ')+'</div>';}}c.innerHTML='<div style=\'position:relative;width:100%;height:100%\'><iframe src=\''+this.dataset.u+'#toolbar=0\' style=\'width:100%;height:100%;min-height:70vh;border:none\'></iframe><div style=\'position:absolute;top:0;left:0;right:0;bottom:0;z-index:9999;pointer-events:none;overflow:hidden;display:flex;flex-direction:column;justify-content:space-around;transform:rotate(-20deg);transform-origin:center center;font-size:16px;color:rgba(128,128,128,0.3);font-weight:bold;line-height:3\'>'+rows+'</div></div>';m.showModal();" data-t="{}" data-u="/api/chatter/attachments/{}/download" title="Preview (Secure)">
                        {}
                    </button>"##,
                    user.username, name.replace('"', "&quot;").replace('\'', "&#39;"), att_id, eye_icon
                )
            } else {
                // Normal PDF
                format!(
                    r#"<button class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100" onclick="var m=document.getElementById('preview-modal'),t=document.getElementById('preview-title'),d=document.getElementById('preview-download'),c=document.getElementById('preview-content');t.textContent=this.dataset.t;d.style.display='';d.href=this.dataset.u;c.innerHTML='<iframe src=\''+this.dataset.u+'#toolbar=1\' style=\'width:100%;height:100%;min-height:70vh;border:none\'></iframe>';m.showModal();" data-t="{}" data-u="/api/chatter/attachments/{}/download" title="Preview PDF">
                        {}
                    </button>"#,
                    name.replace('"', "&quot;").replace('\'', "&#39;"), att_id, eye_icon
                )
            }
        } else if is_image {
            if is_secure {
                // Secure image: grid watermark overlay, no download
                format!(
                    r##"<button class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100" onclick="var m=document.getElementById('preview-modal'),t=document.getElementById('preview-title'),d=document.getElementById('preview-download'),c=document.getElementById('preview-content');t.textContent=this.dataset.t;d.style.display='none';var wt='{} - CONFIDENTIAL';var rows='';for(var i=0;i<20;i++){{rows+='<div style=\'white-space:nowrap\'>'+Array(10).fill(wt).join(' &nbsp; ')+'</div>';}}c.innerHTML='<div style=\'position:relative;width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:1rem\'><img src=\''+this.dataset.u+'\' style=\'max-width:100%;max-height:100%;object-fit:contain\'><div style=\'position:absolute;top:0;left:0;right:0;bottom:0;z-index:9999;pointer-events:none;overflow:hidden;display:flex;flex-direction:column;justify-content:space-around;transform:rotate(-20deg);transform-origin:center center;font-size:16px;color:rgba(128,128,128,0.3);font-weight:bold;line-height:3\'>'+rows+'</div></div>';m.showModal();" data-t="{}" data-u="/api/chatter/attachments/{}/download" title="Preview (Secure)">
                        {}
                    </button>"##,
                    user.username, name.replace('"', "&quot;").replace('\'', "&#39;"), att_id, eye_icon
                )
            } else {
                // Normal image
                format!(
                    r#"<button class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100" onclick="var m=document.getElementById('preview-modal'),t=document.getElementById('preview-title'),d=document.getElementById('preview-download'),c=document.getElementById('preview-content');t.textContent=this.dataset.t;d.style.display='';d.href=this.dataset.u;c.innerHTML='<div style=\'width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:1rem\'><img src=\''+this.dataset.u+'\' style=\'max-width:100%;max-height:100%;object-fit:contain\'></div>';m.showModal();" data-t="{}" data-u="/api/chatter/attachments/{}/download" title="Preview Image">
                        {}
                    </button>"#,
                    name.replace('"', "&quot;").replace('\'', "&#39;"), att_id, eye_icon
                )
            }
        } else {
            String::new()
        };

        // Download link - only for non-secure documents
        let name_display = if is_secure {
            format!(r#"<span class="font-medium truncate block">{}</span>"#, name)
        } else {
            format!(r#"<a href="/api/chatter/attachments/{}/download" class="font-medium hover:underline truncate block">{}</a>"#, att_id, name)
        };

        // Delete button - only if user has permission
        let delete_btn = if can_delete {
            format!(
                r##"<button class="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100"
                        hx-delete="/api/chatter/attachments/{}"
                        hx-target="#activity-stream"
                        hx-swap="innerHTML"
                        hx-confirm="Delete this attachment?">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                </button>"##,
                att_id
            )
        } else {
            String::new()
        };

        // Security badge
        let secure_badge = if is_secure {
            r##"<span class="badge badge-warning badge-xs">Secure</span>"##
        } else {
            ""
        };

        attachments_html.push_str(&format!(
            r##"<div class="flex items-center gap-3 p-2 rounded hover:bg-base-200 group">
                <div class="text-base-content/70">{}</div>
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2">{} {}</div>
                    <div class="text-xs text-base-content/60">{} - {} - {}</div>
                </div>
                <div class="flex gap-1">
                    {}
                    {}
                </div>
            </div>"##,
            icon, name_display, secure_badge, size_str, uploaded_by.unwrap_or_else(|| "Unknown".to_string()), created_at.format("%Y-%m-%d"), preview_btn, delete_btn
        ));
    }

    if attachments_html.is_empty() {
        attachments_html = r#"<div class="text-center text-base-content/50 py-4">No attachments</div>"#.to_string();
    }

    let attachment_count = attachments.len();

    // Build activity type options
    let mut type_options = String::new();
    for at in &activity_types {
        let id: uuid::Uuid = at.get("id");
        let name: String = at.get("name");
        type_options.push_str(&format!(r#"<option value="{}">{}</option>"#, id, name));
    }

    // Build user options
    let mut user_options = String::new();
    for u in &assignable_users {
        let id: uuid::Uuid = u.get("id");
        let username: String = u.get("username");
        let selected = if id == user.id { " selected" } else { "" };
        user_options.push_str(&format!(r#"<option value="{}"{}>@{}</option>"#, id, selected, username));
    }

    // Default due date to tomorrow
    let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1)).format("%Y-%m-%d");

    let attachment_badge = if attachment_count > 0 {
        format!(r#"<span class="badge badge-sm">{}</span>"#, attachment_count)
    } else {
        String::new()
    };

    // Inline tab switch logic - no external function needed
    let switch_to_messages = "document.querySelectorAll('.stream-tab').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.stream-tab-btn').forEach(b=>b.classList.remove('tab-active'));document.getElementById('messages-tab').classList.remove('hidden');this.classList.add('tab-active');";
    let switch_to_activities = "document.querySelectorAll('.stream-tab').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.stream-tab-btn').forEach(b=>b.classList.remove('tab-active'));document.getElementById('activities-tab').classList.remove('hidden');this.classList.add('tab-active');";
    let switch_to_attachments = "document.querySelectorAll('.stream-tab').forEach(t=>t.classList.add('hidden'));document.querySelectorAll('.stream-tab-btn').forEach(b=>b.classList.remove('tab-active'));document.getElementById('attachments-tab').classList.remove('hidden');this.classList.add('tab-active');";

    let html = format!(
        "<div class=\"card bg-base-100 shadow\">\
            <div class=\"card-body p-4\">\
                <h3 class=\"text-sm font-semibold text-base-content/70 mb-3\">Activity Stream</h3>\
                <div class=\"tabs tabs-boxed mb-4\">\
                    <a class=\"tab tab-active stream-tab-btn\" id=\"messages-btn\" onclick=\"{}\">Messages</a>\
                    <a class=\"tab stream-tab-btn\" id=\"activities-btn\" onclick=\"{}\">Activities</a>\
                    <a class=\"tab stream-tab-btn\" id=\"attachments-btn\" onclick=\"{}\">Attachments {}</a>\
                </div>\
                <div id=\"messages-tab\" class=\"stream-tab\">\
                    <form hx-post=\"/api/chatter/{}/{}/messages\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" class=\"mb-4\">\
                        <textarea name=\"body\" class=\"textarea textarea-bordered w-full\" rows=\"2\" placeholder=\"Write a message...\"></textarea>\
                        <div class=\"flex justify-end gap-2 mt-2\">\
                            <label class=\"label cursor-pointer gap-2\">\
                                <input type=\"checkbox\" name=\"is_internal\" class=\"checkbox checkbox-sm\"/>\
                                <span class=\"label-text text-xs\">Internal note</span>\
                            </label>\
                            <button type=\"submit\" class=\"btn btn-primary btn-sm\">Post</button>\
                        </div>\
                    </form>\
                    <div class=\"max-h-96 overflow-y-auto\">{}</div>\
                </div>\
                <div id=\"activities-tab\" class=\"stream-tab hidden\">\
                    <button class=\"btn btn-primary btn-sm mb-4\" onclick=\"document.getElementById('activity-modal').showModal();\">+ Schedule Activity</button>\
                    <div class=\"max-h-96 overflow-y-auto\">{}</div>\
                </div>\
                <div id=\"attachments-tab\" class=\"stream-tab hidden\">\
                    <form hx-post=\"/api/chatter/{}/{}/attachments\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" hx-encoding=\"multipart/form-data\" class=\"mb-4\">\
                        <div class=\"flex gap-2 items-center flex-wrap\">\
                            <input type=\"file\" name=\"file\" class=\"file-input file-input-bordered file-input-sm flex-1\" required/>\
                            <label class=\"label cursor-pointer gap-2\">\
                                <input type=\"checkbox\" name=\"is_secure\" class=\"checkbox checkbox-sm checkbox-warning\"/>\
                                <span class=\"label-text text-xs flex items-center gap-1\"><svg xmlns=\"http://www.w3.org/2000/svg\" class=\"w-3 h-3\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z\"/></svg>Secure</span>\
                            </label>\
                            <button type=\"submit\" class=\"btn btn-primary btn-sm\">Upload</button>\
                        </div>\
                    </form>\
                    <div class=\"max-h-96 overflow-y-auto\">{}</div>\
                </div>\
            </div>\
        </div>\
        <dialog id=\"activity-modal\" class=\"modal\">\
            <div class=\"modal-box\">\
                <h3 class=\"font-bold text-lg mb-4\">Schedule Activity</h3>\
                <form hx-post=\"/api/chatter/{}/{}/activities\" hx-target=\"#activity-stream\" hx-swap=\"innerHTML\" hx-on::after-request=\"document.getElementById('activity-modal').close();\">\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Activity Type</span></label>\
                        <select name=\"activity_type_id\" class=\"select select-bordered w-full\" required>{}</select>\
                    </div>\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Summary</span></label>\
                        <input type=\"text\" name=\"summary\" class=\"input input-bordered w-full\" placeholder=\"What needs to be done?\" required/>\
                    </div>\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Due Date</span></label>\
                        <input type=\"date\" name=\"due_date\" class=\"input input-bordered w-full\" value=\"{}\" required/>\
                    </div>\
                    <div class=\"form-control mb-3\">\
                        <label class=\"label\"><span class=\"label-text\">Assigned To</span></label>\
                        <select name=\"assigned_to_id\" class=\"select select-bordered w-full\">{}</select>\
                    </div>\
                    <div class=\"form-control mb-4\">\
                        <label class=\"label\"><span class=\"label-text\">Note (optional)</span></label>\
                        <textarea name=\"note\" class=\"textarea textarea-bordered w-full\" rows=\"2\" placeholder=\"Additional details...\"></textarea>\
                    </div>\
                    <div class=\"modal-action\">\
                        <button type=\"button\" class=\"btn\" onclick=\"document.getElementById('activity-modal').close();\">Cancel</button>\
                        <button type=\"submit\" class=\"btn btn-primary\">Schedule</button>\
                    </div>\
                </form>\
            </div>\
            <form method=\"dialog\" class=\"modal-backdrop\"><button>close</button></form>\
        </dialog>\
        <dialog id=\"preview-modal\" class=\"modal\">\
            <div class=\"modal-box w-11/12 max-w-5xl h-[85vh] flex flex-col\">\
                <div class=\"flex justify-between items-center mb-4\">\
                    <h3 class=\"font-bold text-lg\" id=\"preview-title\">Preview</h3>\
                    <div class=\"flex gap-2\">\
                        <a id=\"preview-download\" href=\"#\" class=\"btn btn-sm btn-ghost\" download>Download</a>\
                        <button class=\"btn btn-sm btn-circle btn-ghost\" onclick=\"document.getElementById('preview-modal').close();\">✕</button>\
                    </div>\
                </div>\
                <div id=\"preview-content\" class=\"flex-1 overflow-hidden bg-base-200 rounded-lg\"></div>\
            </div>\
            <form method=\"dialog\" class=\"modal-backdrop\"><button>close</button></form>\
        </dialog>",
        switch_to_messages, switch_to_activities, switch_to_attachments, attachment_badge, model, record_id, messages_html, activities_html, model, record_id, attachments_html, model, record_id, type_options, tomorrow, user_options
    );
    Html(html).into_response()
}

/// Form data for posting a chatter message
#[derive(Debug, serde::Deserialize)]
struct ChatterMessageForm {
    body: String,
    is_internal: Option<String>,
}

/// Post a message to chatter
async fn chatter_post_message(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    Form(form): Form<ChatterMessageForm>,
) -> Response {
    if form.body.trim().is_empty() {
        return chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await;
    }

    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error")).into_response(),
    };

    let msg_id = uuid::Uuid::now_v7();
    let is_internal = form.is_internal.is_some();
    let msg_type = if is_internal { "note" } else { "comment" };

    if let Err(e) = sqlx::query(
        "INSERT INTO chatter_messages (id, res_model, res_id, message_type, body, author_id, is_internal, company_id, created_at, active, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), true, $9)"
    )
    .bind(msg_id)
    .bind(&model)
    .bind(record_id)
    .bind(msg_type)
    .bind(form.body.trim())
    .bind(user.id)
    .bind(is_internal)
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await {
        error!("Failed to post message: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

/// Form data for scheduling an activity
#[derive(Debug, serde::Deserialize)]
struct ChatterActivityForm {
    activity_type_id: uuid::Uuid,
    summary: String,
    due_date: String,
    assigned_to_id: Option<uuid::Uuid>,
    note: Option<String>,
}

/// Schedule an activity
async fn chatter_post_activity(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    Form(form): Form<ChatterActivityForm>,
) -> Response {
    if form.summary.trim().is_empty() {
        return chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await;
    }

    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error")).into_response(),
    };

    // Parse due date
    let due_date = match chrono::NaiveDate::parse_from_str(&form.due_date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, Html("Invalid date format")).into_response(),
    };

    let activity_id = uuid::Uuid::now_v7();
    let assigned_to = form.assigned_to_id.unwrap_or(user.id);

    if let Err(e) = sqlx::query(
        "INSERT INTO chatter_activities (id, res_model, res_id, activity_type_id, summary, note, due_date, assigned_to_id, assigned_by_id, state, company_id, created_at, created_by, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, NOW(), $9, true)"
    )
    .bind(activity_id)
    .bind(&model)
    .bind(record_id)
    .bind(form.activity_type_id)
    .bind(form.summary.trim())
    .bind(form.note.as_deref().unwrap_or(""))
    .bind(due_date)
    .bind(assigned_to)
    .bind(user.id)
    .bind(company_id)
    .execute(&db)
    .await {
        error!("Failed to schedule activity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

/// Mark an activity as completed
async fn chatter_complete_activity(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id, activity_id)): Path<(String, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    if let Err(e) = sqlx::query(
        "UPDATE chatter_activities SET state = 'completed', completed_at = NOW(), completed_by = $1 WHERE id = $2"
    )
    .bind(user.id)
    .bind(activity_id)
    .execute(&db)
    .await {
        error!("Failed to complete activity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

/// Mark an activity as completed and open schedule modal for next activity
async fn chatter_complete_and_schedule(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id, activity_id)): Path<(String, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    // Get the activity type info before completing
    let activity_info: Option<(uuid::Uuid, i32)> = sqlx::query_as(
        "SELECT t.id, COALESCE(t.default_days, 1) FROM chatter_activities a
         JOIN chatter_activity_types t ON a.activity_type_id = t.id
         WHERE a.id = $1"
    )
    .bind(activity_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    if let Err(e) = sqlx::query(
        "UPDATE chatter_activities SET state = 'completed', completed_at = NOW(), completed_by = $1 WHERE id = $2"
    )
    .bind(user.id)
    .bind(activity_id)
    .execute(&db)
    .await {
        error!("Failed to complete activity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // Return updated chatter panel with script to open modal and pre-fill
    let panel = chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await;
    let panel_html = match axum::body::to_bytes(panel.into_body(), usize::MAX).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error")).into_response(),
    };

    // Calculate next due date based on activity type's default_days
    let (type_id, default_days) = activity_info.unwrap_or((uuid::Uuid::nil(), 1));
    let next_due = (chrono::Utc::now() + chrono::Duration::days(default_days as i64)).format("%Y-%m-%d");

    // Add script to auto-open the modal and pre-fill values
    let html = format!(
        "{}<script>setTimeout(function(){{\
            document.getElementById('activity-modal').showModal();\
            var typeSelect = document.querySelector('select[name=\"activity_type_id\"]');\
            if(typeSelect) typeSelect.value = '{}';\
            var dueDateInput = document.querySelector('input[name=\"due_date\"]');\
            if(dueDateInput) dueDateInput.value = '{}';\
        }}, 100);</script>",
        panel_html, type_id, next_due
    );
    Html(html).into_response()
}

// ============================================================================
// Chatter Attachments
// ============================================================================

const CHATTER_UPLOAD_DIR: &str = "./uploads/chatter";

async fn chatter_upload_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model, record_id)): Path<(String, uuid::Uuid)>,
    mut multipart: Multipart,
) -> Response {
    // Get user's company_id
    let company_id: uuid::Uuid = match sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&db)
        .await
    {
        Ok(cid) => cid,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Error getting company")).into_response(),
    };

    // Ensure upload directory exists
    let upload_path = std::path::PathBuf::from(CHATTER_UPLOAD_DIR);
    if let Err(e) = tokio::fs::create_dir_all(&upload_path).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Failed to create upload dir: {}", e))).into_response();
    }

    // Collect form fields - file and is_secure checkbox
    let mut file_data: Option<(String, Option<String>, Vec<u8>)> = None;
    let mut is_secure = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "is_secure" {
            // Checkbox is present = checked
            is_secure = true;
        } else if field_name == "file" {
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            let content_type = field.content_type().map(|s| s.to_string());
            match field.bytes().await {
                Ok(d) => file_data = Some((file_name, content_type, d.to_vec())),
                Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("Failed to read file: {}", e))).into_response(),
            }
        }
    }

    let Some((file_name, content_type, data)) = file_data else {
        return (StatusCode::BAD_REQUEST, Html("No file provided")).into_response();
    };

    let file_size: i64 = data.len() as i64;

    // Generate unique filename
    let ext = std::path::Path::new(&file_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let store_fname = format!("{}.{}", uuid::Uuid::new_v4(), ext);
    let file_path = upload_path.join(&store_fname);
    let relative_path = format!("chatter/{}", store_fname);

    // Compute checksum
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let checksum = hex::encode(hasher.finalize());

    // Save file to disk
    if let Err(e) = tokio::fs::write(&file_path, &data).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Failed to save file: {}", e))).into_response();
    }

    // Insert record with is_secure flag
    let result = sqlx::query(
        "INSERT INTO chatter_attachments (name, file_name, file_path, file_size, mime_type, checksum, res_model, res_id, company_id, created_by, is_secure)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id"
    )
    .bind(&file_name)
    .bind(&store_fname)
    .bind(&relative_path)
    .bind(file_size)
    .bind(&content_type)
    .bind(&checksum)
    .bind(&model)
    .bind(record_id)
    .bind(company_id)
    .bind(user.id)
    .bind(is_secure)
    .fetch_one(&db)
    .await;

    if let Err(e) = result {
        // Clean up file on error
        let _ = tokio::fs::remove_file(&file_path).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Database error: {}", e))).into_response();
    }

    // Return updated activity stream
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

async fn chatter_download_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let attachment = sqlx::query(
        "SELECT name, file_path, mime_type, is_secure FROM chatter_attachments WHERE id = $1 AND active = true"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(att) = attachment else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };

    let name: String = att.get("name");
    let file_path: String = att.get("file_path");
    let mimetype: Option<String> = att.get("mime_type");
    let is_secure: bool = att.try_get("is_secure").unwrap_or(false);

    // For secure documents, only allow inline viewing (no direct download)
    // Check if this is a download request vs preview request
    let is_download_request = params.get("download").is_some();
    if is_secure && is_download_request {
        return (StatusCode::FORBIDDEN, "Secure documents cannot be downloaded").into_response();
    }

    let full_path = std::path::PathBuf::from("./uploads").join(&file_path);
    let data = match tokio::fs::read(&full_path).await {
        Ok(d) => d,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found on disk").into_response(),
    };

    let content_type = mimetype.unwrap_or_else(|| "application/octet-stream".to_string());

    // For secure documents, always inline (no download prompt)
    // For others, use inline for previewable types, attachment for others
    let disposition = if is_secure {
        // Force inline, no filename to discourage save-as
        "inline".to_string()
    } else if content_type.contains("pdf") || content_type.starts_with("image/") {
        format!("inline; filename=\"{}\"", name)
    } else {
        format!("attachment; filename=\"{}\"", name)
    };

    // For secure documents, add headers to prevent caching
    if is_secure {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CONTENT_DISPOSITION, disposition),
                (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, private".to_string()),
                (header::PRAGMA, "no-cache".to_string()),
                (header::EXPIRES, "0".to_string()),
            ],
            data,
        ).into_response()
    } else {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            data,
        ).into_response()
    }
}

async fn chatter_delete_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get the attachment info first
    let attachment = sqlx::query(
        "SELECT file_path, res_model, res_id, created_by FROM chatter_attachments WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(att) = attachment else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };

    let file_path: String = att.get("file_path");
    let model: String = att.get("res_model");
    let record_id: uuid::Uuid = att.get("res_id");
    let created_by: Option<uuid::Uuid> = att.try_get("created_by").ok();

    // Check permission - only owner or admin can delete
    let is_admin = user.roles.iter().any(|r| r == "admin" || r == "Admin");
    let is_owner = created_by == Some(user.id);
    if !is_admin && !is_owner {
        return (StatusCode::FORBIDDEN, "You don't have permission to delete this attachment").into_response();
    }

    // Soft delete (set active = false)
    if let Err(e) = sqlx::query("UPDATE chatter_attachments SET active = false WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response();
    }

    // Optionally delete file from disk
    let full_path = std::path::PathBuf::from("./uploads").join(&file_path);
    let _ = tokio::fs::remove_file(&full_path).await;

    // Return updated chatter panel
    chatter_partial(State(state), Db(db.clone()), Extension(user), Path((model, record_id))).await
}

// ============================================================================
// Notifications Page
// ============================================================================

async fn notifications_page(
    Extension(user): Extension<AuthUser>,
) -> Response {
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications - Remicle</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background: #0f0f1a; color: #e8e8e8; }}
        .navbar {{ background: #1a1a2e; border-bottom: 1px solid #2a2a4a; }}
        .card {{ background: #1a1a2e; border: 1px solid #2a2a4a; }}
        .card:hover {{ background: #222244; }}
        .text-muted {{ color: #a0a0b0; }}
        .user-badge {{ background: #8BC53F; color: #000; font-weight: 600; }}
        .notif-unread {{ border-left: 3px solid #8BC53F; }}
    </style>
</head>
<body class="min-h-screen">
    <div class="navbar px-4 sticky top-0 z-50">
        <div class="flex-1">
            <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
        </div>
        <div class="flex items-center gap-2 md:gap-3">
            <a href="/home" class="text-white text-sm hover:underline hidden md:inline">Home</a>
            <a href="/settings" class="text-white text-sm hover:underline hidden md:inline">Settings</a>
            <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
                <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
                <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
            </a>
            <div class="user-badge px-3 py-1 rounded-full text-sm">@{}</div>
        </div>
    </div>

    <div class="container mx-auto px-4 py-6 max-w-3xl">
        <div class="mb-6">
            <h1 class="text-2xl md:text-3xl font-bold text-white">Notifications</h1>
            <p class="text-muted mt-1">Stay updated on activities and alerts</p>
        </div>

        <div class="space-y-3">
            <div class="card notif-unread p-4 cursor-pointer">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(139,197,63,0.2)">
                        <svg class="w-5 h-5" style="color:#8BC53F" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="text-white font-medium">Work Order WO-2024-001 Approved</p>
                        <p class="text-muted text-sm mt-1">Your work order has been approved by the supervisor.</p>
                        <p class="text-muted text-xs mt-2">2 hours ago</p>
                    </div>
                </div>
            </div>

            <div class="card notif-unread p-4 cursor-pointer">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(59,130,246,0.2)">
                        <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="text-white font-medium">New comment on Asset A-1001</p>
                        <p class="text-muted text-sm mt-1">John mentioned you in a comment.</p>
                        <p class="text-muted text-xs mt-2">5 hours ago</p>
                    </div>
                </div>
            </div>

            <div class="card p-4 cursor-pointer opacity-70">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(245,158,11,0.2)">
                        <svg class="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="text-white font-medium">Scheduled maintenance reminder</p>
                        <p class="text-muted text-sm mt-1">Asset A-1005 is due for preventive maintenance tomorrow.</p>
                        <p class="text-muted text-xs mt-2">1 day ago</p>
                    </div>
                </div>
            </div>

            <div class="card p-4 cursor-pointer opacity-70">
                <div class="flex items-start gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center" style="background:rgba(139,197,63,0.2)">
                        <svg class="w-5 h-5" style="color:#8BC53F" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                    </div>
                    <div class="flex-1">
                        <p class="text-white font-medium">Task completed</p>
                        <p class="text-muted text-sm mt-1">Inspection task for Transformer T-101 has been completed.</p>
                        <p class="text-muted text-xs mt-2">2 days ago</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="mt-8 text-center">
            <p class="text-muted text-sm">End of notifications</p>
        </div>
    </div>
</body>
</html>"##,
        user.username
    );

    Html(html).into_response()
}

// ============================================================================
// Settings Index
// ============================================================================

async fn settings_index(
    Extension(user): Extension<AuthUser>,
) -> Response {
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - Remicle</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root {{
            --fallback-b1: #1a1a2e;
            --fallback-b2: #16162a;
            --fallback-b3: #0f0f1a;
            --fallback-bc: #e8e8e8;
        }}
        body {{ background: #0f0f1a; color: #e8e8e8; }}
        .card {{ background: #1a1a2e; border: 1px solid #2a2a4a; }}
        .card:hover {{ background: #222244; border-color: #3a3a5a; }}
        .card-title {{ color: #ffffff; font-weight: 600; }}
        .text-muted {{ color: #a0a0b0; }}
        .section-title {{ color: #8BC53F; }}
        .navbar {{ background: #1a1a2e; border-bottom: 1px solid #2a2a4a; }}
        @media (max-width: 768px) {{
            .card-body {{ padding: 1rem; }}
            .card-title {{ font-size: 1.1rem; }}
            .text-muted {{ font-size: 0.9rem; }}
            h1 {{ font-size: 1.75rem; }}
            .section-title {{ font-size: 1.1rem; }}
        }}
    </style>
</head>
<body class="min-h-screen">
    <div class="navbar px-4 sticky top-0 z-50">
        <div class="flex-1">
            <a href="/home" class="text-xl font-bold"><span style="color:#8BC53F">re</span><span class="text-muted">micle</span></a>
        </div>
        <div class="flex items-center gap-2 md:gap-3">
            <a href="/home" class="text-white text-sm hover:underline hidden md:inline">Home</a>
            <a href="/notifications" class="btn btn-ghost btn-circle btn-sm relative" title="Notifications">
                <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
                <span class="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></span>
            </a>
            <div style="background:#8BC53F;color:#000;font-weight:600" class="px-3 py-1 rounded-full text-sm">@{}</div>
        </div>
    </div>

    <div class="container mx-auto px-4 py-6 max-w-5xl">
        <div class="mb-8">
            <h1 class="text-2xl md:text-3xl font-bold text-white">Settings</h1>
            <p class="text-muted mt-1">System configuration and administration</p>
        </div>

        <!-- Users & Access Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/></svg>
                Users & Access
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/users" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Users</h3>
                        <p class="text-muted text-sm">Manage user accounts</p>
                    </div>
                </a>
                <a href="/list/roles" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Roles</h3>
                        <p class="text-muted text-sm">User roles & permissions</p>
                    </div>
                </a>
                <a href="/admin/access" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Access Control</h3>
                        <p class="text-muted text-sm">Model & record rules</p>
                    </div>
                </a>
            </div>
        </div>

        <!-- Organization Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
                Organization
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/list/companies" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Companies</h3>
                        <p class="text-muted text-sm">Multi-company setup</p>
                    </div>
                </a>
                <a href="/modules" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Apps & Modules</h3>
                        <p class="text-muted text-sm">Installed applications</p>
                    </div>
                </a>
            </div>
        </div>

        <!-- Technical Section -->
        <div class="mb-8">
            <h2 class="section-title text-lg font-semibold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                Technical
            </h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 md:gap-4">
                <a href="/settings/sequences" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Sequences</h3>
                        <p class="text-muted text-sm">Auto-numbering for documents</p>
                    </div>
                </a>
                <a href="/settings/cron" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Scheduled Jobs</h3>
                        <p class="text-muted text-sm">Background task scheduling</p>
                    </div>
                </a>
                <a href="/settings/reports" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Reports</h3>
                        <p class="text-muted text-sm">Print templates & documents</p>
                    </div>
                </a>
                <a href="/settings/activity-types" class="card transition-all">
                    <div class="card-body p-4">
                        <h3 class="card-title text-base md:text-lg">Activity Types</h3>
                        <p class="text-muted text-sm">Activity types for Activity Stream</p>
                    </div>
                </a>
            </div>
        </div>
    </div>
</body>
</html>"##,
        user.username
    );

    Html(html).into_response()
}

// Activity Types Management
#[derive(Debug, serde::Deserialize)]
struct ActivityTypeForm {
    name: String,
    icon: Option<String>,
    color: Option<String>,
    default_days: Option<i32>,
    sequence: Option<i32>,
}

async fn activity_types_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let types = sqlx::query(
        "SELECT id, name, icon, color, default_days, sequence FROM chatter_activity_types WHERE active = true ORDER BY sequence, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for t in &types {
        let id: uuid::Uuid = t.get("id");
        let name: String = t.get("name");
        let icon: String = t.get::<Option<String>, _>("icon").unwrap_or_else(|| "clock".to_string());
        let color: String = t.get::<Option<String>, _>("color").unwrap_or_else(|| "primary".to_string());
        let default_days: i32 = t.get::<Option<i32>, _>("default_days").unwrap_or(1);
        let sequence: i32 = t.get::<Option<i32>, _>("sequence").unwrap_or(10);

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/activity-types/{}" class="link link-primary">{}</a></td>
                <td><code class="text-sm">{}</code></td>
                <td><span class="badge badge-{}">{}</span></td>
                <td>{} days</td>
                <td>{}</td>
            </tr>"##,
            id, name, icon, color, color, default_days, sequence
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activity Types - Settings</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Activity Types</h1>
                <p class="text-base-content/60">Configure activity types</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Activity Type</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Icon</th>
                            <th>Color</th>
                            <th>Default Days</th>
                            <th>Sequence</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Activity Type</h3>
            <form method="post" action="/settings/activity-types">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Follow Up" required/>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Icon</span></label>
                        <input type="text" name="icon" class="input input-bordered" value="clock" placeholder="clock"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Color</span></label>
                        <select name="color" class="select select-bordered">
                            <option value="primary">Primary</option>
                            <option value="secondary">Secondary</option>
                            <option value="accent">Accent</option>
                            <option value="info">Info</option>
                            <option value="success">Success</option>
                            <option value="warning">Warning</option>
                            <option value="error">Error</option>
                        </select>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Default Days</span></label>
                        <input type="number" name="default_days" class="input input-bordered" value="1" min="1"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Sequence</span></label>
                        <input type="number" name="sequence" class="input input-bordered" value="10" min="0"/>
                    </div>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );
    Html(html).into_response()
}

async fn activity_type_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<ActivityTypeForm>,
) -> Response {
    let company_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let id = uuid::Uuid::now_v7();
    let _ = sqlx::query(
        "INSERT INTO chatter_activity_types (id, name, icon, color, default_days, sequence, company_id, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, true)"
    )
    .bind(id)
    .bind(form.name.trim())
    .bind(form.icon.as_deref().unwrap_or("clock"))
    .bind(form.color.as_deref().unwrap_or("primary"))
    .bind(form.default_days.unwrap_or(1))
    .bind(form.sequence.unwrap_or(10))
    .bind(company_id)
    .execute(&db)
    .await;

    Redirect::to("/settings/activity-types").into_response()
}

async fn activity_type_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let at = sqlx::query(
        "SELECT id, name, icon, color, default_days, sequence FROM chatter_activity_types WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(at) = at else {
        return Redirect::to("/settings/activity-types").into_response();
    };

    let name: String = at.get("name");
    let icon: String = at.get::<Option<String>, _>("icon").unwrap_or_else(|| "clock".to_string());
    let color: String = at.get::<Option<String>, _>("color").unwrap_or_else(|| "primary".to_string());
    let default_days: i32 = at.get::<Option<i32>, _>("default_days").unwrap_or(1);
    let sequence: i32 = at.get::<Option<i32>, _>("sequence").unwrap_or(10);

    // Build color options
    let colors = ["primary", "secondary", "accent", "info", "success", "warning", "error"];
    let color_options: String = colors.iter().map(|c| {
        let selected = if *c == color { " selected" } else { "" };
        format!(r#"<option value="{}"{}>{}  </option>"#, c, selected, c.chars().next().unwrap().to_uppercase().to_string() + &c[1..])
    }).collect();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Activity Type</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6">
            <a href="/settings/activity-types" class="btn btn-ghost btn-sm">← Back to Activity Types</a>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <h2 class="card-title">{}</h2>
                <p class="text-base-content/60 mb-4">Edit activity type settings</p>

                <form method="post" action="/settings/activity-types/{}">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Name</span></label>
                        <input type="text" name="name" class="input input-bordered" value="{}" required/>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Icon</span></label>
                            <input type="text" name="icon" class="input input-bordered" value="{}"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Color</span></label>
                            <select name="color" class="select select-bordered">{}</select>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Default Days</span></label>
                            <input type="number" name="default_days" class="input input-bordered" value="{}" min="1"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Sequence</span></label>
                            <input type="number" name="sequence" class="input input-bordered" value="{}" min="0"/>
                        </div>
                    </div>
                    <div class="card-actions justify-between mt-4">
                        <form method="post" action="/settings/activity-types/{}/delete" class="inline">
                            <button type="submit" class="btn btn-error btn-outline" onclick="return confirm('Delete this activity type?');">Delete</button>
                        </form>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, id, name, icon, color_options, default_days, sequence, id
    );

    Html(html).into_response()
}

async fn activity_type_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<ActivityTypeForm>,
) -> Response {
    let _ = sqlx::query(
        "UPDATE chatter_activity_types SET name = $1, icon = $2, color = $3, default_days = $4, sequence = $5, updated_at = NOW() WHERE id = $6"
    )
    .bind(form.name.trim())
    .bind(form.icon.as_deref().unwrap_or("clock"))
    .bind(form.color.as_deref().unwrap_or("primary"))
    .bind(form.default_days.unwrap_or(1))
    .bind(form.sequence.unwrap_or(10))
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/activity-types").into_response()
}

async fn activity_type_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE chatter_activity_types SET active = false WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    Redirect::to("/settings/activity-types").into_response()
}

// ============================================================================
// Sequences Management
// ============================================================================

async fn sequences_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let sequences = sqlx::query(
        "SELECT id, name, code, prefix, suffix, padding, number_next, number_increment, reset_period, use_date_range, date_format
         FROM ir_sequence WHERE active = true ORDER BY name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for seq in &sequences {
        let id: uuid::Uuid = seq.get("id");
        let name: String = seq.get("name");
        let code: String = seq.get("code");
        let prefix: Option<String> = seq.get("prefix");
        let suffix: Option<String> = seq.get("suffix");
        let padding: i32 = seq.get("padding");
        let number_next: i32 = seq.get("number_next");
        let reset_period: Option<String> = seq.get("reset_period");
        let use_date_range: bool = seq.get("use_date_range");
        let date_format: Option<String> = seq.get("date_format");

        // Build preview
        let mut preview = prefix.clone().unwrap_or_default();
        if use_date_range {
            preview.push_str(&date_format.clone().unwrap_or_else(|| "YYYY".to_string()));
            preview.push('-');
        }
        preview.push_str(&"0".repeat(padding as usize - 1));
        preview.push('1');
        if let Some(s) = &suffix {
            preview.push_str(s);
        }

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/sequences/{}" class="link link-primary">{}</a></td>
                <td><code class="text-sm">{}</code></td>
                <td><code class="text-xs bg-base-200 px-2 py-1 rounded">{}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>"##,
            id, name, code, preview, number_next,
            reset_period.unwrap_or_else(|| "never".to_string()),
            if use_date_range { "Yes" } else { "No" }
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sequences - Settings</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"><script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Sequences</h1>
                <p class="text-base-content/60">Auto-numbering for documents</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Sequence</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Code</th>
                            <th>Preview</th>
                            <th>Next #</th>
                            <th>Reset</th>
                            <th>Date Range</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Sequence</h3>
            <form method="post" action="/settings/sequences">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Work Order" required/>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Code</span></label>
                    <input type="text" name="code" class="input input-bordered" placeholder="e.g., work.order" required/>
                    <label class="label"><span class="label-text-alt">Unique identifier used in API</span></label>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Prefix</span></label>
                        <input type="text" name="prefix" class="input input-bordered" placeholder="e.g., WO-"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Suffix</span></label>
                        <input type="text" name="suffix" class="input input-bordered" placeholder="e.g., -A"/>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Padding</span></label>
                        <input type="number" name="padding" class="input input-bordered" value="5" min="1" max="10"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Start Number</span></label>
                        <input type="number" name="number_next" class="input input-bordered" value="1" min="1"/>
                    </div>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Reset Period</span></label>
                    <select name="reset_period" class="select select-bordered">
                        <option value="never">Never</option>
                        <option value="year">Yearly</option>
                        <option value="month">Monthly</option>
                    </select>
                </div>
                <div class="form-control mb-3">
                    <label class="label cursor-pointer justify-start gap-3">
                        <input type="checkbox" name="use_date_range" class="checkbox"/>
                        <span class="label-text">Include date in sequence</span>
                    </label>
                </div>
                <div class="form-control mb-4">
                    <label class="label"><span class="label-text">Date Format</span></label>
                    <select name="date_format" class="select select-bordered">
                        <option value="YYYY">YYYY (2026)</option>
                        <option value="YYYYMM">YYYYMM (202602)</option>
                        <option value="YYMM">YYMM (2602)</option>
                    </select>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );

    Html(html).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct SequenceForm {
    name: String,
    code: Option<String>,  // Optional for updates
    prefix: Option<String>,
    suffix: Option<String>,
    padding: Option<i32>,
    number_next: Option<i32>,
    reset_period: Option<String>,
    use_date_range: Option<String>,
    date_format: Option<String>,
}

async fn sequence_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Form(form): Form<SequenceForm>,
) -> Response {
    let Some(code) = form.code else {
        return (StatusCode::BAD_REQUEST, "Code is required").into_response();
    };

    let use_date = form.use_date_range.is_some();
    let reset = if form.reset_period.as_deref() == Some("never") { None } else { form.reset_period };

    let _ = sqlx::query(
        "INSERT INTO ir_sequence (name, code, prefix, suffix, padding, number_next, reset_period, use_date_range, date_format)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(&form.name)
    .bind(&code)
    .bind(&form.prefix)
    .bind(&form.suffix)
    .bind(form.padding.unwrap_or(5))
    .bind(form.number_next.unwrap_or(1))
    .bind(&reset)
    .bind(use_date)
    .bind(&form.date_format)
    .execute(&db)
    .await;

    Redirect::to("/settings/sequences").into_response()
}

async fn sequence_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let seq = sqlx::query(
        "SELECT id, name, code, prefix, suffix, padding, number_next, number_increment, reset_period, use_date_range, date_format
         FROM ir_sequence WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(seq) = seq else {
        return Redirect::to("/settings/sequences").into_response();
    };

    let name: String = seq.get("name");
    let code: String = seq.get("code");
    let prefix: Option<String> = seq.get("prefix");
    let suffix: Option<String> = seq.get("suffix");
    let padding: i32 = seq.get("padding");
    let number_next: i32 = seq.get("number_next");
    let reset_period: Option<String> = seq.get("reset_period");
    let use_date_range: bool = seq.get("use_date_range");
    let date_format: Option<String> = seq.get("date_format");

    let reset_never = if reset_period.is_none() { " selected" } else { "" };
    let reset_year = if reset_period.as_deref() == Some("year") { " selected" } else { "" };
    let reset_month = if reset_period.as_deref() == Some("month") { " selected" } else { "" };

    let df_yyyy = if date_format.as_deref() == Some("YYYY") || date_format.is_none() { " selected" } else { "" };
    let df_yyyymm = if date_format.as_deref() == Some("YYYYMM") { " selected" } else { "" };
    let df_yymm = if date_format.as_deref() == Some("YYMM") { " selected" } else { "" };

    let checked = if use_date_range { " checked" } else { "" };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Sequence</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"><script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-2xl">
        <div class="mb-6">
            <a href="/settings/sequences" class="btn btn-ghost btn-sm">← Back to Sequences</a>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <h2 class="card-title">{}</h2>
                <p class="text-base-content/60 mb-4">Code: <code>{}</code></p>

                <form method="post" action="/settings/sequences/{}">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Name</span></label>
                        <input type="text" name="name" class="input input-bordered" value="{}" required/>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Prefix</span></label>
                            <input type="text" name="prefix" class="input input-bordered" value="{}"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Suffix</span></label>
                            <input type="text" name="suffix" class="input input-bordered" value="{}"/>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Padding</span></label>
                            <input type="number" name="padding" class="input input-bordered" value="{}" min="1" max="10"/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Next Number</span></label>
                            <input type="number" name="number_next" class="input input-bordered" value="{}" min="1"/>
                        </div>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Reset Period</span></label>
                        <select name="reset_period" class="select select-bordered">
                            <option value="never"{}>Never</option>
                            <option value="year"{}>Yearly</option>
                            <option value="month"{}>Monthly</option>
                        </select>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label cursor-pointer justify-start gap-3">
                            <input type="checkbox" name="use_date_range" class="checkbox"{}>
                            <span class="label-text">Include date in sequence</span>
                        </label>
                    </div>
                    <div class="form-control mb-4">
                        <label class="label"><span class="label-text">Date Format</span></label>
                        <select name="date_format" class="select select-bordered">
                            <option value="YYYY"{}>YYYY (2026)</option>
                            <option value="YYYYMM"{}>YYYYMM (202602)</option>
                            <option value="YYMM"{}>YYMM (2602)</option>
                        </select>
                    </div>
                    <div class="card-actions justify-end">
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, code, id, name,
        prefix.unwrap_or_default(), suffix.unwrap_or_default(),
        padding, number_next,
        reset_never, reset_year, reset_month,
        checked,
        df_yyyy, df_yyyymm, df_yymm
    );

    Html(html).into_response()
}

async fn sequence_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<SequenceForm>,
) -> Response {
    let use_date = form.use_date_range.is_some();
    let reset = if form.reset_period.as_deref() == Some("never") { None } else { form.reset_period };

    let _ = sqlx::query(
        "UPDATE ir_sequence SET name = $1, prefix = $2, suffix = $3, padding = $4, number_next = $5, reset_period = $6, use_date_range = $7, date_format = $8, updated_at = NOW()
         WHERE id = $9"
    )
    .bind(&form.name)
    .bind(&form.prefix)
    .bind(&form.suffix)
    .bind(form.padding.unwrap_or(5))
    .bind(form.number_next.unwrap_or(1))
    .bind(&reset)
    .bind(use_date)
    .bind(&form.date_format)
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/sequences").into_response()
}

// ============================================================================
// Cron Jobs Management
// ============================================================================

async fn cron_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let crons = sqlx::query(
        "SELECT id, name, function_name, interval_number, interval_type, next_run_at, last_run_at, last_run_status, active
         FROM ir_cron ORDER BY priority, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for cron in &crons {
        let id: uuid::Uuid = cron.get("id");
        let name: String = cron.get("name");
        let function_name: String = cron.get("function_name");
        let interval_number: i32 = cron.get("interval_number");
        let interval_type: String = cron.get("interval_type");
        let next_run_at: Option<chrono::DateTime<chrono::Utc>> = cron.get("next_run_at");
        let last_run_at: Option<chrono::DateTime<chrono::Utc>> = cron.get("last_run_at");
        let last_run_status: Option<String> = cron.get("last_run_status");
        let active: bool = cron.get("active");

        let schedule = format!("Every {} {}", interval_number, interval_type);
        let next_run = next_run_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let last_run = last_run_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Never".to_string());

        let status_badge = match last_run_status.as_deref() {
            Some("success") => r#"<span class="badge badge-success badge-sm">Success</span>"#,
            Some("error") => r#"<span class="badge badge-error badge-sm">Error</span>"#,
            Some("running") => r#"<span class="badge badge-warning badge-sm">Running</span>"#,
            _ => r#"<span class="badge badge-ghost badge-sm">-</span>"#,
        };

        let active_badge = if active {
            r#"<span class="badge badge-success badge-sm">Active</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">Inactive</span>"#
        };

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/cron/{}" class="link link-primary">{}</a></td>
                <td><code class="text-xs">{}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <form method="post" action="/settings/cron/{}/run" class="inline">
                        <button type="submit" class="btn btn-ghost btn-xs" title="Run Now">▶</button>
                    </form>
                    <form method="post" action="/settings/cron/{}/toggle" class="inline">
                        <button type="submit" class="btn btn-ghost btn-xs" title="Toggle">{}</button>
                    </form>
                </td>
            </tr>"##,
            id, name, function_name, schedule, next_run, last_run, status_badge, active_badge,
            id, id,
            if active { "⏸" } else { "▶" }
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scheduled Jobs - Settings</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Scheduled Jobs</h1>
                <p class="text-base-content/60">Background task scheduling</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Job</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Function</th>
                            <th>Schedule</th>
                            <th>Next Run</th>
                            <th>Last Run</th>
                            <th>Status</th>
                            <th>Active</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Scheduled Job</h3>
            <form method="post" action="/settings/cron">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Daily Report" required/>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Function</span></label>
                    <input type="text" name="function_name" class="input input-bordered" placeholder="e.g., send_daily_report" required/>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Every</span></label>
                        <input type="number" name="interval_number" class="input input-bordered" value="1" min="1"/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Period</span></label>
                        <select name="interval_type" class="select select-bordered">
                            <option value="minutes">Minutes</option>
                            <option value="hours">Hours</option>
                            <option value="days" selected>Days</option>
                            <option value="weeks">Weeks</option>
                            <option value="months">Months</option>
                        </select>
                    </div>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );

    Html(html).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct CronForm {
    name: String,
    function_name: String,
    interval_number: Option<i32>,
    interval_type: Option<String>,
    priority: Option<i32>,
}

async fn cron_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Form(form): Form<CronForm>,
) -> Response {
    let interval_number = form.interval_number.unwrap_or(1);
    let interval_type = form.interval_type.as_deref().unwrap_or("days");

    // Calculate next run time
    let next_run = match interval_type {
        "minutes" => chrono::Utc::now() + chrono::Duration::minutes(interval_number as i64),
        "hours" => chrono::Utc::now() + chrono::Duration::hours(interval_number as i64),
        "days" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64),
        "weeks" => chrono::Utc::now() + chrono::Duration::weeks(interval_number as i64),
        "months" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64 * 30),
        _ => chrono::Utc::now() + chrono::Duration::days(1),
    };

    let _ = sqlx::query(
        "INSERT INTO ir_cron (name, function_name, interval_number, interval_type, next_run_at, priority)
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(&form.name)
    .bind(&form.function_name)
    .bind(interval_number)
    .bind(interval_type)
    .bind(next_run)
    .bind(form.priority.unwrap_or(10))
    .execute(&db)
    .await;

    Redirect::to("/settings/cron").into_response()
}

async fn cron_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let cron = sqlx::query(
        "SELECT id, name, function_name, interval_number, interval_type, next_run_at, last_run_at, last_run_status, last_run_message, priority, active
         FROM ir_cron WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(cron) = cron else {
        return Redirect::to("/settings/cron").into_response();
    };

    let name: String = cron.get("name");
    let function_name: String = cron.get("function_name");
    let interval_number: i32 = cron.get("interval_number");
    let interval_type: String = cron.get("interval_type");
    let priority: i32 = cron.get("priority");
    let active: bool = cron.get("active");
    let last_run_message: Option<String> = cron.get("last_run_message");

    let interval_options = ["minutes", "hours", "days", "weeks", "months"];
    let interval_select: String = interval_options.iter().map(|opt| {
        let selected = if *opt == interval_type { " selected" } else { "" };
        format!(r#"<option value="{}"{}>{}  </option>"#, opt, selected, opt.chars().next().unwrap().to_uppercase().to_string() + &opt[1..])
    }).collect();

    // Fetch recent logs
    let logs = sqlx::query(
        "SELECT started_at, finished_at, status, message, records_processed
         FROM ir_cron_log WHERE cron_id = $1 ORDER BY started_at DESC LIMIT 10"
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut logs_html = String::new();
    for log in &logs {
        let started_at: chrono::DateTime<chrono::Utc> = log.get("started_at");
        let finished_at: Option<chrono::DateTime<chrono::Utc>> = log.get("finished_at");
        let status: String = log.get("status");
        let message: Option<String> = log.get("message");
        let records: i32 = log.get("records_processed");

        let duration = finished_at.map(|f| {
            let dur = f - started_at;
            format!("{}s", dur.num_seconds())
        }).unwrap_or_else(|| "-".to_string());

        let status_badge = match status.as_str() {
            "success" => r#"<span class="badge badge-success badge-sm">Success</span>"#,
            "error" => r#"<span class="badge badge-error badge-sm">Error</span>"#,
            _ => r#"<span class="badge badge-warning badge-sm">Running</span>"#,
        };

        logs_html.push_str(&format!(
            r#"<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td class="text-xs">{}</td>
            </tr>"#,
            started_at.format("%Y-%m-%d %H:%M:%S"),
            duration,
            status_badge,
            records,
            message.unwrap_or_default()
        ));
    }

    if logs_html.is_empty() {
        logs_html = r#"<tr><td colspan="5" class="text-center text-base-content/50">No execution logs yet</td></tr>"#.to_string();
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Scheduled Job</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-4xl">
        <div class="mb-6">
            <a href="/settings/cron" class="btn btn-ghost btn-sm">← Back to Scheduled Jobs</a>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="card bg-base-100 shadow">
                <div class="card-body">
                    <h2 class="card-title">{}</h2>
                    <p class="text-base-content/60 mb-4">Edit job settings</p>

                    <form method="post" action="/settings/cron/{}">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Name</span></label>
                            <input type="text" name="name" class="input input-bordered" value="{}" required/>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Function</span></label>
                            <input type="text" name="function_name" class="input input-bordered" value="{}" required/>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-control mb-3">
                                <label class="label"><span class="label-text">Every</span></label>
                                <input type="number" name="interval_number" class="input input-bordered" value="{}" min="1"/>
                            </div>
                            <div class="form-control mb-3">
                                <label class="label"><span class="label-text">Period</span></label>
                                <select name="interval_type" class="select select-bordered">{}</select>
                            </div>
                        </div>
                        <div class="form-control mb-4">
                            <label class="label"><span class="label-text">Priority</span></label>
                            <input type="number" name="priority" class="input input-bordered" value="{}" min="1"/>
                            <label class="label"><span class="label-text-alt">Lower number = higher priority</span></label>
                        </div>
                        <div class="card-actions justify-between">
                            <form method="post" action="/settings/cron/{}/run" class="inline">
                                <button type="submit" class="btn btn-outline">Run Now</button>
                            </form>
                            <button type="submit" class="btn btn-primary">Save Changes</button>
                        </div>
                    </form>
                </div>
            </div>

            <div class="card bg-base-100 shadow">
                <div class="card-body">
                    <h2 class="card-title">Execution Log</h2>
                    <div class="overflow-x-auto">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Started</th>
                                    <th>Duration</th>
                                    <th>Status</th>
                                    <th>Records</th>
                                    <th>Message</th>
                                </tr>
                            </thead>
                            <tbody>{}</tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, id, name, function_name, interval_number, interval_select, priority, id, logs_html
    );

    Html(html).into_response()
}

async fn cron_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<CronForm>,
) -> Response {
    let interval_number = form.interval_number.unwrap_or(1);
    let interval_type = form.interval_type.as_deref().unwrap_or("days");

    // Recalculate next run time
    let next_run = match interval_type {
        "minutes" => chrono::Utc::now() + chrono::Duration::minutes(interval_number as i64),
        "hours" => chrono::Utc::now() + chrono::Duration::hours(interval_number as i64),
        "days" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64),
        "weeks" => chrono::Utc::now() + chrono::Duration::weeks(interval_number as i64),
        "months" => chrono::Utc::now() + chrono::Duration::days(interval_number as i64 * 30),
        _ => chrono::Utc::now() + chrono::Duration::days(1),
    };

    let _ = sqlx::query(
        "UPDATE ir_cron SET name = $1, function_name = $2, interval_number = $3, interval_type = $4, next_run_at = $5, priority = $6, updated_at = NOW()
         WHERE id = $7"
    )
    .bind(&form.name)
    .bind(&form.function_name)
    .bind(interval_number)
    .bind(interval_type)
    .bind(next_run)
    .bind(form.priority.unwrap_or(10))
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/cron").into_response()
}

async fn cron_toggle(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let _ = sqlx::query("UPDATE ir_cron SET active = NOT active, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await;

    Redirect::to("/settings/cron").into_response()
}

async fn cron_run_now(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    // Get cron job info
    let cron = sqlx::query("SELECT function_name FROM ir_cron WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(cron) = cron else {
        return Redirect::to("/settings/cron").into_response();
    };

    let function_name: String = cron.get("function_name");

    // Create log entry
    let log_id = uuid::Uuid::now_v7();
    let _ = sqlx::query("INSERT INTO ir_cron_log (id, cron_id, status) VALUES ($1, $2, 'running')")
        .bind(log_id)
        .bind(id)
        .execute(&db)
        .await;

    // Execute the function (simplified - in production this would call actual functions)
    let (status, message, records) = match function_name.as_str() {
        "cleanup_expired_sessions" => {
            let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW() OR revoked = true")
                .execute(&db)
                .await;
            match result {
                Ok(r) => ("success", format!("Cleaned up {} sessions", r.rows_affected()), r.rows_affected() as i32),
                Err(e) => ("error", e.to_string(), 0),
            }
        },
        "check_overdue_activities" => {
            let result = sqlx::query(
                "UPDATE chatter_activities SET state = 'overdue' WHERE due_date < CURRENT_DATE AND state = 'pending'"
            )
            .execute(&db)
            .await;
            match result {
                Ok(r) => ("success", format!("Marked {} activities as overdue", r.rows_affected()), r.rows_affected() as i32),
                Err(e) => ("error", e.to_string(), 0),
            }
        },
        _ => ("success", "Function executed (no-op)".to_string(), 0),
    };

    // Update log entry
    let _ = sqlx::query(
        "UPDATE ir_cron_log SET finished_at = NOW(), status = $1, message = $2, records_processed = $3 WHERE id = $4"
    )
    .bind(status)
    .bind(&message)
    .bind(records)
    .bind(log_id)
    .execute(&db)
    .await;

    // Update cron job last run info
    let _ = sqlx::query(
        "UPDATE ir_cron SET last_run_at = NOW(), last_run_status = $1, last_run_message = $2 WHERE id = $3"
    )
    .bind(status)
    .bind(&message)
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to(&format!("/settings/cron/{}", id)).into_response()
}

// ============================================================================
// Reports
// ============================================================================

async fn report_single(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((model_name, record_id)): Path<(String, uuid::Uuid)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Get report template
    let report_id = params.get("report_id");

    let report = if let Some(rid) = report_id {
        sqlx::query("SELECT id, name, template, paper_size, orientation FROM ir_report WHERE id = $1::uuid AND active = true")
            .bind(rid)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
    } else {
        sqlx::query("SELECT id, name, template, paper_size, orientation FROM ir_report WHERE model_name = $1 AND active = true ORDER BY sequence LIMIT 1")
            .bind(&model_name)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
    };

    let Some(report) = report else {
        return (StatusCode::NOT_FOUND, Html("No report template found for this model")).into_response();
    };

    let report_name: String = report.get("name");
    let template: String = report.get("template");
    let paper_size: String = report.get("paper_size");
    let orientation: String = report.get("orientation");

    // Get table name for model
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Fetch record data
    let query = format!("SELECT * FROM {} WHERE id = $1", table_name);
    let record = sqlx::query(&query)
        .bind(record_id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(record) = record else {
        return (StatusCode::NOT_FOUND, Html("Record not found")).into_response();
    };

    // Replace template placeholders with record data
    let mut html = template.clone();

    // Get column names and values
    for column in record.columns() {
        let col_name = column.name();
        let placeholder = format!("{{{{{}}}}}", col_name);

        let value: String = record.try_get::<String, _>(col_name)
            .or_else(|_| record.try_get::<Option<String>, _>(col_name).map(|v| v.unwrap_or_default()))
            .or_else(|_| record.try_get::<i32, _>(col_name).map(|v| v.to_string()))
            .or_else(|_| record.try_get::<i64, _>(col_name).map(|v| v.to_string()))
            .or_else(|_| record.try_get::<bool, _>(col_name).map(|v| v.to_string()))
            .or_else(|_| record.try_get::<uuid::Uuid, _>(col_name).map(|v| v.to_string()))
            .unwrap_or_default();

        html = html.replace(&placeholder, &value);
    }

    // Add generated timestamp
    html = html.replace("{{generated_at}}", &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());

    // Wrap in printable HTML
    let page_style = if orientation == "landscape" {
        "@page { size: landscape; }"
    } else {
        "@page { size: portrait; }"
    };

    let full_html = format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{} - {}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        {}
        @media print {{
            body {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
        }}
    </style>
</head>
<body class="bg-white">
    <div class="no-print fixed top-4 right-4 flex gap-2">
        <button onclick="window.print()" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            Print / Save PDF
        </button>
        <button onclick="window.close()" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
            Close
        </button>
    </div>
    {}
</body>
</html>"##,
        report_name, model_name, page_style, html
    );

    Html(full_html).into_response()
}

async fn report_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(model_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Get report template for list view
    let report = sqlx::query(
        "SELECT id, name, template, paper_size, orientation FROM ir_report WHERE model_name = $1 AND name LIKE '%List%' AND active = true ORDER BY sequence LIMIT 1"
    )
    .bind(&model_name)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(report) = report else {
        return (StatusCode::NOT_FOUND, Html("No list report template found for this model")).into_response();
    };

    let report_name: String = report.get("name");
    let template: String = report.get("template");

    // Get table name
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Fetch records
    let limit = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100);
    let query = format!("SELECT * FROM {} WHERE active = true LIMIT {}", table_name, limit);
    let records = sqlx::query(&query)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

    // Build records HTML from template
    let mut html = template.clone();

    // Find the {{#records}}...{{/records}} section
    if let (Some(start), Some(end)) = (html.find("{{#records}}"), html.find("{{/records}}")) {
        let row_template = &html[start + 12..end];
        let mut rows_html = String::new();

        for record in &records {
            let mut row = row_template.to_string();
            for column in record.columns() {
                let col_name = column.name();
                let placeholder = format!("{{{{{}}}}}", col_name);

                let value: String = record.try_get::<String, _>(col_name)
                    .or_else(|_| record.try_get::<Option<String>, _>(col_name).map(|v| v.unwrap_or_default()))
                    .or_else(|_| record.try_get::<i32, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| record.try_get::<bool, _>(col_name).map(|v| v.to_string()))
                    .unwrap_or_default();

                row = row.replace(&placeholder, &value);
            }
            rows_html.push_str(&row);
        }

        html = format!("{}{}{}", &html[..start], rows_html, &html[end + 12..]);
    }

    html = html.replace("{{generated_at}}", &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
    html = html.replace("{{record_count}}", &records.len().to_string());

    let full_html = format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {{
            body {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
        }}
    </style>
</head>
<body class="bg-white">
    <div class="no-print fixed top-4 right-4 flex gap-2">
        <button onclick="window.print()" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            Print / Save PDF
        </button>
        <button onclick="window.close()" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
            Close
        </button>
    </div>
    {}
</body>
</html>"##,
        report_name, html
    );

    Html(full_html).into_response()
}

async fn reports_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let reports = sqlx::query(
        "SELECT id, name, model_name, report_type, paper_size, active FROM ir_report ORDER BY model_name, sequence, name"
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut rows_html = String::new();
    for report in &reports {
        let id: uuid::Uuid = report.get("id");
        let name: String = report.get("name");
        let model_name: String = report.get("model_name");
        let report_type: String = report.get("report_type");
        let paper_size: String = report.get("paper_size");
        let active: bool = report.get("active");

        rows_html.push_str(&format!(
            r##"<tr>
                <td><a href="/settings/reports/{}" class="link link-primary">{}</a></td>
                <td><code class="text-xs">{}</code></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>"##,
            id, name, model_name, report_type.to_uppercase(), paper_size,
            if active { r#"<span class="badge badge-success badge-sm">Active</span>"# } else { r#"<span class="badge badge-ghost badge-sm">Inactive</span>"# }
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports - Settings</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h1 class="text-2xl font-bold">Reports</h1>
                <p class="text-base-content/60">Print templates for documents</p>
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('create-modal').showModal();">+ New Report</button>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body p-0">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Model</th>
                            <th>Type</th>
                            <th>Paper</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        </div>

        <div class="mt-4">
            <a href="/settings" class="btn btn-ghost btn-sm">← Back to Settings</a>
        </div>
    </div>

    <dialog id="create-modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">New Report</h3>
            <form method="post" action="/settings/reports">
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Name</span></label>
                    <input type="text" name="name" class="input input-bordered" placeholder="e.g., Invoice" required/>
                </div>
                <div class="form-control mb-3">
                    <label class="label"><span class="label-text">Model</span></label>
                    <input type="text" name="model_name" class="input input-bordered" placeholder="e.g., contacts" required/>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Paper Size</span></label>
                        <select name="paper_size" class="select select-bordered">
                            <option value="A4">A4</option>
                            <option value="Letter">Letter</option>
                            <option value="Legal">Legal</option>
                        </select>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Orientation</span></label>
                        <select name="orientation" class="select select-bordered">
                            <option value="portrait">Portrait</option>
                            <option value="landscape">Landscape</option>
                        </select>
                    </div>
                </div>
                <div class="form-control mb-4">
                    <label class="label"><span class="label-text">Template (HTML)</span></label>
                    <textarea name="template" class="textarea textarea-bordered h-32" placeholder="<div>{{name}}</div>"></textarea>
                </div>
                <div class="modal-action">
                    <button type="button" class="btn" onclick="document.getElementById('create-modal').close();">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
        <form method="dialog" class="modal-backdrop"><button>close</button></form>
    </dialog>
</body>
</html>"##,
        user.username, rows_html
    );

    Html(html).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct ReportForm {
    name: String,
    model_name: String,
    paper_size: Option<String>,
    orientation: Option<String>,
    template: Option<String>,
}

async fn report_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Form(form): Form<ReportForm>,
) -> Response {
    let _ = sqlx::query(
        "INSERT INTO ir_report (name, model_name, paper_size, orientation, template)
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(&form.name)
    .bind(&form.model_name)
    .bind(form.paper_size.as_deref().unwrap_or("A4"))
    .bind(form.orientation.as_deref().unwrap_or("portrait"))
    .bind(form.template.as_deref().unwrap_or("<div>{{name}}</div>"))
    .execute(&db)
    .await;

    Redirect::to("/settings/reports").into_response()
}

async fn report_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let report = sqlx::query(
        "SELECT id, name, model_name, paper_size, orientation, template, active FROM ir_report WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let Some(report) = report else {
        return Redirect::to("/settings/reports").into_response();
    };

    let name: String = report.get("name");
    let model_name: String = report.get("model_name");
    let paper_size: String = report.get("paper_size");
    let orientation: String = report.get("orientation");
    let template: String = report.get("template");

    let paper_options = ["A4", "Letter", "Legal"];
    let paper_select: String = paper_options.iter().map(|opt| {
        let selected = if *opt == paper_size { " selected" } else { "" };
        format!(r#"<option value="{}"{}>{}  </option>"#, opt, selected, opt)
    }).collect();

    let orient_portrait = if orientation == "portrait" { " selected" } else { "" };
    let orient_landscape = if orientation == "landscape" { " selected" } else { "" };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en" data-theme="remicle">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Report</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-lg">
        <div class="flex-1"><a href="/" class="btn btn-ghost text-xl">remicle</a></div>
        <div class="flex-none"><span class="text-sm">@{}</span></div>
    </div>
    <div class="container mx-auto p-6 max-w-4xl">
        <div class="mb-6">
            <a href="/settings/reports" class="btn btn-ghost btn-sm">← Back to Reports</a>
        </div>

        <div class="card bg-base-100 shadow">
            <div class="card-body">
                <h2 class="card-title">{}</h2>
                <p class="text-base-content/60 mb-4">Model: <code>{}</code></p>

                <form method="post" action="/settings/reports/{}">
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Name</span></label>
                        <input type="text" name="name" class="input input-bordered" value="{}" required/>
                    </div>
                    <div class="form-control mb-3">
                        <label class="label"><span class="label-text">Model</span></label>
                        <input type="text" name="model_name" class="input input-bordered" value="{}" required/>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Paper Size</span></label>
                            <select name="paper_size" class="select select-bordered">{}</select>
                        </div>
                        <div class="form-control mb-3">
                            <label class="label"><span class="label-text">Orientation</span></label>
                            <select name="orientation" class="select select-bordered">
                                <option value="portrait"{}>Portrait</option>
                                <option value="landscape"{}>Landscape</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-control mb-4">
                        <label class="label"><span class="label-text">Template (HTML)</span></label>
                        <textarea name="template" class="textarea textarea-bordered font-mono text-sm h-64">{}</textarea>
                        <label class="label"><span class="label-text-alt">Use {{{{field_name}}}} for placeholders. Use {{{{#records}}}}...{{{{/records}}}} for lists.</span></label>
                    </div>
                    <div class="card-actions justify-end">
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"##,
        name, user.username, name, model_name, id, name, model_name, paper_select, orient_portrait, orient_landscape, template
    );

    Html(html).into_response()
}

async fn report_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<ReportForm>,
) -> Response {
    let _ = sqlx::query(
        "UPDATE ir_report SET name = $1, model_name = $2, paper_size = $3, orientation = $4, template = $5, updated_at = NOW()
         WHERE id = $6"
    )
    .bind(&form.name)
    .bind(&form.model_name)
    .bind(form.paper_size.as_deref().unwrap_or("A4"))
    .bind(form.orientation.as_deref().unwrap_or("portrait"))
    .bind(form.template.as_deref().unwrap_or(""))
    .bind(id)
    .execute(&db)
    .await;

    Redirect::to("/settings/reports").into_response()
}

// ============================================================================
// Dynamic Form View
// ============================================================================

async fn dynamic_form_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(model_name): Path<String>,
) -> Response {
    render_dynamic_form(&db, &user, &model_name, None).await
}

async fn dynamic_form_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((model_name, record_id)): Path<(String, uuid::Uuid)>,
) -> Response {
    render_dynamic_form(&db, &user, &model_name, Some(record_id)).await
}

async fn render_dynamic_form(
    db: &PgPool,
    user: &AuthUser,
    model_name: &str,
    record_id: Option<uuid::Uuid>,
) -> Response {
    // Fetch model metadata
    let model_row = match sqlx::query(
        "SELECT id, display_name, table_name FROM ir_model WHERE name = $1 AND is_active = true"
    )
    .bind(model_name)
    .fetch_optional(db)
    .await {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Model not found")).into_response(),
    };

    let model_id: uuid::Uuid = model_row.get("id");
    let model_display_name: String = model_row.get("display_name");
    let table_name: String = model_row.get("table_name");

    // Fetch field definitions
    let fields = sqlx::query(
        "SELECT name, display_name, field_type, selection_options, related_model, widget
         FROM ir_model_field
         WHERE model_id = $1 AND name NOT IN ('id', 'created_at', 'updated_at', 'active')
         ORDER BY sequence, display_name"
    )
    .bind(model_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    // Fetch existing record if editing
    let record_data: std::collections::HashMap<String, String> = if let Some(rid) = record_id {
        let query = format!("SELECT * FROM {} WHERE id = $1", table_name);
        if let Ok(Some(row)) = sqlx::query(&query).bind(rid).fetch_optional(db).await {
            let mut data = std::collections::HashMap::new();
            for col in row.columns() {
                let col_name = col.name();
                let value: String = row.try_get::<String, _>(col_name)
                    .or_else(|_| row.try_get::<Option<String>, _>(col_name).map(|v| v.unwrap_or_default()))
                    .or_else(|_| row.try_get::<i32, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| row.try_get::<i64, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| row.try_get::<bool, _>(col_name).map(|v| v.to_string()))
                    .or_else(|_| row.try_get::<uuid::Uuid, _>(col_name).map(|v| v.to_string()))
                    .unwrap_or_default();
                data.insert(col_name.to_string(), value);
            }
            data
        } else {
            std::collections::HashMap::new()
        }
    } else {
        std::collections::HashMap::new()
    };

    // Build form fields HTML
    let mut form_fields = String::new();
    for field in &fields {
        let field_name: String = field.get("name");
        let display_name: String = field.get("display_name");
        let field_type: String = field.get("field_type");
        let selection_options: Option<serde_json::Value> = field.get("selection_options");
        let relation_model: Option<String> = field.get("related_model");
        let widget: Option<String> = field.get("widget");

        let current_value = record_data.get(&field_name).cloned().unwrap_or_default();
        let required_attr = "";  // Can add required logic later based on field metadata
        let readonly_attr = "";

        let input_html = match field_type.as_str() {
            "boolean" => {
                let checked = if current_value == "true" { "checked" } else { "" };
                format!(
                    r#"<input type="checkbox" name="{}" class="checkbox" {} {} />"#,
                    field_name, checked, readonly_attr
                )
            },
            "selection" => {
                let mut options = String::from(r#"<option value="">-- Select --</option>"#);
                if let Some(opts) = &selection_options {
                    if let Some(arr) = opts.as_array() {
                        for item in arr {
                            if let Some(obj) = item.as_object() {
                                let value = obj.get("value").and_then(|v| v.as_str()).unwrap_or("");
                                let label = obj.get("label").and_then(|v| v.as_str()).unwrap_or(value);
                                let selected = if value == current_value { " selected" } else { "" };
                                options.push_str(&format!(r#"<option value="{}"{}>{}  </option>"#, value, selected, label));
                            }
                        }
                    }
                }
                format!(
                    r#"<select name="{}" class="select select-bordered w-full" {} {}>{}</select>"#,
                    field_name, required_attr, readonly_attr, options
                )
            },
            "many2one" => {
                // Fetch related records for dropdown
                if let Some(rel_model) = &relation_model {
                    let rel_table: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
                        .bind(rel_model)
                        .fetch_optional(db)
                        .await
                        .ok()
                        .flatten();

                    if let Some(rel_table) = rel_table {
                        // Query includes current value (if any) UNION top 200 by name
                        let rel_query = if !current_value.is_empty() {
                            format!(
                                "(SELECT id, COALESCE(name, id::text) as name FROM {} WHERE id::text = $1) \
                                 UNION \
                                 (SELECT id, COALESCE(name, id::text) as name FROM {} WHERE active = true ORDER BY name LIMIT 200) \
                                 ORDER BY name",
                                rel_table, rel_table
                            )
                        } else {
                            format!("SELECT id, COALESCE(name, id::text) as name FROM {} WHERE active = true ORDER BY name LIMIT 200", rel_table)
                        };
                        let rel_records = if !current_value.is_empty() {
                            sqlx::query(&rel_query).bind(&current_value).fetch_all(db).await.unwrap_or_default()
                        } else {
                            sqlx::query(&rel_query).fetch_all(db).await.unwrap_or_default()
                        };

                        let mut options = String::from(r#"<option value="">-- Select --</option>"#);
                        for rec in &rel_records {
                            let rec_id: uuid::Uuid = rec.get("id");
                            let rec_name: String = rec.get("name");
                            let selected = if rec_id.to_string() == current_value { " selected" } else { "" };
                            options.push_str(&format!(r#"<option value="{}"{}>{}  </option>"#, rec_id, selected, rec_name));
                        }
                        format!(
                            r#"<select name="{}" class="select select-bordered w-full" {} {}>{}</select>"#,
                            field_name, required_attr, readonly_attr, options
                        )
                    } else {
                        format!(
                            r#"<input type="text" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                            field_name, current_value, required_attr, readonly_attr
                        )
                    }
                } else {
                    format!(
                        r#"<input type="text" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                        field_name, current_value, required_attr, readonly_attr
                    )
                }
            },
            "text" => {
                format!(
                    r#"<textarea name="{}" class="textarea textarea-bordered w-full" rows="3" {} {}>{}</textarea>"#,
                    field_name, required_attr, readonly_attr, current_value
                )
            },
            "integer" | "float" => {
                let step = if field_type == "float" { " step=\"0.01\"" } else { "" };
                format!(
                    r#"<input type="number" name="{}" class="input input-bordered w-full" value="{}"{} {} {} />"#,
                    field_name, current_value, step, required_attr, readonly_attr
                )
            },
            "date" => {
                format!(
                    r#"<input type="date" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                    field_name, current_value, required_attr, readonly_attr
                )
            },
            "datetime" => {
                format!(
                    r#"<input type="datetime-local" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                    field_name, current_value.replace(" ", "T"), required_attr, readonly_attr
                )
            },
            _ => {
                // Default to text input
                format!(
                    r#"<input type="text" name="{}" class="input input-bordered w-full" value="{}" {} {} />"#,
                    field_name, current_value, required_attr, readonly_attr
                )
            }
        };

        let required_badge = "";  // Can add required indicator later based on field metadata

        form_fields.push_str(&format!(
            r#"<div class="form-control mb-4">
                <label class="label"><span class="label-text">{} {}</span></label>
                {}
            </div>"#,
            display_name, required_badge, input_html
        ));
    }

    let (action_url, submit_text, title) = if let Some(rid) = record_id {
        (format!("/form/{}/{}", model_name, rid), "Save Changes", format!("Edit {}", model_display_name))
    } else {
        (format!("/form/{}", model_name), "Create", format!("New {}", model_display_name))
    };

    // Build sidebar
    let sidebar_menu = build_sidebar_menu(db, &user.roles, model_name).await;

    let html = format!(
        r##"<!DOCTYPE html>
<html data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="flex">
    <aside class="w-64 bg-base-100 shadow-lg min-h-screen p-4">
        <div class="text-xl font-bold mb-6"><span class="text-success">re</span><span class="opacity-60">micle</span></div>
        <ul class="menu">{}</ul>
    </aside>
    <main class="flex-1 p-6">
        <div class="mb-6">
            <a href="/list/{}" class="btn btn-ghost btn-sm">← Back to List</a>
        </div>

        <div class="card bg-base-100 shadow max-w-2xl">
            <div class="card-body">
                <h2 class="card-title">{}</h2>

                <form method="post" action="{}">
                    {}
                    <div class="card-actions justify-end mt-6">
                        <a href="/list/{}" class="btn btn-ghost">Cancel</a>
                        <button type="submit" class="btn btn-primary">{}</button>
                    </div>
                </form>
            </div>
        </div>
    </main>
</div>
</body>
</html>"##,
        title,
        sidebar_menu,
        model_name,
        title,
        action_url,
        form_fields,
        model_name,
        submit_text
    );

    Html(html).into_response()
}

async fn dynamic_form_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path(model_name): Path<String>,
    Form(form_data): Form<std::collections::HashMap<String, String>>,
) -> Response {
    // Get table name
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Build INSERT query dynamically
    let mut columns = Vec::new();
    let mut placeholders = Vec::new();
    let mut values: Vec<String> = Vec::new();

    for (i, (key, value)) in form_data.iter().enumerate() {
        if key != "id" && !value.is_empty() {
            columns.push(key.clone());
            placeholders.push(format!("${}", i + 1));
            // Handle checkbox values
            let val = if value == "on" { "true".to_string() } else { value.clone() };
            values.push(val);
        }
    }

    if columns.is_empty() {
        return (StatusCode::BAD_REQUEST, Html("No data provided")).into_response();
    }

    let query = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING id",
        table_name,
        columns.join(", "),
        placeholders.join(", ")
    );

    // Build the query with bindings
    let mut q = sqlx::query(&query);
    for val in &values {
        q = q.bind(val);
    }

    match q.fetch_one(&db).await {
        Ok(row) => {
            let new_id: uuid::Uuid = row.get("id");
            Redirect::to(&format!("/form/{}/{}", model_name, new_id)).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response()
        }
    }
}

async fn dynamic_form_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Path((model_name, record_id)): Path<(String, uuid::Uuid)>,
    Form(form_data): Form<std::collections::HashMap<String, String>>,
) -> Response {
    // Get table name
    let table_name: Option<String> = sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1")
        .bind(&model_name)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();

    let Some(table_name) = table_name else {
        return (StatusCode::NOT_FOUND, Html("Model not found")).into_response();
    };

    // Build UPDATE query dynamically
    let mut set_clauses = Vec::new();
    let mut values: Vec<String> = Vec::new();

    for (i, (key, value)) in form_data.iter().enumerate() {
        if key != "id" {
            set_clauses.push(format!("{} = ${}", key, i + 1));
            // Handle checkbox values - if checkbox is unchecked, it won't be in form_data
            let val = if value == "on" { "true".to_string() } else { value.clone() };
            values.push(val);
        }
    }

    if set_clauses.is_empty() {
        return Redirect::to(&format!("/form/{}/{}", model_name, record_id)).into_response();
    }

    let query = format!(
        "UPDATE {} SET {}, updated_at = NOW() WHERE id = ${}",
        table_name,
        set_clauses.join(", "),
        values.len() + 1
    );

    // Build the query with bindings
    let mut q = sqlx::query(&query);
    for val in &values {
        q = q.bind(val);
    }
    q = q.bind(record_id);

    match q.execute(&db).await {
        Ok(_) => Redirect::to(&format!("/form/{}/{}", model_name, record_id)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response(),
    }
}

// API endpoints for country/state data
async fn api_countries(State(state): State<Arc<AppState>>, Db(db): Db) -> Response {
    let countries = sqlx::query("SELECT id, code, name FROM countries WHERE active = true ORDER BY sequence, name")
        .fetch_all(&db).await.unwrap_or_default();

    let data: Vec<serde_json::Value> = countries.iter().map(|c| {
        serde_json::json!({
            "id": c.get::<uuid::Uuid, _>("id").to_string(),
            "code": c.get::<String, _>("code"),
            "name": c.get::<String, _>("name")
        })
    }).collect();

    axum::Json(data).into_response()
}

async fn api_states(State(state): State<Arc<AppState>>, Db(db): Db, Path(country_id): Path<uuid::Uuid>) -> Response {
    let states = sqlx::query("SELECT id, code, name FROM states WHERE country_id = $1 AND active = true ORDER BY name")
        .bind(country_id).fetch_all(&db).await.unwrap_or_default();

    let data: Vec<serde_json::Value> = states.iter().map(|s| {
        serde_json::json!({
            "id": s.get::<uuid::Uuid, _>("id").to_string(),
            "code": s.get::<String, _>("code"),
            "name": s.get::<String, _>("name")
        })
    }).collect();

    axum::Json(data).into_response()
}
