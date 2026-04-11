//! API route definitions

use axum::{
    middleware,
    routing::{get, post, put, delete},
    Router,
};
use tower_http::services::ServeDir;

use crate::middleware::auth::{auth_middleware, require_auth_html};
use crate::state::AppState;
use crate::views::{access, auth, chatter, contacts, dashboard, eam, home, modules, users};

/// Build the main application router
pub fn build_router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        // Static files
        .nest_service("/static", ServeDir::new("crates/vortex-server/static"))
        // Auth pages (HTML)
        .route("/", get(|| async { axum::response::Redirect::to("/login") }))
        .route("/login", get(auth::login_page))
        .route("/auth/login", post(auth::login_submit));

    // Protected HTML routes (redirect to login if not authenticated)
    let protected_html_routes = Router::new()
        // Home (module selection)
        .route("/home", get(home::home_page))
        // Dashboard
        .route("/dashboard", get(dashboard::dashboard_page))
        // User management
        .route("/users", get(users::users_list))
        .route("/users/new", get(users::user_new))
        .route("/users", post(users::user_create))
        .route("/users/{id}/edit", get(users::user_edit))
        .route("/users/{id}", post(users::user_update))
        // Contacts management
        .route("/contacts", get(contacts::contacts_list))
        .route("/contacts/new", get(contacts::contacts_new))
        .route("/contacts", post(contacts::contacts_create))
        .route("/contacts/{id}", get(contacts::contacts_edit))
        .route("/contacts/{id}", post(contacts::contacts_update))
        .route("/contacts/{id}/delete", post(contacts::contacts_delete))
        // Module management (HTML)
        .route("/modules", get(modules::modules_list))
        .route("/modules/{filter}", get(modules::modules_list_with_filter))
        .route("/modules/{id}/install", post(modules::module_install))
        .route("/modules/{id}/uninstall", post(modules::module_uninstall))
        .route("/modules/{id}/upgrade", post(modules::module_upgrade))
        // Access control management (HTML admin UI)
        .nest("/admin/access", access::access_html_routes())
        // EAM routes
        .route("/eam", get(eam::eam_dashboard))
        .route("/eam/sites", get(eam::eam_sites))
        .route("/eam/assets", get(eam::eam_assets))
        .route("/eam/work-orders", get(eam::eam_work_orders))
        .route("/eam/equipment", get(eam::eam_equipment))
        .route("/eam/condition", get(eam::eam_condition_monitoring))
        .route("/eam/manufacturers", get(eam::eam_manufacturers))
        .route("/eam/configuration", get(eam::eam_configuration))
        .route("/eam/inspections", get(eam::eam_inspections))
        .route("/eam/checklists", get(eam::eam_checklists))
        .route("/eam/plans", get(eam::eam_maintenance_plans))
        // Partials for HTMX
        .route("/partials/recent-activity", get(dashboard::recent_activity))
        .route("/partials/system-status", get(dashboard::system_status))
        // Chatter partials
        .nest("/partials/chatter", chatter::chatter_partials())
        // Logout (must be authenticated)
        .route("/auth/logout", post(auth::logout))
        // Apply auth middleware that redirects to login
        .layer(middleware::from_fn_with_state(state.clone(), require_auth_html))
        // Apply base auth context middleware
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Protected API routes (return 401 if not authenticated)
    // Note: this Router is part of the legacy vortex-server path and is
    // NOT the one the CLI binary uses — the CLI composes its own router
    // in commands/server.rs with plugins merged in via PluginRegistry.
    // Plugin routes (EAM, CR, etc.) are contributed by plugin crates at
    // the binary level, not here. This router stays core-only.
    let protected_api_routes = Router::new()
        .nest("/api/auth", api_auth_routes())
        .nest("/api/v1", api_model_routes())
        .nest("/api/modules", api_module_routes())
        .nest("/api/admin", api_admin_routes())
        .nest("/api/access", access::access_routes())
        .nest("/api/chatter", chatter::chatter_routes())
        // Apply auth context middleware
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Combine all routes
    Router::new()
        .merge(public_routes)
        .merge(protected_html_routes)
        .merge(protected_api_routes)
        .with_state(state)
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Readiness check endpoint
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<&'static str, axum::http::StatusCode> {
    // Check database connection
    state
        .db
        .health_check()
        .await
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;

    Ok("READY")
}

/// API Authentication routes
fn api_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(api_login))
        .route("/logout", post(api_logout))
        .route("/refresh", post(api_refresh))
        .route("/me", get(api_me))
        .route("/password", put(api_change_password))
}

/// API Generic model CRUD routes
fn api_model_routes() -> Router<AppState> {
    Router::new()
        .route("/:model", get(model_list))
        .route("/:model", post(model_create))
        .route("/:model/:id", get(model_read))
        .route("/:model/:id", put(model_update))
        .route("/:model/:id", delete(model_delete))
        .route("/:model/batch", post(model_batch))
        .route("/:model/search", post(model_search))
}

/// API Module management routes
fn api_module_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_modules))
        .route("/:id/install", post(install_module))
        .route("/:id/uninstall", post(uninstall_module))
        .route("/:id/upgrade", post(upgrade_module))
}

/// API Admin routes
fn api_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users))
        .route("/users/:id", get(get_user))
        .route("/roles", get(list_roles))
        .route("/audit", get(list_audit_logs))
        .route("/sessions", get(list_sessions))
}

// Placeholder API handlers
async fn api_login() -> &'static str {
    r#"{"success": true}"#
}
async fn api_logout() -> &'static str {
    r#"{"success": true}"#
}
async fn api_refresh() -> &'static str {
    r#"{"success": true}"#
}
async fn api_me() -> &'static str {
    r#"{"id": "1", "name": "Admin"}"#
}
async fn api_change_password() -> &'static str {
    r#"{"success": true}"#
}

async fn model_list() -> &'static str {
    r#"{"data": []}"#
}
async fn model_create() -> &'static str {
    r#"{"success": true}"#
}
async fn model_read() -> &'static str {
    r#"{"data": {}}"#
}
async fn model_update() -> &'static str {
    r#"{"success": true}"#
}
async fn model_delete() -> &'static str {
    r#"{"success": true}"#
}
async fn model_batch() -> &'static str {
    r#"{"success": true}"#
}
async fn model_search() -> &'static str {
    r#"{"data": []}"#
}

async fn list_modules() -> &'static str {
    r#"{"data": []}"#
}
async fn install_module() -> &'static str {
    r#"{"success": true}"#
}
async fn uninstall_module() -> &'static str {
    r#"{"success": true}"#
}
async fn upgrade_module() -> &'static str {
    r#"{"success": true}"#
}

async fn list_users() -> &'static str {
    r#"{"data": []}"#
}
async fn get_user() -> &'static str {
    r#"{"data": {}}"#
}
async fn list_roles() -> &'static str {
    r#"{"data": []}"#
}
async fn list_audit_logs() -> &'static str {
    r#"{"data": []}"#
}
async fn list_sessions() -> &'static str {
    r#"{"data": []}"#
}
