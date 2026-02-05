//! User management views

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;
use vortex_common::Context;
use vortex_orm::prelude::*;

use super::common::generate_csrf_token;
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

/// User data for display
#[derive(Debug, Clone)]
pub struct UserDisplay {
    pub id: Uuid,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub active: bool,
    pub roles: Vec<String>,
    pub company_name: Option<String>,
}

/// Role for selection
#[derive(Debug, Clone)]
pub struct RoleOption {
    pub id: Uuid,
    pub name: String,
    pub selected: bool,
}

/// User list page template
#[derive(Template)]
#[template(path = "pages/users.html")]
pub struct UsersListTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub users: Vec<UserDisplay>,
}

/// User form data for template
#[derive(Debug, Clone, Default)]
pub struct UserFormData {
    pub id: String,
    pub username: String,
    pub name: String,
    pub email: String,
    pub active: bool,
}

/// User edit page template
#[derive(Template)]
#[template(path = "pages/user_edit.html")]
pub struct UserEditTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub form_data: UserFormData,
    pub available_roles: Vec<RoleOption>,
    pub is_new: bool,
}

/// Form data for user create/edit
#[derive(Debug, Deserialize)]
pub struct UserForm {
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub active: Option<String>,
    #[serde(default)]
    pub roles: Vec<Uuid>,
}

/// List all users
pub async fn users_list(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    // Check admin access
    if !is_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let current_user_id = match ctx.user_id {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Html("Unauthorized")).into_response(),
    };

    // Get current user info
    let current_user_name = crate::db::user_lookup::get_user_display_name(&state.db, current_user_id)
        .await
        .unwrap_or_else(|_| "User".to_string());

    let user_initials = current_user_name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();

    // Fetch users with their roles
    let users = fetch_users_list(&state, is_system_admin(&ctx), ctx.company_id).await;

    let template = UsersListTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "users".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        users,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Show user create form
pub async fn user_new(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    if !is_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

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

    // Get available roles
    let available_roles = fetch_available_roles(&state, is_system_admin(&ctx)).await;

    let template = UserEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "users".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data: UserFormData {
            active: true, // Default to active for new users
            ..Default::default()
        },
        available_roles,
        is_new: true,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Show user edit form
pub async fn user_edit(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(user_id): Path<Uuid>,
) -> Response {
    if !is_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

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

    // Fetch user to edit
    let edit_user = match fetch_user_by_id(&state, user_id).await {
        Some(u) => u,
        None => return (StatusCode::NOT_FOUND, Html("User not found")).into_response(),
    };

    // Get available roles with current selections
    let mut available_roles = fetch_available_roles(&state, is_system_admin(&ctx)).await;
    for role in &mut available_roles {
        role.selected = edit_user.roles.contains(&role.name);
    }

    // Convert to form data
    let form_data = UserFormData {
        id: edit_user.id.to_string(),
        username: edit_user.username,
        name: edit_user.name.unwrap_or_default(),
        email: edit_user.email.unwrap_or_default(),
        active: edit_user.active,
    };

    let template = UserEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "users".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data,
        available_roles,
        is_new: false,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Handle user create
pub async fn user_create(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Form(form): Form<UserForm>,
) -> Response {
    if !is_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    // Validate
    if form.username.is_empty() {
        return (StatusCode::BAD_REQUEST, Html("Username is required")).into_response();
    }

    let password = form.password.as_deref().unwrap_or("changeme");
    let password_hash = match vortex_security::PasswordHasher::new().hash(password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response(),
    };

    let dialect = state.db.dialect();
    let user_id = Uuid::now_v7();
    let company_id = ctx.company_id.map(|c| c.0);

    // Insert user with dialect-aware placeholders
    let insert_query = format!(
        r#"
        INSERT INTO users (id, username, name, email, password_hash, active, company_id, created_at, updated_at)
        VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.param_placeholder(5),
        dialect.param_placeholder(6),
        dialect.param_placeholder(7),
        dialect.now_function(),
        dialect.now_function(),
    );

    let result = sqlx::query(&insert_query)
        .bind(user_id)
        .bind(&form.username)
        .bind(&form.name)
        .bind(&form.email)
        .bind(&password_hash)
        .bind(form.active.is_some())
        .bind(company_id)
        .execute(state.db.pool())
        .await;

    if let Err(e) = result {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error creating user: {}", e))).into_response();
    }

    // Assign roles with dialect-aware placeholders
    let role_insert = format!(
        "INSERT INTO user_roles (user_id, role_id) VALUES ({}, {})",
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
    );
    for role_id in &form.roles {
        let _ = sqlx::query(&role_insert)
            .bind(user_id)
            .bind(role_id)
            .execute(state.db.pool())
            .await;
    }

    // Redirect to users list
    axum::response::Redirect::to("/users").into_response()
}

/// Handle user update
pub async fn user_update(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(user_id): Path<Uuid>,
    Form(form): Form<UserForm>,
) -> Response {
    if !is_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();

    // Update user with dialect-aware placeholders
    let update_query = format!(
        r#"
        UPDATE users
        SET username = {}, name = {}, email = {}, active = {}, updated_at = {}
        WHERE id = {}
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.now_function(),
        dialect.param_placeholder(5),
    );

    let result = sqlx::query(&update_query)
        .bind(&form.username)
        .bind(&form.name)
        .bind(&form.email)
        .bind(form.active.is_some())
        .bind(user_id)
        .execute(state.db.pool())
        .await;

    if let Err(e) = result {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error updating user: {}", e))).into_response();
    }

    // Update password if provided
    if let Some(password) = &form.password {
        if !password.is_empty() {
            if let Ok(hash) = vortex_security::PasswordHasher::new().hash(password) {
                let pwd_query = format!(
                    "UPDATE users SET password_hash = {}, password_changed_at = {} WHERE id = {}",
                    dialect.param_placeholder(1),
                    dialect.now_function(),
                    dialect.param_placeholder(2),
                );
                let _ = sqlx::query(&pwd_query)
                    .bind(&hash)
                    .bind(user_id)
                    .execute(state.db.pool())
                    .await;
            }
        }
    }

    // Update roles - delete existing and insert new
    let delete_roles = format!(
        "DELETE FROM user_roles WHERE user_id = {}",
        dialect.param_placeholder(1),
    );
    let _ = sqlx::query(&delete_roles)
        .bind(user_id)
        .execute(state.db.pool())
        .await;

    let role_insert = format!(
        "INSERT INTO user_roles (user_id, role_id) VALUES ({}, {})",
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
    );
    for role_id in &form.roles {
        let _ = sqlx::query(&role_insert)
            .bind(user_id)
            .bind(role_id)
            .execute(state.db.pool())
            .await;
    }

    // Redirect to users list
    axum::response::Redirect::to("/users").into_response()
}

/// Fetch users list from database
async fn fetch_users_list(
    state: &AppState,
    is_system_admin: bool,
    company_id: Option<vortex_common::CompanyId>,
) -> Vec<UserDisplay> {
    let dialect = state.db.dialect();

    // Build role aggregation subquery based on dialect
    let (roles_subquery, empty_array) = match dialect.backend() {
        DatabaseBackend::Postgres => (
            "(SELECT array_agg(r.name) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id)".to_string(),
            "ARRAY[]::text[]".to_string(),
        ),
        #[cfg(feature = "mssql")]
        DatabaseBackend::MsSql => (
            "(SELECT STRING_AGG(r.name, ',') FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id)".to_string(),
            "''".to_string(),
        ),
    };

    let query = if is_system_admin {
        // System admin sees all users
        format!(
            r#"
            SELECT
                u.id, u.username, u.name, u.email, u.active,
                c.name as company_name,
                COALESCE({}, {}) as roles
            FROM users u
            LEFT JOIN companies c ON c.id = u.company_id
            ORDER BY u.username
            "#,
            roles_subquery, empty_array
        )
    } else {
        // Regular admin sees only their company's users
        format!(
            r#"
            SELECT
                u.id, u.username, u.name, u.email, u.active,
                c.name as company_name,
                COALESCE({}, {}) as roles
            FROM users u
            LEFT JOIN companies c ON c.id = u.company_id
            WHERE u.company_id = {}
            ORDER BY u.username
            "#,
            roles_subquery,
            empty_array,
            dialect.param_placeholder(1),
        )
    };

    let rows = if is_system_admin {
        sqlx::query(&query)
            .fetch_all(state.db.pool())
            .await
            .unwrap_or_default()
    } else {
        sqlx::query(&query)
            .bind(company_id.map(|c| c.0).unwrap_or(Uuid::nil()))
            .fetch_all(state.db.pool())
            .await
            .unwrap_or_default()
    };

    rows.iter()
        .map(|row| {
            // Handle roles based on dialect
            let roles: Vec<String> = match dialect.backend() {
                DatabaseBackend::Postgres => row.get("roles"),
                #[cfg(feature = "mssql")]
                DatabaseBackend::MsSql => {
                    let roles_str: String = row.get("roles");
                    if roles_str.is_empty() {
                        Vec::new()
                    } else {
                        roles_str.split(',').map(|s| s.to_string()).collect()
                    }
                }
            };

            UserDisplay {
                id: row.get("id"),
                username: row.get("username"),
                name: row.get("name"),
                email: row.get("email"),
                active: row.get("active"),
                roles,
                company_name: row.get("company_name"),
            }
        })
        .collect()
}

/// Fetch a single user by ID
async fn fetch_user_by_id(state: &AppState, user_id: Uuid) -> Option<UserDisplay> {
    let dialect = state.db.dialect();

    let (roles_subquery, empty_array) = match dialect.backend() {
        DatabaseBackend::Postgres => (
            "(SELECT array_agg(r.name) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id)".to_string(),
            "ARRAY[]::text[]".to_string(),
        ),
        #[cfg(feature = "mssql")]
        DatabaseBackend::MsSql => (
            "(SELECT STRING_AGG(r.name, ',') FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id)".to_string(),
            "''".to_string(),
        ),
    };

    let query = format!(
        r#"
        SELECT
            u.id, u.username, u.name, u.email, u.active,
            c.name as company_name,
            COALESCE({}, {}) as roles
        FROM users u
        LEFT JOIN companies c ON c.id = u.company_id
        WHERE u.id = {}
        "#,
        roles_subquery,
        empty_array,
        dialect.param_placeholder(1),
    );

    let row = sqlx::query(&query)
        .bind(user_id)
        .fetch_optional(state.db.pool())
        .await
        .ok()
        .flatten()?;

    let roles: Vec<String> = match dialect.backend() {
        DatabaseBackend::Postgres => row.get("roles"),
        #[cfg(feature = "mssql")]
        DatabaseBackend::MsSql => {
            let roles_str: String = row.get("roles");
            if roles_str.is_empty() {
                Vec::new()
            } else {
                roles_str.split(',').map(|s| s.to_string()).collect()
            }
        }
    };

    Some(UserDisplay {
        id: row.get("id"),
        username: row.get("username"),
        name: row.get("name"),
        email: row.get("email"),
        active: row.get("active"),
        roles,
        company_name: row.get("company_name"),
    })
}

/// Fetch available roles
async fn fetch_available_roles(state: &AppState, is_system_admin: bool) -> Vec<RoleOption> {
    let dialect = state.db.dialect();

    let query = if is_system_admin {
        "SELECT id, name FROM roles ORDER BY name".to_string()
    } else {
        // Non-system admins can't assign System Administrator role
        format!(
            "SELECT id, name FROM roles WHERE name != {} ORDER BY name",
            dialect.param_placeholder(1),
        )
    };

    let rows = if is_system_admin {
        sqlx::query(&query)
            .fetch_all(state.db.pool())
            .await
            .unwrap_or_default()
    } else {
        sqlx::query(&query)
            .bind("System Administrator")
            .fetch_all(state.db.pool())
            .await
            .unwrap_or_default()
    };

    rows.iter()
        .map(|row| RoleOption {
            id: row.get("id"),
            name: row.get("name"),
            selected: false,
        })
        .collect()
}
