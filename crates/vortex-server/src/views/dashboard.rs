//! Dashboard views

use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use sqlx::Row;
use vortex_common::Context;
use vortex_orm::prelude::*;

use super::common::{generate_csrf_token, DashboardStats};
use crate::db::user_lookup::get_user_display_name;
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

/// Dashboard page template
#[derive(Template)]
#[template(path = "pages/dashboard.html")]
pub struct DashboardTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub stats: DashboardStats,
    pub is_admin: bool,
    pub is_system_admin: bool,
}

/// Fetch admin stats (all companies)
async fn fetch_admin_stats(state: &AppState) -> DashboardStats {
    let dialect = state.db.dialect();

    // Query total users
    let total_users = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0) as u32;

    // Query active users with dialect-aware bool literal
    let active_query = format!(
        "SELECT COUNT(*) FROM users WHERE active = {}",
        dialect.bool_literal(true)
    );
    let active_users = sqlx::query_scalar::<_, i64>(&active_query)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0) as u32;

    // Query total companies
    let total_companies = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM companies")
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0) as u32;

    // Get audit events in last 24 hours using dialect-aware date math
    let audit_query = format!(
        "SELECT COUNT(*) FROM audit_log WHERE timestamp > {}",
        dialect.date_subtract_hours(24)
    );
    let audit_events_24h = sqlx::query_scalar::<_, i64>(&audit_query)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(0) as u32;

    // Get active sessions
    let active_sessions = state.sessions.session_count().await as u32;

    DashboardStats {
        total_users,
        active_users,
        total_companies,
        installed_modules: 2, // TODO: Get from module loader
        available_modules: 10,
        audit_events_24h,
        active_sessions,
    }
}

/// Fetch user stats (company-scoped)
async fn fetch_user_stats(state: &AppState, company_id: Option<vortex_common::CompanyId>) -> DashboardStats {
    let dialect = state.db.dialect();
    let company_filter = company_id.map(|c| c.0);

    // Query users in company
    let total_users = if let Some(cid) = company_filter {
        let query = format!(
            "SELECT COUNT(*) FROM users WHERE company_id = {}",
            dialect.param_placeholder(1)
        );
        sqlx::query_scalar::<_, i64>(&query)
            .bind(cid)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0) as u32
    } else {
        0
    };

    let active_users = if let Some(cid) = company_filter {
        let query = format!(
            "SELECT COUNT(*) FROM users WHERE company_id = {} AND active = {}",
            dialect.param_placeholder(1),
            dialect.bool_literal(true)
        );
        sqlx::query_scalar::<_, i64>(&query)
            .bind(cid)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0) as u32
    } else {
        0
    };

    // Get active sessions for current user only
    let active_sessions = 1; // Current session

    DashboardStats {
        total_users,
        active_users,
        total_companies: 1, // User sees only their company
        installed_modules: 2,
        available_modules: 10,
        audit_events_24h: 0, // Not shown to regular users
        active_sessions,
    }
}

/// Show dashboard page
pub async fn dashboard_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    // Get user ID or return error
    let user_id = match ctx.user_id {
        Some(id) => id,
        None => {
            return (StatusCode::UNAUTHORIZED, Html("Unauthorized")).into_response();
        }
    };

    // Check user roles
    let user_is_system_admin = is_system_admin(&ctx);
    let user_is_admin = is_admin(&ctx);

    // Fetch appropriate stats based on role
    let stats = if user_is_admin {
        fetch_admin_stats(&state).await
    } else {
        fetch_user_stats(&state, ctx.company_id).await
    };

    // Get user display name
    let user_name = get_user_display_name(&state.db, user_id)
        .await
        .unwrap_or_else(|_| "User".to_string());

    // Generate initials
    let user_initials = user_name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();

    let template = DashboardTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "dashboard".to_string(),
        stats,
        is_admin: user_is_admin,
        is_system_admin: user_is_system_admin,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Recent activity partial
pub async fn recent_activity() -> impl IntoResponse {
    Html(r#"
        <table class="table table-sm">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Resource</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td class="text-base-content/60">Just now</td>
                    <td>Admin User</td>
                    <td><span class="badge badge-info badge-sm">Login</span></td>
                    <td>Session</td>
                </tr>
                <tr>
                    <td class="text-base-content/60">2 min ago</td>
                    <td>System</td>
                    <td><span class="badge badge-success badge-sm">Startup</span></td>
                    <td>Vortex Core</td>
                </tr>
                <tr>
                    <td class="text-base-content/60">5 min ago</td>
                    <td>System</td>
                    <td><span class="badge badge-primary badge-sm">Load</span></td>
                    <td>Base Module</td>
                </tr>
            </tbody>
        </table>
    "#)
}

/// System status partial
pub async fn system_status() -> impl IntoResponse {
    Html(r#"
        <div class="space-y-3">
            <div class="flex items-center justify-between">
                <span>Database</span>
                <span class="badge badge-success">Connected</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Sessions</span>
                <span class="badge badge-info">1</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Compliance</span>
                <span class="badge badge-success">Active</span>
            </div>
            <div class="flex items-center justify-between">
                <span>Audit Logging</span>
                <span class="badge badge-success">Enabled</span>
            </div>
        </div>
    "#)
}
