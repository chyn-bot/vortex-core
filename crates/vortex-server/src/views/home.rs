//! Home page view - Module selection screen

use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use vortex_common::Context;

use super::common::generate_csrf_token;
use crate::db::user_lookup::get_user_display_name;
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

/// Module card data for the home page
pub struct ModuleCard {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub icon: &'static str,
    pub href: &'static str,
    pub color: &'static str,
    pub admin_only: bool,
    pub system_admin_only: bool,
}

/// Home page template
#[derive(Template)]
#[template(path = "pages/home.html")]
pub struct HomeTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub modules: Vec<ModuleCard>,
    pub is_admin: bool,
    pub is_system_admin: bool,
}

/// Get available modules based on user role
fn get_modules(is_admin: bool, is_system_admin: bool) -> Vec<ModuleCard> {
    let mut modules = vec![
        ModuleCard {
            id: "dashboard",
            name: "Dashboard",
            description: "View system overview, statistics, and recent activity",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>"#,
            href: "/dashboard",
            color: "primary",
            admin_only: false,
            system_admin_only: false,
        },
        ModuleCard {
            id: "contacts",
            name: "Contacts",
            description: "Manage contacts and stakeholder information",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>"#,
            href: "/contacts",
            color: "secondary",
            admin_only: false,
            system_admin_only: false,
        },
        ModuleCard {
            id: "eam",
            name: "Asset Management",
            description: "Manage substations, equipment, and maintenance schedules",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>"#,
            href: "/eam",
            color: "warning",
            admin_only: false,
            system_admin_only: false,
        },
        ModuleCard {
            id: "modules",
            name: "Modules",
            description: "Browse and manage installed system modules",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/>"#,
            href: "/modules",
            color: "accent",
            admin_only: false,
            system_admin_only: false,
        },
    ];

    // Admin-only modules
    if is_admin {
        modules.push(ModuleCard {
            id: "users",
            name: "User Management",
            description: "Create, edit, and manage user accounts and permissions",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m9 5.197v-1"/>"#,
            href: "/users",
            color: "info",
            admin_only: true,
            system_admin_only: false,
        });
    }

    // System admin-only modules
    if is_system_admin {
        modules.push(ModuleCard {
            id: "access",
            name: "Access Control",
            description: "Configure roles, permissions, and security policies",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>"#,
            href: "/admin/access",
            color: "warning",
            admin_only: false,
            system_admin_only: true,
        });

        modules.push(ModuleCard {
            id: "audit",
            name: "Audit Log",
            description: "View system audit trail and compliance reports",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/>"#,
            href: "/audit",
            color: "error",
            admin_only: false,
            system_admin_only: true,
        });

        modules.push(ModuleCard {
            id: "settings",
            name: "System Settings",
            description: "Configure system-wide settings and preferences",
            icon: r#"<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>"#,
            href: "/settings",
            color: "neutral",
            admin_only: false,
            system_admin_only: true,
        });
    }

    modules
}

/// Show home page
pub async fn home_page(
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

    // Get available modules based on role
    let modules = get_modules(user_is_admin, user_is_system_admin);

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

    let template = HomeTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "home".to_string(),
        modules,
        is_admin: user_is_admin,
        is_system_admin: user_is_system_admin,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}
