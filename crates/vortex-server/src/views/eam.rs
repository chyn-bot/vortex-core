//! Enterprise Asset Management views

use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use sqlx::Row;
use vortex_common::Context;

use super::common::generate_csrf_token;
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

/// EAM Dashboard statistics
#[derive(Debug, Clone, Default)]
pub struct EamStats {
    pub total_sites: i64,
    pub total_functional_locations: i64,
    pub total_assets: i64,
    pub assets_in_service: i64,
    pub assets_under_maintenance: i64,
    pub assets_faulty: i64,
}

/// EAM Dashboard page template
#[derive(Template)]
#[template(path = "pages/eam/dashboard.html")]
pub struct EamDashboardTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub stats: EamStats,
}

/// EAM Sites list template
#[derive(Template)]
#[template(path = "pages/eam/sites.html")]
pub struct EamSitesTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub sites: Vec<SiteDisplay>,
}

/// Site data for display
#[derive(Debug, Clone)]
pub struct SiteDisplay {
    pub id: String,
    pub code: String,
    pub name: String,
    pub site_type: String,
    pub region: String,
    pub status: String,
    pub asset_count: i64,
}

/// EAM Assets list template
#[derive(Template)]
#[template(path = "pages/eam/assets.html")]
pub struct EamAssetsTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub assets: Vec<AssetDisplay>,
}

/// Asset data for display
#[derive(Debug, Clone)]
pub struct AssetDisplay {
    pub id: String,
    pub asset_number: String,
    pub name: String,
    pub category: String,
    pub site_name: String,
    pub location_name: String,
    pub status: String,
    pub status_color: String,
}

/// EAM Configuration page template
#[derive(Template)]
#[template(path = "pages/eam/configuration.html")]
pub struct EamConfigurationTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub voltage_levels_count: i64,
    pub unit_types_count: i64,
    pub asset_categories_count: i64,
    pub asset_statuses_count: i64,
}

/// EAM Dashboard page
pub async fn eam_dashboard(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    // Get stats from database
    let stats = get_eam_stats(&state, &company_id).await.unwrap_or_default();

    let template = EamDashboardTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_dashboard".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        stats,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// EAM Sites list page
pub async fn eam_sites(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let sites = get_sites(&state, &company_id).await.unwrap_or_default();

    let template = EamSitesTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_sites".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        sites,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// EAM Assets list page
pub async fn eam_assets(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let assets = get_assets(&state, &company_id).await.unwrap_or_default();

    let template = EamAssetsTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_assets".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        assets,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// EAM Configuration page
pub async fn eam_configuration(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    // Get counts for configuration items
    let (voltage_levels_count, unit_types_count, asset_categories_count, asset_statuses_count) =
        get_config_counts(&state, &company_id).await.unwrap_or((0, 0, 0, 0));

    let template = EamConfigurationTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_configuration".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        voltage_levels_count,
        unit_types_count,
        asset_categories_count,
        asset_statuses_count,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

// Helper functions

async fn get_eam_stats(state: &AppState, company_id: &uuid::Uuid) -> Result<EamStats, sqlx::Error> {
    let pool = state.db.pool();

    // Total sites
    let total_sites: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_sites WHERE company_id = $1 AND active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Total functional locations
    let total_functional_locations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_functional_locations WHERE company_id = $1 AND active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Total assets
    let total_assets: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets WHERE company_id = $1 AND active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Assets by status
    let assets_in_service: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM eam_assets a
           JOIN eam_asset_statuses s ON a.status_id = s.id
           WHERE a.company_id = $1 AND a.active = true AND s.code = 'ACTIVE'"#
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let assets_under_maintenance: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM eam_assets a
           JOIN eam_asset_statuses s ON a.status_id = s.id
           WHERE a.company_id = $1 AND a.active = true AND s.code = 'MAINT'"#
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let assets_faulty: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM eam_assets a
           JOIN eam_asset_statuses s ON a.status_id = s.id
           WHERE a.company_id = $1 AND a.active = true AND s.code = 'FAULTY'"#
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok(EamStats {
        total_sites,
        total_functional_locations,
        total_assets,
        assets_in_service,
        assets_under_maintenance,
        assets_faulty,
    })
}

async fn get_sites(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<SiteDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT s.id, s.code, s.name, s.site_type, s.region, s.status,
                  COALESCE((SELECT COUNT(*) FROM eam_assets a
                            JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
                            WHERE fl.site_id = s.id), 0) as asset_count
           FROM eam_sites s
           WHERE s.company_id = $1 AND s.active = true
           ORDER BY s.code"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let sites = rows.iter().map(|row| {
        SiteDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            code: row.get("code"),
            name: row.get("name"),
            site_type: row.get::<Option<String>, _>("site_type").unwrap_or_else(|| "-".to_string()),
            region: row.get::<Option<String>, _>("region").unwrap_or_else(|| "-".to_string()),
            status: row.get::<Option<String>, _>("status").unwrap_or_else(|| "Unknown".to_string()),
            asset_count: row.get("asset_count"),
        }
    }).collect();

    Ok(sites)
}

async fn get_assets(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<AssetDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT a.id, a.asset_number, a.name,
                  c.name as category_name,
                  s.name as site_name,
                  fl.name as location_name,
                  st.name as status_name,
                  st.color as status_color
           FROM eam_assets a
           LEFT JOIN eam_asset_categories c ON a.category_id = c.id
           LEFT JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_asset_statuses st ON a.status_id = st.id
           WHERE a.company_id = $1 AND a.active = true
           ORDER BY a.asset_number
           LIMIT 100"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let assets = rows.iter().map(|row| {
        AssetDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            asset_number: row.get("asset_number"),
            name: row.get("name"),
            category: row.get::<Option<String>, _>("category_name").unwrap_or_else(|| "-".to_string()),
            site_name: row.get::<Option<String>, _>("site_name").unwrap_or_else(|| "-".to_string()),
            location_name: row.get::<Option<String>, _>("location_name").unwrap_or_else(|| "-".to_string()),
            status: row.get::<Option<String>, _>("status_name").unwrap_or_else(|| "Unknown".to_string()),
            status_color: row.get::<Option<String>, _>("status_color").unwrap_or_else(|| "#6C757D".to_string()),
        }
    }).collect();

    Ok(assets)
}

async fn get_config_counts(state: &AppState, company_id: &uuid::Uuid) -> Result<(i64, i64, i64, i64), sqlx::Error> {
    let pool = state.db.pool();

    let voltage_levels: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let unit_types: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_unit_types WHERE company_id = $1 AND is_active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let asset_categories: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_asset_categories WHERE company_id = $1 AND is_active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let asset_statuses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true"
    )
    .bind(company_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok((voltage_levels, unit_types, asset_categories, asset_statuses))
}

// ============================================================================
// WORK ORDERS
// ============================================================================

/// Work Order display data
#[derive(Debug, Clone)]
pub struct WorkOrderDisplay {
    pub id: String,
    pub wo_number: String,
    pub title: String,
    pub asset_name: String,
    pub maintenance_type: String,
    pub priority: String,
    pub priority_color: String,
    pub state: String,
    pub state_color: String,
    pub scheduled_date: Option<String>,
    pub assigned_to: Option<String>,
}

/// Work Orders list template
#[derive(Template)]
#[template(path = "pages/eam/work_orders.html")]
pub struct EamWorkOrdersTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub work_orders: Vec<WorkOrderDisplay>,
    pub stats: WorkOrderStats,
}

#[derive(Debug, Clone, Default)]
pub struct WorkOrderStats {
    pub total: i64,
    pub draft: i64,
    pub scheduled: i64,
    pub in_progress: i64,
    pub on_hold: i64,
    pub completed: i64,
}

/// Work Orders list page
pub async fn eam_work_orders(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let work_orders = get_work_orders(&state, &company_id).await.unwrap_or_default();
    let stats = get_work_order_stats(&state, &company_id).await.unwrap_or_default();

    let template = EamWorkOrdersTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_work_orders".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        work_orders,
        stats,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_work_orders(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<WorkOrderDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start_date,
                  a.name as asset_name,
                  u.full_name as assigned_to
           FROM eam_work_orders wo
           LEFT JOIN eam_assets a ON wo.asset_id = a.id
           LEFT JOIN users u ON wo.assigned_to_id = u.id
           WHERE wo.company_id = $1 AND wo.active = true
           ORDER BY
               CASE wo.state
                   WHEN 'in_progress' THEN 1
                   WHEN 'scheduled' THEN 2
                   WHEN 'on_hold' THEN 3
                   WHEN 'draft' THEN 4
                   ELSE 5
               END,
               wo.scheduled_start_date NULLS LAST
           LIMIT 100"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let work_orders = rows.iter().map(|row| {
        let state: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let priority: String = row.get::<Option<String>, _>("priority").unwrap_or_else(|| "medium".to_string());

        WorkOrderDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            wo_number: row.get("wo_number"),
            title: row.get("title"),
            asset_name: row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string()),
            maintenance_type: row.get::<Option<String>, _>("maintenance_type").unwrap_or_else(|| "-".to_string()),
            priority: priority.clone(),
            priority_color: match priority.as_str() {
                "critical" => "#DC2626".to_string(),
                "high" => "#F97316".to_string(),
                "medium" => "#EAB308".to_string(),
                "low" => "#22C55E".to_string(),
                _ => "#6B7280".to_string(),
            },
            state: state.clone(),
            state_color: match state.as_str() {
                "draft" => "#6B7280".to_string(),
                "scheduled" => "#3B82F6".to_string(),
                "in_progress" => "#F59E0B".to_string(),
                "on_hold" => "#EF4444".to_string(),
                "completed" => "#10B981".to_string(),
                "cancelled" => "#9CA3AF".to_string(),
                _ => "#6B7280".to_string(),
            },
            scheduled_date: row.get::<Option<chrono::NaiveDate>, _>("scheduled_start_date")
                .map(|d| d.format("%d/%m/%Y").to_string()),
            assigned_to: row.get("assigned_to"),
        }
    }).collect();

    Ok(work_orders)
}

async fn get_work_order_stats(state: &AppState, company_id: &uuid::Uuid) -> Result<WorkOrderStats, sqlx::Error> {
    let pool = state.db.pool();

    let row = sqlx::query(
        r#"SELECT
               COUNT(*) as total,
               COUNT(*) FILTER (WHERE state = 'draft') as draft,
               COUNT(*) FILTER (WHERE state = 'scheduled') as scheduled,
               COUNT(*) FILTER (WHERE state = 'in_progress') as in_progress,
               COUNT(*) FILTER (WHERE state = 'on_hold') as on_hold,
               COUNT(*) FILTER (WHERE state = 'completed') as completed
           FROM eam_work_orders
           WHERE company_id = $1 AND active = true"#
    )
    .bind(company_id)
    .fetch_one(pool)
    .await?;

    Ok(WorkOrderStats {
        total: row.get("total"),
        draft: row.get("draft"),
        scheduled: row.get("scheduled"),
        in_progress: row.get("in_progress"),
        on_hold: row.get("on_hold"),
        completed: row.get("completed"),
    })
}

// ============================================================================
// EQUIPMENT
// ============================================================================

/// Equipment display data
#[derive(Debug, Clone)]
pub struct EquipmentDisplay {
    pub id: String,
    pub equipment_type: String,
    pub equipment_code: String,
    pub name: String,
    pub serial_number: Option<String>,
    pub manufacturer: Option<String>,
    pub asset_name: String,
    pub voltage_level: Option<String>,
    pub status: String,
    pub status_color: String,
}

/// Equipment list template
#[derive(Template)]
#[template(path = "pages/eam/equipment.html")]
pub struct EamEquipmentTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub equipment: Vec<EquipmentDisplay>,
    pub equipment_counts: EquipmentCounts,
    pub filter: String,
}

#[derive(Debug, Clone, Default)]
pub struct EquipmentCounts {
    pub transformers: i64,
    pub switchgear: i64,
    pub rmu: i64,
    pub batteries: i64,
    pub ct_vt: i64,
    pub surge_arresters: i64,
    pub cables: i64,
    pub busbars: i64,
    pub isolators: i64,
    pub earthing: i64,
}

/// Equipment list page
pub async fn eam_equipment(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();
    let filter = params.get("type").cloned().unwrap_or_else(|| "all".to_string());

    let equipment = get_equipment(&state, &company_id, &filter).await.unwrap_or_default();
    let equipment_counts = get_equipment_counts(&state, &company_id).await.unwrap_or_default();

    let template = EamEquipmentTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_equipment".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        equipment,
        equipment_counts,
        filter,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_equipment(state: &AppState, company_id: &uuid::Uuid, filter: &str) -> Result<Vec<EquipmentDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    // Query all equipment types with UNION ALL
    let base_query = r#"
        SELECT id, 'Transformer' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_transformers WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Switchgear' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_switchgear WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'RMU' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_ring_main_units WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Battery' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, NULL as voltage_level_id, operational_status
        FROM eam_batteries WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'CT/VT' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_ct_vt WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Surge Arrester' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_surge_arresters WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Cable' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_cables WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Busbar' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_busbars WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Isolator' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, voltage_level_id, operational_status
        FROM eam_isolators WHERE company_id = $1 AND active = true
        UNION ALL
        SELECT id, 'Earthing System' as equipment_type, equipment_code, name, serial_number,
               asset_id, manufacturer_id, NULL as voltage_level_id, operational_status
        FROM eam_earthing_systems WHERE company_id = $1 AND active = true
    "#;

    let query = if filter != "all" {
        let type_filter = match filter {
            "transformer" => "Transformer",
            "switchgear" => "Switchgear",
            "rmu" => "RMU",
            "battery" => "Battery",
            "ct_vt" => "CT/VT",
            "surge_arrester" => "Surge Arrester",
            "cable" => "Cable",
            "busbar" => "Busbar",
            "isolator" => "Isolator",
            "earthing" => "Earthing System",
            _ => "all",
        };
        if type_filter != "all" {
            format!(
                "SELECT e.*, a.name as asset_name, m.name as manufacturer_name, v.name as voltage_name
                 FROM ({}) e
                 LEFT JOIN eam_assets a ON e.asset_id = a.id
                 LEFT JOIN eam_manufacturers m ON e.manufacturer_id = m.id
                 LEFT JOIN eam_voltage_levels v ON e.voltage_level_id = v.id
                 WHERE e.equipment_type = '{}'
                 ORDER BY e.equipment_code LIMIT 100",
                base_query, type_filter
            )
        } else {
            format!(
                "SELECT e.*, a.name as asset_name, m.name as manufacturer_name, v.name as voltage_name
                 FROM ({}) e
                 LEFT JOIN eam_assets a ON e.asset_id = a.id
                 LEFT JOIN eam_manufacturers m ON e.manufacturer_id = m.id
                 LEFT JOIN eam_voltage_levels v ON e.voltage_level_id = v.id
                 ORDER BY e.equipment_type, e.equipment_code LIMIT 100",
                base_query
            )
        }
    } else {
        format!(
            "SELECT e.*, a.name as asset_name, m.name as manufacturer_name, v.name as voltage_name
             FROM ({}) e
             LEFT JOIN eam_assets a ON e.asset_id = a.id
             LEFT JOIN eam_manufacturers m ON e.manufacturer_id = m.id
             LEFT JOIN eam_voltage_levels v ON e.voltage_level_id = v.id
             ORDER BY e.equipment_type, e.equipment_code LIMIT 100",
            base_query
        )
    };

    let rows = sqlx::query(&query)
        .bind(company_id)
        .fetch_all(pool)
        .await?;

    let equipment = rows.iter().map(|row| {
        let status: String = row.get::<Option<String>, _>("operational_status").unwrap_or_else(|| "unknown".to_string());

        EquipmentDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            equipment_type: row.get("equipment_type"),
            equipment_code: row.get("equipment_code"),
            name: row.get("name"),
            serial_number: row.get("serial_number"),
            manufacturer: row.get("manufacturer_name"),
            asset_name: row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string()),
            voltage_level: row.get("voltage_name"),
            status: status.clone(),
            status_color: match status.as_str() {
                "in_service" => "#10B981".to_string(),
                "out_of_service" => "#EF4444".to_string(),
                "under_maintenance" => "#F59E0B".to_string(),
                "standby" => "#3B82F6".to_string(),
                "decommissioned" => "#6B7280".to_string(),
                _ => "#9CA3AF".to_string(),
            },
        }
    }).collect();

    Ok(equipment)
}

async fn get_equipment_counts(state: &AppState, company_id: &uuid::Uuid) -> Result<EquipmentCounts, sqlx::Error> {
    let pool = state.db.pool();

    let transformers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transformers WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let switchgear: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_switchgear WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let rmu: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_ring_main_units WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let batteries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_batteries WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let ct_vt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_ct_vt WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let surge_arresters: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_surge_arresters WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let cables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_cables WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let busbars: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_busbars WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let isolators: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_isolators WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let earthing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_earthing_systems WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);

    Ok(EquipmentCounts {
        transformers,
        switchgear,
        rmu,
        batteries,
        ct_vt,
        surge_arresters,
        cables,
        busbars,
        isolators,
        earthing,
    })
}

// ============================================================================
// CONDITION MONITORING
// ============================================================================

/// DGA Analysis display data
#[derive(Debug, Clone)]
pub struct DgaDisplay {
    pub id: String,
    pub equipment_code: String,
    pub equipment_name: String,
    pub sample_date: String,
    pub hydrogen: f64,
    pub hydrogen_display: String,
    pub methane: f64,
    pub methane_display: String,
    pub ethane: f64,
    pub ethane_display: String,
    pub ethylene: f64,
    pub ethylene_display: String,
    pub acetylene: f64,
    pub acetylene_display: String,
    pub tcg: f64,
    pub tcg_display: String,
    pub fault_type: Option<String>,
    pub status: String,
    pub status_color: String,
}

/// Condition Monitoring template
#[derive(Template)]
#[template(path = "pages/eam/condition_monitoring.html")]
pub struct EamConditionMonitoringTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub dga_results: Vec<DgaDisplay>,
    pub condition_stats: ConditionStats,
}

#[derive(Debug, Clone, Default)]
pub struct ConditionStats {
    pub dga_tests: i64,
    pub oil_quality_tests: i64,
    pub thermal_scans: i64,
    pub pd_tests: i64,
    pub ir_tests: i64,
    pub critical_alerts: i64,
}

/// Condition Monitoring page
pub async fn eam_condition_monitoring(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let dga_results = get_dga_results(&state, &company_id).await.unwrap_or_default();
    let condition_stats = get_condition_stats(&state, &company_id).await.unwrap_or_default();

    let template = EamConditionMonitoringTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_condition".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        dga_results,
        condition_stats,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_dga_results(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<DgaDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT d.id, d.sample_date, d.hydrogen_ppm, d.methane_ppm, d.ethane_ppm,
                  d.ethylene_ppm, d.acetylene_ppm, d.total_combustible_gas,
                  d.fault_type, d.ieee_status,
                  t.equipment_code, t.name as equipment_name
           FROM eam_dga_analyses d
           JOIN eam_transformers t ON d.transformer_id = t.id
           WHERE d.company_id = $1 AND d.active = true
           ORDER BY d.sample_date DESC
           LIMIT 50"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let results = rows.iter().map(|row| {
        let status: String = row.get::<Option<String>, _>("ieee_status").unwrap_or_else(|| "unknown".to_string());
        let hydrogen = row.get::<Option<f64>, _>("hydrogen_ppm").unwrap_or(0.0);
        let methane = row.get::<Option<f64>, _>("methane_ppm").unwrap_or(0.0);
        let ethane = row.get::<Option<f64>, _>("ethane_ppm").unwrap_or(0.0);
        let ethylene = row.get::<Option<f64>, _>("ethylene_ppm").unwrap_or(0.0);
        let acetylene = row.get::<Option<f64>, _>("acetylene_ppm").unwrap_or(0.0);
        let tcg = row.get::<Option<f64>, _>("total_combustible_gas").unwrap_or(0.0);

        DgaDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            equipment_code: row.get("equipment_code"),
            equipment_name: row.get("equipment_name"),
            sample_date: row.get::<chrono::NaiveDate, _>("sample_date").format("%d/%m/%Y").to_string(),
            hydrogen,
            hydrogen_display: format!("{:.0}", hydrogen),
            methane,
            methane_display: format!("{:.0}", methane),
            ethane,
            ethane_display: format!("{:.0}", ethane),
            ethylene,
            ethylene_display: format!("{:.0}", ethylene),
            acetylene,
            acetylene_display: format!("{:.1}", acetylene),
            tcg,
            tcg_display: format!("{:.0}", tcg),
            fault_type: row.get("fault_type"),
            status: status.clone(),
            status_color: match status.as_str() {
                "normal" => "#10B981".to_string(),
                "caution" => "#EAB308".to_string(),
                "warning" => "#F97316".to_string(),
                "critical" => "#EF4444".to_string(),
                _ => "#6B7280".to_string(),
            },
        }
    }).collect();

    Ok(results)
}

async fn get_condition_stats(state: &AppState, company_id: &uuid::Uuid) -> Result<ConditionStats, sqlx::Error> {
    let pool = state.db.pool();

    let dga_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_dga_analyses WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let oil_quality_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_oil_quality_tests WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let thermal_scans: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_thermal_imaging WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let pd_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_partial_discharge WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);
    let ir_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_insulation_resistance WHERE company_id = $1 AND active = true")
        .bind(company_id).fetch_one(pool).await.unwrap_or(0);

    let critical_alerts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_dga_analyses WHERE company_id = $1 AND active = true AND ieee_status = 'critical'"
    ).bind(company_id).fetch_one(pool).await.unwrap_or(0);

    Ok(ConditionStats {
        dga_tests,
        oil_quality_tests,
        thermal_scans,
        pd_tests,
        ir_tests,
        critical_alerts,
    })
}

// ============================================================================
// MANUFACTURERS
// ============================================================================

/// Manufacturer display data
#[derive(Debug, Clone)]
pub struct ManufacturerDisplay {
    pub id: String,
    pub code: String,
    pub name: String,
    pub country: Option<String>,
    pub website: Option<String>,
    pub is_approved: bool,
    pub equipment_count: i64,
}

/// Manufacturers list template
#[derive(Template)]
#[template(path = "pages/eam/manufacturers.html")]
pub struct EamManufacturersTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub manufacturers: Vec<ManufacturerDisplay>,
}

/// Manufacturers list page
pub async fn eam_manufacturers(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let manufacturers = get_manufacturers(&state, &company_id).await.unwrap_or_default();

    let template = EamManufacturersTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_manufacturers".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        manufacturers,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_manufacturers(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<ManufacturerDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT m.id, m.code, m.name, m.country_code, m.website, m.is_approved,
                  (SELECT COUNT(*) FROM eam_transformers WHERE manufacturer_id = m.id AND active = true) +
                  (SELECT COUNT(*) FROM eam_switchgear WHERE manufacturer_id = m.id AND active = true) +
                  (SELECT COUNT(*) FROM eam_batteries WHERE manufacturer_id = m.id AND active = true) as equipment_count
           FROM eam_manufacturers m
           WHERE m.company_id = $1 AND m.active = true
           ORDER BY m.name"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let manufacturers = rows.iter().map(|row| {
        ManufacturerDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            code: row.get("code"),
            name: row.get("name"),
            country: row.get("country_code"),
            website: row.get("website"),
            is_approved: row.get::<Option<bool>, _>("is_approved").unwrap_or(false),
            equipment_count: row.get("equipment_count"),
        }
    }).collect();

    Ok(manufacturers)
}

// ============================================================================
// INSPECTIONS
// ============================================================================

#[derive(Debug, Clone)]
pub struct InspectionDisplay {
    pub id: String,
    pub inspection_code: String,
    pub asset_name: String,
    pub inspection_type: String,
    pub inspection_date: String,
    pub inspector_name: String,
    pub overall_condition: String,
    pub condition_color: String,
    pub state: String,
    pub state_color: String,
}

#[derive(Template)]
#[template(path = "pages/eam/inspections.html")]
pub struct EamInspectionsTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub inspections: Vec<InspectionDisplay>,
}

pub async fn eam_inspections(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let inspections = get_inspections(&state, &company_id).await.unwrap_or_default();

    let template = EamInspectionsTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_inspections".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        inspections,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_inspections(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<InspectionDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT ir.id, ir.inspection_code, ir.inspection_type, ir.inspection_date,
                  ir.overall_condition, ir.state,
                  a.name as asset_name,
                  u.display_name as inspector_name
           FROM eam_inspection_results ir
           LEFT JOIN eam_assets a ON a.id = ir.asset_id
           LEFT JOIN users u ON u.id = ir.inspector_id
           WHERE ir.company_id = $1
           ORDER BY ir.inspection_date DESC
           LIMIT 100"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let inspections = rows.iter().map(|row| {
        let state: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let condition: String = row.get::<Option<String>, _>("overall_condition").unwrap_or_else(|| "-".to_string());

        InspectionDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            inspection_code: row.get::<Option<String>, _>("inspection_code").unwrap_or_else(|| "-".to_string()),
            asset_name: row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string()),
            inspection_type: row.get::<Option<String>, _>("inspection_type").unwrap_or_else(|| "-".to_string()),
            inspection_date: row.get::<chrono::DateTime<chrono::Utc>, _>("inspection_date")
                .format("%d/%m/%Y").to_string(),
            inspector_name: row.get::<Option<String>, _>("inspector_name").unwrap_or_else(|| "-".to_string()),
            overall_condition: condition.clone(),
            condition_color: match condition.as_str() {
                "good" | "excellent" => "#10B981".to_string(),
                "acceptable" | "fair" => "#F59E0B".to_string(),
                "marginal" | "poor" => "#EF4444".to_string(),
                _ => "#6B7280".to_string(),
            },
            state: state.clone(),
            state_color: match state.as_str() {
                "draft" => "#6B7280".to_string(),
                "submitted" => "#3B82F6".to_string(),
                "approved" => "#10B981".to_string(),
                "rejected" => "#EF4444".to_string(),
                _ => "#6B7280".to_string(),
            },
        }
    }).collect();

    Ok(inspections)
}

// ============================================================================
// CHECKLISTS
// ============================================================================

#[derive(Debug, Clone)]
pub struct ChecklistTemplateDisplay {
    pub id: String,
    pub name: String,
    pub equipment_category: String,
    pub maintenance_type: String,
    pub version: i32,
    pub is_active: bool,
    pub item_count: i64,
}

#[derive(Template)]
#[template(path = "pages/eam/checklists.html")]
pub struct EamChecklistsTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub templates: Vec<ChecklistTemplateDisplay>,
}

pub async fn eam_checklists(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let templates = get_checklist_templates(&state, &company_id).await.unwrap_or_default();

    let template = EamChecklistsTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_checklists".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        templates,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_checklist_templates(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<ChecklistTemplateDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT ct.id, ct.name, ct.equipment_category, ct.maintenance_type,
                  COALESCE(ct.version, 1) as version,
                  COALESCE(ct.is_active, true) as is_active,
                  (SELECT COUNT(*) FROM eam_checklist_template_items WHERE template_id = ct.id) as item_count
           FROM eam_checklist_templates ct
           WHERE ct.company_id = $1
           ORDER BY ct.name"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let templates = rows.iter().map(|row| {
        ChecklistTemplateDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            name: row.get("name"),
            equipment_category: row.get("equipment_category"),
            maintenance_type: row.get("maintenance_type"),
            version: row.get("version"),
            is_active: row.get("is_active"),
            item_count: row.get("item_count"),
        }
    }).collect();

    Ok(templates)
}

// ============================================================================
// MAINTENANCE PLANS
// ============================================================================

#[derive(Debug, Clone)]
pub struct MaintenancePlanDisplay {
    pub id: String,
    pub plan_code: String,
    pub asset_name: String,
    pub maintenance_type: String,
    pub frequency: String,
    pub next_date: String,
    pub state: String,
    pub state_color: String,
}

#[derive(Template)]
#[template(path = "pages/eam/maintenance_plans.html")]
pub struct EamMaintenancePlansTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub plans: Vec<MaintenancePlanDisplay>,
}

pub async fn eam_maintenance_plans(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
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

    let company_id = ctx.company_id.map(|c| c.0).unwrap_or_default();

    let plans = get_maintenance_plans(&state, &company_id).await.unwrap_or_default();

    let template = EamMaintenancePlansTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "eam_plans".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        plans,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn get_maintenance_plans(state: &AppState, company_id: &uuid::Uuid) -> Result<Vec<MaintenancePlanDisplay>, sqlx::Error> {
    let pool = state.db.pool();

    let rows = sqlx::query(
        r#"SELECT mp.id, mp.plan_code, mp.maintenance_type,
                  mp.frequency_interval, mp.frequency_unit,
                  mp.next_maintenance_date, mp.state,
                  a.name as asset_name
           FROM eam_maintenance_plans mp
           LEFT JOIN eam_assets a ON a.id = mp.asset_id
           WHERE mp.company_id = $1
           ORDER BY mp.created_at DESC NULLS LAST
           LIMIT 100"#
    )
    .bind(company_id)
    .fetch_all(pool)
    .await?;

    let plans = rows.iter().map(|row| {
        let state: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let freq_interval: Option<i32> = row.get("frequency_interval");
        let freq_unit: Option<String> = row.get("frequency_unit");
        let frequency = match (freq_interval, freq_unit) {
            (Some(i), Some(u)) => format!("Every {} {}{}", i, u, if i > 1 { "s" } else { "" }),
            _ => "-".to_string(),
        };

        MaintenancePlanDisplay {
            id: row.get::<uuid::Uuid, _>("id").to_string(),
            plan_code: row.get::<Option<String>, _>("plan_code").unwrap_or_else(|| "-".to_string()),
            asset_name: row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string()),
            maintenance_type: row.get::<Option<String>, _>("maintenance_type").unwrap_or_else(|| "-".to_string()),
            frequency,
            next_date: row.get::<Option<String>, _>("next_maintenance_date").unwrap_or_else(|| "-".to_string()),
            state: state.clone(),
            state_color: match state.as_str() {
                "draft" => "#6B7280".to_string(),
                "active" => "#10B981".to_string(),
                "done" => "#3B82F6".to_string(),
                "cancelled" => "#9CA3AF".to_string(),
                _ => "#6B7280".to_string(),
            },
        }
    }).collect();

    Ok(plans)
}
