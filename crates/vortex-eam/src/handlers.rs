//! EAM HTTP Handlers
//!
//! REST API handlers for the EAM module. Provides CRUD endpoints for all
//! EAM entities, plus domain-specific actions (state transitions, checklist
//! generation, maintenance plan execution).
//!
//! These handlers extract `Arc<ConnectionPool>` from request extensions,
//! which is injected by the auth middleware's DatabaseContext.

use std::sync::Arc;

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vortex_orm::ConnectionPool;

use crate::services;

// ============================================================================
// COMMON TYPES
// ============================================================================

/// Standard API error response
#[derive(Serialize)]
pub struct ApiError {
    pub success: bool,
    pub error: String,
}

/// List query parameters (pagination + filtering)
#[derive(Deserialize, Default)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub search: Option<String>,
    pub state: Option<String>,
    pub asset_id: Option<String>,
}

/// Portal query parameters (include user_id for scoping)
#[derive(Deserialize, Default)]
pub struct PortalListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub search: Option<String>,
    pub state: Option<String>,
    pub user_id: Uuid,
}

/// Portal save request for work details
#[derive(Deserialize)]
pub struct PortalSaveRequest {
    pub user_id: Uuid,
    pub work_description: Option<String>,
    pub findings: Option<String>,
    pub actions_taken: Option<String>,
    pub recommendations: Option<String>,
    pub labor_cost: Option<f64>,
}

/// Portal checklist save request
#[derive(Deserialize)]
pub struct PortalChecklistSaveRequest {
    pub user_id: Uuid,
    pub line_id: Uuid,
    /// Value varies by input type: "pass"/"fail", "yes"/"no", numeric string, text, etc.
    pub value: String,
    pub note: Option<String>,
}

/// Portal maintenance request from equipment page
#[derive(Deserialize)]
pub struct PortalMaintenanceRequest {
    pub user_id: Uuid,
    pub description: Option<String>,
    pub priority: Option<i32>,
}

/// Equipment lookup query
#[derive(Deserialize)]
pub struct EquipmentLookupParams {
    pub q: String,
    pub user_id: Uuid,
}

// ---- Wizard request types ----

/// Batch maintenance creation request
#[derive(Deserialize)]
pub struct CreateMaintenanceWizardRequest {
    pub user_id: Uuid,
    pub company_id: Uuid,
    /// One or more equipment IDs to create WOs for
    pub equipment_ids: Vec<Uuid>,
    pub maintenance_type: String,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub scheduled_date: Option<String>,
    pub planned_duration_hours: Option<f64>,
    pub assigned_to: Option<Uuid>,
    pub work_description: Option<String>,
}

/// Substation hierarchy creation request
#[derive(Deserialize)]
pub struct CreateHierarchyWizardRequest {
    pub user_id: Uuid,
    pub company_id: Uuid,
    pub substation: HierarchySubstation,
    pub bays: Vec<HierarchyBay>,
}

#[derive(Deserialize)]
pub struct HierarchySubstation {
    pub site_id: Uuid,
    pub name: String,
    pub code: String,
    pub substation_type: Option<String>,
    pub busbar_configuration: Option<String>,
    pub voltage_level_id: Option<Uuid>,
    pub ownership: Option<String>,
    pub commissioning_date: Option<String>,
    pub design_life_years: Option<i32>,
}

#[derive(Deserialize)]
pub struct HierarchyBay {
    pub name: String,
    pub code: String,
    pub bay_type: Option<String>,
    pub voltage_level_id: Option<Uuid>,
    pub rated_current_a: Option<f64>,
    pub feeder_name: Option<String>,
    pub equipment: Vec<HierarchyEquipment>,
}

#[derive(Deserialize)]
pub struct HierarchyEquipment {
    pub name: String,
    pub category_id: Uuid,
    pub manufacturer_id: Option<Uuid>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub rated_voltage_kv: Option<f64>,
    pub rated_current_a: Option<f64>,
    pub rated_power_kva: Option<f64>,
    pub components: Vec<HierarchyComponent>,
}

#[derive(Deserialize)]
pub struct HierarchyComponent {
    pub name: String,
    pub component_type: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub position: Option<String>,
}

/// Work order action request
#[derive(Deserialize)]
pub struct WorkOrderActionRequest {
    pub user_id: Uuid,
    pub reason: Option<String>,
    pub signature: Option<String>,
}

/// Inspection action request
#[derive(Deserialize)]
pub struct InspectionActionRequest {
    pub user_id: Uuid,
    pub signature: Option<String>,
    pub reason: Option<String>,
}

/// Checklist generation request
#[derive(Deserialize)]
pub struct GenerateChecklistRequest {
    pub template_id: Uuid,
}

/// Plan generation request
#[derive(Deserialize)]
pub struct GeneratePlanRequest {
    pub user_id: Uuid,
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { success: false, error: msg.into() }))
}

// ============================================================================
// GENERIC TABLE HELPERS
// ============================================================================

/// Allowed EAM table names for defense-in-depth validation.
/// Only tables explicitly listed here can be queried via generic helpers.
const ALLOWED_EAM_TABLES: &[&str] = &[
    "eam_regions", "eam_sites", "eam_substations", "eam_bays",
    "eam_assets", "eam_components", "eam_parts",
    "eam_dga_analyses", "eam_oil_quality_tests", "eam_thermal_imaging",
    "eam_partial_discharge_tests", "eam_insulation_resistance_tests",
    "eam_sf6_analyses", "eam_contact_timing_tests", "eam_battery_discharge_tests",
    "eam_checklist_templates",
    "eam_transmission_lines", "eam_transmission_towers",
];

/// Tables that have an `is_deleted` column for soft-delete filtering.
const SOFT_DELETE_TABLES: &[&str] = &[
    "eam_assets", "eam_components", "eam_parts",
    "eam_regions", "eam_sites", "eam_substations", "eam_bays",
    "eam_transmission_lines", "eam_transmission_towers",
];

/// Validate that a table name is in the allowlist.
fn validate_table(table: &str) -> Result<(), String> {
    if ALLOWED_EAM_TABLES.contains(&table) {
        Ok(())
    } else {
        Err(format!("Table '{}' not in EAM allowlist", table))
    }
}

/// Returns true if this table uses soft-delete (has is_deleted column).
fn has_soft_delete(table: &str) -> bool {
    SOFT_DELETE_TABLES.contains(&table)
}

/// List records from a table with pagination.
/// Applies soft-delete filter (WHERE deleted_at IS NULL) for tables that have it.
async fn list_from_table(
    pool: &ConnectionPool,
    table: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    // Defense-in-depth: only allow known EAM tables
    if let Err(e) = validate_table(table) {
        tracing::error!("Invalid table in list_from_table: {}", e);
        return Ok(vec![]);
    }

    let where_clause = if has_soft_delete(table) {
        "WHERE (is_deleted IS NULL OR is_deleted = FALSE)"
    } else {
        ""
    };

    let sql = format!(
        "SELECT row_to_json(t) FROM (\
            SELECT * FROM {} {} \
            ORDER BY created_at DESC NULLS LAST \
            LIMIT $1 OFFSET $2\
        ) t",
        table, where_clause
    );
    sqlx::query_scalar::<_, serde_json::Value>(&sql)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.pool())
        .await
}

/// Get a single record by ID from a table.
/// Applies soft-delete filter for tables that have deleted_at.
async fn get_from_table(
    pool: &ConnectionPool,
    table: &str,
    id: Uuid,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    // Defense-in-depth: only allow known EAM tables
    if let Err(e) = validate_table(table) {
        tracing::error!("Invalid table in get_from_table: {}", e);
        return Ok(None);
    }

    let soft_delete = if has_soft_delete(table) {
        " AND (is_deleted IS NULL OR is_deleted = FALSE)"
    } else {
        ""
    };

    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT * FROM {} WHERE id = $1{}) t",
        table, soft_delete
    );
    sqlx::query_scalar::<_, serde_json::Value>(&sql)
        .bind(id)
        .fetch_optional(pool.pool())
        .await
}

/// Create a list + get route pair for a simple table (uses Extension for pool)
fn crud_list_get(table: &'static str) -> Router {
    let list_handler = move |Extension(pool): Extension<Arc<ConnectionPool>>, Query(params): Query<ListParams>| async move {
        let limit = params.limit.unwrap_or(100).min(500);
        let offset = params.offset.unwrap_or(0);
        match list_from_table(&pool, table, limit, offset).await {
            Ok(rows) => Json(serde_json::json!({
                "success": true, "data": rows, "meta": { "limit": limit, "offset": offset }
            })).into_response(),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    };

    let get_handler = move |Extension(pool): Extension<Arc<ConnectionPool>>, Path(id): Path<Uuid>| async move {
        match get_from_table(&pool, table, id).await {
            Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row })).into_response(),
            Ok(None) => json_err(StatusCode::NOT_FOUND, "Record not found").into_response(),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    };

    Router::new()
        .route("/", get(list_handler))
        .route("/{id}", get(get_handler))
}

/// Create a list-only route for a simple table (uses Extension for pool)
fn crud_list(table: &'static str) -> Router {
    let list_handler = move |Extension(pool): Extension<Arc<ConnectionPool>>, Query(params): Query<ListParams>| async move {
        let limit = params.limit.unwrap_or(100).min(500);
        let offset = params.offset.unwrap_or(0);
        match list_from_table(&pool, table, limit, offset).await {
            Ok(rows) => Json(serde_json::json!({
                "success": true, "data": rows, "meta": { "limit": limit, "offset": offset }
            })).into_response(),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    };

    Router::new().route("/", get(list_handler))
}

// ============================================================================
// ROUTER
// ============================================================================

/// Build the complete EAM API router.
///
/// Mount this under `/api/eam` in the server routes.
/// Expects `Arc<ConnectionPool>` to be available as a request extension
/// (injected by auth middleware via DatabaseContext).
pub fn eam_api_routes() -> Router {
    Router::new()
        // === Hierarchy ===
        .nest("/regions", crud_list_get("eam_regions"))
        .nest("/sites", crud_list_get("eam_sites"))
        .nest("/substations", crud_list_get("eam_substations"))
        .nest("/bays", crud_list_get("eam_bays"))
        .nest("/assets", crud_list_get("eam_assets"))
        .nest("/components", crud_list("eam_components"))
        .nest("/parts", crud_list("eam_parts"))
        // === Transmission ===
        .nest("/transmission-lines", crud_list_get("eam_transmission_lines"))
        .nest("/transmission-towers", crud_list_get("eam_transmission_towers"))
        .route("/transmission-lines/{id}/towers", get(list_line_towers))
        // === Work Orders (with state machine) ===
        .route("/work-orders", get(list_work_orders))
        .route("/work-orders/{id}", get(get_work_order))
        .route("/work-orders/{id}/schedule", post(wo_schedule))
        .route("/work-orders/{id}/start", post(wo_start))
        .route("/work-orders/{id}/hold", post(wo_hold))
        .route("/work-orders/{id}/resume", post(wo_resume))
        .route("/work-orders/{id}/complete", post(wo_complete))
        .route("/work-orders/{id}/cancel", post(wo_cancel))
        .route("/work-orders/{id}/generate-checklist", post(wo_generate_checklist))
        .route("/work-orders/{id}/checklist-progress", get(wo_checklist_progress))
        .route("/work-orders/{id}/checklist-score", get(wo_checklist_score))
        // === Inspections (with approval) ===
        .route("/inspections", get(list_inspections))
        .route("/inspections/{id}", get(get_inspection))
        .route("/inspections/{id}/submit", post(inspection_submit))
        .route("/inspections/{id}/approve", post(inspection_approve))
        .route("/inspections/{id}/reject", post(inspection_reject))
        // === Condition Monitoring ===
        .nest("/dga", crud_list_get("eam_dga_analyses"))
        .nest("/oil-quality", crud_list_get("eam_oil_quality_tests"))
        .nest("/thermal", crud_list_get("eam_thermal_imaging"))
        .nest("/pd", crud_list_get("eam_partial_discharge_tests"))
        .nest("/ir", crud_list_get("eam_insulation_resistance_tests"))
        .nest("/sf6", crud_list_get("eam_sf6_analyses"))
        .nest("/contact-timing", crud_list("eam_contact_timing_tests"))
        .nest("/battery-discharge", crud_list("eam_battery_discharge_tests"))
        // === Checklists ===
        .nest("/checklist-templates", crud_list_get("eam_checklist_templates"))
        .route("/checklist-lines/{id}/score", post(score_checklist_line))
        // === Maintenance Plans ===
        .route("/maintenance-plans", get(list_maintenance_plans))
        .route("/maintenance-plans/{id}", get(get_maintenance_plan))
        .route("/maintenance-plans/{id}/activate", post(plan_activate))
        .route("/maintenance-plans/{id}/cancel", post(plan_cancel))
        .route("/maintenance-plans/{id}/generate", post(plan_generate))
        // === Health & QR ===
        .route("/health-index/{asset_id}", get(compute_health_index))
        .route("/qr/{entity_type}/{code}", get(generate_qr_code))
        // === Portal (field technician self-service) ===
        .nest("/portal", eam_portal_routes())
        // === Wizards (batch operations) ===
        .nest("/wizards", eam_wizard_routes())
}

// ============================================================================
// WORK ORDER HANDLERS
// ============================================================================

async fn list_work_orders(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);

    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT wo.*, a.name as asset_name, a.asset_code as asset_code
            FROM eam_work_orders wo
            LEFT JOIN eam_assets a ON a.id = wo.asset_id
            WHERE ($1::text IS NULL OR wo.state = $1)
              AND ($2::text IS NULL OR wo.asset_id::text = $2)
            ORDER BY wo.created_at DESC NULLS LAST
            LIMIT $3 OFFSET $4
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(params.state.as_deref())
        .bind(params.asset_id.as_deref())
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.pool())
        .await
    {
        Ok(rows) => Json(serde_json::json!({
            "success": true,
            "data": rows,
            "meta": { "limit": limit, "offset": offset }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_work_order(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT wo.*, a.name as asset_name, a.asset_code as asset_code,
                   (SELECT json_agg(cl) FROM eam_checklist_lines cl WHERE cl.work_order_id = wo.id) as checklist_lines,
                   (SELECT json_agg(pl) FROM eam_maintenance_part_lines pl WHERE pl.work_order_id = wo.id) as part_lines
            FROM eam_work_orders wo
            LEFT JOIN eam_assets a ON a.id = wo.asset_id
            WHERE wo.id = $1
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(id)
        .fetch_optional(pool.pool())
        .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row })).into_response(),
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Work order not found").into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn wo_schedule(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    match services::transition_work_order(&pool, id, services::WorkOrderAction::Schedule, req.user_id, req.signature).await {
        Ok(state) => Json(serde_json::json!({ "success": true, "state": state.as_str() })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_start(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    match services::transition_work_order(&pool, id, services::WorkOrderAction::Start, req.user_id, req.signature).await {
        Ok(state) => Json(serde_json::json!({ "success": true, "state": state.as_str() })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_hold(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    let reason = req.reason.unwrap_or_default();
    match services::transition_work_order(&pool, id, services::WorkOrderAction::Hold { reason }, req.user_id, req.signature).await {
        Ok(state) => Json(serde_json::json!({ "success": true, "state": state.as_str() })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_resume(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    match services::transition_work_order(&pool, id, services::WorkOrderAction::Resume, req.user_id, req.signature).await {
        Ok(state) => Json(serde_json::json!({ "success": true, "state": state.as_str() })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_complete(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    match services::transition_work_order(&pool, id, services::WorkOrderAction::Complete, req.user_id, req.signature).await {
        Ok(state) => Json(serde_json::json!({ "success": true, "state": state.as_str() })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_cancel(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    let reason = req.reason.unwrap_or_default();
    match services::transition_work_order(&pool, id, services::WorkOrderAction::Cancel { reason }, req.user_id, req.signature).await {
        Ok(state) => Json(serde_json::json!({ "success": true, "state": state.as_str() })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_generate_checklist(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<GenerateChecklistRequest>,
) -> impl IntoResponse {
    match services::generate_checklist_lines(&pool, id, req.template_id).await {
        Ok(count) => Json(serde_json::json!({
            "success": true,
            "lines_created": count
        })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn wo_checklist_progress(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match services::compute_checklist_progress(&pool, id).await {
        Ok(progress) => Json(serde_json::json!({
            "success": true,
            "data": {
                "total": progress.total,
                "completed": progress.completed,
                "progress_percent": progress.progress_percent,
            }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn wo_checklist_score(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match services::compute_checklist_score(&pool, id).await {
        Ok(score) => Json(serde_json::json!({
            "success": true,
            "data": {
                "score": score.score,
                "result": score.result.as_str(),
                "has_critical_failure": score.has_critical_failure,
            }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// INSPECTION HANDLERS
// ============================================================================

async fn list_inspections(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);

    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT ir.*, a.name as asset_name, a.asset_code as asset_code
            FROM eam_inspection_results ir
            LEFT JOIN eam_assets a ON a.id = ir.asset_id
            WHERE ($1::text IS NULL OR ir.state = $1)
              AND ($2::text IS NULL OR ir.asset_id::text = $2)
            ORDER BY ir.inspection_date DESC
            LIMIT $3 OFFSET $4
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(params.state.as_deref())
        .bind(params.asset_id.as_deref())
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.pool())
        .await
    {
        Ok(rows) => Json(serde_json::json!({
            "success": true,
            "data": rows,
            "meta": { "limit": limit, "offset": offset }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_inspection(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT ir.*, a.name as asset_name, a.asset_code as asset_code
            FROM eam_inspection_results ir
            LEFT JOIN eam_assets a ON a.id = ir.asset_id
            WHERE ir.id = $1
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(id)
        .fetch_optional(pool.pool())
        .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row })).into_response(),
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Inspection not found").into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn inspection_submit(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<InspectionActionRequest>,
) -> impl IntoResponse {
    match services::submit_inspection(&pool, id, req.user_id).await {
        Ok(()) => Json(serde_json::json!({ "success": true, "state": "submitted" })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn inspection_approve(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<InspectionActionRequest>,
) -> impl IntoResponse {
    let signature = req.signature.unwrap_or_default();
    match services::approve_inspection(&pool, id, req.user_id, signature).await {
        Ok(()) => Json(serde_json::json!({ "success": true, "state": "approved" })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn inspection_reject(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<InspectionActionRequest>,
) -> impl IntoResponse {
    let reason = req.reason.unwrap_or_default();
    match services::reject_inspection(&pool, id, req.user_id, reason).await {
        Ok(()) => Json(serde_json::json!({ "success": true, "state": "rejected" })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// ============================================================================
// CHECKLIST HANDLERS
// ============================================================================

async fn score_checklist_line(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match services::score_checklist_line(&pool, id).await {
        Ok(score) => Json(serde_json::json!({ "success": true, "score": score })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// ============================================================================
// MAINTENANCE PLAN HANDLERS
// ============================================================================

async fn list_maintenance_plans(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);

    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT mp.*, a.name as asset_name, a.asset_code as asset_code
            FROM eam_maintenance_plans mp
            LEFT JOIN eam_assets a ON a.id = mp.asset_id
            WHERE ($1::text IS NULL OR mp.state = $1)
            ORDER BY mp.created_at DESC NULLS LAST
            LIMIT $2 OFFSET $3
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(params.state.as_deref())
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.pool())
        .await
    {
        Ok(rows) => Json(serde_json::json!({
            "success": true,
            "data": rows,
            "meta": { "limit": limit, "offset": offset }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_maintenance_plan(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT mp.*, a.name as asset_name, a.asset_code as asset_code,
                   ct.name as checklist_name
            FROM eam_maintenance_plans mp
            LEFT JOIN eam_assets a ON a.id = mp.asset_id
            LEFT JOIN eam_checklist_templates ct ON ct.id = mp.checklist_template_id
            WHERE mp.id = $1
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(id)
        .fetch_optional(pool.pool())
        .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row })).into_response(),
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Maintenance plan not found").into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn plan_activate(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<GeneratePlanRequest>,
) -> impl IntoResponse {
    match services::activate_plan(&pool, id, req.user_id).await {
        Ok(()) => Json(serde_json::json!({ "success": true, "state": "active" })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn plan_cancel(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<GeneratePlanRequest>,
) -> impl IntoResponse {
    match services::cancel_plan(&pool, id, req.user_id).await {
        Ok(()) => Json(serde_json::json!({ "success": true, "state": "cancelled" })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn plan_generate(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<GeneratePlanRequest>,
) -> impl IntoResponse {
    match services::generate_planned_orders(&pool, id, req.user_id).await {
        Ok(count) => Json(serde_json::json!({
            "success": true,
            "work_orders_created": count
        })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// ============================================================================
// TRANSMISSION HANDLERS
// ============================================================================

async fn list_line_towers(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);

    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT tt.*
            FROM eam_transmission_towers tt
            WHERE tt.transmission_line_id = $1
              AND (tt.is_deleted IS NULL OR tt.is_deleted = FALSE)
            ORDER BY tt.tower_number ASC NULLS LAST, tt.code ASC
            LIMIT $2 OFFSET $3
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.pool())
        .await
    {
        Ok(rows) => Json(serde_json::json!({
            "success": true,
            "data": rows,
            "meta": { "transmission_line_id": id, "limit": limit, "offset": offset }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// HEALTH INDEX & QR CODE HANDLERS
// ============================================================================

async fn compute_health_index(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(asset_id): Path<Uuid>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT
            (SELECT json_agg(d) FROM (
                SELECT * FROM eam_dga_analyses WHERE asset_id = $1 ORDER BY sample_date DESC LIMIT 1
            ) d) as latest_dga,
            (SELECT json_agg(o) FROM (
                SELECT * FROM eam_oil_quality_tests WHERE asset_id = $1 ORDER BY test_date DESC LIMIT 1
            ) o) as latest_oil,
            (SELECT json_agg(t) FROM (
                SELECT * FROM eam_thermal_imaging WHERE asset_id = $1 ORDER BY scan_date DESC LIMIT 1
            ) t) as latest_thermal,
            (SELECT json_agg(h) FROM (
                SELECT * FROM eam_asset_health_indices WHERE asset_id = $1 ORDER BY calculated_at DESC LIMIT 1
            ) h) as latest_health
    "#;

    match sqlx::query_as::<_, (
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
    )>(sql)
        .bind(asset_id)
        .fetch_one(pool.pool())
        .await
    {
        Ok((dga, oil, thermal, health)) => {
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "asset_id": asset_id,
                    "latest_dga": dga,
                    "latest_oil": oil,
                    "latest_thermal": thermal,
                    "latest_health_index": health,
                }
            })).into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn generate_qr_code(
    Path((entity_type, code)): Path<(String, String)>,
) -> impl IntoResponse {
    let et = services::QrEntityType::from_code(&entity_type);
    match et {
        Some(et) => {
            let qr_string = services::generate_qr_code_string(et, &code);
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "entity_type": entity_type,
                    "code": code,
                    "qr_string": qr_string,
                }
            })).into_response()
        }
        None => json_err(StatusCode::BAD_REQUEST, format!("Unknown entity type: {}", entity_type)).into_response(),
    }
}

// ============================================================================
// PORTAL ROUTES (Field Technician Self-Service)
// ============================================================================

/// Portal routes for field technicians.
/// Mounted under `/api/eam/portal/`.
/// All endpoints are user-scoped (filter by assigned_to or team membership).
pub fn eam_portal_routes() -> Router {
    Router::new()
        // Maintenance (my work orders)
        .route("/maintenance", get(portal_list_maintenance))
        .route("/maintenance/{id}", get(portal_get_maintenance))
        .route("/maintenance/{id}/action", post(portal_maintenance_action))
        .route("/maintenance/{id}/save", post(portal_maintenance_save))
        .route("/maintenance/checklist/save", post(portal_checklist_save))
        // Equipment
        .route("/equipment", get(portal_list_equipment))
        .route("/equipment/lookup", get(portal_equipment_lookup))
        .route("/equipment/{id}", get(portal_get_equipment))
        .route("/equipment/{id}/request-maintenance", post(portal_request_maintenance))
        .route("/equipment/{id}/qr", get(portal_equipment_qr))
}

/// List maintenance orders assigned to the current user
async fn portal_list_maintenance(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Query(params): Query<PortalListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);
    let user_id = params.user_id;

    let mut conditions = vec!["(wo.assigned_to = $1 OR wo.team_ids @> to_jsonb($1::text))".to_string()];
    let mut param_idx = 2_u32;

    if let Some(ref state) = params.state {
        conditions.push(format!("wo.state = ${}", param_idx));
        param_idx += 1;
        let _ = state; // used below in bind
    }
    if let Some(ref search) = params.search {
        conditions.push(format!(
            "(wo.wo_number ILIKE ${0} OR wo.title ILIKE ${0} OR a.name ILIKE ${0})",
            param_idx
        ));
        let _ = search;
    }

    let where_clause = conditions.join(" AND ");
    let sql = format!(
        r#"SELECT row_to_json(t) FROM (
            SELECT wo.id, wo.wo_number, wo.title, wo.description, wo.state,
                   wo.maintenance_type, wo.priority, wo.scheduled_start,
                   wo.actual_start, wo.actual_end, wo.request_date,
                   wo.checklist_progress, wo.checklist_result,
                   a.name as asset_name, a.asset_code
            FROM eam_work_orders wo
            LEFT JOIN eam_assets a ON wo.asset_id = a.id
            WHERE {}
            ORDER BY
                CASE wo.state
                    WHEN 'in_progress' THEN 1
                    WHEN 'scheduled' THEN 2
                    WHEN 'on_hold' THEN 3
                    WHEN 'draft' THEN 4
                    ELSE 5
                END,
                wo.scheduled_start ASC NULLS LAST
            LIMIT {} OFFSET {}
        ) t"#,
        where_clause, limit, offset
    );

    let mut query = sqlx::query_scalar::<_, serde_json::Value>(&sql).bind(user_id);

    if let Some(ref state) = params.state {
        query = query.bind(state);
    }
    if let Some(ref search) = params.search {
        query = query.bind(format!("%{}%", search.replace('%', "\\%").replace('_', "\\_")));
    }

    match query.fetch_all(pool.pool()).await {
        Ok(rows) => Json(serde_json::json!({
            "success": true, "data": rows,
            "meta": { "limit": limit, "offset": offset }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Get maintenance order detail with checklist lines
async fn portal_get_maintenance(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT wo.*,
                   a.name as asset_name, a.asset_code,
                   (SELECT json_agg(cl ORDER BY cl.sequence)
                    FROM eam_checklist_lines cl
                    WHERE cl.work_order_id = wo.id
                   ) as checklist_lines
            FROM eam_work_orders wo
            LEFT JOIN eam_assets a ON wo.asset_id = a.id
            WHERE wo.id = $1
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(id)
        .fetch_optional(pool.pool())
        .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row })).into_response(),
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Work order not found").into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Portal state transitions: start, hold, resume, complete
async fn portal_maintenance_action(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WorkOrderActionRequest>,
) -> impl IntoResponse {
    let action_str = req.reason.as_deref().unwrap_or("");
    let action = match action_str {
        "start" => services::WorkOrderAction::Start,
        "hold" => services::WorkOrderAction::Hold {
            reason: req.signature.clone().unwrap_or_default(),
        },
        "resume" => services::WorkOrderAction::Resume,
        "complete" => services::WorkOrderAction::Complete,
        other => {
            return json_err(
                StatusCode::BAD_REQUEST,
                format!("Unknown action: {}. Use start, hold, resume, or complete", other),
            ).into_response();
        }
    };

    match services::transition_work_order(&pool, id, action, req.user_id, req.signature.clone()).await {
        Ok(state) => Json(serde_json::json!({
            "success": true, "state": state.as_str()
        })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Save work details or costs on a work order
async fn portal_maintenance_save(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
    Json(req): Json<PortalSaveRequest>,
) -> impl IntoResponse {
    // Build dynamic SET clause from provided fields
    let mut sets = Vec::new();
    let mut values: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
    let mut param_idx = 2_u32; // $1 is the work order id

    // We build raw parameterized SQL for the fields that are provided
    let mut sql_parts: Vec<String> = Vec::new();

    if let Some(ref v) = req.work_description {
        sql_parts.push(format!("work_description = ${}", param_idx));
        sets.push(v.clone());
        param_idx += 1;
    }
    if let Some(ref v) = req.findings {
        sql_parts.push(format!("findings = ${}", param_idx));
        sets.push(v.clone());
        param_idx += 1;
    }
    if let Some(ref v) = req.actions_taken {
        sql_parts.push(format!("actions_taken = ${}", param_idx));
        sets.push(v.clone());
        param_idx += 1;
    }
    if let Some(ref v) = req.recommendations {
        sql_parts.push(format!("recommendations = ${}", param_idx));
        sets.push(v.clone());
        param_idx += 1;
    }

    let _ = (values, param_idx); // used conceptually

    if sql_parts.is_empty() && req.labor_cost.is_none() {
        return json_err(StatusCode::BAD_REQUEST, "No fields to update").into_response();
    }

    // Use a simpler approach: update each field individually with parameterized queries
    let mut updated = 0u32;

    if let Some(ref v) = req.work_description {
        let _ = sqlx::query("UPDATE eam_work_orders SET work_description = $2, updated_by = $3, updated_at = NOW() WHERE id = $1")
            .bind(id).bind(v).bind(req.user_id)
            .execute(pool.pool()).await;
        updated += 1;
    }
    if let Some(ref v) = req.findings {
        let _ = sqlx::query("UPDATE eam_work_orders SET findings = $2, updated_by = $3, updated_at = NOW() WHERE id = $1")
            .bind(id).bind(v).bind(req.user_id)
            .execute(pool.pool()).await;
        updated += 1;
    }
    if let Some(ref v) = req.actions_taken {
        let _ = sqlx::query("UPDATE eam_work_orders SET actions_taken = $2, updated_by = $3, updated_at = NOW() WHERE id = $1")
            .bind(id).bind(v).bind(req.user_id)
            .execute(pool.pool()).await;
        updated += 1;
    }
    if let Some(ref v) = req.recommendations {
        let _ = sqlx::query("UPDATE eam_work_orders SET recommendations = $2, updated_by = $3, updated_at = NOW() WHERE id = $1")
            .bind(id).bind(v).bind(req.user_id)
            .execute(pool.pool()).await;
        updated += 1;
    }
    if let Some(cost) = req.labor_cost {
        let _ = sqlx::query("UPDATE eam_work_orders SET labor_cost = $2, updated_by = $3, updated_at = NOW() WHERE id = $1")
            .bind(id).bind(cost).bind(req.user_id)
            .execute(pool.pool()).await;
        updated += 1;
    }

    Json(serde_json::json!({ "success": true, "updated_fields": updated })).into_response()
}

/// Save individual checklist line value (AJAX)
async fn portal_checklist_save(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Json(req): Json<PortalChecklistSaveRequest>,
) -> impl IntoResponse {
    // First get the line's input_type to validate
    let line_info: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT input_type, work_order_id FROM eam_checklist_lines WHERE id = $1"
    )
        .bind(req.line_id)
        .fetch_optional(pool.pool())
        .await
        .ok()
        .flatten();

    let Some((input_type, wo_id)) = line_info else {
        return json_err(StatusCode::NOT_FOUND, "Checklist line not found").into_response();
    };

    // Update the value based on input type
    let result = match input_type.as_str() {
        "pass_fail" | "yes_no" | "selection" => {
            sqlx::query(
                "UPDATE eam_checklist_lines SET value_text = $2, note = $3, is_completed = TRUE, updated_at = NOW() WHERE id = $1"
            )
                .bind(req.line_id).bind(&req.value).bind(&req.note)
                .execute(pool.pool()).await
        }
        "measurement" => {
            let numeric: f64 = req.value.parse().unwrap_or(0.0);
            sqlx::query(
                "UPDATE eam_checklist_lines SET value_numeric = $2, note = $3, is_completed = TRUE, updated_at = NOW() WHERE id = $1"
            )
                .bind(req.line_id).bind(numeric).bind(&req.note)
                .execute(pool.pool()).await
        }
        "text" => {
            sqlx::query(
                "UPDATE eam_checklist_lines SET value_text = $2, note = $3, is_completed = TRUE, updated_at = NOW() WHERE id = $1"
            )
                .bind(req.line_id).bind(&req.value).bind(&req.note)
                .execute(pool.pool()).await
        }
        "rating" => {
            let numeric: f64 = req.value.parse().unwrap_or(0.0);
            sqlx::query(
                "UPDATE eam_checklist_lines SET value_numeric = $2, note = $3, is_completed = TRUE, updated_at = NOW() WHERE id = $1"
            )
                .bind(req.line_id).bind(numeric).bind(&req.note)
                .execute(pool.pool()).await
        }
        _ => {
            return json_err(StatusCode::BAD_REQUEST, format!("Unknown input type: {}", input_type)).into_response();
        }
    };

    match result {
        Ok(_) => {
            // Recompute checklist progress for the work order
            if let Some(wo_id) = wo_id {
                let stats: Option<(i64, i64)> = sqlx::query_as(
                    "SELECT COUNT(*), COUNT(*) FILTER (WHERE is_completed = TRUE) FROM eam_checklist_lines WHERE work_order_id = $1"
                )
                    .bind(wo_id)
                    .fetch_optional(pool.pool())
                    .await
                    .ok()
                    .flatten();

                if let Some((total, completed)) = stats {
                    let progress = if total > 0 { (completed as f64 / total as f64) * 100.0 } else { 0.0 };
                    let _ = sqlx::query(
                        "UPDATE eam_work_orders SET checklist_total = $2, checklist_completed = $3, checklist_progress = $4, updated_at = NOW() WHERE id = $1"
                    )
                        .bind(wo_id).bind(total as i32).bind(completed as i32).bind(progress)
                        .execute(pool.pool()).await;
                }

                return Json(serde_json::json!({
                    "success": true,
                    "work_order_id": wo_id,
                })).into_response();
            }
            Json(serde_json::json!({ "success": true })).into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// List active equipment with pagination and search
async fn portal_list_equipment(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    let (sql, has_search) = if params.search.is_some() {
        (r#"SELECT row_to_json(t) FROM (
            SELECT a.id, a.asset_code, a.name, a.operational_status, a.condition_status,
                   a.serial_number, a.qr_code,
                   c.name as category_name,
                   s.name as substation_name
            FROM eam_assets a
            LEFT JOIN eam_asset_categories c ON a.category_id = c.id
            LEFT JOIN eam_bays b ON a.bay_id = b.id
            LEFT JOIN eam_substations s ON b.substation_id = s.id
            WHERE a.is_active = TRUE AND (a.is_deleted IS NULL OR a.is_deleted = FALSE)
              AND (a.asset_code ILIKE $1 OR a.name ILIKE $1 OR a.serial_number ILIKE $1)
            ORDER BY a.name
            LIMIT $2 OFFSET $3
        ) t"#.to_string(), true)
    } else {
        (r#"SELECT row_to_json(t) FROM (
            SELECT a.id, a.asset_code, a.name, a.operational_status, a.condition_status,
                   a.serial_number, a.qr_code,
                   c.name as category_name,
                   s.name as substation_name
            FROM eam_assets a
            LEFT JOIN eam_asset_categories c ON a.category_id = c.id
            LEFT JOIN eam_bays b ON a.bay_id = b.id
            LEFT JOIN eam_substations s ON b.substation_id = s.id
            WHERE a.is_active = TRUE AND (a.is_deleted IS NULL OR a.is_deleted = FALSE)
            ORDER BY a.name
            LIMIT $1 OFFSET $2
        ) t"#.to_string(), false)
    };

    let result = if has_search {
        let search = format!("%{}%", params.search.as_ref().unwrap().replace('%', "\\%").replace('_', "\\_"));
        sqlx::query_scalar::<_, serde_json::Value>(&sql)
            .bind(search).bind(limit).bind(offset)
            .fetch_all(pool.pool()).await
    } else {
        sqlx::query_scalar::<_, serde_json::Value>(&sql)
            .bind(limit).bind(offset)
            .fetch_all(pool.pool()).await
    };

    match result {
        Ok(rows) => Json(serde_json::json!({
            "success": true, "data": rows,
            "meta": { "limit": limit, "offset": offset }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Smart equipment lookup by code, QR code, or serial number
async fn portal_equipment_lookup(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Query(params): Query<EquipmentLookupParams>,
) -> impl IntoResponse {
    let q = params.q.trim();

    // Try exact match first (code, QR, serial)
    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT a.id, a.asset_code, a.name, a.serial_number, a.qr_code
            FROM eam_assets a
            WHERE a.is_active = TRUE
              AND (a.asset_code = $1 OR a.serial_number = $1 OR a.qr_code = $1)
            LIMIT 1
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(q)
        .fetch_optional(pool.pool())
        .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row, "exact": true })).into_response(),
        Ok(None) => {
            // Try partial match
            let fuzzy_sql = r#"
                SELECT row_to_json(t) FROM (
                    SELECT a.id, a.asset_code, a.name, a.serial_number
                    FROM eam_assets a
                    WHERE a.is_active = TRUE
                      AND (a.asset_code ILIKE $1 OR a.name ILIKE $1 OR a.serial_number ILIKE $1)
                    ORDER BY a.name
                    LIMIT 10
                ) t
            "#;
            let pattern = format!("%{}%", q.replace('%', "\\%").replace('_', "\\_"));
            match sqlx::query_scalar::<_, serde_json::Value>(fuzzy_sql)
                .bind(pattern)
                .fetch_all(pool.pool())
                .await
            {
                Ok(rows) => Json(serde_json::json!({
                    "success": true, "data": rows, "exact": false
                })).into_response(),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Get equipment detail with last 10 maintenance orders
async fn portal_get_equipment(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let sql = r#"
        SELECT row_to_json(t) FROM (
            SELECT a.*,
                   c.name as category_name,
                   m.name as manufacturer_name,
                   s.name as substation_name,
                   b.name as bay_name,
                   (SELECT json_agg(wo ORDER BY wo.created_at DESC)
                    FROM (
                        SELECT wo.id, wo.wo_number, wo.title, wo.state, wo.maintenance_type,
                               wo.scheduled_start, wo.actual_end
                        FROM eam_work_orders wo
                        WHERE wo.asset_id = a.id
                        ORDER BY wo.created_at DESC
                        LIMIT 10
                    ) wo
                   ) as recent_work_orders
            FROM eam_assets a
            LEFT JOIN eam_asset_categories c ON a.category_id = c.id
            LEFT JOIN eam_manufacturers m ON a.manufacturer_id = m.id
            LEFT JOIN eam_bays b ON a.bay_id = b.id
            LEFT JOIN eam_substations s ON b.substation_id = s.id
            WHERE a.id = $1
        ) t
    "#;

    match sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(id)
        .fetch_optional(pool.pool())
        .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "success": true, "data": row })).into_response(),
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Equipment not found").into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Create a corrective maintenance request from equipment page
async fn portal_request_maintenance(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(equipment_id): Path<Uuid>,
    Json(req): Json<PortalMaintenanceRequest>,
) -> impl IntoResponse {
    // Get equipment info for auto-description
    let asset_info: Option<(String, String)> = sqlx::query_as(
        "SELECT name, asset_code FROM eam_assets WHERE id = $1 AND is_active = TRUE"
    )
        .bind(equipment_id)
        .fetch_optional(pool.pool())
        .await
        .ok()
        .flatten();

    let Some((asset_name, asset_code)) = asset_info else {
        return json_err(StatusCode::NOT_FOUND, "Equipment not found or inactive").into_response();
    };

    // Generate WO number
    let wo_code = match services::next_maintenance_code(&pool).await {
        Ok(code) => code,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let default_title = format!("Corrective Maintenance - {} ({})", asset_name, asset_code);
    let title = req.description.as_deref().unwrap_or(&default_title);
    let priority = req.priority.unwrap_or(2); // Medium default

    // Get company_id from asset
    let company_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT company_id FROM eam_assets WHERE id = $1"
    )
        .bind(equipment_id)
        .fetch_optional(pool.pool())
        .await
        .ok()
        .flatten();

    let Some(company_id) = company_id else {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "Could not determine company").into_response();
    };

    let wo_id = Uuid::new_v4();
    let result = sqlx::query(
        r#"INSERT INTO eam_work_orders (id, company_id, wo_number, asset_id, title, maintenance_type, priority, state, request_date, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5, 'cm', $6, 'draft', CURRENT_DATE, $7, NOW())"#
    )
        .bind(wo_id)
        .bind(company_id)
        .bind(&wo_code)
        .bind(equipment_id)
        .bind(title)
        .bind(priority)
        .bind(req.user_id)
        .execute(pool.pool())
        .await;

    match result {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "data": { "id": wo_id, "wo_number": wo_code }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Download QR code for equipment
async fn portal_equipment_qr(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Get asset code
    let code: Option<String> = sqlx::query_scalar(
        "SELECT asset_code FROM eam_assets WHERE id = $1"
    )
        .bind(id)
        .fetch_optional(pool.pool())
        .await
        .ok()
        .flatten();

    let Some(code) = code else {
        return json_err(StatusCode::NOT_FOUND, "Equipment not found").into_response();
    };

    let qr_string = services::generate_qr_code_string(
        services::QrEntityType::Equipment, &code
    );

    match services::generate_qr_image(&qr_string) {
        Ok(bytes) => {
            (
                StatusCode::OK,
                [
                    ("content-type", "image/png"),
                    ("content-disposition", "inline; filename=\"qr.png\""),
                ],
                bytes,
            ).into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// WIZARD ROUTES (Batch Operations)
// ============================================================================

/// Wizard routes for batch operations.
/// Mounted under `/api/eam/wizards/`.
pub fn eam_wizard_routes() -> Router {
    Router::new()
        .route("/create-maintenance", post(wizard_create_maintenance))
        .route("/create-hierarchy", post(wizard_create_hierarchy))
}

/// Batch create maintenance orders for one or more equipment
async fn wizard_create_maintenance(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Json(req): Json<CreateMaintenanceWizardRequest>,
) -> impl IntoResponse {
    if req.equipment_ids.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "At least one equipment_id is required").into_response();
    }

    let mut created = Vec::new();

    for equipment_id in &req.equipment_ids {
        // Get equipment info for auto-description
        let asset_info: Option<(String, String)> = sqlx::query_as(
            "SELECT name, asset_code FROM eam_assets WHERE id = $1"
        )
            .bind(equipment_id)
            .fetch_optional(pool.pool())
            .await
            .ok()
            .flatten();

        let (asset_name, asset_code) = asset_info.unwrap_or_else(|| ("Unknown".to_string(), "???".to_string()));

        // Generate WO number
        let wo_code = match services::next_maintenance_code(&pool).await {
            Ok(code) => code,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };

        let auto_title = format!("{} - {} ({})",
            req.description.as_deref().unwrap_or(&req.maintenance_type.to_uppercase()),
            asset_name, asset_code
        );
        let priority = req.priority.unwrap_or(2);
        let state = if req.scheduled_date.is_some() { "scheduled" } else { "draft" };

        let wo_id = Uuid::new_v4();
        let result = sqlx::query(
            r#"INSERT INTO eam_work_orders
                (id, company_id, wo_number, asset_id, title, work_description,
                 maintenance_type, priority, state, request_date,
                 planned_duration_hours, assigned_to,
                 created_by, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_DATE, $10, $11, $12, NOW())"#
        )
            .bind(wo_id)
            .bind(req.company_id)
            .bind(&wo_code)
            .bind(equipment_id)
            .bind(&auto_title)
            .bind(&req.work_description)
            .bind(&req.maintenance_type)
            .bind(priority)
            .bind(state)
            .bind(req.planned_duration_hours)
            .bind(req.assigned_to)
            .bind(req.user_id)
            .execute(pool.pool())
            .await;

        match result {
            Ok(_) => created.push(serde_json::json!({
                "id": wo_id, "wo_number": wo_code, "equipment_id": equipment_id,
                "title": auto_title, "state": state
            })),
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create WO for {}: {}", asset_code, e)).into_response(),
        }
    }

    Json(serde_json::json!({
        "success": true,
        "data": created,
        "count": created.len()
    })).into_response()
}

/// Transactional substation hierarchy creation
/// Creates substation + bays + equipment + components in one request
async fn wizard_create_hierarchy(
    Extension(pool): Extension<Arc<ConnectionPool>>,
    Json(req): Json<CreateHierarchyWizardRequest>,
) -> impl IntoResponse {
    // Use a transaction for atomicity
    let mut tx = match pool.pool().begin().await {
        Ok(tx) => tx,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // 1. Create substation
    let sub_id = Uuid::new_v4();
    let sub_result = sqlx::query(
        r#"INSERT INTO eam_substations
            (id, company_id, site_id, code, name, substation_type, busbar_configuration,
             voltage_level_id, ownership, commissioning_date, design_life_years,
             status, is_active, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active', TRUE, $12, NOW())"#
    )
        .bind(sub_id)
        .bind(req.company_id)
        .bind(req.substation.site_id)
        .bind(&req.substation.code)
        .bind(&req.substation.name)
        .bind(&req.substation.substation_type)
        .bind(&req.substation.busbar_configuration)
        .bind(req.substation.voltage_level_id)
        .bind(&req.substation.ownership)
        .bind(&req.substation.commissioning_date)
        .bind(req.substation.design_life_years)
        .bind(req.user_id)
        .execute(&mut *tx)
        .await;

    if let Err(e) = sub_result {
        let _ = tx.rollback().await;
        return json_err(StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create substation: {}", e)).into_response();
    }

    let mut bay_count = 0u32;
    let mut equipment_count = 0u32;
    let mut component_count = 0u32;

    // We need a unit_type_id for bays - use a default lookup
    let default_unit_type: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM eam_unit_types WHERE is_active = TRUE LIMIT 1"
    )
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();

    let unit_type_id = default_unit_type.unwrap_or_else(Uuid::new_v4);

    // 2. Create bays
    for (bay_idx, bay) in req.bays.iter().enumerate() {
        let bay_id = Uuid::new_v4();
        let bay_result = sqlx::query(
            r#"INSERT INTO eam_bays
                (id, company_id, substation_id, unit_type_id, code, name, bay_type,
                 voltage_level_id, rated_current_a, feeder_name,
                 display_order, status, is_active, created_by, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active', TRUE, $12, NOW())"#
        )
            .bind(bay_id)
            .bind(req.company_id)
            .bind(sub_id)
            .bind(unit_type_id)
            .bind(&bay.code)
            .bind(&bay.name)
            .bind(&bay.bay_type)
            .bind(bay.voltage_level_id)
            .bind(bay.rated_current_a)
            .bind(&bay.feeder_name)
            .bind(bay_idx as i32)
            .bind(req.user_id)
            .execute(&mut *tx)
            .await;

        if let Err(e) = bay_result {
            let _ = tx.rollback().await;
            return json_err(StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create bay '{}': {}", bay.name, e)).into_response();
        }
        bay_count += 1;

        // 3. Create equipment in this bay
        for eqp in &bay.equipment {
            let eqp_code = match services::next_equipment_code(&pool).await {
                Ok(code) => code,
                Err(e) => {
                    let _ = tx.rollback().await;
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };

            let eqp_id = Uuid::new_v4();
            let eqp_result = sqlx::query(
                r#"INSERT INTO eam_assets
                    (id, company_id, bay_id, category_id, asset_code, name,
                     manufacturer_id, model, serial_number,
                     rated_voltage_kv, rated_current_a, rated_power_kva,
                     operational_status, condition_status,
                     is_active, created_by, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                           'operational', 'good', TRUE, $13, NOW())"#
            )
                .bind(eqp_id)
                .bind(req.company_id)
                .bind(bay_id)
                .bind(eqp.category_id)
                .bind(&eqp_code)
                .bind(&eqp.name)
                .bind(eqp.manufacturer_id)
                .bind(&eqp.model)
                .bind(&eqp.serial_number)
                .bind(eqp.rated_voltage_kv)
                .bind(eqp.rated_current_a)
                .bind(eqp.rated_power_kva)
                .bind(req.user_id)
                .execute(&mut *tx)
                .await;

            if let Err(e) = eqp_result {
                let _ = tx.rollback().await;
                return json_err(StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to create equipment '{}': {}", eqp.name, e)).into_response();
            }
            equipment_count += 1;

            // 4. Create components for this equipment
            for cmp in &eqp.components {
                let cmp_code = match services::next_component_code(&pool).await {
                    Ok(code) => code,
                    Err(e) => {
                        let _ = tx.rollback().await;
                        return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                    }
                };

                let cmp_id = Uuid::new_v4();
                let cmp_result = sqlx::query(
                    r#"INSERT INTO eam_components
                        (id, asset_id, code, name, component_type, manufacturer,
                         model, serial_number, status, is_active, created_by, created_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', TRUE, $9, NOW())"#
                )
                    .bind(cmp_id)
                    .bind(eqp_id)
                    .bind(&cmp_code)
                    .bind(&cmp.name)
                    .bind(&cmp.component_type)
                    .bind(&cmp.manufacturer)
                    .bind(&cmp.model)
                    .bind(&cmp.serial_number)
                    .bind(req.user_id)
                    .execute(&mut *tx)
                    .await;

                if let Err(e) = cmp_result {
                    let _ = tx.rollback().await;
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to create component '{}': {}", cmp.name, e)).into_response();
                }
                component_count += 1;
            }
        }
    }

    // Commit transaction
    match tx.commit().await {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "data": {
                "substation_id": sub_id,
                "substation_code": req.substation.code,
                "bays_created": bay_count,
                "equipment_created": equipment_count,
                "components_created": component_count,
            }
        })).into_response(),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to commit: {}", e)).into_response(),
    }
}
