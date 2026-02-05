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

/// List records from a table with pagination
async fn list_from_table(
    pool: &ConnectionPool,
    table: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT * FROM {} ORDER BY created_at DESC NULLS LAST LIMIT $1 OFFSET $2) t",
        table
    );
    sqlx::query_scalar::<_, serde_json::Value>(&sql)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.pool())
        .await
}

/// Get a single record by ID from a table
async fn get_from_table(
    pool: &ConnectionPool,
    table: &str,
    id: Uuid,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT * FROM {} WHERE id = $1) t",
        table
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
