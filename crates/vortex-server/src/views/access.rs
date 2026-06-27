//! Access Control Admin API and HTML Views
//!
//! REST endpoints and HTML views for managing access control rules:
//! - Model access (CRUD permissions per role)
//! - Record rules (domain-based filtering)
//! - Field access (field-level permissions)
//!
//! # Compliance
//!
//! - Access management and authorization

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use vortex_common::Context;

use super::common::generate_csrf_token;
use crate::api::{ApiError, ApiResponse, ApiResult, PaginationInfo};
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// Request/Response Types
// ─────────────────────────────────────────────────────────────────────────────

/// Model access rule response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAccessResponse {
    pub id: Uuid,
    pub model_name: String,
    pub role_id: Uuid,
    pub role_name: Option<String>,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub company_id: Option<Uuid>,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Create/update model access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAccessRequest {
    pub model_name: String,
    pub role_id: Uuid,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    #[serde(default)]
    pub company_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub active: bool,
}

/// Record rule response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub model_name: String,
    pub domain_expression: String,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub is_global: bool,
    pub priority: i32,
    pub active: bool,
    pub company_id: Option<Uuid>,
    pub created_at: String,
    pub updated_at: String,
}

/// Create/update record rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRuleRequest {
    pub name: String,
    pub model_name: String,
    pub domain_expression: String,
    #[serde(default)]
    pub role_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub perm_read: bool,
    #[serde(default = "default_true")]
    pub perm_write: bool,
    #[serde(default = "default_true")]
    pub perm_create: bool,
    #[serde(default = "default_true")]
    pub perm_delete: bool,
    #[serde(default)]
    pub is_global: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub company_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub active: bool,
}

/// Field access rule response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccessResponse {
    pub id: Uuid,
    pub model_name: String,
    pub field_name: String,
    pub role_id: Uuid,
    pub role_name: Option<String>,
    pub readable: bool,
    pub writable: bool,
    pub company_id: Option<Uuid>,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Create/update field access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccessRequest {
    pub model_name: String,
    pub field_name: String,
    pub role_id: Uuid,
    #[serde(default = "default_true")]
    pub readable: bool,
    #[serde(default = "default_true")]
    pub writable: bool,
    #[serde(default)]
    pub company_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub active: bool,
}

/// Access check request for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckRequest {
    pub model_name: String,
    pub mode: String,
    #[serde(default)]
    pub record: Option<serde_json::Value>,
}

/// Access check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckResponse {
    pub allowed: bool,
    pub model_access: bool,
    pub record_rules_applied: Vec<String>,
    pub domain_filter: Option<String>,
    pub hidden_fields: Vec<String>,
    pub readonly_fields: Vec<String>,
}

/// Query parameters for listing
#[derive(Debug, Clone, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(default)]
    pub role_id: Option<Uuid>,
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

fn default_true() -> bool {
    true
}

fn default_page() -> u64 {
    1
}

fn default_per_page() -> u64 {
    25
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML Template Types
// ─────────────────────────────────────────────────────────────────────────────

/// Role option for dropdowns
#[derive(Debug, Clone)]
pub struct RoleOption {
    pub id: Uuid,
    pub name: String,
    pub selected: bool,
}

/// Model access rule for display
#[derive(Debug, Clone)]
pub struct ModelAccessDisplay {
    pub id: Uuid,
    pub model_name: String,
    pub role_id: Uuid,
    pub role_name: Option<String>,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub active: bool,
}

impl ModelAccessDisplay {
    /// Get display name for the role
    pub fn display_role_name(&self) -> String {
        self.role_name.clone().unwrap_or_else(|| self.role_id.to_string())
    }
}

/// Record rule for display
#[derive(Debug, Clone)]
pub struct RecordRuleDisplay {
    pub id: Uuid,
    pub name: String,
    pub model_name: String,
    pub domain_expression: String,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub is_global: bool,
    pub priority: i32,
    pub active: bool,
}

impl RecordRuleDisplay {
    /// Get truncated domain expression for display (max 40 chars)
    pub fn truncated_domain(&self) -> String {
        if self.domain_expression.len() > 40 {
            format!("{}...", &self.domain_expression[..40])
        } else {
            self.domain_expression.clone()
        }
    }
}

/// Field access rule for display
#[derive(Debug, Clone)]
pub struct FieldAccessDisplay {
    pub id: Uuid,
    pub model_name: String,
    pub field_name: String,
    pub role_id: Uuid,
    pub role_name: Option<String>,
    pub readable: bool,
    pub writable: bool,
    pub active: bool,
}

impl FieldAccessDisplay {
    /// Get display name for the role
    pub fn display_role_name(&self) -> String {
        self.role_name.clone().unwrap_or_else(|| self.role_id.to_string())
    }
}

/// Query params for access page (tab selection)
#[derive(Debug, Deserialize)]
pub struct AccessPageQuery {
    #[serde(default = "default_tab")]
    pub tab: String,
}

fn default_tab() -> String {
    "models".to_string()
}

/// Main access control page template
#[derive(Template)]
#[template(path = "pages/access.html")]
pub struct AccessPageTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub active_tab: String,
    pub model_access_rules: Vec<ModelAccessDisplay>,
    pub record_rules: Vec<RecordRuleDisplay>,
    pub field_access_rules: Vec<FieldAccessDisplay>,
}

/// Form data for model access
#[derive(Debug, Clone, Default)]
pub struct ModelAccessFormData {
    pub id: String,
    pub model_name: String,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub active: bool,
}

/// Model access edit page template
#[derive(Template)]
#[template(path = "pages/access_model_edit.html")]
pub struct AccessModelEditTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub form_data: ModelAccessFormData,
    pub available_roles: Vec<RoleOption>,
    pub is_new: bool,
}

/// Form data for record rules
#[derive(Debug, Clone, Default)]
pub struct RecordRuleFormData {
    pub id: String,
    pub name: String,
    pub model_name: String,
    pub domain_expression: String,
    pub is_global: bool,
    pub priority: i32,
    pub perm_read: bool,
    pub perm_write: bool,
    pub perm_create: bool,
    pub perm_delete: bool,
    pub active: bool,
}

/// Record rule edit page template
#[derive(Template)]
#[template(path = "pages/access_rule_edit.html")]
pub struct AccessRuleEditTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub form_data: RecordRuleFormData,
    pub available_roles: Vec<RoleOption>,
    pub is_new: bool,
}

/// Form data for field access
#[derive(Debug, Clone, Default)]
pub struct FieldAccessFormData {
    pub id: String,
    pub model_name: String,
    pub field_name: String,
    pub readable: bool,
    pub writable: bool,
    pub active: bool,
}

/// Field access edit page template
#[derive(Template)]
#[template(path = "pages/access_field_edit.html")]
pub struct AccessFieldEditTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub form_data: FieldAccessFormData,
    pub available_roles: Vec<RoleOption>,
    pub is_new: bool,
}

/// HTML form data for model access create/update
#[derive(Debug, Deserialize)]
pub struct ModelAccessForm {
    pub model_name: String,
    pub role_id: Uuid,
    pub perm_read: Option<String>,
    pub perm_write: Option<String>,
    pub perm_create: Option<String>,
    pub perm_delete: Option<String>,
    pub active: Option<String>,
}

/// HTML form data for record rule create/update
#[derive(Debug, Deserialize)]
pub struct RecordRuleForm {
    pub name: String,
    pub model_name: String,
    pub domain_expression: String,
    pub role_id: Option<Uuid>,
    pub is_global: Option<String>,
    pub priority: Option<i32>,
    pub perm_read: Option<String>,
    pub perm_write: Option<String>,
    pub perm_create: Option<String>,
    pub perm_delete: Option<String>,
    pub active: Option<String>,
}

/// HTML form data for field access create/update
#[derive(Debug, Deserialize)]
pub struct FieldAccessForm {
    pub model_name: String,
    pub field_name: String,
    pub role_id: Uuid,
    pub readable: Option<String>,
    pub writable: Option<String>,
    pub active: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────────────────

/// Build the access control API router
pub fn access_routes() -> Router<AppState> {
    Router::new()
        // Model access
        .route("/models", get(list_model_access))
        .route("/models", post(create_model_access))
        .route("/models/:id", get(get_model_access))
        .route("/models/:id", put(update_model_access))
        .route("/models/:id", delete(delete_model_access))
        // Record rules
        .route("/rules", get(list_record_rules))
        .route("/rules", post(create_record_rule))
        .route("/rules/:id", get(get_record_rule))
        .route("/rules/:id", put(update_record_rule))
        .route("/rules/:id", delete(delete_record_rule))
        // Field access
        .route("/fields", get(list_field_access))
        .route("/fields", post(create_field_access))
        .route("/fields/:id", get(get_field_access))
        .route("/fields/:id", put(update_field_access))
        .route("/fields/:id", delete(delete_field_access))
        // Debugging
        .route("/check", post(check_access))
}

/// Build the access control HTML router
pub fn access_html_routes() -> Router<AppState> {
    Router::new()
        // Main access control page with tabs
        .route("/", get(access_page))
        // Model access HTML routes
        .route("/models/new", get(model_access_new_page))
        .route("/models", post(model_access_create_html))
        .route("/models/{id}/edit", get(model_access_edit_page))
        .route("/models/{id}", post(model_access_update_html))
        .route("/models/{id}", delete(model_access_delete_html))
        // Record rules HTML routes
        .route("/rules/new", get(record_rule_new_page))
        .route("/rules", post(record_rule_create_html))
        .route("/rules/{id}/edit", get(record_rule_edit_page))
        .route("/rules/{id}", post(record_rule_update_html))
        .route("/rules/{id}", delete(record_rule_delete_html))
        // Field access HTML routes
        .route("/fields/new", get(field_access_new_page))
        .route("/fields", post(field_access_create_html))
        .route("/fields/{id}/edit", get(field_access_edit_page))
        .route("/fields/{id}", post(field_access_update_html))
        .route("/fields/{id}", delete(field_access_delete_html))
}

// ─────────────────────────────────────────────────────────────────────────────
// Model Access Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// List model access rules
async fn list_model_access(
    State(_state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Vec<ModelAccessResponse>> {
    // TODO: Implement database query
    // For now, return empty list
    let rules: Vec<ModelAccessResponse> = vec![];
    let pagination = PaginationInfo::new(0, query.page, query.per_page);
    Ok(Json(ApiResponse::paginated(rules, pagination)))
}

/// Get a single model access rule
async fn get_model_access(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ModelAccessResponse>>, ApiError> {
    // TODO: Implement database query
    Err(ApiError::not_found(format!("Model access rule {}", id)))
}

/// Create a model access rule
async fn create_model_access(
    State(_state): State<AppState>,
    Json(request): Json<ModelAccessRequest>,
) -> Result<(StatusCode, Json<ApiResponse<ModelAccessResponse>>), ApiError> {
    // TODO: Implement database insert
    // Validate the request
    if request.model_name.is_empty() {
        return Err(ApiError::bad_request("model_name is required"));
    }

    // For now, return a mock response
    let response = ModelAccessResponse {
        id: Uuid::now_v7(),
        model_name: request.model_name,
        role_id: request.role_id,
        role_name: None,
        perm_read: request.perm_read,
        perm_write: request.perm_write,
        perm_create: request.perm_create,
        perm_delete: request.perm_delete,
        company_id: request.company_id,
        active: request.active,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(ApiResponse::success(response))))
}

/// Update a model access rule
async fn update_model_access(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<ModelAccessRequest>,
) -> Result<Json<ApiResponse<ModelAccessResponse>>, ApiError> {
    // TODO: Implement database update
    Err(ApiError::not_found(format!("Model access rule {}", id)))
}

/// Delete a model access rule
async fn delete_model_access(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // TODO: Implement database delete
    Err(ApiError::not_found(format!("Model access rule {}", id)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Record Rules Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// List record rules
async fn list_record_rules(
    State(_state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Vec<RecordRuleResponse>> {
    // TODO: Implement database query
    let rules: Vec<RecordRuleResponse> = vec![];
    let pagination = PaginationInfo::new(0, query.page, query.per_page);
    Ok(Json(ApiResponse::paginated(rules, pagination)))
}

/// Get a single record rule
async fn get_record_rule(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<RecordRuleResponse>>, ApiError> {
    // TODO: Implement database query
    Err(ApiError::not_found(format!("Record rule {}", id)))
}

/// Create a record rule
async fn create_record_rule(
    State(_state): State<AppState>,
    Json(request): Json<RecordRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<RecordRuleResponse>>), ApiError> {
    // Validate the request
    if request.name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if request.model_name.is_empty() {
        return Err(ApiError::bad_request("model_name is required"));
    }
    if request.domain_expression.is_empty() {
        return Err(ApiError::bad_request("domain_expression is required"));
    }

    // Validate the domain expression syntax
    // TODO: Use DomainExpr::parse() to validate

    // For now, return a mock response
    let response = RecordRuleResponse {
        id: Uuid::now_v7(),
        name: request.name,
        model_name: request.model_name,
        domain_expression: request.domain_expression,
        role_id: request.role_id,
        role_name: None,
        perm_read: request.perm_read,
        perm_write: request.perm_write,
        perm_create: request.perm_create,
        perm_delete: request.perm_delete,
        is_global: request.is_global,
        priority: request.priority,
        active: request.active,
        company_id: request.company_id,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(ApiResponse::success(response))))
}

/// Update a record rule
async fn update_record_rule(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<RecordRuleRequest>,
) -> Result<Json<ApiResponse<RecordRuleResponse>>, ApiError> {
    // TODO: Implement database update
    Err(ApiError::not_found(format!("Record rule {}", id)))
}

/// Delete a record rule
async fn delete_record_rule(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // TODO: Implement database delete
    Err(ApiError::not_found(format!("Record rule {}", id)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Field Access Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// List field access rules
async fn list_field_access(
    State(_state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Vec<FieldAccessResponse>> {
    // TODO: Implement database query
    let rules: Vec<FieldAccessResponse> = vec![];
    let pagination = PaginationInfo::new(0, query.page, query.per_page);
    Ok(Json(ApiResponse::paginated(rules, pagination)))
}

/// Get a single field access rule
async fn get_field_access(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<FieldAccessResponse>>, ApiError> {
    // TODO: Implement database query
    Err(ApiError::not_found(format!("Field access rule {}", id)))
}

/// Create a field access rule
async fn create_field_access(
    State(_state): State<AppState>,
    Json(request): Json<FieldAccessRequest>,
) -> Result<(StatusCode, Json<ApiResponse<FieldAccessResponse>>), ApiError> {
    // Validate the request
    if request.model_name.is_empty() {
        return Err(ApiError::bad_request("model_name is required"));
    }
    if request.field_name.is_empty() {
        return Err(ApiError::bad_request("field_name is required"));
    }

    // For now, return a mock response
    let response = FieldAccessResponse {
        id: Uuid::now_v7(),
        model_name: request.model_name,
        field_name: request.field_name,
        role_id: request.role_id,
        role_name: None,
        readable: request.readable,
        writable: request.writable,
        company_id: request.company_id,
        active: request.active,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(ApiResponse::success(response))))
}

/// Update a field access rule
async fn update_field_access(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<FieldAccessRequest>,
) -> Result<Json<ApiResponse<FieldAccessResponse>>, ApiError> {
    // TODO: Implement database update
    Err(ApiError::not_found(format!("Field access rule {}", id)))
}

/// Delete a field access rule
async fn delete_field_access(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // TODO: Implement database delete
    Err(ApiError::not_found(format!("Field access rule {}", id)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Access Check Handler
// ─────────────────────────────────────────────────────────────────────────────

/// Test access for debugging
async fn check_access(
    State(_state): State<AppState>,
    Json(_request): Json<AccessCheckRequest>,
) -> ApiResult<AccessCheckResponse> {
    // TODO: Implement actual access check using AccessController
    // For now, return a mock response showing the access check would work

    let response = AccessCheckResponse {
        allowed: true,
        model_access: true,
        record_rules_applied: vec![],
        domain_filter: None,
        hidden_fields: vec![],
        readonly_fields: vec![],
    };

    Ok(Json(ApiResponse::success(response)))
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML View Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Helper to get current user info for templates
async fn get_template_user_info(
    state: &AppState,
    ctx: &Context,
) -> (String, String) {
    let user_id = ctx.user_id.unwrap_or(vortex_common::UserId(Uuid::nil()));
    let user_name = crate::db::user_lookup::get_user_display_name(&state.db, user_id)
        .await
        .unwrap_or_else(|_| "User".to_string());

    let user_initials = user_name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();

    (user_name, user_initials)
}

/// Fetch available roles for dropdowns
async fn fetch_roles(state: &AppState) -> Vec<RoleOption> {
    let query = "SELECT id, name FROM roles ORDER BY name";

    let rows = sqlx::query(query)
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default();

    rows.iter()
        .map(|row| RoleOption {
            id: row.get("id"),
            name: row.get("name"),
            selected: false,
        })
        .collect()
}

/// Fetch model access rules
async fn fetch_model_access_rules(state: &AppState) -> Vec<ModelAccessDisplay> {
    let query = r#"
        SELECT ma.id, ma.model_name, ma.role_id, r.name as role_name,
               ma.perm_read, ma.perm_write, ma.perm_create, ma.perm_delete, ma.active
        FROM model_access ma
        LEFT JOIN roles r ON r.id = ma.role_id
        ORDER BY ma.model_name, r.name
    "#;

    let rows = sqlx::query(query)
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default();

    rows.iter()
        .map(|row| ModelAccessDisplay {
            id: row.get("id"),
            model_name: row.get("model_name"),
            role_id: row.get("role_id"),
            role_name: row.get("role_name"),
            perm_read: row.get("perm_read"),
            perm_write: row.get("perm_write"),
            perm_create: row.get("perm_create"),
            perm_delete: row.get("perm_delete"),
            active: row.get("active"),
        })
        .collect()
}

/// Fetch record rules
async fn fetch_record_rules(state: &AppState) -> Vec<RecordRuleDisplay> {
    let query = r#"
        SELECT rr.id, rr.name, rr.model_name, rr.domain_expression,
               rr.role_id, r.name as role_name, rr.is_global, rr.priority, rr.active
        FROM record_rules rr
        LEFT JOIN roles r ON r.id = rr.role_id
        ORDER BY rr.model_name, rr.priority DESC
    "#;

    let rows = sqlx::query(query)
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default();

    rows.iter()
        .map(|row| RecordRuleDisplay {
            id: row.get("id"),
            name: row.get("name"),
            model_name: row.get("model_name"),
            domain_expression: row.get("domain_expression"),
            role_id: row.get("role_id"),
            role_name: row.get("role_name"),
            is_global: row.get("is_global"),
            priority: row.get("priority"),
            active: row.get("active"),
        })
        .collect()
}

/// Fetch field access rules
async fn fetch_field_access_rules(state: &AppState) -> Vec<FieldAccessDisplay> {
    let query = r#"
        SELECT fa.id, fa.model_name, fa.field_name, fa.role_id, r.name as role_name,
               fa.readable, fa.writable, fa.active
        FROM field_access fa
        LEFT JOIN roles r ON r.id = fa.role_id
        ORDER BY fa.model_name, fa.field_name, r.name
    "#;

    let rows = sqlx::query(query)
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default();

    rows.iter()
        .map(|row| FieldAccessDisplay {
            id: row.get("id"),
            model_name: row.get("model_name"),
            field_name: row.get("field_name"),
            role_id: row.get("role_id"),
            role_name: row.get("role_name"),
            readable: row.get("readable"),
            writable: row.get("writable"),
            active: row.get("active"),
        })
        .collect()
}

/// Main access control page
pub async fn access_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Query(query): Query<AccessPageQuery>,
) -> Response {
    // Check system admin access
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied - System Administrator required")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;

    // Fetch all rules
    let model_access_rules = fetch_model_access_rules(&state).await;
    let record_rules = fetch_record_rules(&state).await;
    let field_access_rules = fetch_field_access_rules(&state).await;

    let template = AccessPageTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        active_tab: query.tab,
        model_access_rules,
        record_rules,
        field_access_rules,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Model Access HTML Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// New model access page
pub async fn model_access_new_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;
    let available_roles = fetch_roles(&state).await;

    let template = AccessModelEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data: ModelAccessFormData {
            active: true,
            ..Default::default()
        },
        available_roles,
        is_new: true,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Edit model access page
pub async fn model_access_edit_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;

    // Fetch the rule
    let dialect = state.db.dialect();
    let query = format!(
        r#"
        SELECT id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, active
        FROM model_access WHERE id = {}
        "#,
        dialect.param_placeholder(1),
    );

    let row = match sqlx::query(&query)
        .bind(id)
        .fetch_optional(state.db.pool())
        .await
    {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Rule not found")).into_response(),
    };

    let role_id: Uuid = row.get("role_id");

    // Get roles with selection
    let mut available_roles = fetch_roles(&state).await;
    for role in &mut available_roles {
        role.selected = role.id == role_id;
    }

    let form_data = ModelAccessFormData {
        id: id.to_string(),
        model_name: row.get("model_name"),
        perm_read: row.get("perm_read"),
        perm_write: row.get("perm_write"),
        perm_create: row.get("perm_create"),
        perm_delete: row.get("perm_delete"),
        active: row.get("active"),
    };

    let template = AccessModelEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data,
        available_roles,
        is_new: false,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Create model access rule (HTML form)
pub async fn model_access_create_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Form(form): Form<ModelAccessForm>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();
    let id = Uuid::now_v7();

    let query = format!(
        r#"
        INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, active, created_at, updated_at)
        VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.param_placeholder(5),
        dialect.param_placeholder(6),
        dialect.param_placeholder(7),
        dialect.param_placeholder(8),
        dialect.now_function(),
        dialect.now_function(),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(id)
        .bind(&form.model_name)
        .bind(form.role_id)
        .bind(form.perm_read.is_some())
        .bind(form.perm_write.is_some())
        .bind(form.perm_create.is_some())
        .bind(form.perm_delete.is_some())
        .bind(form.active.is_some())
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    axum::response::Redirect::to("/admin/access?tab=models").into_response()
}

/// Update model access rule (HTML form)
pub async fn model_access_update_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
    Form(form): Form<ModelAccessForm>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();

    let query = format!(
        r#"
        UPDATE model_access
        SET model_name = {}, role_id = {}, perm_read = {}, perm_write = {}, perm_create = {}, perm_delete = {}, active = {}, updated_at = {}
        WHERE id = {}
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.param_placeholder(5),
        dialect.param_placeholder(6),
        dialect.param_placeholder(7),
        dialect.now_function(),
        dialect.param_placeholder(8),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(&form.model_name)
        .bind(form.role_id)
        .bind(form.perm_read.is_some())
        .bind(form.perm_write.is_some())
        .bind(form.perm_create.is_some())
        .bind(form.perm_delete.is_some())
        .bind(form.active.is_some())
        .bind(id)
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    axum::response::Redirect::to("/admin/access?tab=models").into_response()
}

/// Delete model access rule (HTMX)
pub async fn model_access_delete_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();
    let query = format!(
        "DELETE FROM model_access WHERE id = {}",
        dialect.param_placeholder(1),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(id)
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    // For HTMX, return HX-Refresh header to reload the page
    (
        StatusCode::OK,
        [("HX-Refresh", "true")],
        Html("Deleted"),
    ).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Record Rules HTML Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// New record rule page
pub async fn record_rule_new_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;
    let available_roles = fetch_roles(&state).await;

    let template = AccessRuleEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data: RecordRuleFormData {
            active: true,
            perm_read: true,
            perm_write: true,
            perm_create: true,
            perm_delete: true,
            ..Default::default()
        },
        available_roles,
        is_new: true,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Edit record rule page
pub async fn record_rule_edit_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;

    let dialect = state.db.dialect();
    let query = format!(
        r#"
        SELECT id, name, model_name, domain_expression, role_id, is_global, priority,
               perm_read, perm_write, perm_create, perm_delete, active
        FROM record_rules WHERE id = {}
        "#,
        dialect.param_placeholder(1),
    );

    let row = match sqlx::query(&query)
        .bind(id)
        .fetch_optional(state.db.pool())
        .await
    {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Rule not found")).into_response(),
    };

    let role_id: Option<Uuid> = row.get("role_id");

    let mut available_roles = fetch_roles(&state).await;
    if let Some(rid) = role_id {
        for role in &mut available_roles {
            role.selected = role.id == rid;
        }
    }

    let form_data = RecordRuleFormData {
        id: id.to_string(),
        name: row.get("name"),
        model_name: row.get("model_name"),
        domain_expression: row.get("domain_expression"),
        is_global: row.get("is_global"),
        priority: row.get("priority"),
        perm_read: row.get("perm_read"),
        perm_write: row.get("perm_write"),
        perm_create: row.get("perm_create"),
        perm_delete: row.get("perm_delete"),
        active: row.get("active"),
    };

    let template = AccessRuleEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data,
        available_roles,
        is_new: false,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Create record rule (HTML form)
pub async fn record_rule_create_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Form(form): Form<RecordRuleForm>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();
    let id = Uuid::now_v7();

    let query = format!(
        r#"
        INSERT INTO record_rules (id, name, model_name, domain_expression, role_id, is_global, priority,
                                  perm_read, perm_write, perm_create, perm_delete, active, created_at, updated_at)
        VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.param_placeholder(5),
        dialect.param_placeholder(6),
        dialect.param_placeholder(7),
        dialect.param_placeholder(8),
        dialect.param_placeholder(9),
        dialect.param_placeholder(10),
        dialect.param_placeholder(11),
        dialect.param_placeholder(12),
        dialect.now_function(),
        dialect.now_function(),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(id)
        .bind(&form.name)
        .bind(&form.model_name)
        .bind(&form.domain_expression)
        .bind(form.role_id)
        .bind(form.is_global.is_some())
        .bind(form.priority.unwrap_or(0))
        .bind(form.perm_read.is_some())
        .bind(form.perm_write.is_some())
        .bind(form.perm_create.is_some())
        .bind(form.perm_delete.is_some())
        .bind(form.active.is_some())
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    axum::response::Redirect::to("/admin/access?tab=rules").into_response()
}

/// Update record rule (HTML form)
pub async fn record_rule_update_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
    Form(form): Form<RecordRuleForm>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();

    let query = format!(
        r#"
        UPDATE record_rules
        SET name = {}, model_name = {}, domain_expression = {}, role_id = {}, is_global = {}, priority = {},
            perm_read = {}, perm_write = {}, perm_create = {}, perm_delete = {}, active = {}, updated_at = {}
        WHERE id = {}
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.param_placeholder(5),
        dialect.param_placeholder(6),
        dialect.param_placeholder(7),
        dialect.param_placeholder(8),
        dialect.param_placeholder(9),
        dialect.param_placeholder(10),
        dialect.param_placeholder(11),
        dialect.now_function(),
        dialect.param_placeholder(12),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(&form.name)
        .bind(&form.model_name)
        .bind(&form.domain_expression)
        .bind(form.role_id)
        .bind(form.is_global.is_some())
        .bind(form.priority.unwrap_or(0))
        .bind(form.perm_read.is_some())
        .bind(form.perm_write.is_some())
        .bind(form.perm_create.is_some())
        .bind(form.perm_delete.is_some())
        .bind(form.active.is_some())
        .bind(id)
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    axum::response::Redirect::to("/admin/access?tab=rules").into_response()
}

/// Delete record rule (HTMX)
pub async fn record_rule_delete_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();
    let query = format!(
        "DELETE FROM record_rules WHERE id = {}",
        dialect.param_placeholder(1),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(id)
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    (
        StatusCode::OK,
        [("HX-Refresh", "true")],
        Html("Deleted"),
    ).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Field Access HTML Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// New field access page
pub async fn field_access_new_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;
    let available_roles = fetch_roles(&state).await;

    let template = AccessFieldEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data: FieldAccessFormData {
            active: true,
            readable: true,
            writable: true,
            ..Default::default()
        },
        available_roles,
        is_new: true,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Edit field access page
pub async fn field_access_edit_page(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let (user_name, user_initials) = get_template_user_info(&state, &ctx).await;

    let dialect = state.db.dialect();
    let query = format!(
        r#"
        SELECT id, model_name, field_name, role_id, readable, writable, active
        FROM field_access WHERE id = {}
        "#,
        dialect.param_placeholder(1),
    );

    let row = match sqlx::query(&query)
        .bind(id)
        .fetch_optional(state.db.pool())
        .await
    {
        Ok(Some(row)) => row,
        _ => return (StatusCode::NOT_FOUND, Html("Rule not found")).into_response(),
    };

    let role_id: Uuid = row.get("role_id");

    let mut available_roles = fetch_roles(&state).await;
    for role in &mut available_roles {
        role.selected = role.id == role_id;
    }

    let form_data = FieldAccessFormData {
        id: id.to_string(),
        model_name: row.get("model_name"),
        field_name: row.get("field_name"),
        readable: row.get("readable"),
        writable: row.get("writable"),
        active: row.get("active"),
    };

    let template = AccessFieldEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name,
        user_initials,
        active_page: "access".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data,
        available_roles,
        is_new: false,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Create field access rule (HTML form)
pub async fn field_access_create_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Form(form): Form<FieldAccessForm>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();
    let id = Uuid::now_v7();

    let query = format!(
        r#"
        INSERT INTO field_access (id, model_name, field_name, role_id, readable, writable, active, created_at, updated_at)
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

    if let Err(e) = sqlx::query(&query)
        .bind(id)
        .bind(&form.model_name)
        .bind(&form.field_name)
        .bind(form.role_id)
        .bind(form.readable.is_some())
        .bind(form.writable.is_some())
        .bind(form.active.is_some())
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    axum::response::Redirect::to("/admin/access?tab=fields").into_response()
}

/// Update field access rule (HTML form)
pub async fn field_access_update_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
    Form(form): Form<FieldAccessForm>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();

    let query = format!(
        r#"
        UPDATE field_access
        SET model_name = {}, field_name = {}, role_id = {}, readable = {}, writable = {}, active = {}, updated_at = {}
        WHERE id = {}
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
        dialect.param_placeholder(4),
        dialect.param_placeholder(5),
        dialect.param_placeholder(6),
        dialect.now_function(),
        dialect.param_placeholder(7),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(&form.model_name)
        .bind(&form.field_name)
        .bind(form.role_id)
        .bind(form.readable.is_some())
        .bind(form.writable.is_some())
        .bind(form.active.is_some())
        .bind(id)
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    axum::response::Redirect::to("/admin/access?tab=fields").into_response()
}

/// Delete field access rule (HTMX)
pub async fn field_access_delete_html(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_system_admin(&ctx) {
        return (StatusCode::FORBIDDEN, Html("Access denied")).into_response();
    }

    let dialect = state.db.dialect();
    let query = format!(
        "DELETE FROM field_access WHERE id = {}",
        dialect.param_placeholder(1),
    );

    if let Err(e) = sqlx::query(&query)
        .bind(id)
        .execute(state.db.pool())
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error: {}", e))).into_response();
    }

    (
        StatusCode::OK,
        [("HX-Refresh", "true")],
        Html("Deleted"),
    ).into_response()
}
