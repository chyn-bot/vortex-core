//! Contacts management views

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

use super::common::generate_csrf_token;
use crate::middleware::auth::{is_admin, is_system_admin};
use crate::state::AppState;

/// Contact data for display
#[derive(Debug, Clone)]
pub struct ContactDisplay {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub code: Option<String>,
    pub contact_type: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub is_company: bool,
    pub active: bool,
}

/// Contact list page template
#[derive(Template)]
#[template(path = "pages/contacts.html")]
pub struct ContactsListTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub contacts: Vec<ContactDisplay>,
}

/// Contact form data for template
#[derive(Debug, Clone, Default)]
pub struct ContactFormData {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub code: String,
    pub contact_type: String,
    pub email: String,
    pub phone: String,
    pub mobile: String,
    pub street: String,
    pub street2: String,
    pub city: String,
    pub state: String,
    pub zip: String,
    pub country: String,
    pub vat_number: String,
    pub is_company: bool,
    pub credit_limit: String,
    pub notes: String,
    pub active: bool,
}

/// Contact edit page template
#[derive(Template)]
#[template(path = "pages/contact_edit.html")]
pub struct ContactEditTemplate {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
    pub form_data: ContactFormData,
    pub is_new: bool,
}

/// Form data for contact create/edit
#[derive(Debug, Deserialize)]
pub struct ContactForm {
    pub name: String,
    pub display_name: Option<String>,
    pub code: Option<String>,
    pub contact_type: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub street: Option<String>,
    pub street2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub zip: Option<String>,
    pub country: Option<String>,
    pub vat_number: Option<String>,
    pub is_company: Option<String>,
    pub credit_limit: Option<String>,
    pub notes: Option<String>,
    pub active: Option<String>,
}

/// List all contacts
pub async fn contacts_list(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
) -> Response {
    // Check authentication
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

    // Fetch contacts for company
    let contacts = fetch_contacts_list(&state, ctx.company_id).await;

    let template = ContactsListTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "contacts".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        contacts,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Show contact create form
pub async fn contacts_new(
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

    let template = ContactEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "contacts".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data: ContactFormData {
            contact_type: "customer".to_string(),
            active: true,
            ..Default::default()
        },
        is_new: true,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Show contact edit form
pub async fn contacts_edit(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(contact_id): Path<Uuid>,
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

    // Fetch contact to edit
    let contact = match fetch_contact_by_id(&state, contact_id, ctx.company_id).await {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Html("Contact not found")).into_response(),
    };

    let template = ContactEditTemplate {
        csrf_token: generate_csrf_token(),
        user_name: current_user_name,
        user_initials,
        active_page: "contacts".to_string(),
        is_admin: is_admin(&ctx),
        is_system_admin: is_system_admin(&ctx),
        form_data: contact,
        is_new: false,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// Handle contact create
pub async fn contacts_create(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Form(form): Form<ContactForm>,
) -> Response {
    tracing::info!("Creating contact: name={}", form.name);

    // Validate
    if form.name.is_empty() {
        tracing::warn!("Contact creation failed: name is empty");
        return (StatusCode::BAD_REQUEST, Html("Name is required")).into_response();
    }

    let company_id = match ctx.company_id {
        Some(c) => c.0,
        None => {
            tracing::warn!("Contact creation failed: no company context");
            return (StatusCode::BAD_REQUEST, Html("Company context required")).into_response()
        }
    };

    tracing::info!("Creating contact in company {}", company_id);
    let dialect = state.db.dialect();
    let contact_id = Uuid::now_v7();
    let contact_type = form.contact_type.as_deref().unwrap_or("customer");
    let is_company = form.is_company.is_some();
    let active = form.active.is_some();

    // Parse credit_limit
    let credit_limit: f64 = form
        .credit_limit
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    // Insert contact with dialect-aware placeholders
    let insert_query = format!(
        r#"
        INSERT INTO contacts (
            id, company_id, name, display_name, code, contact_type,
            email, phone, mobile, street, street2, city, state, zip, country,
            vat_number, is_company, credit_limit, notes, active,
            created_at, updated_at, created_by
        )
        VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})
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
        dialect.param_placeholder(13),
        dialect.param_placeholder(14),
        dialect.param_placeholder(15),
        dialect.param_placeholder(16),
        dialect.param_placeholder(17),
        dialect.param_placeholder(18),
        dialect.param_placeholder(19),
        dialect.param_placeholder(20),
        dialect.now_function(),
        dialect.now_function(),
        dialect.param_placeholder(21),
    );

    let result = sqlx::query(&insert_query)
        .bind(contact_id)
        .bind(company_id)
        .bind(&form.name)
        .bind(&form.display_name)
        .bind(&form.code)
        .bind(contact_type)
        .bind(&form.email)
        .bind(&form.phone)
        .bind(&form.mobile)
        .bind(&form.street)
        .bind(&form.street2)
        .bind(&form.city)
        .bind(&form.state)
        .bind(&form.zip)
        .bind(&form.country)
        .bind(&form.vat_number)
        .bind(is_company)
        .bind(credit_limit)
        .bind(&form.notes)
        .bind(active)
        .bind(ctx.user_id.map(|u| u.0))
        .execute(state.db.pool())
        .await;

    match result {
        Ok(_) => {
            tracing::info!("Contact created successfully: {}", contact_id);
            axum::response::Redirect::to("/contacts").into_response()
        }
        Err(e) => {
            tracing::error!("Contact creation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error creating contact: {}", e))).into_response()
        }
    }
}

/// Handle contact update
pub async fn contacts_update(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(contact_id): Path<Uuid>,
    Form(form): Form<ContactForm>,
) -> Response {
    // Validate
    if form.name.is_empty() {
        return (StatusCode::BAD_REQUEST, Html("Name is required")).into_response();
    }

    let company_id = match ctx.company_id {
        Some(c) => c.0,
        None => return (StatusCode::BAD_REQUEST, Html("Company context required")).into_response(),
    };

    let dialect = state.db.dialect();
    let contact_type = form.contact_type.as_deref().unwrap_or("customer");
    let is_company = form.is_company.is_some();
    let active = form.active.is_some();

    // Parse credit_limit
    let credit_limit: f64 = form
        .credit_limit
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    // Update contact with dialect-aware placeholders
    let update_query = format!(
        r#"
        UPDATE contacts SET
            name = {}, display_name = {}, code = {}, contact_type = {},
            email = {}, phone = {}, mobile = {},
            street = {}, street2 = {}, city = {}, state = {}, zip = {}, country = {},
            vat_number = {}, is_company = {}, credit_limit = {}, notes = {}, active = {},
            updated_at = {}, updated_by = {}
        WHERE id = {} AND company_id = {}
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
        dialect.param_placeholder(13),
        dialect.param_placeholder(14),
        dialect.param_placeholder(15),
        dialect.param_placeholder(16),
        dialect.param_placeholder(17),
        dialect.param_placeholder(18),
        dialect.now_function(),
        dialect.param_placeholder(19),
        dialect.param_placeholder(20),
        dialect.param_placeholder(21),
    );

    let result = sqlx::query(&update_query)
        .bind(&form.name)
        .bind(&form.display_name)
        .bind(&form.code)
        .bind(contact_type)
        .bind(&form.email)
        .bind(&form.phone)
        .bind(&form.mobile)
        .bind(&form.street)
        .bind(&form.street2)
        .bind(&form.city)
        .bind(&form.state)
        .bind(&form.zip)
        .bind(&form.country)
        .bind(&form.vat_number)
        .bind(is_company)
        .bind(credit_limit)
        .bind(&form.notes)
        .bind(active)
        .bind(ctx.user_id.map(|u| u.0))
        .bind(contact_id)
        .bind(company_id)
        .execute(state.db.pool())
        .await;

    if let Err(e) = result {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error updating contact: {}", e))).into_response();
    }

    // Redirect to contacts list
    axum::response::Redirect::to("/contacts").into_response()
}

/// Handle contact delete (soft delete)
pub async fn contacts_delete(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<Context>,
    Path(contact_id): Path<Uuid>,
) -> Response {
    let company_id = match ctx.company_id {
        Some(c) => c.0,
        None => return (StatusCode::BAD_REQUEST, Html("Company context required")).into_response(),
    };

    let dialect = state.db.dialect();

    // Soft delete - set active = false
    let delete_query = format!(
        "UPDATE contacts SET active = false, updated_at = {}, updated_by = {} WHERE id = {} AND company_id = {}",
        dialect.now_function(),
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
        dialect.param_placeholder(3),
    );

    let result = sqlx::query(&delete_query)
        .bind(ctx.user_id.map(|u| u.0))
        .bind(contact_id)
        .bind(company_id)
        .execute(state.db.pool())
        .await;

    if let Err(e) = result {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html(format!("Error deleting contact: {}", e))).into_response();
    }

    // Redirect to contacts list
    axum::response::Redirect::to("/contacts").into_response()
}

/// Fetch contacts list from database
async fn fetch_contacts_list(
    state: &AppState,
    company_id: Option<vortex_common::CompanyId>,
) -> Vec<ContactDisplay> {
    let company_id = match company_id {
        Some(c) => c.0,
        None => return Vec::new(),
    };

    let dialect = state.db.dialect();

    let query = format!(
        r#"
        SELECT
            id, name, display_name, code, contact_type,
            email, phone, mobile, city, country, is_company, active
        FROM contacts
        WHERE company_id = {}
        ORDER BY name
        "#,
        dialect.param_placeholder(1),
    );

    let rows = sqlx::query(&query)
        .bind(company_id)
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default();

    rows.iter()
        .map(|row| ContactDisplay {
            id: row.get("id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            code: row.get("code"),
            contact_type: row.get("contact_type"),
            email: row.get("email"),
            phone: row.get("phone"),
            mobile: row.get("mobile"),
            city: row.get("city"),
            country: row.get("country"),
            is_company: row.get("is_company"),
            active: row.get("active"),
        })
        .collect()
}

/// Fetch a single contact by ID with full details
async fn fetch_contact_by_id(
    state: &AppState,
    contact_id: Uuid,
    company_id: Option<vortex_common::CompanyId>,
) -> Option<ContactFormData> {
    let company_id = company_id?.0;
    let dialect = state.db.dialect();

    let query = format!(
        r#"
        SELECT
            id, name, display_name, code, contact_type,
            email, phone, mobile, street, street2, city, state, zip, country,
            vat_number, is_company, COALESCE(credit_limit::text, '0') as credit_limit, notes, active
        FROM contacts
        WHERE id = {} AND company_id = {}
        "#,
        dialect.param_placeholder(1),
        dialect.param_placeholder(2),
    );

    let row = sqlx::query(&query)
        .bind(contact_id)
        .bind(company_id)
        .fetch_optional(state.db.pool())
        .await
        .ok()
        .flatten()?;

    Some(ContactFormData {
        id: row.get::<Uuid, _>("id").to_string(),
        name: row.get("name"),
        display_name: row.get::<Option<String>, _>("display_name").unwrap_or_default(),
        code: row.get::<Option<String>, _>("code").unwrap_or_default(),
        contact_type: row.get("contact_type"),
        email: row.get::<Option<String>, _>("email").unwrap_or_default(),
        phone: row.get::<Option<String>, _>("phone").unwrap_or_default(),
        mobile: row.get::<Option<String>, _>("mobile").unwrap_or_default(),
        street: row.get::<Option<String>, _>("street").unwrap_or_default(),
        street2: row.get::<Option<String>, _>("street2").unwrap_or_default(),
        city: row.get::<Option<String>, _>("city").unwrap_or_default(),
        state: row.get::<Option<String>, _>("state").unwrap_or_default(),
        zip: row.get::<Option<String>, _>("zip").unwrap_or_default(),
        country: row.get::<Option<String>, _>("country").unwrap_or_default(),
        vat_number: row.get::<Option<String>, _>("vat_number").unwrap_or_default(),
        is_company: row.get("is_company"),
        credit_limit: row.get::<String, _>("credit_limit"),
        notes: row.get::<Option<String>, _>("notes").unwrap_or_default(),
        active: row.get("active"),
    })
}
