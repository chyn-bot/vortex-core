//! Payment-terms master: CRUD screen + reusable helpers.
//!
//! A payment term is a named due-date rule (`document date + due_days`). It is
//! shared by sales and accounting, so it lives here in the lowest layer. This
//! module owns the Accounting Setup ▸ Payment Terms screen and exposes two
//! helpers other modules reuse: [`payment_term_options`] (build a `<select>`)
//! and [`due_date_for`] (compute a due date from a term).

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::handlers::{opt_str, page_shell, redirect, render_sidebar};

pub fn payment_term_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/payment-terms", get(list_payment_terms))
        .route("/accounting/payment-terms/new", get(new_payment_term_form))
        .route("/accounting/payment-terms/create", post(create_payment_term))
        .route("/accounting/payment-terms/{id}", get(edit_payment_term))
        .route("/accounting/payment-terms/{id}", post(update_payment_term))
}

/// `<option>` list of active payment terms (plus the currently-selected one even
/// if archived), with a leading blank. Reused by the contact Accounting panel
/// and the sales quotation editor.
pub async fn payment_term_options(db: &PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, due_days FROM payment_term \
         WHERE active OR id = $1 ORDER BY due_days, name",
    )
    .bind(selected)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from("<option value=\"\">— No payment terms —</option>");
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!("<option value=\"{id}\"{sel}>{}</option>", esc(&name)));
    }
    out
}

/// Compute a due date as `base + due_days` for the given term. Returns `None`
/// when the term is missing (caller keeps its own fallback).
pub async fn due_date_for(db: &PgPool, term_id: Option<Uuid>, base: NaiveDate) -> Option<NaiveDate> {
    let term_id = term_id?;
    let days: i32 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT due_days FROM payment_term WHERE id = $1",
    )
    .bind(term_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    Some(base + vortex_plugin_sdk::chrono::Duration::days(days as i64))
}

async fn list_payment_terms(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let config = ListConfig::new("Payment Terms", "payment_term")
        .custom_select(
            "id, name, due_days::text AS due_days, \
             CASE WHEN active THEN 'yes' ELSE 'no' END AS active",
        )
        .column(ListColumn::new("name", "Name").sortable().searchable())
        .column(ListColumn::new("due_days", "Due (days)").sortable())
        .column(ListColumn::new("active", "Active").bool_badge(
            "Active",
            "badge-success",
            "Archived",
            "badge-ghost",
        ))
        .detail_url("/accounting/payment-terms/{id}")
        .create("New Payment Term", "/accounting/payment-terms/new")
        .default_sort("due_days");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            vortex_plugin_sdk::tracing::error!(error = %e, "payment terms list failed");
            return Html("<h1>Failed to load payment terms</h1>").into_response();
        }
    };
    let list_html = render_list(&config, &result, &params, "/accounting/payment-terms");
    Html(page_shell(&sidebar, "Payment Terms", &list_html)).into_response()
}

#[allow(clippy::too_many_arguments)]
fn payment_term_form(
    action: &str,
    title: &str,
    name: &str,
    due_days: &str,
    note: &str,
    active: bool,
    is_new: bool,
    below: &str,
) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let active_row = if is_new {
        String::new()
    } else {
        format!(
            r#"<div class="form-control mb-3">
<label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="active" value="1" class="checkbox checkbox-sm"{checked}/><span class="label-text">Active</span></label>
</div>"#,
            checked = if active { " checked" } else { "" },
        )
    };
    let fields = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" value="{name}" class="input input-bordered input-sm" required maxlength="120" placeholder="e.g. Net 30"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Due in (days) *</span></label>
<input name="due_days" type="number" min="0" step="1" value="{due_days}" class="input input-bordered input-sm w-40" required/>
<span class="label-text-alt opacity-60 mt-1">Days from the document date until payment is due. 0 = due on receipt.</span>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Note</span></label>
<textarea name="note" class="textarea textarea-bordered textarea-sm" rows="2" maxlength="500" placeholder="Optional wording printed on documents">{note}</textarea>
</div>
{active_row}"#,
        name = esc(name),
        due_days = esc(due_days),
        note = esc(note),
        active_row = active_row,
    );
    let inner = vortex_plugin_sdk::framework::form_section_raw("", &fields);
    vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/accounting/payment-terms",
        control_row: "",
        form_attrs: &format!(r#"method="POST" action="{action}""#, action = action),
        title,
        inner: &inner,
        footer: r#"<a href="/accounting/payment-terms" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Save</button>"#,
        below,
    })
}

async fn new_payment_term_form(
    State(state): State<Arc<AppState>>,
    Db(_db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let content = payment_term_form(
        "/accounting/payment-terms/create",
        "New Payment Term",
        "",
        "30",
        "",
        true,
        true,
        "",
    );
    Html(page_shell(&sidebar, "New Payment Term", &content)).into_response()
}

async fn create_payment_term(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let Some(name) = opt_str(&form, "name") else {
        return (StatusCode::BAD_REQUEST, "Name is required").into_response();
    };
    let due_days: i32 = form
        .get("due_days")
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|d| *d >= 0)
        .unwrap_or(0);
    let note = opt_str(&form, "note").unwrap_or("");
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO payment_term (id, name, due_days, note) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(due_days)
    .bind(note)
    .execute(&db)
    .await;
    match res {
        Ok(_) => {
            let entry = AuditEntry::new(AuditAction::RecordCreated, AuditSeverity::Info)
                .with_user(UserId(user.id))
                .with_username(&user.username)
                .with_database(&db_ctx.db_name)
                .with_resource("payment_term", id.to_string())
                .with_resource_name(name);
            let _ = state.audit.log(entry).await;
            redirect("/accounting/payment-terms")
        }
        Err(e) => {
            vortex_plugin_sdk::tracing::error!(error = %e, "payment term create failed");
            (StatusCode::UNPROCESSABLE_ENTITY, "Failed to create payment term").into_response()
        }
    }
}

async fn edit_payment_term(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let Some(row) = vortex_plugin_sdk::sqlx::query(
        "SELECT name, due_days, note, active FROM payment_term WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (StatusCode::NOT_FOUND, "Payment term not found").into_response();
    };
    let name: String = row.get("name");
    let due_days: i32 = row.get("due_days");
    let note: String = row.get("note");
    let active: bool = row.get("active");
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("payment_term", id);
    let content = payment_term_form(
        &format!("/accounting/payment-terms/{id}"),
        &name,
        &name,
        &due_days.to_string(),
        &note,
        active,
        false,
        &activity_panel,
    );
    Html(page_shell(&sidebar, "Edit Payment Term", &content)).into_response()
}

async fn update_payment_term(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let Some(name) = opt_str(&form, "name") else {
        return (StatusCode::BAD_REQUEST, "Name is required").into_response();
    };
    let due_days: i32 = form
        .get("due_days")
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|d| *d >= 0)
        .unwrap_or(0);
    let note = opt_str(&form, "note").unwrap_or("");
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE payment_term SET name = $2, due_days = $3, note = $4, active = $5, \
            updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(due_days)
    .bind(note)
    .bind(form.contains_key("active"))
    .execute(&db)
    .await;
    if let Err(e) = res {
        vortex_plugin_sdk::tracing::error!(error = %e, "payment term update failed");
        return (StatusCode::UNPROCESSABLE_ENTITY, "Failed to update payment term").into_response();
    }
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("payment_term", id.to_string())
        .with_resource_name(name);
    let _ = state.audit.log(entry).await;
    redirect("/accounting/payment-terms")
}
