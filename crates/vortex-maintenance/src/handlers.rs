//! Maintenance/CMMS handlers — assets, work orders (with part
//! consumption through the inventory primitive), and preventive plans.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

/// Asset code sequence — `AST/000001`.
const ASSET_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("maintenance.asset", "AST").with_padding(6);

/// Work-order number sequence — `WO/000001`.
pub(crate) const WO_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("maintenance.work_order", "WO").with_padding(6);

pub fn maintenance_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Work orders (primary landing)
        .route("/maintenance", get(list_work_orders))
        .route("/maintenance/work-orders/new", get(new_work_order_form))
        .route("/maintenance/work-orders/create", post(create_work_order))
        .route("/maintenance/work-orders/{id}", get(edit_work_order))
        .route("/maintenance/work-orders/{id}", post(update_work_order))
        .route("/maintenance/work-orders/{id}/parts", post(add_part))
        .route("/maintenance/work-orders/{id}/parts/{part_id}/delete", post(delete_part))
        .route("/maintenance/work-orders/{id}/duplicate", post(duplicate_work_order))
        .route("/maintenance/work-orders/{id}/start", post(start_work_order))
        .route("/maintenance/work-orders/{id}/complete", post(complete_work_order))
        .route("/maintenance/work-orders/{id}/cancel", post(cancel_work_order))
        // Assets
        .route("/maintenance/assets", get(list_assets))
        .route("/maintenance/assets/new", get(new_asset_form))
        .route("/maintenance/assets/create", post(create_asset))
        .route("/maintenance/assets/{id}", get(edit_asset))
        .route("/maintenance/assets/{id}", post(update_asset))
        .route("/maintenance/assets/{id}/delete", post(delete_asset))
        // Asset categories
        .route("/maintenance/asset-categories", get(list_categories))
        .route("/maintenance/asset-categories/new", get(new_category_form))
        .route("/maintenance/asset-categories/create", post(create_category))
        .route("/maintenance/asset-categories/{id}", get(edit_category))
        .route("/maintenance/asset-categories/{id}", post(update_category))
        // Plans
        .route("/maintenance/plans", get(list_plans))
        .route("/maintenance/plans/new", get(new_plan_form))
        .route("/maintenance/plans/create", post(create_plan))
        .route("/maintenance/plans/{id}", get(edit_plan))
        .route("/maintenance/plans/{id}", post(update_plan))
        .route("/maintenance/plans/{id}/duplicate", post(duplicate_plan))
        .route("/maintenance/plans/generate", post(generate_now))
}

// ─────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────

fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=20" rel="stylesheet"/>
<script src="/static/vortex.js?v=20" defer></script>
<script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden">
<button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square">
<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
</button>
<a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">vor</span><span class="opacity-60">tex</span></a>
</div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
{content}
</main></div></body></html>"##,
        title = title, sidebar = sidebar, content = content,
    )
}

fn render_sidebar(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext) -> String {
    render_sidebar_active(state, user, db_ctx, "maintenance")
}

/// Sidebar with a specific menu-entry id marked active — used for
/// sub-menu pages (e.g. `maintenance.asset_categories`) so the
/// Configuration branch auto-expands and the item highlights.
fn render_sidebar_active(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext, active: &str) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    vortex_plugin_sdk::framework::build_sidebar(
        active, display_name, &initials, &db_ctx.installed_modules,
        user.is_admin(),
        &state.plugin_registry, &user.roles,
        &db_ctx.custom_apps_html,
    )
}

async fn default_company(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_optional(db).await.ok().flatten()
}

fn opt_uuid(form: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    form.get(key).filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
}

fn dec_or(form: &HashMap<String, String>, key: &str, default: Decimal) -> Decimal {
    form.get(key).and_then(|s| s.trim().parse::<Decimal>().ok()).unwrap_or(default)
}

fn money(d: Decimal) -> String {
    d.round_dp(2).to_string()
}

fn esc(s: &str) -> String {
    vortex_plugin_sdk::framework::html_escape(s)
}

/// `<option>` builder from (id, label) rows of a simple query.
async fn options_query(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    sql: &str,
    placeholder: &str,
    selected: Option<Uuid>,
) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(sql).fetch_all(db).await.unwrap_or_default();
    let mut out = format!(r#"<option value="">{}</option>"#, placeholder);
    for r in &rows {
        let id: Uuid = r.get("id");
        let label: String = r.get("label");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(r#"<option value="{id}"{sel}>{label}</option>"#, id = id, sel = sel, label = esc(&label)));
    }
    out
}

async fn category_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM maint_asset_category WHERE active ORDER BY name", "-- Category --", selected).await
}
async fn asset_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM maint_asset WHERE active ORDER BY code", "-- Asset --", selected).await
}
async fn user_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    options_query(db, "SELECT id, username AS label FROM users ORDER BY username", "-- Unassigned --", selected).await
}
async fn vendor_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM contacts WHERE active AND contact_type IN ('supplier','both') ORDER BY name", "-- Vendor --", selected).await
}
async fn location_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM stock_location WHERE active AND location_type = 'internal' ORDER BY code", "-- Stock Location --", selected).await
}
async fn product_options(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM stock_product WHERE active AND product_type <> 'service' ORDER BY code", "-- Product --", None).await
}

fn wo_state_badge(s: &str) -> &'static str {
    match s {
        "draft" => r#"<span class="badge badge-ghost">Draft</span>"#,
        "in_progress" => r#"<span class="badge badge-warning">In Progress</span>"#,
        "done" => r#"<span class="badge badge-success">Done</span>"#,
        "cancelled" => r#"<span class="badge badge-error">Cancelled</span>"#,
        _ => "",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Preventive-plan work-order generator (also used by the scheduler)
// ─────────────────────────────────────────────────────────────────────────

/// Generate draft work orders for every active plan due within its lead
/// time, then advance each plan's next date. Idempotent per day in the
/// sense that a plan only generates once its next_date is reached.
pub async fn generate_due_work_orders(state: &AppState) -> VortexResult<()> {
    let plans = vortex_plugin_sdk::sqlx::query(
        "SELECT id, asset_id, wo_type, priority, assigned_to, consume_location_id, \
                next_date, company_id \
         FROM maint_plan \
         WHERE active AND state = 'active' AND next_date <= CURRENT_DATE + lead_time_days",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let mut generated = 0i64;
    for p in &plans {
        let plan_id: Uuid = p.get("id");
        let asset_id: Option<Uuid> = p.try_get("asset_id").ok();
        let wo_type: String = p.get("wo_type");
        let priority: String = p.get("priority");
        let assigned_to: Option<Uuid> = p.try_get("assigned_to").ok();
        let consume_location_id: Option<Uuid> = p.try_get("consume_location_id").ok();
        let next_date: vortex_plugin_sdk::chrono::NaiveDate = p.get("next_date");
        let company_id: Option<Uuid> = p.try_get("company_id").ok();

        let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &WO_SEQ)
            .await
            .map_err(|e| VortexError::Internal(e.to_string()))?;

        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO maint_work_order \
             (id, number, asset_id, wo_type, priority, state, scheduled_date, \
              assigned_to, plan_id, consume_location_id, description, company_id) \
             VALUES ($1,$2,$3,$4,$5,'draft',$6,$7,$8,$9,$10,$11)",
        )
        .bind(Uuid::now_v7())
        .bind(&number)
        .bind(asset_id)
        .bind(&wo_type)
        .bind(&priority)
        .bind(next_date)
        .bind(assigned_to)
        .bind(plan_id)
        .bind(consume_location_id)
        .bind("Auto-generated from preventive maintenance plan")
        .bind(company_id)
        .execute(&state.db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        vortex_plugin_sdk::sqlx::query(
            "UPDATE maint_plan SET \
                next_date = (next_date + frequency_interval * ('1 ' || frequency_unit)::interval)::date, \
                updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(plan_id)
        .execute(&state.db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

        generated += 1;
    }

    if generated > 0 {
        info!(count = generated, "generated work orders from maintenance plans");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Asset categories
// ─────────────────────────────────────────────────────────────────────────

async fn list_categories(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "maintenance.asset_categories");
    let config = ListConfig::new("Asset Categories", "maint_asset_category")
        .custom_from("maint_asset_category c LEFT JOIN maint_asset_category p ON p.id = c.parent_id")
        .custom_select("c.id, c.name, p.name AS parent_name, c.active")
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("c.name"))
        .column(ListColumn::new("parent_name", "Parent").sql_expr("p.name"))
        .column(ListColumn::new("active", "Status").bool_badge("Active", "badge-success", "Archived", "badge-warning").sql_expr("c.active"))
        .detail_url("/maintenance/asset-categories/{id}")
        .create("New Category", "/maintenance/asset-categories/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error=%e, "category list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/maintenance/asset-categories");
    Html(page_shell(&sidebar, "Asset Categories", &list_html)).into_response()
}

fn category_form_body(action: &str, title: &str, name: &str, parents: &str, active: bool, is_new: bool) -> String {
    let active_box = if is_new { String::new() } else {
        format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="active" class="checkbox checkbox-sm" {}/><span class="label-text">Active</span></label></div>"#, if active { "checked" } else { "" })
    };
    // Flat sheet section (see vortex_plugin_sdk::framework::form_section_raw)
    // instead of a floating card — the whole form reads as one Odoo-style sheet.
    let fields = format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parent Category</span></label>
<select name="parent_id" class="select select-bordered select-sm">{parents}</select></div>
{active_box}"#,
        name = name, parents = parents, active_box = active_box,
    );
    let form_attrs = format!(r#"method="POST" action="{action}""#);
    let inner = vortex_plugin_sdk::framework::form_section_raw("", &fields);
    vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/maintenance/asset-categories",
        control_row: "",
        form_attrs: &form_attrs,
        title,
        inner: &inner,
        footer: r#"<a href="/maintenance/asset-categories" class="btn btn-ghost btn-sm">Cancel</a><button type="submit" class="btn btn-primary btn-sm">Save</button>"#,
        below: "",
    })
}

async fn new_category_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let parents = category_options(&db, None).await;
    let body = category_form_body("/maintenance/asset-categories/create", "New Category", "", &parents, true, true);
    Html(page_shell(&sidebar, "New Category", &body)).into_response()
}

async fn create_category(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query("INSERT INTO maint_asset_category (id, name, parent_id, company_id) VALUES ($1,$2,$3,$4)")
        .bind(Uuid::now_v7()).bind(&name).bind(opt_uuid(&form, "parent_id")).bind(company_id)
        .execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to("/maintenance/asset-categories").into_response()
}

async fn edit_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, parent_id, active FROM maint_asset_category WHERE id = $1")
        .bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        _ => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let name: String = row.get("name");
    let parent_id: Option<Uuid> = row.try_get("parent_id").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let parents = category_options(&db, parent_id).await;
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("maint_category", id);
    let body = category_form_body(&format!("/maintenance/asset-categories/{id}"), &format!("Edit {}", name), &esc(&name), &parents, active, false);
    let body = format!(r#"{body}<div class="mt-6">{activity_panel}</div>"#);
    Html(page_shell(&sidebar, "Edit Category", &body)).into_response()
}

async fn update_category(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let parent_id = opt_uuid(&form, "parent_id").filter(|p| *p != id);
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE maint_asset_category SET name=$1, parent_id=$2, active=$3, updated_at=NOW() WHERE id=$4")
        .bind(&name).bind(parent_id).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to("/maintenance/asset-categories").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Assets
// ─────────────────────────────────────────────────────────────────────────

async fn list_assets(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let config = ListConfig::new("Assets", "maint_asset")
        .custom_from(
            "maint_asset a \
             LEFT JOIN maint_asset_category c ON c.id = a.category_id \
             LEFT JOIN ( \
                SELECT asset_id, COUNT(*) FILTER (WHERE state IN ('draft','in_progress')) AS open_wo \
                FROM maint_work_order GROUP BY asset_id \
             ) w ON w.asset_id = a.id",
        )
        .custom_select(
            "a.id, a.code, a.name, c.name AS category_name, a.criticality, a.state, \
             a.location, COALESCE(w.open_wo,0)::text AS open_wo, a.active",
        )
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("a.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("a.name"))
        .column(ListColumn::new("category_name", "Category").sortable().sql_expr("c.name"))
        .column(ListColumn::new("location", "Location").searchable().sql_expr("a.location"))
        .column(
            ListColumn::new("criticality", "Criticality")
                .filterable(&[("low","Low"),("medium","Medium"),("high","High"),("critical","Critical")])
                .badge(&[("low","Low","badge-ghost"),("medium","Medium","badge-info"),("high","High","badge-warning"),("critical","Critical","badge-error")])
                .sql_expr("a.criticality"),
        )
        .column(
            ListColumn::new("state", "State")
                .filterable(&[("operational","Operational"),("under_maintenance","Under Maintenance"),("down","Down"),("decommissioned","Decommissioned")])
                .badge(&[("operational","Operational","badge-success"),("under_maintenance","Under Maintenance","badge-warning"),("down","Down","badge-error"),("decommissioned","Decommissioned","badge-ghost")])
                .sql_expr("a.state"),
        )
        .column(ListColumn::new("open_wo", "Open WOs").sql_expr("COALESCE(w.open_wo,0)"))
        .detail_url("/maintenance/assets/{id}")
        .create("New Asset", "/maintenance/assets/new")
        .pivot_url("/pivot/maint_asset?rows=criticality")
        .default_sort("code")
        .group_by_options(&[("category_name","Category"),("criticality","Criticality"),("state","State")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error=%e, "asset list failed"); return Html("<h1>Failed to load assets</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/maintenance/assets");
    let toolbar = r#"<div class="flex justify-end mb-3"><a href="/maintenance/asset-categories" class="btn btn-ghost btn-sm">Manage Categories</a></div>"#;
    Html(page_shell(&sidebar, "Assets", &format!("{}{}", toolbar, list_html))).into_response()
}

/// Render the asset create/edit form fields (shared by new + edit).
#[allow(clippy::too_many_arguments)]
fn asset_fields(
    crit: &str, astate: &str, location: &str, model: &str, serial: &str,
    purchase_date: &str, warranty_end: &str, purchase_cost: &str, note: &str,
    categories: &str, vendors: &str, parents: &str,
) -> String {
    let sel = |val: &str, opt: &str| if val == opt { "selected" } else { "" };
    format!(
        r#"<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
<div class="form-control"><label class="label"><span class="label-text">Category</span></label>
<select name="category_id" class="select select-bordered select-sm">{categories}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Location</span></label>
<input name="location" class="input input-bordered input-sm" value="{location}" placeholder="Site / area"/></div>
<div class="form-control"><label class="label"><span class="label-text">Criticality</span></label>
<select name="criticality" class="select select-bordered select-sm">
<option value="low" {sc_low}>Low</option><option value="medium" {sc_med}>Medium</option>
<option value="high" {sc_high}>High</option><option value="critical" {sc_crit}>Critical</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">State</span></label>
<select name="state" class="select select-bordered select-sm">
<option value="operational" {ss_op}>Operational</option><option value="under_maintenance" {ss_um}>Under Maintenance</option>
<option value="down" {ss_down}>Down</option><option value="decommissioned" {ss_dec}>Decommissioned</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Model</span></label>
<input name="model" class="input input-bordered input-sm" value="{model}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Serial Number</span></label>
<input name="serial_number" class="input input-bordered input-sm" value="{serial}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Vendor</span></label>
<select name="vendor_id" class="select select-bordered select-sm">{vendors}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Parent Asset</span></label>
<select name="parent_id" class="select select-bordered select-sm">{parents}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Purchase Date</span></label>
<input name="purchase_date" type="date" class="input input-bordered input-sm" value="{purchase_date}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Warranty End</span></label>
<input name="warranty_end" type="date" class="input input-bordered input-sm" value="{warranty_end}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Purchase Cost</span></label>
<input name="purchase_cost" type="number" step="0.01" class="input input-bordered input-sm" value="{purchase_cost}"/></div>
</div>
<div class="form-control mt-3"><label class="label"><span class="label-text">Notes</span></label>
<textarea name="note" class="textarea textarea-bordered" rows="2">{note}</textarea></div>"#,
        categories = categories, vendors = vendors, parents = parents,
        location = location, model = model, serial = serial,
        purchase_date = purchase_date, warranty_end = warranty_end, purchase_cost = purchase_cost, note = note,
        sc_low = sel(crit, "low"), sc_med = sel(crit, "medium"), sc_high = sel(crit, "high"), sc_crit = sel(crit, "critical"),
        ss_op = sel(astate, "operational"), ss_um = sel(astate, "under_maintenance"), ss_down = sel(astate, "down"), ss_dec = sel(astate, "decommissioned"),
    )
}

async fn new_asset_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let categories = category_options(&db, None).await;
    let vendors = vendor_options(&db, None).await;
    let parents = asset_options(&db, None).await;
    let fields = asset_fields("medium", "operational", "", "", "", "", "", "0", "", &categories, &vendors, &parents);
    let section = format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" required/></div>
{fields}"#,
        fields = fields,
    );
    let inner = vortex_plugin_sdk::framework::form_section_raw("", &section);
    let content = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/maintenance/assets",
        control_row: "",
        form_attrs: r#"method="POST" action="/maintenance/assets/create""#,
        title: "New Asset",
        inner: &inner,
        footer: r#"<a href="/maintenance/assets" class="btn btn-ghost btn-sm">Cancel</a><button type="submit" class="btn btn-primary btn-sm">Create</button>"#,
        below: "",
    });
    Html(page_shell(&sidebar, "New Asset", &content)).into_response()
}

async fn create_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &ASSET_SEQ).await {
        Ok(c) => c,
        Err(e) => { error!(error=%e, "asset seq failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate code").into_response(); }
    };
    let company_id = default_company(&db).await;
    let pdate: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("purchase_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let wend: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("warranty_end").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());

    let asset_id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO maint_asset \
         (id, code, name, category_id, criticality, state, location, model, serial_number, \
          vendor_id, parent_id, purchase_date, warranty_end, purchase_cost, note, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
    )
    .bind(asset_id).bind(&code).bind(&name)
    .bind(opt_uuid(&form, "category_id"))
    .bind(form.get("criticality").map(|s| s.as_str()).unwrap_or("medium"))
    .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
    .bind(form.get("location").filter(|s| !s.is_empty()))
    .bind(form.get("model").filter(|s| !s.is_empty()))
    .bind(form.get("serial_number").filter(|s| !s.is_empty()))
    .bind(opt_uuid(&form, "vendor_id"))
    .bind(opt_uuid(&form, "parent_id"))
    .bind(pdate).bind(wend)
    .bind(dec_or(&form, "purchase_cost", Decimal::ZERO))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(company_id).bind(user.id)
    .execute(&db).await;
    if let Err(e) = res {
        error!(error=%e, "asset insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {e}")).into_response();
    }
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("maint_asset", asset_id.to_string()).with_resource_name(&name)
     .with_details(json!({"code": code}));
    let _ = state.audit.log(entry).await;
    info!(code=%code, "asset created");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/assets/{asset_id}")).into_response()
}

async fn edit_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, category_id, criticality, state, location, model, serial_number, \
                vendor_id, parent_id, purchase_date::text AS purchase_date, warranty_end::text AS warranty_end, \
                purchase_cost, note, active FROM maint_asset WHERE id = $1",
    ).bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Asset not found").into_response(),
        Err(e) => { error!(error=%e, "asset fetch failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(); }
    };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let category_id: Option<Uuid> = row.try_get("category_id").ok();
    let criticality: String = row.get("criticality");
    let astate: String = row.get("state");
    let location: Option<String> = row.try_get("location").ok();
    let model: Option<String> = row.try_get("model").ok();
    let serial: Option<String> = row.try_get("serial_number").ok();
    let vendor_id: Option<Uuid> = row.try_get("vendor_id").ok();
    let parent_id: Option<Uuid> = row.try_get("parent_id").ok();
    let pdate: Option<String> = row.try_get("purchase_date").ok();
    let wend: Option<String> = row.try_get("warranty_end").ok();
    let cost: Decimal = row.try_get("purchase_cost").unwrap_or(Decimal::ZERO);
    let note: Option<String> = row.try_get("note").ok();
    let active: bool = row.try_get("active").unwrap_or(true);

    let categories = category_options(&db, category_id).await;
    let vendors = vendor_options(&db, vendor_id).await;
    let parents = asset_options(&db, parent_id).await;
    let fields = asset_fields(
        &criticality, &astate,
        &esc(location.as_deref().unwrap_or("")), &esc(model.as_deref().unwrap_or("")),
        &esc(serial.as_deref().unwrap_or("")), pdate.as_deref().unwrap_or(""), wend.as_deref().unwrap_or(""),
        &money(cost), &esc(note.as_deref().unwrap_or("")), &categories, &vendors, &parents,
    );

    // Work-order history for this asset.
    let wo_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, number, wo_type, state, scheduled_date::text AS scheduled_date \
         FROM maint_work_order WHERE asset_id = $1 ORDER BY created_at DESC LIMIT 50",
    ).bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut wo_html = String::new();
    for r in &wo_rows {
        let wid: Uuid = r.get("id");
        let num: String = r.get("number");
        let wtype: String = r.get("wo_type");
        let st: String = r.get("state");
        let sched: Option<String> = r.try_get("scheduled_date").ok();
        wo_html.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/maintenance/work-orders/{wid}'"><td class="font-mono">{num}</td><td>{wtype}</td><td>{sched}</td><td>{badge}</td></tr>"#,
            wid = wid, num = esc(&num), wtype = esc(&wtype), sched = esc(sched.as_deref().unwrap_or("—")), badge = wo_state_badge(&st),
        ));
    }
    if wo_html.is_empty() {
        wo_html.push_str(r#"<tr><td colspan="4" class="text-base-content/50">No work orders yet</td></tr>"#);
    }

    let history = vortex_plugin_sdk::framework::render_audit_trail(&db, "maint_asset", id).await;
    // Activity stream: schedule/assign/complete tasks, messages, attachments.
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("maint_asset", id);
    let active_checked = if active { "checked" } else { "" };

    let content = format!(
        r#"<div class="flex items-center justify-between mb-4">
<div><a href="/maintenance/assets" class="btn btn-ghost btn-sm mb-2">← Back to Assets</a>
<h1 class="text-2xl font-bold">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span></h1></div>
<div class="flex gap-2">
<a href="/maintenance/work-orders/new?asset={id}" class="btn btn-primary btn-sm">New Work Order</a>
<form method="POST" action="/maintenance/assets/{id}/delete" onsubmit="return confirm('Archive this asset?')"><button class="btn btn-error btn-sm btn-outline">Archive</button></form>
</div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
<div class="lg:col-span-2"><form method="POST" action="/maintenance/assets/{id}">
<div class="bg-base-100 rounded-lg shadow-sm border border-base-300 p-6 md:p-8">
<section class="break-inside-avoid mb-8 last:mb-0">
<h2 class="text-xs font-semibold uppercase tracking-wider text-base-content/50 border-b border-base-300 pb-2 mb-4">Details</h2>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name_val}" required/></div>
{fields}
<div class="form-control mt-3"><label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" {active_checked}/><span class="label-text">Active</span></label></div>
</section>
</div>
<div class="flex justify-end gap-2 mt-4"><button class="btn btn-primary btn-sm">Save</button></div>
</form></div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-2">Work Orders</h2>
<table class="table table-sm"><thead><tr><th>Number</th><th>Type</th><th>Scheduled</th><th>Status</th></tr></thead>
<tbody>{wo_html}</tbody></table>
</div></div>
{activity_panel}
{history}
</div>
</div>"#,
        id = id, name = esc(&name), code = esc(&code), name_val = esc(&name),
        fields = fields, active_checked = active_checked, wo_html = wo_html, history = history,
        activity_panel = activity_panel,
    );
    Html(page_shell(&sidebar, &format!("Asset {}", name), &content)).into_response()
}

async fn update_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let pdate: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("purchase_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let wend: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("warranty_end").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let parent_id = opt_uuid(&form, "parent_id").filter(|p| *p != id);
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE maint_asset SET name=$1, category_id=$2, criticality=$3, state=$4, location=$5, \
         model=$6, serial_number=$7, vendor_id=$8, parent_id=$9, purchase_date=$10, warranty_end=$11, \
         purchase_cost=$12, note=$13, active=$14, updated_by=$15, updated_at=NOW() WHERE id=$16",
    )
    .bind(&name).bind(opt_uuid(&form, "category_id"))
    .bind(form.get("criticality").map(|s| s.as_str()).unwrap_or("medium"))
    .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
    .bind(form.get("location").filter(|s| !s.is_empty()))
    .bind(form.get("model").filter(|s| !s.is_empty()))
    .bind(form.get("serial_number").filter(|s| !s.is_empty()))
    .bind(opt_uuid(&form, "vendor_id")).bind(parent_id)
    .bind(pdate).bind(wend).bind(dec_or(&form, "purchase_cost", Decimal::ZERO))
    .bind(form.get("note").filter(|s| !s.is_empty())).bind(form.contains_key("active"))
    .bind(user.id).bind(id)
    .execute(&db).await;
    if let Err(e) = res {
        error!(error=%e, "asset update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {e}")).into_response();
    }
    let _ = db_ctx; let _ = &state;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/assets/{id}")).into_response()
}

async fn delete_asset(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE maint_asset SET active=false, updated_by=$1, updated_at=NOW() WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to("/maintenance/assets").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Work orders
// ─────────────────────────────────────────────────────────────────────────

async fn list_work_orders(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let config = ListConfig::new("Work Orders", "maint_work_order")
        .custom_from(
            "maint_work_order w \
             LEFT JOIN maint_asset a ON a.id = w.asset_id \
             LEFT JOIN users u ON u.id = w.assigned_to",
        )
        .custom_select(
            "w.id, w.number, a.name AS asset_name, w.wo_type, w.priority, w.state, \
             w.scheduled_date::text AS scheduled_date, u.username AS assignee",
        )
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("w.number"))
        .column(ListColumn::new("asset_name", "Asset").searchable().sql_expr("a.name"))
        .column(
            ListColumn::new("wo_type", "Type")
                .filterable(&[("corrective","Corrective"),("preventive","Preventive"),("inspection","Inspection")])
                .badge(&[("corrective","Corrective","badge-warning"),("preventive","Preventive","badge-info"),("inspection","Inspection","badge-ghost")])
                .sql_expr("w.wo_type"),
        )
        .column(
            ListColumn::new("priority", "Priority")
                .filterable(&[("low","Low"),("normal","Normal"),("high","High"),("urgent","Urgent")])
                .badge(&[("low","Low","badge-ghost"),("normal","Normal","badge-info"),("high","High","badge-warning"),("urgent","Urgent","badge-error")])
                .sql_expr("w.priority"),
        )
        .column(ListColumn::new("scheduled_date", "Scheduled").sortable().sql_expr("w.scheduled_date"))
        .column(ListColumn::new("assignee", "Assignee").sql_expr("u.username"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[("draft","Draft"),("in_progress","In Progress"),("done","Done"),("cancelled","Cancelled")])
                .badge(&[("draft","Draft","badge-ghost"),("in_progress","In Progress","badge-warning"),("done","Done","badge-success"),("cancelled","Cancelled","badge-error")])
                .sql_expr("w.state"),
        )
        .detail_url("/maintenance/work-orders/{id}")
        .create("New Work Order", "/maintenance/work-orders/new")
        .pivot_url("/pivot/maint_work_order?rows=state")
        .default_sort("number")
        .group_by_options(&[("state","Status"),("wo_type","Type"),("priority","Priority")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error=%e, "WO list failed"); return Html("<h1>Failed to load work orders</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/maintenance");
    Html(page_shell(&sidebar, "Work Orders", &list_html)).into_response()
}

async fn new_work_order_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let preselect = q.get("asset").and_then(|s| s.parse::<Uuid>().ok());
    let assets = asset_options(&db, preselect).await;
    let users = user_options(&db, None).await;
    let locations = location_options(&db, None).await;
    let section = format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered select-sm">{assets}</select></div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3"><label class="label"><span class="label-text">Type</span></label>
<select name="wo_type" class="select select-bordered select-sm">
<option value="corrective">Corrective</option><option value="preventive">Preventive</option><option value="inspection">Inspection</option></select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered select-sm">
<option value="low">Low</option><option value="normal" selected>Normal</option><option value="high">High</option><option value="urgent">Urgent</option></select></div>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3"><label class="label"><span class="label-text">Scheduled Date</span></label>
<input name="scheduled_date" type="date" class="input input-bordered input-sm"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered select-sm">{users}</select></div>
</div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parts Source Location</span></label>
<select name="consume_location_id" class="select select-bordered select-sm">{locations}</select></div>
<div class="form-control mb-4"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered" rows="3"></textarea></div>"#,
        assets = assets, users = users, locations = locations,
    );
    let inner = vortex_plugin_sdk::framework::form_section_raw("", &section);
    let content = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/maintenance",
        control_row: "",
        form_attrs: r#"method="POST" action="/maintenance/work-orders/create""#,
        title: "New Work Order",
        inner: &inner,
        footer: r#"<a href="/maintenance" class="btn btn-ghost btn-sm">Cancel</a><button type="submit" class="btn btn-primary btn-sm">Create</button>"#,
        below: "",
    });
    Html(page_shell(&sidebar, "New Work Order", &content)).into_response()
}

async fn create_work_order(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &WO_SEQ).await {
        Ok(n) => n,
        Err(e) => { error!(error=%e, "WO seq failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate number").into_response(); }
    };
    let company_id = default_company(&db).await;
    let sched: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("scheduled_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let wo_id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO maint_work_order \
         (id, number, asset_id, wo_type, priority, scheduled_date, assigned_to, consume_location_id, description, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(wo_id).bind(&number).bind(opt_uuid(&form, "asset_id"))
    .bind(form.get("wo_type").map(|s| s.as_str()).unwrap_or("corrective"))
    .bind(form.get("priority").map(|s| s.as_str()).unwrap_or("normal"))
    .bind(sched).bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "consume_location_id"))
    .bind(form.get("description").filter(|s| !s.is_empty()))
    .bind(company_id).bind(user.id)
    .execute(&db).await;
    if let Err(e) = res {
        error!(error=%e, "WO insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {e}")).into_response();
    }
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("maint_work_order", wo_id.to_string()).with_resource_name(&number)
     .with_details(json!({"number": number}));
    let _ = state.audit.log(entry).await;
    info!(number=%number, "work order created");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{wo_id}")).into_response()
}

async fn edit_work_order(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT w.number, w.asset_id, w.wo_type, w.priority, w.state, \
                w.scheduled_date::text AS scheduled_date, w.assigned_to, w.consume_location_id, \
                w.description, w.resolution, w.downtime_hours, a.name AS asset_name \
         FROM maint_work_order w LEFT JOIN maint_asset a ON a.id = w.asset_id WHERE w.id = $1",
    ).bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Work order not found").into_response(),
        Err(e) => { error!(error=%e, "WO fetch failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(); }
    };
    let number: String = row.get("number");
    let asset_id: Option<Uuid> = row.try_get("asset_id").ok();
    let wo_type: String = row.get("wo_type");
    let priority: String = row.get("priority");
    let wstate: String = row.get("state");
    let sched: Option<String> = row.try_get("scheduled_date").ok();
    let assigned_to: Option<Uuid> = row.try_get("assigned_to").ok();
    let consume_loc: Option<Uuid> = row.try_get("consume_location_id").ok();
    let description: Option<String> = row.try_get("description").ok();
    let resolution: Option<String> = row.try_get("resolution").ok();
    let downtime: Decimal = row.try_get("downtime_hours").unwrap_or(Decimal::ZERO);
    let editable = wstate == "draft" || wstate == "in_progress";

    // Parts.
    let part_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT pt.id, p.code AS product_code, p.name AS product_name, pt.description, \
                pt.quantity, pt.lot_name, pt.unit_cost, pt.consumed \
         FROM maint_work_order_part pt JOIN stock_product p ON p.id = pt.product_id \
         WHERE pt.work_order_id = $1 ORDER BY pt.created_at",
    ).bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut parts_html = String::new();
    for r in &part_rows {
        let pid: Uuid = r.get("id");
        let pcode: String = r.get("product_code");
        let pname: String = r.get("product_name");
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        let lot: Option<String> = r.try_get("lot_name").ok();
        let cost: Decimal = r.try_get("unit_cost").unwrap_or(Decimal::ZERO);
        let consumed: bool = r.try_get("consumed").unwrap_or(false);
        let del = if editable && !consumed {
            format!(r#"<form method="POST" action="/maintenance/work-orders/{id}/parts/{pid}/delete"><button class="btn btn-ghost btn-xs text-error">✕</button></form>"#, id = id, pid = pid)
        } else { String::new() };
        let status = if consumed { r#"<span class="badge badge-success badge-xs">consumed</span>"# } else { r#"<span class="badge badge-ghost badge-xs">planned</span>"# };
        parts_html.push_str(&format!(
            r#"<tr><td class="font-mono">{pcode}</td><td>{pname}</td><td class="text-right">{qty}</td><td>{lot}</td><td class="text-right">{cost}</td><td>{status}</td><td class="text-right">{del}</td></tr>"#,
            pcode = esc(&pcode), pname = esc(&pname), qty = qty,
            lot = esc(lot.as_deref().unwrap_or("—")), cost = money(cost), status = status, del = del,
        ));
    }
    if parts_html.is_empty() {
        parts_html.push_str(r#"<tr><td colspan="7" class="text-base-content/50">No parts planned</td></tr>"#);
    }

    let add_part = if editable {
        let products = product_options(&db).await;
        format!(
            r#"<form method="POST" action="/maintenance/work-orders/{id}/parts" class="mt-3">
<div class="grid grid-cols-12 gap-2 items-end">
<div class="form-control col-span-5"><label class="label py-1"><span class="label-text text-xs">Product</span></label>
<select name="product_id" class="select select-bordered select-sm" required>{products}</select></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Qty</span></label>
<input name="quantity" type="number" step="0.0001" min="0.0001" value="1" class="input input-bordered input-sm" required/></div>
<div class="form-control col-span-3"><label class="label py-1"><span class="label-text text-xs">Lot/Serial (if tracked)</span></label>
<input name="lot_name" class="input input-bordered input-sm"/></div>
<div class="col-span-2"><button class="btn btn-primary btn-sm w-full">Add Part</button></div>
</div></form>"#,
            id = id, products = products,
        )
    } else { String::new() };

    // Header form (editable in draft/in_progress).
    let header = {
        let assets = asset_options(&db, asset_id).await;
        let users = user_options(&db, assigned_to).await;
        let locations = location_options(&db, consume_loc).await;
        let sel = |val: &str, opt: &str| if val == opt { "selected" } else { "" };
        let dis = if editable { "" } else { " disabled" };
        format!(
            r#"<form method="POST" action="/maintenance/work-orders/{id}">
<fieldset{dis}>
<div class="bg-base-100 rounded-lg shadow-sm border border-base-300 p-6 md:p-8">
<section class="break-inside-avoid mb-8 last:mb-0">
<h2 class="text-xs font-semibold uppercase tracking-wider text-base-content/50 border-b border-base-300 pb-2 mb-4">Details</h2>
<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
<div class="form-control"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered select-sm">{assets}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered select-sm">{users}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Type</span></label>
<select name="wo_type" class="select select-bordered select-sm">
<option value="corrective" {t_c}>Corrective</option><option value="preventive" {t_p}>Preventive</option><option value="inspection" {t_i}>Inspection</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered select-sm">
<option value="low" {p_l}>Low</option><option value="normal" {p_n}>Normal</option><option value="high" {p_h}>High</option><option value="urgent" {p_u}>Urgent</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Scheduled Date</span></label>
<input name="scheduled_date" type="date" value="{sched}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Parts Source Location</span></label>
<select name="consume_location_id" class="select select-bordered select-sm">{locations}</select></div>
</div>
<div class="form-control mt-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered" rows="2">{description}</textarea></div>
<div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-1">
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Resolution</span></label>
<textarea name="resolution" class="textarea textarea-bordered" rows="2">{resolution}</textarea></div>
<div class="form-control"><label class="label"><span class="label-text">Downtime (hours)</span></label>
<input name="downtime_hours" type="number" step="0.01" value="{downtime}" class="input input-bordered input-sm"/></div>
</div>
</section>
</div>
{footer}
</fieldset>
</form>"#,
            id = id, dis = dis, assets = assets, users = users, locations = locations,
            sched = esc(sched.as_deref().unwrap_or("")),
            description = esc(description.as_deref().unwrap_or("")),
            resolution = esc(resolution.as_deref().unwrap_or("")),
            downtime = money(downtime),
            t_c = sel(&wo_type, "corrective"), t_p = sel(&wo_type, "preventive"), t_i = sel(&wo_type, "inspection"),
            p_l = sel(&priority, "low"), p_n = sel(&priority, "normal"), p_h = sel(&priority, "high"), p_u = sel(&priority, "urgent"),
            footer = if editable { r#"<div class="flex justify-end gap-2 mt-4"><button class="btn btn-primary btn-sm">Save</button></div>"# } else { "" },
        )
    };

    // Action buttons.
    let mut actions = String::new();
    match wstate.as_str() {
        "draft" => {
            actions.push_str(&format!(r#"<form method="POST" action="/maintenance/work-orders/{id}/start" class="inline"><button class="btn btn-warning btn-sm">Start</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/maintenance/work-orders/{id}/complete" class="inline ml-2"><button class="btn btn-success btn-sm">Complete</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/maintenance/work-orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this work order?')"><button class="btn btn-ghost btn-sm">Cancel</button></form>"#, id = id));
        }
        "in_progress" => {
            actions.push_str(&format!(r#"<form method="POST" action="/maintenance/work-orders/{id}/complete" class="inline"><button class="btn btn-success btn-sm">Complete</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/maintenance/work-orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this work order?')"><button class="btn btn-ghost btn-sm">Cancel</button></form>"#, id = id));
        }
        _ => {}
    }
    // Duplicate is available in every state — re-raising a done/cancelled
    // work order as a fresh draft is its main use case.
    let dup = duplicate_button(&format!("/maintenance/work-orders/{id}/duplicate"));
    if actions.is_empty() {
        actions.push_str(&dup);
    } else {
        actions.push_str(&format!(r#"<span class="inline-block ml-2">{dup}</span>"#));
    }

    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("maint_work_order", id);
    let content = format!(
        r#"<div class="flex items-center justify-between mb-4">
<div><a href="/maintenance" class="btn btn-ghost btn-sm mb-2">← Back to Work Orders</a>
<h1 class="text-2xl font-bold">{number} {badge}</h1></div>
<div>{actions}</div></div>

<div class="mb-6">{header}</div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-2">Parts</h2>
<p class="text-xs text-base-content/50 mb-2">Parts are consumed from the source location as stock moves when the work order is completed.</p>
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Code</th><th>Product</th><th class="text-right">Qty</th><th>Lot/Serial</th><th class="text-right">Unit Cost</th><th>Status</th><th></th></tr></thead>
<tbody>{parts}</tbody></table></div>
{add_part}
</div></div>
<div class="mt-6">{activity_panel}</div>"#,
        number = esc(&number), badge = wo_state_badge(&wstate), actions = actions,
        header = header, parts = parts_html, add_part = add_part,
    );
    Html(page_shell(&sidebar, &format!("WO {}", number), &content)).into_response()
}

async fn update_work_order(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if !wo_in_states(&db, id, &["draft", "in_progress"]).await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "This work order can no longer be edited").into_response();
    }
    let sched: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("scheduled_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE maint_work_order SET asset_id=$1, wo_type=$2, priority=$3, scheduled_date=$4, \
         assigned_to=$5, consume_location_id=$6, description=$7, resolution=$8, downtime_hours=$9, updated_at=NOW() WHERE id=$10",
    )
    .bind(opt_uuid(&form, "asset_id"))
    .bind(form.get("wo_type").map(|s| s.as_str()).unwrap_or("corrective"))
    .bind(form.get("priority").map(|s| s.as_str()).unwrap_or("normal"))
    .bind(sched).bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "consume_location_id"))
    .bind(form.get("description").filter(|s| !s.is_empty()))
    .bind(form.get("resolution").filter(|s| !s.is_empty()))
    .bind(dec_or(&form, "downtime_hours", Decimal::ZERO))
    .bind(id)
    .execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{id}")).into_response()
}

/// POST /maintenance/work-orders/{id}/duplicate — copy a work order (with
/// its planned parts) into a fresh draft: new number from the WO sequence,
/// state back to draft, all execution history (schedule, start/completion,
/// resolution, downtime) reset. Copied parts come out un-consumed with no
/// stock-move reference — completing the duplicate posts its own moves;
/// the source's moves are never referenced or replayed.
async fn duplicate_work_order(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &WO_SEQ).await {
        Ok(n) => n,
        Err(e) => { error!(error=%e, "duplicate WO seq failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate number").into_response(); }
    };
    let spec = DuplicateSpec::new("maint_work_order")
        .set("number", json!(number))       // fresh unique document number
        .skip("state")                      // DB default 'draft'
        .skip("scheduled_date")             // NULL — the copy is scheduled anew
        .skip("started_at")                 // execution history stays on the source
        .skip("completed_at")
        .skip("resolution")
        .skip("downtime_hours")             // DB default 0
        .skip("plan_id")                    // a manual copy was not plan-generated
        .skip("updated_by")
        .child(
            ChildCopy::new("maint_work_order_part", "work_order_id")
                .set("consumed", json!(false)) // copy is un-consumed…
                .skip("move_id"),              // …and references no stock move
        );
    match spec.execute(&db, id, Some(user.id)).await {
        Ok(new_id) => {
            let entry = vortex_plugin_sdk::security::AuditEntry::new(
                vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
            ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
             .with_database(&db_ctx.db_name).with_resource("maint_work_order", new_id.to_string()).with_resource_name(&number)
             .with_details(json!({"duplicated_from": id, "number": number}));
            let _ = state.audit.log(entry).await;
            info!(number=%number, "work order duplicated");
            vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{new_id}")).into_response()
        }
        Err(e) => {
            error!(error=%e, "WO duplicate failed");
            (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response()
        }
    }
}

/// True iff the work order is in one of `wants`.
async fn wo_in_states(db: &vortex_plugin_sdk::sqlx::PgPool, id: Uuid, wants: &[&str]) -> bool {
    let s: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM maint_work_order WHERE id = $1")
        .bind(id).fetch_optional(db).await.ok().flatten();
    s.map(|st| wants.contains(&st.as_str())).unwrap_or(false)
}

async fn add_part(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if !wo_in_states(&db, id, &["draft", "in_progress"]).await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Parts can only be added while the work order is open").into_response();
    }
    let Some(product_id) = opt_uuid(&form, "product_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product is required").into_response();
    };
    let quantity = dec_or(&form, "quantity", Decimal::ONE);
    if quantity <= Decimal::ZERO {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Quantity must be positive").into_response();
    }
    // Default unit cost from the product.
    let unit_cost: Decimal = vortex_plugin_sdk::sqlx::query_scalar("SELECT cost FROM stock_product WHERE id = $1")
        .bind(product_id).fetch_optional(&db).await.ok().flatten().unwrap_or(Decimal::ZERO);
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO maint_work_order_part (id, work_order_id, product_id, quantity, lot_name, unit_cost, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::now_v7()).bind(id).bind(product_id).bind(quantity)
    .bind(form.get("lot_name").filter(|s| !s.is_empty())).bind(unit_cost).bind(company_id)
    .execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{id}")).into_response()
}

async fn delete_part(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path((id, part_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM maint_work_order_part WHERE id=$1 AND work_order_id=$2 AND NOT consumed")
        .bind(part_id).bind(id).execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{id}")).into_response()
}

async fn start_work_order(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE maint_work_order SET state='in_progress', started_at=COALESCE(started_at, NOW()), updated_by=$1, updated_at=NOW() WHERE id=$2 AND state='draft'",
    ).bind(user.id).bind(id).execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{id}")).into_response()
}

async fn cancel_work_order(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE maint_work_order SET state='cancelled', updated_by=$1, updated_at=NOW() WHERE id=$2 AND state IN ('draft','in_progress')",
    ).bind(user.id).bind(id).execute(&db).await;
    if let Ok(r) = res {
        if r.rows_affected() == 0 {
            return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open work orders can be cancelled").into_response();
        }
    }
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{id}")).into_response()
}

/// Complete a work order: consume its planned parts as stock moves out of
/// the source location, then mark it done.
async fn complete_work_order(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let wo = vortex_plugin_sdk::sqlx::query("SELECT number, state, consume_location_id, company_id FROM maint_work_order WHERE id = $1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let Some(wo) = wo else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Work order not found").into_response();
    };
    let number: String = wo.get("number");
    let wstate: String = wo.get("state");
    let company_id: Option<Uuid> = wo.try_get("company_id").ok();
    if wstate != "draft" && wstate != "in_progress" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open work orders can be completed").into_response();
    }

    // Resolve the source location: the WO's, else the first internal location.
    let consume_location: Option<Uuid> = match wo.try_get::<Option<Uuid>, _>("consume_location_id").ok().flatten() {
        Some(l) => Some(l),
        None => vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM stock_location WHERE location_type='internal' AND active ORDER BY created_at LIMIT 1")
            .fetch_optional(&db).await.ok().flatten(),
    };

    // Consumption sink: the Inventory Adjustment (inventory-type) location.
    let sink_location: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM stock_location WHERE location_type='inventory' AND active ORDER BY created_at LIMIT 1",
    ).fetch_optional(&db).await.ok().flatten();

    // Planned (unconsumed) parts joined with product tracking + uom.
    let parts = vortex_plugin_sdk::sqlx::query(
        "SELECT pt.id, pt.product_id, pt.quantity, pt.lot_name, p.tracking, p.uom_id \
         FROM maint_work_order_part pt JOIN stock_product p ON p.id = pt.product_id \
         WHERE pt.work_order_id = $1 AND NOT pt.consumed",
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    // Pre-validate: any parts to consume need stock plumbing + lots.
    if !parts.is_empty() {
        if consume_location.is_none() {
            return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No source stock location set or available for parts.").into_response();
        }
        if sink_location.is_none() {
            return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No Inventory Adjustment location exists to absorb consumption.").into_response();
        }
        for r in &parts {
            let tracking: String = r.get("tracking");
            let lot: Option<String> = r.try_get("lot_name").ok();
            if tracking != "none" && lot.as_deref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                return (
                    vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
                    "A lot/serial number is required on every tracked part before completing.",
                ).into_response();
            }
        }
    }

    let consume_location = consume_location.unwrap_or_default();
    let sink_location = sink_location.unwrap_or_default();

    // Consume each part: post a move source → sink and mark it consumed.
    for r in &parts {
        let part_id: Uuid = r.get("id");
        let product_id: Uuid = r.get("product_id");
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        let tracking: String = r.get("tracking");
        let uom_id: Option<Uuid> = r.try_get("uom_id").ok();
        let lot_name: Option<String> = r.try_get("lot_name").ok();

        let lot_id: Option<Uuid> = if tracking == "none" {
            None
        } else {
            match vortex_inventory::service::resolve_lot(&db, product_id, lot_name.as_deref().unwrap_or("").trim(), &tracking, company_id, user.id).await {
                Ok(l) => Some(l),
                Err(e) => { error!(error=%e, "lot resolve failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve lot").into_response(); }
            }
        };

        let reference = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &vortex_inventory::move_sequence()).await {
            Ok(n) => n,
            Err(e) => { error!(error=%e, "move seq failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate move reference").into_response(); }
        };
        let move_id = match vortex_inventory::post_move(
            &db, &reference, company_id, user.id, product_id, lot_id, uom_id, qty,
            consume_location, sink_location, Some(&number),
        ).await {
            Ok(m) => m,
            Err(e) => { error!(error=%e, "consume move failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to consume parts: {e}")).into_response(); }
        };
        let _ = vortex_plugin_sdk::sqlx::query("UPDATE maint_work_order_part SET consumed=true, move_id=$1 WHERE id=$2")
            .bind(move_id).bind(part_id).execute(&db).await;
    }

    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE maint_work_order SET state='done', completed_at=NOW(), updated_by=$1, updated_at=NOW() WHERE id=$2",
    ).bind(user.id).bind(id).execute(&db).await;

    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("maint_work_order", id.to_string()).with_resource_name(&number)
     .with_details(json!({"action": "completed", "parts_consumed": parts.len()}));
    let _ = state.audit.log(entry).await;
    info!(number=%number, "work order completed");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/work-orders/{id}")).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Plans
// ─────────────────────────────────────────────────────────────────────────

async fn list_plans(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let config = ListConfig::new("Maintenance Plans", "maint_plan")
        .custom_from("maint_plan pl LEFT JOIN maint_asset a ON a.id = pl.asset_id")
        .custom_select(
            "pl.id, pl.name, a.name AS asset_name, \
             (pl.frequency_interval::text || ' ' || pl.frequency_unit) AS frequency, \
             pl.next_date::text AS next_date, pl.state",
        )
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("pl.name"))
        .column(ListColumn::new("asset_name", "Asset").searchable().sql_expr("a.name"))
        .column(ListColumn::new("frequency", "Every").sql_expr("pl.frequency_unit"))
        .column(ListColumn::new("next_date", "Next Date").sortable().sql_expr("pl.next_date"))
        .column(
            ListColumn::new("state", "State")
                .filterable(&[("active","Active"),("paused","Paused")])
                .badge(&[("active","Active","badge-success"),("paused","Paused","badge-ghost")])
                .sql_expr("pl.state"),
        )
        .detail_url("/maintenance/plans/{id}")
        .create("New Plan", "/maintenance/plans/new")
        .default_sort("next_date")
        .group_by_options(&[("asset_name","Asset"),("state","State")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error=%e, "plan list failed"); return Html("<h1>Failed to load plans</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/maintenance/plans");
    let toolbar = r#"<div class="flex justify-end mb-3"><form method="POST" action="/maintenance/plans/generate"><button class="btn btn-primary btn-sm">Generate Due Work Orders</button></form></div>"#;
    Html(page_shell(&sidebar, "Maintenance Plans", &format!("{}{}", toolbar, list_html))).into_response()
}

fn plan_form_fields(
    wo_type: &str, priority: &str, interval: &str, unit: &str, next_date: &str,
    lead: &str, pstate: &str, description: &str, assets: &str, users: &str, locations: &str, is_new: bool,
) -> String {
    let sel = |val: &str, opt: &str| if val == opt { "selected" } else { "" };
    let state_box = if is_new { String::new() } else {
        format!(
            r#"<div class="form-control"><label class="label"><span class="label-text">State</span></label>
<select name="state" class="select select-bordered select-sm">
<option value="active" {a}>Active</option><option value="paused" {p}>Paused</option></select></div>"#,
            a = sel(pstate, "active"), p = sel(pstate, "paused"),
        )
    };
    format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name_placeholder}" required/></div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
<div class="form-control"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered select-sm">{assets}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Work Order Type</span></label>
<select name="wo_type" class="select select-bordered select-sm">
<option value="preventive" {t_p}>Preventive</option><option value="inspection" {t_i}>Inspection</option><option value="corrective" {t_c}>Corrective</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered select-sm">
<option value="low" {p_l}>Low</option><option value="normal" {p_n}>Normal</option><option value="high" {p_h}>High</option><option value="urgent" {p_u}>Urgent</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered select-sm">{users}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Every</span></label>
<div class="flex gap-2">
<input name="frequency_interval" type="number" min="1" value="{interval}" class="input input-bordered input-sm w-24"/>
<select name="frequency_unit" class="select select-bordered select-sm">
<option value="day" {u_d}>Day(s)</option><option value="week" {u_w}>Week(s)</option><option value="month" {u_m}>Month(s)</option><option value="year" {u_y}>Year(s)</option></select>
</div></div>
<div class="form-control"><label class="label"><span class="label-text">Next Date *</span></label>
<input name="next_date" type="date" value="{next_date}" class="input input-bordered input-sm" required/></div>
<div class="form-control"><label class="label"><span class="label-text">Lead Time (days)</span></label>
<input name="lead_time_days" type="number" min="0" value="{lead}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Parts Source Location</span></label>
<select name="consume_location_id" class="select select-bordered select-sm">{locations}</select></div>
{state_box}
</div>
<div class="form-control mt-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered" rows="2">{description}</textarea></div>"#,
        name_placeholder = "",
        assets = assets, users = users, locations = locations,
        interval = interval, next_date = next_date, lead = lead, description = description, state_box = state_box,
        t_p = sel(wo_type, "preventive"), t_i = sel(wo_type, "inspection"), t_c = sel(wo_type, "corrective"),
        p_l = sel(priority, "low"), p_n = sel(priority, "normal"), p_h = sel(priority, "high"), p_u = sel(priority, "urgent"),
        u_d = sel(unit, "day"), u_w = sel(unit, "week"), u_m = sel(unit, "month"), u_y = sel(unit, "year"),
    )
}

async fn new_plan_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let assets = asset_options(&db, None).await;
    let users = user_options(&db, None).await;
    let locations = location_options(&db, None).await;
    let fields = plan_form_fields("preventive", "normal", "1", "month", "", "0", "active", "", &assets, &users, &locations, true);
    let inner = vortex_plugin_sdk::framework::form_section_raw("", &fields);
    let content = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/maintenance/plans",
        control_row: "",
        form_attrs: r#"method="POST" action="/maintenance/plans/create""#,
        title: "New Maintenance Plan",
        inner: &inner,
        footer: r#"<a href="/maintenance/plans" class="btn btn-ghost btn-sm">Cancel</a><button type="submit" class="btn btn-primary btn-sm">Create</button>"#,
        below: "",
    });
    Html(page_shell(&sidebar, "New Plan", &content)).into_response()
}

async fn create_plan(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let next_date: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("next_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let Some(next_date) = next_date else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Next date is required").into_response();
    };
    let interval: i32 = form.get("frequency_interval").and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let lead: i32 = form.get("lead_time_days").and_then(|s| s.parse().ok()).unwrap_or(0).max(0);
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO maint_plan \
         (id, name, asset_id, wo_type, priority, frequency_interval, frequency_unit, next_date, \
          lead_time_days, assigned_to, consume_location_id, description, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(Uuid::now_v7()).bind(&name).bind(opt_uuid(&form, "asset_id"))
    .bind(form.get("wo_type").map(|s| s.as_str()).unwrap_or("preventive"))
    .bind(form.get("priority").map(|s| s.as_str()).unwrap_or("normal"))
    .bind(interval).bind(form.get("frequency_unit").map(|s| s.as_str()).unwrap_or("month"))
    .bind(next_date).bind(lead).bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "consume_location_id"))
    .bind(form.get("description").filter(|s| !s.is_empty())).bind(company_id).bind(user.id)
    .execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to("/maintenance/plans").into_response()
}

async fn edit_plan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, asset_id, wo_type, priority, frequency_interval, frequency_unit, \
                next_date::text AS next_date, lead_time_days, assigned_to, consume_location_id, \
                description, state FROM maint_plan WHERE id = $1",
    ).bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Plan not found").into_response(),
        Err(e) => { error!(error=%e, "plan fetch failed"); return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response(); }
    };
    let name: String = row.get("name");
    let asset_id: Option<Uuid> = row.try_get("asset_id").ok();
    let wo_type: String = row.get("wo_type");
    let priority: String = row.get("priority");
    let interval: i32 = row.try_get("frequency_interval").unwrap_or(1);
    let unit: String = row.get("frequency_unit");
    let next_date: Option<String> = row.try_get("next_date").ok();
    let lead: i32 = row.try_get("lead_time_days").unwrap_or(0);
    let assigned_to: Option<Uuid> = row.try_get("assigned_to").ok();
    let consume_loc: Option<Uuid> = row.try_get("consume_location_id").ok();
    let description: Option<String> = row.try_get("description").ok();
    let pstate: String = row.get("state");

    let assets = asset_options(&db, asset_id).await;
    let users = user_options(&db, assigned_to).await;
    let locations = location_options(&db, consume_loc).await;
    let fields = plan_form_fields(
        &wo_type, &priority, &interval.to_string(), &unit, next_date.as_deref().unwrap_or(""),
        &lead.to_string(), &pstate, &esc(description.as_deref().unwrap_or("")),
        &assets, &users, &locations, false,
    );
    // Inject the existing name into the (placeholder-only) name input.
    let fields = fields.replacen(r#"<input name="name" class="input input-bordered input-sm" value=""#, &format!(r#"<input name="name" class="input input-bordered input-sm" value="{}"#, esc(&name)), 1);

    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("maint_plan", id);
    let content = format!(
        r#"<div class="max-w-6xl mx-auto">
<a href="/maintenance/plans" class="btn btn-ghost btn-sm mb-4">← Back to Plans</a>
<div class="flex items-center justify-between mb-6">
<h1 class="text-2xl font-bold">Edit Plan</h1>
<div>{dup}</div></div>
<form method="POST" action="/maintenance/plans/{id}">
<div class="bg-base-100 rounded-lg shadow-sm border border-base-300 p-6 md:p-8">
<section class="break-inside-avoid mb-8 last:mb-0">{fields}</section>
</div>
<div class="flex justify-end gap-2 mt-4">
<a href="/maintenance/plans" class="btn btn-ghost btn-sm">Cancel</a>
<button class="btn btn-primary btn-sm">Save</button></div>
</form>
<div class="mt-8 flex flex-col gap-6">{activity_panel}</div></div>"#,
        id = id, fields = fields, activity_panel = activity_panel,
        dup = duplicate_button(&format!("/maintenance/plans/{id}/duplicate")),
    );
    Html(page_shell(&sidebar, &format!("Plan {}", name), &content)).into_response()
}

async fn update_plan(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let next_date: Option<vortex_plugin_sdk::chrono::NaiveDate> = form.get("next_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let interval: i32 = form.get("frequency_interval").and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let lead: i32 = form.get("lead_time_days").and_then(|s| s.parse().ok()).unwrap_or(0).max(0);
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE maint_plan SET name=$1, asset_id=$2, wo_type=$3, priority=$4, frequency_interval=$5, \
         frequency_unit=$6, next_date=COALESCE($7, next_date), lead_time_days=$8, assigned_to=$9, \
         consume_location_id=$10, description=$11, state=$12, updated_at=NOW() WHERE id=$13",
    )
    .bind(&name).bind(opt_uuid(&form, "asset_id"))
    .bind(form.get("wo_type").map(|s| s.as_str()).unwrap_or("preventive"))
    .bind(form.get("priority").map(|s| s.as_str()).unwrap_or("normal"))
    .bind(interval).bind(form.get("frequency_unit").map(|s| s.as_str()).unwrap_or("month"))
    .bind(next_date).bind(lead).bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "consume_location_id"))
    .bind(form.get("description").filter(|s| !s.is_empty()))
    .bind(form.get("state").map(|s| s.as_str()).unwrap_or("active"))
    .bind(id)
    .execute(&db).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/plans/{id}")).into_response()
}

/// POST /maintenance/plans/{id}/duplicate — copy a preventive plan. The
/// copy is created *paused*: an active duplicate on the same cadence would
/// silently double-generate work orders, so the user reviews (asset,
/// next date) and activates it deliberately.
async fn duplicate_plan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let spec = DuplicateSpec::new("maint_plan")
        .copy_suffix("name")                 // "Monthly service" -> "Monthly service (copy)"
        .set("state", json!("paused"))       // no double WO generation until activated
        .skip("updated_by");
    match spec.execute(&db, id, Some(user.id)).await {
        Ok(new_id) => {
            let entry = vortex_plugin_sdk::security::AuditEntry::new(
                vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
            ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
             .with_database(&db_ctx.db_name).with_resource("maint_plan", new_id.to_string())
             .with_details(json!({"duplicated_from": id}));
            let _ = state.audit.log(entry).await;
            info!(plan=%new_id, "maintenance plan duplicated");
            vortex_plugin_sdk::axum::response::Redirect::to(&format!("/maintenance/plans/{new_id}")).into_response()
        }
        Err(e) => {
            error!(error=%e, "plan duplicate failed");
            (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response()
        }
    }
}

async fn generate_now(
    State(state): State<Arc<AppState>>,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
) -> Response {
    if let Err(e) = generate_due_work_orders(&state).await {
        error!(error=%e, "manual WO generation failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate work orders").into_response();
    }
    vortex_plugin_sdk::axum::response::Redirect::to("/maintenance").into_response()
}
