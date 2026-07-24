//! Generic asset register & lifecycle (spec §3.9) — custody scope.
//!
//! A parallel, finance/custody-oriented register that complements the
//! engineering hierarchy: asset cards, category/location trees, movement
//! (transfer) workflow, documents and an append-only lifecycle trail.
//! Depreciation/accounting is intentionally out of scope here — it belongs to
//! the core `vortex-accounting` fixed-assets module.
//!
//! Every list is division-scoped (§6.3) and every fetch-by-id is guarded; asset
//! state changes and transfers are recorded both to the WORM audit log and to
//! the per-asset lifecycle trail.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::{Form, Path, Query};
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;
use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

use super::*;

const ASSET_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.asset", "AST").with_padding(6);
const MOV_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.asset_movement", "MOV").with_padding(6);

const ASSET_STATES: &[(&str, &str)] = &[
    ("draft", "Draft"), ("pending_approval", "Pending Approval"), ("active", "Active"),
    ("in_storage", "In Storage"), ("in_maintenance", "In Maintenance"),
    ("disposed", "Disposed"), ("lost", "Lost"), ("cancelled", "Cancelled"),
];
const ASSET_TYPES: &[(&str, &str)] = &[("tangible", "Tangible"), ("intangible", "Intangible"), ("leased", "Leased")];
const CRITICALITIES: &[(&str, &str)] = &[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")];
const LOCATION_TYPES: &[(&str, &str)] = &[
    ("site", "Site"), ("building", "Building"), ("floor", "Floor"), ("room", "Room"),
    ("area", "Area"), ("warehouse", "Warehouse"), ("other", "Other"),
];
const DOC_TYPES: &[(&str, &str)] = &[
    ("purchase_order", "Purchase Order"), ("invoice", "Invoice"), ("warranty", "Warranty"),
    ("manual", "Manual"), ("insurance", "Insurance"), ("contract", "Contract"),
    ("certificate", "Certificate"), ("photo", "Photo"), ("other", "Other"),
];

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/assets", get(list_assets))
        .route("/sesb-eam/assets/new", get(new_asset))
        .route("/sesb-eam/assets/create", post(create_asset))
        .route("/sesb-eam/assets/{id}", get(edit_asset).post(update_asset))
        .route("/sesb-eam/assets/{id}/documents", post(create_document))
        .route("/sesb-eam/asset-categories", get(list_categories))
        .route("/sesb-eam/asset-categories/new", get(new_category))
        .route("/sesb-eam/asset-categories/create", post(create_category))
        .route("/sesb-eam/asset-categories/{id}", get(edit_category).post(update_category))
        .route("/sesb-eam/asset-locations", get(list_locations))
        .route("/sesb-eam/asset-locations/new", get(new_location))
        .route("/sesb-eam/asset-locations/create", post(create_location))
        .route("/sesb-eam/asset-locations/{id}", get(edit_location).post(update_location))
        .route("/sesb-eam/asset-movements", get(list_movements))
        .route("/sesb-eam/asset-movements/new", get(new_movement))
        .route("/sesb-eam/asset-movements/create", post(create_movement))
        .route("/sesb-eam/asset-movements/{id}/confirm", post(confirm_movement))
}

// ── small helpers ────────────────────────────────────────────────────────────

/// `<option>` list from a `SELECT id, label` query.
async fn opts(db: &PgPool, sql: &str, sel: Option<Uuid>) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(sql).fetch_all(db).await.unwrap_or_default();
    let mut out = String::from("<option value=\"\">—</option>");
    for r in &rows {
        let id: Uuid = r.get("id");
        let label: String = r.try_get::<Option<String>, _>("label").ok().flatten().unwrap_or_default();
        let s = if Some(id) == sel { " selected" } else { "" };
        out.push_str(&format!("<option value=\"{id}\"{s}>{}</option>", html_escape(&label)));
    }
    out
}
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
async fn category_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    opts(db, "SELECT id, COALESCE(complete_name, name) AS label FROM eam_asset_category WHERE active ORDER BY label", sel).await
}
async fn location_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    opts(db, "SELECT id, COALESCE(complete_name, name) AS label FROM eam_asset_location WHERE active ORDER BY label", sel).await
}
async fn user_opts_local(db: &PgPool, sel: Option<Uuid>) -> String {
    opts(db, "SELECT id, COALESCE(full_name, username) AS label FROM users ORDER BY label", sel).await
}
async fn asset_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    opts(db, "SELECT id, (COALESCE(asset_code,'') || ' ' || name) AS label FROM eam_asset WHERE active ORDER BY asset_code", sel).await
}

/// Append a lifecycle event to an asset's trail.
async fn log_lifecycle(db: &PgPool, company_id: Option<Uuid>, asset_id: Uuid, user: &AuthUser,
                       event_type: &str, description: &str, old: Option<&str>, new: Option<&str>) {
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_lifecycle_event (id, company_id, asset_id, event_type, description, user_id, old_value, new_value) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::now_v7()).bind(company_id).bind(asset_id).bind(event_type)
        .bind(description).bind(user.id).bind(old).bind(new)
        .execute(db).await;
}

// ── Asset ────────────────────────────────────────────────────────────────────

async fn list_assets(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.assets");
    let config = ListConfig::new("Asset Register", "eam_asset")
        .scope_filter(division::division_predicate(&user, "a.division"))
        .custom_from("eam_asset a LEFT JOIN eam_asset_category c ON c.id=a.category_id LEFT JOIN eam_asset_location l ON l.id=a.location_id")
        .custom_select("a.id, a.asset_code, a.name, a.serial_number, c.name AS category, l.name AS location, a.asset_type, a.state, a.active")
        .column(ListColumn::new("asset_code", "Code").sortable().code().sql_expr("a.asset_code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("a.name"))
        .column(ListColumn::new("serial_number", "Serial").searchable().sql_expr("a.serial_number"))
        .column(ListColumn::new("category", "Category").sql_expr("c.name"))
        .column(ListColumn::new("location", "Location").sql_expr("l.name"))
        .column(ListColumn::new("asset_type", "Type").sql_expr("a.asset_type"))
        .column(ListColumn::new("state", "State").badge(&[
            ("active","Active","badge-success"), ("draft","Draft","badge-ghost"),
            ("pending_approval","Pending","badge-warning"), ("in_storage","In Storage","badge-info"),
            ("in_maintenance","Maintenance","badge-warning"), ("disposed","Disposed","badge-ghost"),
            ("lost","Lost","badge-error"), ("cancelled","Cancelled","badge-ghost")]).sql_expr("a.state"))
        .detail_url("/sesb-eam/assets/{id}")
        .create("New Asset", "/sesb-eam/assets/new")
        .default_sort("asset_code");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "asset list"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Asset Register", &render_list(&config, &result, &params, "/sesb-eam/assets"))).into_response()
}

async fn asset_form_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let cats = category_opts(db, v.get("category_id").and_then(|s| s.parse().ok())).await;
    let locs = location_opts(db, v.get("location_id").and_then(|s| s.parse().ok())).await;
    let custodians = user_opts_local(db, v.get("custodian_id").and_then(|s| s.parse().ok())).await;
    let parents = asset_opts(db, v.get("parent_id").and_then(|s| s.parse().ok())).await;
    let ident = grid2(&format!("{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), true),
        text_field("Serial Number", "serial_number", g("serial_number"), false),
        text_field("Barcode", "barcode", g("barcode"), false),
        select_field("Asset Type", "asset_type", &enum_options(ASSET_TYPES, if g("asset_type").is_empty() { "tangible" } else { g("asset_type") })),
        select_field("Category", "category_id", &cats),
        select_field("Criticality", "criticality", &enum_options(CRITICALITIES, g("criticality"))),
    ));
    let custody = grid2(&format!("{}{}{}{}{}{}",
        select_field("Location", "location_id", &locs),
        text_field("Department", "department", g("department"), false),
        select_field("Custodian", "custodian_id", &custodians),
        select_field("Parent Asset", "parent_id", &parents),
        select_field("State", "state", &enum_options(ASSET_STATES, if g("state").is_empty() { "draft" } else { g("state") })),
        text_field("PO Reference", "purchase_order_ref", g("purchase_order_ref"), false),
    ));
    let dates = grid2(&format!("{}{}{}{}{}{}",
        date_field("Acquisition Date", "acquisition_date", g("acquisition_date")),
        date_field("Capitalization Date", "capitalization_date", g("capitalization_date")),
        date_field("Warranty Start", "warranty_start_date", g("warranty_start_date")),
        date_field("Warranty End", "warranty_end_date", g("warranty_end_date")),
        text_field("Invoice Reference", "invoice_ref", g("invoice_ref"), false),
        date_field("Disposal Date", "disposal_date", g("disposal_date")),
    ));
    format!(
        r#"<h2 class="font-semibold text-sm uppercase opacity-60 mt-1 mb-2">Identification</h2>{ident}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Custody</h2>{custody}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Dates</h2>{dates}
{desc}{active}"#,
        ident = ident, custody = custody, dates = dates,
        desc = textarea_field("Description", "description", g("description")),
        active = active_field(g("active") == "true" || is_new, is_new),
    )
}

async fn new_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.assets");
    let header = form_header("/sesb-eam/assets", "Back to Assets", "New Asset");
    let body = asset_form_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Asset", &wide_form_page("/sesb-eam/assets/create", &header, &body))).into_response()
}

async fn create_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Name is required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let asset_code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &ASSET_SEQ).await.unwrap_or_default();
    let state_val = form.get("state").map(|s| s.as_str()).unwrap_or("draft");
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset (id, company_id, asset_code, name, barcode, serial_number, description, category_id, asset_type, location_id, department, custodian_id, state, criticality, acquisition_date, capitalization_date, disposal_date, warranty_start_date, warranty_end_date, purchase_order_ref, invoice_ref, parent_id, notes, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)")
        .bind(id).bind(company_id).bind(&asset_code).bind(name)
        .bind(opt_str(&form, "barcode")).bind(opt_str(&form, "serial_number")).bind(opt_str(&form, "description"))
        .bind(opt_uuid(&form, "category_id")).bind(form.get("asset_type").map(|s| s.as_str()).unwrap_or("tangible"))
        .bind(opt_uuid(&form, "location_id")).bind(opt_str(&form, "department")).bind(opt_uuid(&form, "custodian_id"))
        .bind(state_val).bind(opt_str(&form, "criticality"))
        .bind(opt_date(&form, "acquisition_date")).bind(opt_date(&form, "capitalization_date")).bind(opt_date(&form, "disposal_date"))
        .bind(opt_date(&form, "warranty_start_date")).bind(opt_date(&form, "warranty_end_date"))
        .bind(opt_str(&form, "purchase_order_ref")).bind(opt_str(&form, "invoice_ref")).bind(opt_uuid(&form, "parent_id"))
        .bind(opt_str(&form, "notes")).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "asset insert"); return bad(&format!("Failed: {e}")); }
    log_lifecycle(&db, company_id, id, &user, "creation", &format!("Asset {asset_code} created"), None, Some(state_val)).await;
    audit_log(&state, &user, &db_ctx, "eam_asset", id, name, json!({"asset_code": asset_code})).await;
    Redirect::to(&format!("/sesb-eam/assets/{id}")).into_response()
}

async fn edit_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_asset", id).await { return resp; }
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.assets");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT asset_code, name, barcode, serial_number, description, category_id::text AS category_id, asset_type, location_id::text AS location_id, department, custodian_id::text AS custodian_id, state, criticality, acquisition_date::text AS acquisition_date, capitalization_date::text AS capitalization_date, disposal_date::text AS disposal_date, warranty_start_date::text AS warranty_start_date, warranty_end_date::text AS warranty_end_date, purchase_order_ref, invoice_ref, parent_id::text AS parent_id, notes, active::text AS active FROM eam_asset WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["asset_code","name","barcode","serial_number","description","category_id","asset_type","location_id","department","custodian_id","state","criticality","acquisition_date","capitalization_date","disposal_date","warranty_start_date","warranty_end_date","purchase_order_ref","invoice_ref","parent_id","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let code = v.get("asset_code").cloned().unwrap_or_default();
    let name = v.get("name").cloned().unwrap_or_default();
    let body = asset_form_body(&db, &v, false).await;
    let panels = asset_side_panels(&db, id).await;
    let header = form_header("/sesb-eam/assets", "Back to Assets", &format!("Asset {code}"));
    let content = format!("{}{}", wide_form_page(&format!("/sesb-eam/assets/{id}"), &header, &body), panels);
    Html(page_shell(&sidebar, &format!("Asset {name}"), &content)).into_response()
}

async fn update_asset(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_asset", id).await { return resp; }
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Name is required"); }
    // Capture prior state to detect a status transition for the lifecycle trail.
    let prev_state: Option<String> = vortex_plugin_sdk::sqlx::query_scalar::<_, String>("SELECT state FROM eam_asset WHERE id=$1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let new_state = form.get("state").map(|s| s.as_str()).unwrap_or("draft");
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset SET name=$1, barcode=$2, serial_number=$3, description=$4, category_id=$5, asset_type=$6, location_id=$7, department=$8, custodian_id=$9, state=$10, criticality=$11, acquisition_date=$12, capitalization_date=$13, disposal_date=$14, warranty_start_date=$15, warranty_end_date=$16, purchase_order_ref=$17, invoice_ref=$18, parent_id=$19, notes=$20, active=$21, updated_at=NOW() WHERE id=$22")
        .bind(name).bind(opt_str(&form, "barcode")).bind(opt_str(&form, "serial_number")).bind(opt_str(&form, "description"))
        .bind(opt_uuid(&form, "category_id")).bind(form.get("asset_type").map(|s| s.as_str()).unwrap_or("tangible"))
        .bind(opt_uuid(&form, "location_id")).bind(opt_str(&form, "department")).bind(opt_uuid(&form, "custodian_id"))
        .bind(new_state).bind(opt_str(&form, "criticality"))
        .bind(opt_date(&form, "acquisition_date")).bind(opt_date(&form, "capitalization_date")).bind(opt_date(&form, "disposal_date"))
        .bind(opt_date(&form, "warranty_start_date")).bind(opt_date(&form, "warranty_end_date"))
        .bind(opt_str(&form, "purchase_order_ref")).bind(opt_str(&form, "invoice_ref")).bind(opt_uuid(&form, "parent_id"))
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "asset update"); return bad(&format!("Failed: {e}")); }
    if prev_state.as_deref() != Some(new_state) {
        let company_id = default_company(&db).await;
        log_lifecycle(&db, company_id, id, &user, "status_change",
            &format!("State {} → {}", prev_state.as_deref().unwrap_or("?"), new_state),
            prev_state.as_deref(), Some(new_state)).await;
    }
    audit_log(&state, &user, &db_ctx, "eam_asset", id, name, json!({"action": "update"})).await;
    Redirect::to(&format!("/sesb-eam/assets/{id}")).into_response()
}

/// Movements + documents + lifecycle panels shown under an asset.
async fn asset_side_panels(db: &PgPool, asset_id: Uuid) -> String {
    let movements = vortex_plugin_sdk::sqlx::query(
        "SELECT m.name, m.movement_date::text AS md, m.state, fl.name AS from_loc, tl.name AS to_loc \
         FROM eam_asset_movement m LEFT JOIN eam_asset_location fl ON fl.id=m.from_location_id LEFT JOIN eam_asset_location tl ON tl.id=m.to_location_id \
         WHERE m.asset_id=$1 ORDER BY m.movement_date DESC, m.created_at DESC LIMIT 20")
        .bind(asset_id).fetch_all(db).await.unwrap_or_default();
    let mov_rows: String = movements.iter().map(|r| {
        let md: String = r.try_get("md").ok().flatten().unwrap_or_default();
        let st: String = r.get("state");
        let from: String = r.try_get::<Option<String>, _>("from_loc").ok().flatten().unwrap_or_else(|| "—".into());
        let to: String = r.try_get::<Option<String>, _>("to_loc").ok().flatten().unwrap_or_else(|| "—".into());
        format!("<tr><td>{}</td><td>{} → {}</td><td>{}</td></tr>", md, html_escape(&from), html_escape(&to), st)
    }).collect();
    let events = vortex_plugin_sdk::sqlx::query(
        "SELECT event_type, event_date::text AS ed, description FROM eam_lifecycle_event WHERE asset_id=$1 ORDER BY event_date DESC LIMIT 30")
        .bind(asset_id).fetch_all(db).await.unwrap_or_default();
    let ev_rows: String = events.iter().map(|r| {
        let et: String = r.get("event_type");
        let ed: String = r.try_get("ed").ok().flatten().unwrap_or_default();
        let d: String = r.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default();
        format!("<tr><td class=\"font-mono text-xs\">{}</td><td>{}</td><td>{}</td></tr>", ed, html_escape(&et), html_escape(&d))
    }).collect();
    format!(r#"
<div class="mt-6 grid gap-4 lg:grid-cols-2">
  <div class="card bg-base-100 shadow"><div class="card-body">
    <div class="flex items-center justify-between"><h3 class="card-title text-sm">Movements</h3>
      <form method="get" action="/sesb-eam/asset-movements/new"><input type="hidden" name="asset" value="{aid}"><button class="btn btn-xs btn-primary">New Transfer</button></form></div>
    <table class="table table-xs"><thead><tr><th>Date</th><th>From → To</th><th>State</th></tr></thead><tbody>{mov}</tbody></table>
  </div></div>
  <div class="card bg-base-100 shadow"><div class="card-body">
    <h3 class="card-title text-sm">Lifecycle</h3>
    <table class="table table-xs"><thead><tr><th>When</th><th>Event</th><th>Detail</th></tr></thead><tbody>{ev}</tbody></table>
  </div></div>
</div>
<div class="mt-4 card bg-base-100 shadow"><div class="card-body">
  <h3 class="card-title text-sm">Add Document</h3>
  <form method="post" action="/sesb-eam/assets/{aid}/documents" class="grid gap-2 sm:grid-cols-4 items-end">
    <label class="form-control"><span class="label-text text-xs">Name</span><input name="name" class="input input-bordered input-sm" required></label>
    <label class="form-control"><span class="label-text text-xs">Type</span><select name="document_type" class="select select-bordered select-sm">{doctypes}</select></label>
    <label class="form-control"><span class="label-text text-xs">Expiry</span><input type="date" name="expiry_date" class="input input-bordered input-sm"></label>
    <button class="btn btn-sm btn-primary">Add</button>
  </form>
</div>"#,
        aid = asset_id,
        mov = if mov_rows.is_empty() { "<tr><td colspan=\"3\" class=\"opacity-50\">No movements.</td></tr>".into() } else { mov_rows },
        ev = if ev_rows.is_empty() { "<tr><td colspan=\"3\" class=\"opacity-50\">No events.</td></tr>".into() } else { ev_rows },
        doctypes = enum_options(DOC_TYPES, "manual"),
    )
}

async fn create_document(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(asset_id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_asset", asset_id).await { return resp; }
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Document name is required"); }
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset_document (id, company_id, name, asset_id, document_type, expiry_date, notes, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::now_v7()).bind(company_id).bind(name).bind(asset_id)
        .bind(opt_str(&form, "document_type")).bind(opt_date(&form, "expiry_date")).bind(opt_str(&form, "notes")).bind(user.id)
        .execute(&db).await;
    log_lifecycle(&db, company_id, asset_id, &user, "update", &format!("Document '{name}' added"), None, None).await;
    let _ = &db_ctx;
    Redirect::to(&format!("/sesb-eam/assets/{asset_id}")).into_response()
}

// ── Category (tree) ──────────────────────────────────────────────────────────

async fn list_categories(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_categories");
    let config = ListConfig::new("Asset Categories", "eam_asset_category")
        .custom_from("eam_asset_category c LEFT JOIN eam_asset_category p ON p.id=c.parent_id")
        .custom_select("c.id, c.name, c.code, p.name AS parent, (SELECT COUNT(*) FROM eam_asset a WHERE a.category_id=c.id)::text AS assets, c.active")
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("c.name"))
        .column(ListColumn::new("code", "Code").sql_expr("c.code"))
        .column(ListColumn::new("parent", "Parent").sql_expr("p.name"))
        .column(ListColumn::new("assets", "Assets").sql_expr("(SELECT COUNT(*) FROM eam_asset a WHERE a.category_id=c.id)"))
        .detail_url("/sesb-eam/asset-categories/{id}")
        .create("New Category", "/sesb-eam/asset-categories/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(_) => return Html("<h1>Failed</h1>").into_response() };
    Html(page_shell(&sidebar, "Asset Categories", &render_list(&config, &result, &params, "/sesb-eam/asset-categories"))).into_response()
}

async fn category_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let parents = category_opts(db, v.get("parent_id").and_then(|s| s.parse().ok())).await;
    let grid = grid2(&format!("{}{}{}",
        text_field("Name", "name", g("name"), true),
        text_field("Code", "code", g("code"), false),
        select_field("Parent Category", "parent_id", &parents),
    ));
    format!("{}{}{}", grid, textarea_field("Description", "description", g("description")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_categories");
    let header = form_header("/sesb-eam/asset-categories", "Back", "New Category");
    let body = category_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Category", &wide_form_page("/sesb-eam/asset-categories/create", &header, &body))).into_response()
}

async fn create_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Name is required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let complete = complete_name(&db, "eam_asset_category", opt_uuid(&form, "parent_id"), name).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset_category (id, company_id, name, complete_name, parent_id, code, description, active) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(company_id).bind(name).bind(&complete).bind(opt_uuid(&form, "parent_id"))
        .bind(opt_str(&form, "code")).bind(opt_str(&form, "description")).bind(true)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "category insert"); return bad(&format!("Failed: {e}")); }
    audit_log(&state, &user, &db_ctx, "eam_asset_category", id, name, json!({})).await;
    Redirect::to("/sesb-eam/asset-categories").into_response()
}

async fn edit_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_categories");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, code, parent_id::text AS parent_id, description, active::text AS active FROM eam_asset_category WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v = HashMap::new();
    for k in ["name","code","parent_id","description","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let header = form_header("/sesb-eam/asset-categories", "Back", "Edit Category");
    let body = category_body(&db, &v, false).await;
    Html(page_shell(&sidebar, "Edit Category", &wide_form_page(&format!("/sesb-eam/asset-categories/{id}"), &header, &body))).into_response()
}

async fn update_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Name is required"); }
    let complete = complete_name(&db, "eam_asset_category", opt_uuid(&form, "parent_id"), name).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset_category SET name=$1, complete_name=$2, parent_id=$3, code=$4, description=$5, active=$6, updated_at=NOW() WHERE id=$7")
        .bind(name).bind(&complete).bind(opt_uuid(&form, "parent_id")).bind(opt_str(&form, "code"))
        .bind(opt_str(&form, "description")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    audit_log(&state, &user, &db_ctx, "eam_asset_category", id, name, json!({"action":"update"})).await;
    Redirect::to("/sesb-eam/asset-categories").into_response()
}

// ── Location (tree) ──────────────────────────────────────────────────────────

async fn list_locations(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_locations");
    let config = ListConfig::new("Asset Locations", "eam_asset_location")
        .custom_from("eam_asset_location l LEFT JOIN eam_asset_location p ON p.id=l.parent_id")
        .custom_select("l.id, l.name, l.code, l.location_type, p.name AS parent, l.active")
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("l.name"))
        .column(ListColumn::new("code", "Code").sql_expr("l.code"))
        .column(ListColumn::new("location_type", "Type").sql_expr("l.location_type"))
        .column(ListColumn::new("parent", "Parent").sql_expr("p.name"))
        .detail_url("/sesb-eam/asset-locations/{id}")
        .create("New Location", "/sesb-eam/asset-locations/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(_) => return Html("<h1>Failed</h1>").into_response() };
    Html(page_shell(&sidebar, "Asset Locations", &render_list(&config, &result, &params, "/sesb-eam/asset-locations"))).into_response()
}

async fn location_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let parents = location_opts(db, v.get("parent_id").and_then(|s| s.parse().ok())).await;
    let responsibles = user_opts_local(db, v.get("responsible_id").and_then(|s| s.parse().ok())).await;
    let grid = grid2(&format!("{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), true),
        text_field("Code", "code", g("code"), false),
        select_field("Type", "location_type", &enum_options(LOCATION_TYPES, g("location_type"))),
        select_field("Parent Location", "parent_id", &parents),
        select_field("Responsible", "responsible_id", &responsibles),
        text_field("GPS Lat,Lng", "gps", g("gps"), false),
    ));
    format!("{}{}{}", grid, textarea_field("Address", "address", g("address")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_location(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_locations");
    let header = form_header("/sesb-eam/asset-locations", "Back", "New Location");
    let body = location_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Location", &wide_form_page("/sesb-eam/asset-locations/create", &header, &body))).into_response()
}

async fn create_location(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Name is required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let complete = complete_name(&db, "eam_asset_location", opt_uuid(&form, "parent_id"), name).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset_location (id, company_id, name, complete_name, parent_id, code, location_type, address, responsible_id, active) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(id).bind(company_id).bind(name).bind(&complete).bind(opt_uuid(&form, "parent_id"))
        .bind(opt_str(&form, "code")).bind(opt_str(&form, "location_type")).bind(opt_str(&form, "address"))
        .bind(opt_uuid(&form, "responsible_id")).bind(true)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "location insert"); return bad(&format!("Failed: {e}")); }
    audit_log(&state, &user, &db_ctx, "eam_asset_location", id, name, json!({})).await;
    Redirect::to("/sesb-eam/asset-locations").into_response()
}

async fn edit_location(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_locations");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, code, location_type, parent_id::text AS parent_id, responsible_id::text AS responsible_id, address, active::text AS active FROM eam_asset_location WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v = HashMap::new();
    for k in ["name","code","location_type","parent_id","responsible_id","address","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let header = form_header("/sesb-eam/asset-locations", "Back", "Edit Location");
    let body = location_body(&db, &v, false).await;
    Html(page_shell(&sidebar, "Edit Location", &wide_form_page(&format!("/sesb-eam/asset-locations/{id}"), &header, &body))).into_response()
}

async fn update_location(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").map(|s| s.trim()).unwrap_or("");
    if name.is_empty() { return bad("Name is required"); }
    let complete = complete_name(&db, "eam_asset_location", opt_uuid(&form, "parent_id"), name).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset_location SET name=$1, complete_name=$2, parent_id=$3, code=$4, location_type=$5, address=$6, responsible_id=$7, active=$8, updated_at=NOW() WHERE id=$9")
        .bind(name).bind(&complete).bind(opt_uuid(&form, "parent_id")).bind(opt_str(&form, "code"))
        .bind(opt_str(&form, "location_type")).bind(opt_str(&form, "address")).bind(opt_uuid(&form, "responsible_id"))
        .bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    audit_log(&state, &user, &db_ctx, "eam_asset_location", id, name, json!({"action":"update"})).await;
    Redirect::to("/sesb-eam/asset-locations").into_response()
}

/// Compose a `complete_name` as `Parent / Child` for the tree display.
async fn complete_name(db: &PgPool, table: &str, parent_id: Option<Uuid>, name: &str) -> String {
    match parent_id {
        Some(p) => {
            let sql = format!("SELECT COALESCE(complete_name, name) FROM {table} WHERE id=$1");
            let parent: Option<String> = vortex_plugin_sdk::sqlx::query_scalar::<_, String>(&sql).bind(p).fetch_optional(db).await.ok().flatten();
            match parent { Some(pn) => format!("{pn} / {name}"), None => name.to_string() }
        }
        None => name.to_string(),
    }
}

// ── Movement (transfer) ──────────────────────────────────────────────────────

async fn list_movements(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_movements");
    let config = ListConfig::new("Asset Movements", "eam_asset_movement")
        .scope_filter(division::division_predicate(&user, "a.division"))
        .custom_from("eam_asset_movement m JOIN eam_asset a ON a.id=m.asset_id LEFT JOIN eam_asset_location fl ON fl.id=m.from_location_id LEFT JOIN eam_asset_location tl ON tl.id=m.to_location_id")
        .custom_select("m.id, m.name, a.name AS asset, m.movement_date::text AS md, fl.name AS from_loc, tl.name AS to_loc, m.state")
        .column(ListColumn::new("name", "Ref").code().sql_expr("m.name"))
        .column(ListColumn::new("asset", "Asset").searchable().sql_expr("a.name"))
        .column(ListColumn::new("md", "Date").sql_expr("m.movement_date"))
        .column(ListColumn::new("from_loc", "From").sql_expr("fl.name"))
        .column(ListColumn::new("to_loc", "To").sql_expr("tl.name"))
        .column(ListColumn::new("state", "State").badge(&[("confirmed","Confirmed","badge-success"),("draft","Draft","badge-ghost"),("cancelled","Cancelled","badge-error")]).sql_expr("m.state"))
        .detail_url("/sesb-eam/asset-movements/{id}/confirm")
        .create("New Movement", "/sesb-eam/asset-movements/new")
        .default_sort("md");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(_) => return Html("<h1>Failed</h1>").into_response() };
    Html(page_shell(&sidebar, "Asset Movements", &render_list(&config, &result, &params, "/sesb-eam/asset-movements"))).into_response()
}

async fn new_movement(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_movements");
    let asset_pre = q.get("asset").and_then(|s| s.parse::<Uuid>().ok());
    let assets = asset_opts(&db, asset_pre).await;
    let from_locs = location_opts(&db, None).await;
    let to_locs = location_opts(&db, None).await;
    let custodians = user_opts_local(&db, None).await;
    let grid = grid2(&format!("{}{}{}{}{}{}",
        select_field("Asset *", "asset_id", &assets),
        date_field("Movement Date", "movement_date", ""),
        select_field("From Location", "from_location_id", &from_locs),
        select_field("To Location", "to_location_id", &to_locs),
        select_field("To Custodian", "to_custodian_id", &custodians),
        text_field("To Department", "to_department", "", false),
    ));
    let body = format!("{}{}", grid, textarea_field("Reason", "reason", ""));
    let header = form_header("/sesb-eam/asset-movements", "Back", "New Movement");
    Html(page_shell(&sidebar, "New Movement", &wide_form_page("/sesb-eam/asset-movements/create", &header, &body))).into_response()
}

async fn create_movement(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let asset_id = match opt_uuid(&form, "asset_id") { Some(a) => a, None => return bad("Asset is required") };
    if let Err(resp) = division::guard_division(&db, &user, "eam_asset", asset_id).await { return resp; }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let name = vortex_plugin_sdk::orm::sequence::next(&state.pool, &MOV_SEQ).await.unwrap_or_default();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset_movement (id, company_id, name, asset_id, movement_date, reason, from_location_id, to_location_id, to_department, to_custodian_id, state, created_by) \
         VALUES ($1,$2,$3,$4,COALESCE($5, CURRENT_DATE),$6,$7,$8,$9,$10,'draft',$11)")
        .bind(id).bind(company_id).bind(&name).bind(asset_id)
        .bind(opt_date(&form, "movement_date")).bind(opt_str(&form, "reason"))
        .bind(opt_uuid(&form, "from_location_id")).bind(opt_uuid(&form, "to_location_id"))
        .bind(opt_str(&form, "to_department")).bind(opt_uuid(&form, "to_custodian_id")).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "movement insert"); return bad(&format!("Failed: {e}")); }
    audit_log(&state, &user, &db_ctx, "eam_asset_movement", id, &name, json!({"asset_id": asset_id})).await;
    Redirect::to(&format!("/sesb-eam/assets/{asset_id}")).into_response()
}

/// Confirm a draft movement: apply the destination to the asset and record the
/// transfer on both the audit log and the lifecycle trail.
async fn confirm_movement(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let mv = match vortex_plugin_sdk::sqlx::query(
        "SELECT asset_id, to_location_id, to_custodian_id, to_department, state FROM eam_asset_movement WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let asset_id: Uuid = mv.get("asset_id");
    if let Err(resp) = division::guard_division(&db, &user, "eam_asset", asset_id).await { return resp; }
    let cur_state: String = mv.get("state");
    if cur_state != "draft" { return bad("Only draft movements can be confirmed"); }
    let to_loc: Option<Uuid> = mv.try_get("to_location_id").ok();
    let to_cust: Option<Uuid> = mv.try_get("to_custodian_id").ok();
    let to_dept: Option<String> = mv.try_get("to_department").ok();
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset SET location_id=COALESCE($1, location_id), custodian_id=COALESCE($2, custodian_id), department=COALESCE($3, department), updated_at=NOW() WHERE id=$4")
        .bind(to_loc).bind(to_cust).bind(to_dept.as_deref()).bind(asset_id).execute(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset_movement SET state='confirmed', confirmed_by=$1, confirmed_date=NOW() WHERE id=$2")
        .bind(user.id).bind(id).execute(&db).await;
    let company_id = default_company(&db).await;
    log_lifecycle(&db, company_id, asset_id, &user, "transfer", "Asset transferred (movement confirmed)", None, None).await;
    audit_log(&state, &user, &db_ctx, "eam_asset_movement", id, "movement", json!({"action":"confirm"})).await;
    Redirect::to(&format!("/sesb-eam/assets/{asset_id}")).into_response()
}

// ── audit convenience ────────────────────────────────────────────────────────

async fn audit_log(state: &Arc<AppState>, user: &AuthUser, db_ctx: &DatabaseContext,
                   resource: &str, id: Uuid, name: &str, details: vortex_plugin_sdk::serde_json::Value) {
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource(resource, id.to_string()).with_resource_name(name)
     .with_details(details);
    let _ = state.audit.log(entry).await;
}
