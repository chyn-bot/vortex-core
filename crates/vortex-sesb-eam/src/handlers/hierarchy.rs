//! Location-hierarchy CRUD — Region, Zon, Kawasan, Site, Substation, Bay
//! (§3.1). Substation and Bay carry the asset-verification mixin; the
//! full verification state machine (§5.1) lands in a later phase, so here
//! the verification state is shown read-only as a badge.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use vortex_plugin_sdk::framework::list::{
    execute_list, render_list, ListColumn, ListConfig, ListParams,
};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Regions
        .route("/sesb-eam/regions", get(list_region))
        .route("/sesb-eam/regions/new", get(new_region))
        .route("/sesb-eam/regions/create", post(create_region))
        .route("/sesb-eam/regions/{id}", get(edit_region))
        .route("/sesb-eam/regions/{id}", post(update_region))
        // Zones
        .route("/sesb-eam/zones", get(list_zon))
        .route("/sesb-eam/zones/new", get(new_zon))
        .route("/sesb-eam/zones/create", post(create_zon))
        .route("/sesb-eam/zones/{id}", get(edit_zon))
        .route("/sesb-eam/zones/{id}", post(update_zon))
        // Kawasans
        .route("/sesb-eam/kawasans", get(list_kawasan))
        .route("/sesb-eam/kawasans/new", get(new_kawasan))
        .route("/sesb-eam/kawasans/create", post(create_kawasan))
        .route("/sesb-eam/kawasans/{id}", get(edit_kawasan))
        .route("/sesb-eam/kawasans/{id}", post(update_kawasan))
        // Sites
        .route("/sesb-eam/sites", get(list_site))
        .route("/sesb-eam/sites/new", get(new_site))
        .route("/sesb-eam/sites/create", post(create_site))
        .route("/sesb-eam/sites/{id}", get(edit_site))
        .route("/sesb-eam/sites/{id}", post(update_site))
        // Substations
        .route("/sesb-eam/substations", get(list_substation))
        .route("/sesb-eam/substations/new", get(new_substation))
        .route("/sesb-eam/substations/create", post(create_substation))
        .route("/sesb-eam/substations/{id}", get(edit_substation))
        .route("/sesb-eam/substations/{id}", post(update_substation))
        // Bays
        .route("/sesb-eam/bays/new", get(new_bay))
        .route("/sesb-eam/bays/create", post(create_bay))
        .route("/sesb-eam/bays/{id}", get(edit_bay))
        .route("/sesb-eam/bays/{id}", post(update_bay))
}

const DIVISIONS: &[(&str, &str)] = &[("distribution", "Distribution"), ("transmission", "Transmission")];

fn vstate_badge(s: &str) -> String {
    let (label, cls) = match s {
        "draft" => ("Draft", "badge-ghost"),
        "submitted" => ("Submitted", "badge-info"),
        "verified" => ("Verified", "badge-warning"),
        "approved" => ("Approved", "badge-success"),
        "rejected" => ("Rejected", "badge-error"),
        _ => (s, "badge-ghost"),
    };
    format!(r#"<span class="badge {cls}">{label}</span>"#, cls = cls, label = label)
}

// ═════════════════════════════════════════════════════════════════════════
// Region
// ═════════════════════════════════════════════════════════════════════════

async fn list_region(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.regions");
    let config = ListConfig::new("Regions", "eam_region")
        .column(ListColumn::new("code", "Code").sortable().code())
        .column(ListColumn::new("name", "Name").sortable().searchable())
        .column(ListColumn::new("division", "Division")
            .filterable(&[("transmission","Transmission"),("distribution","Distribution")])
            .badge(&[("transmission","Transmission","badge-warning"),("distribution","Distribution","badge-info")]))
        .column(ListColumn::new("sequence", "Seq").sortable())
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning"))
        .detail_url("/sesb-eam/regions/{id}")
        .create("New Region", "/sesb-eam/regions/new")
        .default_sort("sequence");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "region list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Regions", &render_list(&config, &result, &params, "/sesb-eam/regions"))).into_response()
}

async fn region_body(db: &vortex_plugin_sdk::sqlx::PgPool, code: &str, name: &str, seq: &str, division: &str, mgr: Option<Uuid>, desc: &str, active: bool, is_new: bool) -> String {
    let managers = user_options(db, mgr).await;
    format!("{}{}{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        num_field("Sequence", "sequence", seq, "1"),
        select_field("Division", "division", &enum_options(DIVISIONS, division)),
        select_field("Manager", "manager_id", &managers),
        textarea_field("Description", "description", desc),
        active_field(active, is_new),
    )
}

async fn new_region(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.regions");
    let header = form_header("/sesb-eam/regions", "Back to Regions", "New Region");
    let body = region_body(&db, "", "", "0", "distribution", None, "", true, true).await;
    Html(page_shell(&sidebar, "New Region", &form_page("/sesb-eam/regions/create", &header, &body))).into_response()
}

async fn create_region(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_region (id, name, code, sequence, division, manager_id, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(form.get("division").map(|s| s.as_str()).unwrap_or("distribution"))
        .bind(opt_uuid(&form, "manager_id")).bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "region insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/regions").into_response()
}

async fn edit_region(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.regions");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT code, name, sequence, division, manager_id, description, active FROM eam_region WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let seq: i32 = row.try_get("sequence").unwrap_or(0);
    let division: String = row.get("division");
    let mgr: Option<Uuid> = row.try_get("manager_id").ok();
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let header = form_header("/sesb-eam/regions", "Back to Regions", &format!("Edit {}", name));
    let body = region_body(&db, &code, &name, &seq.to_string(), &division, mgr, desc.as_deref().unwrap_or(""), active, false).await;
    Html(page_shell(&sidebar, "Edit Region", &form_page(&format!("/sesb-eam/regions/{id}"), &header, &body))).into_response()
}

async fn update_region(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_region SET name=$1, code=$2, sequence=$3, division=$4, manager_id=$5, description=$6, active=$7 WHERE id=$8")
        .bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(form.get("division").map(|s| s.as_str()).unwrap_or("distribution"))
        .bind(opt_uuid(&form, "manager_id")).bind(opt_str(&form, "description"))
        .bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/regions").into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Zon
// ═════════════════════════════════════════════════════════════════════════

async fn list_zon(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.zones");
    let config = ListConfig::new("Zones", "eam_zon")
        .custom_from("eam_zon z LEFT JOIN eam_region r ON r.id = z.region_id")
        .custom_select("z.id, z.code, z.name, r.name AS region_name, z.sequence, z.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("z.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("z.name"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("sequence", "Seq").sortable().sql_expr("z.sequence"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning").sql_expr("z.active"))
        .detail_url("/sesb-eam/zones/{id}")
        .create("New Zon", "/sesb-eam/zones/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "zon list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Zones", &render_list(&config, &result, &params, "/sesb-eam/zones"))).into_response()
}

async fn zon_body(db: &vortex_plugin_sdk::sqlx::PgPool, code: &str, name: &str, seq: &str, region: Option<Uuid>, mgr: Option<Uuid>, desc: &str, active: bool, is_new: bool) -> String {
    let regions = region_options(db, region).await;
    let managers = user_options(db, mgr).await;
    format!("{}{}{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        num_field("Sequence", "sequence", seq, "1"),
        select_field("Region *", "region_id", &regions),
        select_field("Manager", "manager_id", &managers),
        textarea_field("Description", "description", desc),
        active_field(active, is_new),
    )
}

async fn new_zon(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.zones");
    let header = form_header("/sesb-eam/zones", "Back to Zones", "New Zon");
    let body = zon_body(&db, "", "", "0", None, None, "", true, true).await;
    Html(page_shell(&sidebar, "New Zon", &form_page("/sesb-eam/zones/create", &header, &body))).into_response()
}

async fn create_zon(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_zon (id, name, code, sequence, region_id, manager_id, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(region_id).bind(opt_uuid(&form, "manager_id")).bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "zon insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/zones").into_response()
}

async fn edit_zon(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.zones");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT code, name, sequence, region_id, manager_id, description, active FROM eam_zon WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let seq: i32 = row.try_get("sequence").unwrap_or(0);
    let region: Option<Uuid> = row.try_get("region_id").ok();
    let mgr: Option<Uuid> = row.try_get("manager_id").ok();
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let header = form_header("/sesb-eam/zones", "Back to Zones", &format!("Edit {}", name));
    let body = zon_body(&db, &code, &name, &seq.to_string(), region, mgr, desc.as_deref().unwrap_or(""), active, false).await;
    Html(page_shell(&sidebar, "Edit Zon", &form_page(&format!("/sesb-eam/zones/{id}"), &header, &body))).into_response()
}

async fn update_zon(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_zon SET name=$1, code=$2, sequence=$3, region_id=$4, manager_id=$5, description=$6, active=$7 WHERE id=$8")
        .bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(region_id).bind(opt_uuid(&form, "manager_id")).bind(opt_str(&form, "description"))
        .bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/zones").into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Kawasan
// ═════════════════════════════════════════════════════════════════════════

async fn list_kawasan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.kawasans");
    let config = ListConfig::new("Kawasans", "eam_kawasan")
        .custom_from("eam_kawasan k LEFT JOIN eam_zon z ON z.id = k.zon_id LEFT JOIN eam_region r ON r.id = k.region_id")
        .custom_select("k.id, k.code, k.name, z.name AS zon_name, r.name AS region_name, k.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("k.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("k.name"))
        .column(ListColumn::new("zon_name", "Zon").sql_expr("z.name"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning").sql_expr("k.active"))
        .detail_url("/sesb-eam/kawasans/{id}")
        .create("New Kawasan", "/sesb-eam/kawasans/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "kawasan list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Kawasans", &render_list(&config, &result, &params, "/sesb-eam/kawasans"))).into_response()
}

async fn kawasan_body(db: &vortex_plugin_sdk::sqlx::PgPool, code: &str, name: &str, seq: &str, zon: Option<Uuid>, region: Option<Uuid>, mgr: Option<Uuid>, desc: &str, active: bool, is_new: bool) -> String {
    let zones = zon_options(db, zon).await;
    let regions = region_options(db, region).await;
    let managers = user_options(db, mgr).await;
    format!("{}{}{}{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        num_field("Sequence", "sequence", seq, "1"),
        select_field("Zon *", "zon_id", &zones),
        select_field("Region", "region_id", &regions),
        select_field("Manager", "manager_id", &managers),
        textarea_field("Description", "description", desc),
        active_field(active, is_new),
    )
}

async fn new_kawasan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.kawasans");
    let header = form_header("/sesb-eam/kawasans", "Back to Kawasans", "New Kawasan");
    let body = kawasan_body(&db, "", "", "0", None, None, None, "", true, true).await;
    Html(page_shell(&sidebar, "New Kawasan", &form_page("/sesb-eam/kawasans/create", &header, &body))).into_response()
}

async fn create_kawasan(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    let zon_id = match opt_uuid(&form, "zon_id") { Some(z) => z, None => return bad("Zon is required") };
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_kawasan (id, name, code, sequence, zon_id, region_id, manager_id, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(zon_id).bind(opt_uuid(&form, "region_id")).bind(opt_uuid(&form, "manager_id"))
        .bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "kawasan insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/kawasans").into_response()
}

async fn edit_kawasan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.kawasans");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT code, name, sequence, zon_id, region_id, manager_id, description, active FROM eam_kawasan WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let seq: i32 = row.try_get("sequence").unwrap_or(0);
    let zon: Option<Uuid> = row.try_get("zon_id").ok();
    let region: Option<Uuid> = row.try_get("region_id").ok();
    let mgr: Option<Uuid> = row.try_get("manager_id").ok();
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let header = form_header("/sesb-eam/kawasans", "Back to Kawasans", &format!("Edit {}", name));
    let body = kawasan_body(&db, &code, &name, &seq.to_string(), zon, region, mgr, desc.as_deref().unwrap_or(""), active, false).await;
    Html(page_shell(&sidebar, "Edit Kawasan", &form_page(&format!("/sesb-eam/kawasans/{id}"), &header, &body))).into_response()
}

async fn update_kawasan(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    let zon_id = match opt_uuid(&form, "zon_id") { Some(z) => z, None => return bad("Zon is required") };
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_kawasan SET name=$1, code=$2, sequence=$3, zon_id=$4, region_id=$5, manager_id=$6, description=$7, active=$8 WHERE id=$9")
        .bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(zon_id).bind(opt_uuid(&form, "region_id")).bind(opt_uuid(&form, "manager_id"))
        .bind(opt_str(&form, "description")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/kawasans").into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Site
// ═════════════════════════════════════════════════════════════════════════

const SITE_TYPES: &[(&str, &str)] = &[
    ("pmu","PMU"),("ppu","PPU"),("ssu_33kv","SSU 33kV"),("ssu_11kv","SSU 11kV"),
    ("pp","PP"),("pe","PE"),("ss","SS"),("isolation","Isolation"),("other","Other"),
];
const SITE_STATES: &[(&str, &str)] = &[
    ("planning","Planning"),("construction","Construction"),("operational","Operational"),("decommissioned","Decommissioned"),
];

async fn list_site(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.sites");
    let config = ListConfig::new("Sites", "eam_site")
        .custom_from("eam_site s LEFT JOIN eam_region r ON r.id = s.region_id LEFT JOIN eam_kawasan k ON k.id = s.kawasan_id")
        .custom_select("s.id, s.code, s.name, s.site_type, r.name AS region_name, k.name AS kawasan_name, s.state, s.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("s.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("s.name"))
        .column(ListColumn::new("site_type", "Type")
            .filterable(&[("pmu","PMU"),("ppu","PPU"),("ssu_33kv","SSU 33kV"),("ssu_11kv","SSU 11kV"),("pp","PP"),("pe","PE"),("ss","SS")]).sql_expr("s.site_type"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("kawasan_name", "Kawasan").sql_expr("k.name"))
        .column(ListColumn::new("state", "State")
            .filterable(&[("planning","Planning"),("construction","Construction"),("operational","Operational"),("decommissioned","Decommissioned")])
            .badge(&[("operational","Operational","badge-success"),("construction","Construction","badge-warning"),("planning","Planning","badge-info"),("decommissioned","Decommissioned","badge-ghost")]).sql_expr("s.state"))
        .detail_url("/sesb-eam/sites/{id}")
        .create("New Site", "/sesb-eam/sites/new")
        .default_sort("code")
        .group_by_options(&[("region_name","Region"),("site_type","Type"),("state","State")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "site list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Sites", &render_list(&config, &result, &params, "/sesb-eam/sites"))).into_response()
}

#[allow(clippy::too_many_arguments)]
async fn site_body(db: &vortex_plugin_sdk::sqlx::PgPool, code: &str, name: &str, region: Option<Uuid>, kawasan: Option<Uuid>, zon: Option<Uuid>, stype: &str, sstate: &str, addr: &str, lat: &str, lng: &str, cdate: &str, ddate: &str, notes: &str, active: bool, is_new: bool) -> String {
    let regions = region_options(db, region).await;
    let kawasans = kawasan_options(db, kawasan).await;
    let zones = zon_options(db, zon).await;
    let grid = grid2(&format!("{}{}{}{}{}{}{}{}{}{}",
        select_field("Region *", "region_id", &regions),
        select_field("Kawasan", "kawasan_id", &kawasans),
        select_field("Zon", "zon_id", &zones),
        select_field("Site Type *", "site_type", &enum_options(SITE_TYPES, stype)),
        num_field("GPS Latitude", "gps_latitude", lat, "0.0000001"),
        num_field("GPS Longitude", "gps_longitude", lng, "0.0000001"),
        select_field("State", "state", &enum_options(SITE_STATES, sstate)),
        date_field("Commissioning Date", "commissioning_date", cdate),
        date_field("Decommissioning Date", "decommissioning_date", ddate),
        text_field("", "spacer_unused", "", false),
    ));
    format!("{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        grid,
        textarea_field("Address", "address", addr),
        format!("{}{}", textarea_field("Notes", "notes", notes), active_field(active, is_new)),
    )
}

async fn new_site(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.sites");
    let header = form_header("/sesb-eam/sites", "Back to Sites", "New Site");
    let body = site_body(&db, "", "", None, None, None, "pe", "operational", "", "", "", "", "", "", true, true).await;
    Html(page_shell(&sidebar, "New Site", &wide_form_page("/sesb-eam/sites/create", &header, &body))).into_response()
}

async fn create_site(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_site (id, name, code, region_id, kawasan_id, zon_id, site_type, address, gps_latitude, gps_longitude, state, commissioning_date, decommissioning_date, notes, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code).bind(region_id)
        .bind(opt_uuid(&form, "kawasan_id")).bind(opt_uuid(&form, "zon_id"))
        .bind(form.get("site_type").map(|s| s.as_str()).unwrap_or("pe"))
        .bind(opt_str(&form, "address")).bind(opt_dec(&form, "gps_latitude")).bind(opt_dec(&form, "gps_longitude"))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
        .bind(opt_date(&form, "commissioning_date")).bind(opt_date(&form, "decommissioning_date"))
        .bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "site insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/sites").into_response()
}

async fn edit_site(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.sites");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, region_id, kawasan_id, zon_id, site_type, address, gps_latitude::text AS lat, gps_longitude::text AS lng, state, commissioning_date::text AS cdate, decommissioning_date::text AS ddate, notes, active FROM eam_site WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let region: Option<Uuid> = row.try_get("region_id").ok();
    let kawasan: Option<Uuid> = row.try_get("kawasan_id").ok();
    let zon: Option<Uuid> = row.try_get("zon_id").ok();
    let stype: String = row.get("site_type");
    let addr: Option<String> = row.try_get("address").ok();
    let lat: Option<String> = row.try_get("lat").ok();
    let lng: Option<String> = row.try_get("lng").ok();
    let sstate: String = row.get("state");
    let cdate: Option<String> = row.try_get("cdate").ok();
    let ddate: Option<String> = row.try_get("ddate").ok();
    let notes: Option<String> = row.try_get("notes").ok();
    let active: bool = row.try_get("active").unwrap_or(true);

    let substations = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, verification_state, state FROM eam_substation WHERE site_id=$1 ORDER BY code")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut sub_html = String::new();
    for r in &substations {
        let sid: Uuid = r.get("id");
        let scode: String = r.get("code");
        let sname: String = r.get("name");
        let vstate: String = r.get("verification_state");
        sub_html.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/sesb-eam/substations/{sid}'"><td class="font-mono">{scode}</td><td>{sname}</td><td>{badge}</td></tr>"#,
            sid = sid, scode = esc(&scode), sname = esc(&sname), badge = vstate_badge(&vstate)));
    }
    if sub_html.is_empty() { sub_html.push_str(r#"<tr><td colspan="3" class="text-base-content/50">No substations</td></tr>"#); }

    let header = form_header("/sesb-eam/sites", "Back to Sites", &format!("Edit {}", name));
    let body = site_body(&db, &code, &name, region, kawasan, zon, &stype, &sstate,
        addr.as_deref().unwrap_or(""), lat.as_deref().unwrap_or(""), lng.as_deref().unwrap_or(""),
        cdate.as_deref().unwrap_or(""), ddate.as_deref().unwrap_or(""), notes.as_deref().unwrap_or(""), active, false).await;
    let content = format!(
        r#"{form}
<div class="max-w-4xl mt-6"><div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex items-center justify-between mb-2"><h2 class="card-title text-lg">Substations</h2>
<a href="/sesb-eam/substations/new?site={id}" class="btn btn-primary btn-sm">New Substation</a></div>
<table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Verification</th></tr></thead><tbody>{sub_html}</tbody></table>
</div></div></div>"#,
        form = wide_form_page(&format!("/sesb-eam/sites/{id}"), &header, &body), id = id, sub_html = sub_html);
    Html(page_shell(&sidebar, &format!("Site {}", name), &content)).into_response()
}

async fn update_site(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_site SET name=$1, code=$2, region_id=$3, kawasan_id=$4, zon_id=$5, site_type=$6, address=$7, gps_latitude=$8, gps_longitude=$9, state=$10, commissioning_date=$11, decommissioning_date=$12, notes=$13, active=$14 WHERE id=$15")
        .bind(&name).bind(&code).bind(region_id)
        .bind(opt_uuid(&form, "kawasan_id")).bind(opt_uuid(&form, "zon_id"))
        .bind(form.get("site_type").map(|s| s.as_str()).unwrap_or("pe"))
        .bind(opt_str(&form, "address")).bind(opt_dec(&form, "gps_latitude")).bind(opt_dec(&form, "gps_longitude"))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
        .bind(opt_date(&form, "commissioning_date")).bind(opt_date(&form, "decommissioning_date"))
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/sites/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Substation
// ═════════════════════════════════════════════════════════════════════════

const SUB_TYPES: &[(&str, &str)] = &[("","—"),("indoor","Indoor"),("outdoor","Outdoor"),("compact","Compact"),("underground","Underground")];
const BUSBARS: &[(&str, &str)] = &[("","—"),("single","Single"),("double","Double"),("ring","Ring"),("breaker_half","Breaker-and-a-half")];
const SUB_CLASSES: &[(&str, &str)] = &[("","—"),("pmu","PMU"),("ppu","PPU"),("ssu","SSU"),("pp","PP"),("pe","PE"),("isolation","Isolation")];
const OWNERSHIPS: &[(&str, &str)] = &[("sesb","SESB"),("ipp","IPP"),("customer","Customer"),("shared","Shared")];
const SUB_STATES: &[(&str, &str)] = &[("planning","Planning"),("construction","Construction"),("operational","Operational"),("maintenance","Maintenance"),("decommissioned","Decommissioned")];

async fn list_substation(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.substations");
    let config = ListConfig::new("Substations", "eam_substation")
        .custom_from("eam_substation s LEFT JOIN eam_site si ON si.id = s.site_id LEFT JOIN eam_region r ON r.id = si.region_id")
        .custom_select("s.id, s.code, s.name, s.asset_id, r.name AS region_name, s.substation_class, s.verification_state, s.state, s.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("s.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("s.name"))
        .column(ListColumn::new("asset_id", "MNEC Asset ID").searchable().sql_expr("s.asset_id"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("substation_class", "Class").sql_expr("s.substation_class"))
        .column(ListColumn::new("verification_state", "Verification")
            .filterable(&[("draft","Draft"),("submitted","Submitted"),("verified","Verified"),("approved","Approved"),("rejected","Rejected")])
            .badge(&[("draft","Draft","badge-ghost"),("submitted","Submitted","badge-info"),("verified","Verified","badge-warning"),("approved","Approved","badge-success"),("rejected","Rejected","badge-error")]).sql_expr("s.verification_state"))
        .column(ListColumn::new("state", "State")
            .badge(&[("operational","Operational","badge-success"),("maintenance","Maintenance","badge-warning"),("construction","Construction","badge-info"),("planning","Planning","badge-ghost"),("decommissioned","Decommissioned","badge-ghost")]).sql_expr("s.state"))
        .detail_url("/sesb-eam/substations/{id}")
        .create("New Substation", "/sesb-eam/substations/new")
        .default_sort("code")
        .group_by_options(&[("region_name","Region"),("substation_class","Class"),("verification_state","Verification")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "substation list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Substations", &render_list(&config, &result, &params, "/sesb-eam/substations"))).into_response()
}

/// Build the substation form body. `site_preselect` is used by the
/// "New Substation" link from a site detail page.
#[allow(clippy::too_many_arguments)]
async fn substation_body(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    f: &SubForm, site_preselect: Option<Uuid>, is_new: bool,
) -> String {
    let sites = site_options(db, f.site_id.or(site_preselect)).await;
    let atypes = asset_type_options(db, f.asset_type_id).await;
    let ident = grid2(&format!("{}{}{}{}{}{}",
        text_field("Code", "code", &f.code, true),
        text_field("Name", "name", &f.name, true),
        text_field("MNEC Asset ID", "asset_id", &f.asset_id, false),
        select_field("Asset Type", "asset_type_id", &atypes),
        select_field("Site *", "site_id", &sites),
        select_field("Substation Class", "substation_class", &enum_options(SUB_CLASSES, &f.substation_class)),
    ));
    let tech = grid2(&format!("{}{}{}{}{}{}{}{}",
        select_field("Substation Type", "substation_type", &enum_options(SUB_TYPES, &f.substation_type)),
        select_field("Busbar Configuration", "busbar_configuration", &enum_options(BUSBARS, &f.busbar_configuration)),
        num_field("Primary Voltage (kV)", "primary_voltage_kv", &f.primary_voltage_kv, "0.0001"),
        num_field("Customers Served", "customers_served", &f.customers_served, "1"),
        text_field("Source From", "source_from", &f.source_from, false),
        text_field("Feeder", "feeder", &f.feeder, false),
        text_field("Automation Type", "automation_type", &f.automation_type, false),
        text_field("Site Category", "substation_category", &f.substation_category, false),
    ));
    let loc = grid2(&format!("{}{}{}{}{}{}",
        text_field("GPS Latitude", "gps_latitude", &f.gps_latitude, false),
        text_field("GPS Longitude", "gps_longitude", &f.gps_longitude, false),
        text_field("Site Size", "site_size", &f.site_size, false),
        select_field("Ownership", "ownership", &enum_options(OWNERSHIPS, &f.ownership)),
        date_field("Commissioning Date", "commissioning_date", &f.commissioning_date),
        num_field("Design Life (years)", "design_life_years", &f.design_life_years, "1"),
    ));
    let status = grid2(&select_field("Operational State", "state", &enum_options(SUB_STATES, &f.state)));
    format!(
        r#"<h2 class="font-semibold text-sm uppercase opacity-60 mt-1 mb-2">Identification</h2>{ident}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Technical</h2>{tech}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Location & Lifecycle</h2>{loc}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Status</h2>{status}
{notes}{active}"#,
        ident = ident, tech = tech, loc = loc, status = status,
        notes = textarea_field("Notes", "notes", &f.notes),
        active = active_field(f.active, is_new),
    )
}

#[derive(Default)]
struct SubForm {
    code: String, name: String, asset_id: String, asset_type_id: Option<Uuid>, site_id: Option<Uuid>,
    substation_class: String, substation_type: String, busbar_configuration: String,
    primary_voltage_kv: String, customers_served: String, source_from: String, feeder: String,
    automation_type: String, substation_category: String, gps_latitude: String, gps_longitude: String,
    site_size: String, ownership: String, commissioning_date: String, design_life_years: String,
    state: String, notes: String, active: bool,
}

impl SubForm {
    fn defaults() -> Self {
        SubForm { ownership: "sesb".into(), state: "operational".into(), design_life_years: "40".into(), active: true, ..Default::default() }
    }
    fn from_map(form: &HashMap<String, String>) -> Self {
        let g = |k: &str| form.get(k).cloned().unwrap_or_default();
        SubForm {
            code: g("code"), name: g("name"), asset_id: g("asset_id"),
            asset_type_id: opt_uuid(form, "asset_type_id"), site_id: opt_uuid(form, "site_id"),
            substation_class: g("substation_class"), substation_type: g("substation_type"),
            busbar_configuration: g("busbar_configuration"), primary_voltage_kv: g("primary_voltage_kv"),
            customers_served: g("customers_served"), source_from: g("source_from"), feeder: g("feeder"),
            automation_type: g("automation_type"), substation_category: g("substation_category"),
            gps_latitude: g("gps_latitude"), gps_longitude: g("gps_longitude"), site_size: g("site_size"),
            ownership: g("ownership"), commissioning_date: g("commissioning_date"),
            design_life_years: g("design_life_years"), state: g("state"), notes: g("notes"),
            active: form.contains_key("active"),
        }
    }
}

async fn new_substation(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.substations");
    let site_pre = q.get("site").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/substations", "Back to Substations", "New Substation");
    let body = substation_body(&db, &SubForm::defaults(), site_pre, true).await;
    Html(page_shell(&sidebar, "New Substation", &wide_form_page("/sesb-eam/substations/create", &header, &body))).into_response()
}

async fn create_substation(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = SubForm::from_map(&form);
    let site_id = match f.site_id { Some(s) => s, None => return bad("Site is required") };
    if f.code.trim().is_empty() || f.name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_substation (id, name, code, asset_id, asset_type_id, primary_voltage_kv, site_id, substation_type, busbar_configuration, substation_class, source_from, feeder, customers_served, substation_category, automation_type, site_size, gps_latitude, gps_longitude, ownership, commissioning_date, design_life_years, state, notes, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)")
        .bind(id).bind(&f.name).bind(&f.code).bind(opt_str(&form, "asset_id"))
        .bind(f.asset_type_id).bind(opt_dec(&form, "primary_voltage_kv")).bind(site_id)
        .bind(opt_str(&form, "substation_type")).bind(opt_str(&form, "busbar_configuration"))
        .bind(opt_str(&form, "substation_class")).bind(opt_str(&form, "source_from")).bind(opt_str(&form, "feeder"))
        .bind(opt_i32(&form, "customers_served").unwrap_or(0)).bind(opt_str(&form, "substation_category"))
        .bind(opt_str(&form, "automation_type")).bind(opt_str(&form, "site_size"))
        .bind(opt_str(&form, "gps_latitude")).bind(opt_str(&form, "gps_longitude"))
        .bind(form.get("ownership").map(|s| s.as_str()).unwrap_or("sesb"))
        .bind(opt_date(&form, "commissioning_date")).bind(opt_i32(&form, "design_life_years").unwrap_or(40))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
        .bind(opt_str(&form, "notes")).bind(company_id).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "substation insert failed"); return bad(&format!("Failed: {e}")); }
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_substation", id.to_string()).with_resource_name(&f.name)
     .with_details(json!({"code": f.code}));
    let _ = state.audit.log(entry).await;
    info!(code=%f.code, "substation created");
    Redirect::to(&format!("/sesb-eam/substations/{id}")).into_response()
}

/// Derived (read-only) attributes per §4.1 / §4.9, computed on read.
fn substation_derived(commissioning: Option<&str>, primary_kv: Option<f64>) -> String {
    let age = commissioning.and_then(|d| d.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok())
        .map(|d| {
            let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
            ((today - d).num_days() as f64 / 365.25).floor() as i64
        });
    let aging = age.map(|a| if a < 15 { "A (<15y)" } else if a < 25 { "E (15-25y)" } else if a < 30 { "C (25-30y)" } else { "D (≥30y)" });
    let mnec = primary_kv.map(|kv| if kv >= 66.0 { "TS (≥66kV)" } else { "DS (<66kV)" });
    format!(
        r#"<div class="stats stats-vertical sm:stats-horizontal shadow w-full">
<div class="stat"><div class="stat-title">MNEC Type</div><div class="stat-value text-lg">{mnec}</div></div>
<div class="stat"><div class="stat-title">Age</div><div class="stat-value text-lg">{age}</div></div>
<div class="stat"><div class="stat-title">Aging Matrix</div><div class="stat-value text-lg">{aging}</div></div>
</div>"#,
        mnec = mnec.unwrap_or("—"),
        age = age.map(|a| format!("{a} yrs")).unwrap_or_else(|| "—".into()),
        aging = aging.unwrap_or("—"),
    )
}

async fn edit_substation(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.substations");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, asset_id, asset_type_id, primary_voltage_kv::float8 AS pkv, primary_voltage_kv::text AS pkv_t, site_id, substation_type, busbar_configuration, substation_class, source_from, feeder, customers_served, substation_category, automation_type, site_size, gps_latitude, gps_longitude, ownership, commissioning_date::text AS cdate, design_life_years, state, notes, active, verification_state FROM eam_substation WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let gets = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let vstate: String = row.get("verification_state");
    let f = SubForm {
        code: row.get("code"), name: row.get("name"), asset_id: gets("asset_id"),
        asset_type_id: row.try_get("asset_type_id").ok(), site_id: row.try_get("site_id").ok(),
        substation_class: gets("substation_class"), substation_type: gets("substation_type"),
        busbar_configuration: gets("busbar_configuration"), primary_voltage_kv: gets("pkv_t"),
        customers_served: row.try_get::<i32, _>("customers_served").map(|v| v.to_string()).unwrap_or_default(),
        source_from: gets("source_from"), feeder: gets("feeder"), automation_type: gets("automation_type"),
        substation_category: gets("substation_category"), gps_latitude: gets("gps_latitude"), gps_longitude: gets("gps_longitude"),
        site_size: gets("site_size"), ownership: row.get("ownership"), commissioning_date: gets("cdate"),
        design_life_years: row.try_get::<i32, _>("design_life_years").map(|v| v.to_string()).unwrap_or_default(),
        state: row.get("state"), notes: gets("notes"), active: row.try_get("active").unwrap_or(true),
    };
    let pkv: Option<f64> = row.try_get("pkv").ok();
    let cdate_opt = if f.commissioning_date.is_empty() { None } else { Some(f.commissioning_date.as_str()) };
    let derived = substation_derived(cdate_opt, pkv);

    // Bays under this substation
    let bays = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, bay_type, verification_state, state FROM eam_bay WHERE substation_id=$1 ORDER BY bay_number, code")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut bay_html = String::new();
    for r in &bays {
        let bid: Uuid = r.get("id");
        let bcode: String = r.get("code");
        let bname: String = r.get("name");
        let btype: String = r.get("bay_type");
        let bv: String = r.get("verification_state");
        bay_html.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/sesb-eam/bays/{bid}'"><td class="font-mono">{bcode}</td><td>{bname}</td><td>{btype}</td><td>{badge}</td></tr>"#,
            bid = bid, bcode = esc(&bcode), bname = esc(&bname), btype = esc(&btype), badge = vstate_badge(&bv)));
    }
    if bay_html.is_empty() { bay_html.push_str(r#"<tr><td colspan="4" class="text-base-content/50">No bays</td></tr>"#); }

    let history = vortex_plugin_sdk::framework::render_audit_trail(&db, "eam_substation", id).await;
    let header = format!(
        r#"<div class="flex items-center justify-between mb-4"><div>
<a href="/sesb-eam/substations" class="btn btn-ghost btn-sm mb-2">← Back to Substations</a>
<h1 class="text-2xl font-bold">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span> {badge}</h1></div></div>"#,
        name = esc(&f.name), code = esc(&f.code), badge = vstate_badge(&vstate));
    let body = substation_body(&db, &f, None, false).await;
    let content = format!(
        r#"<div class="max-w-4xl">{header}{derived}
<form method="POST" action="/sesb-eam/substations/{id}"><div class="card bg-base-100 shadow mt-4"><div class="card-body">{body}
<div class="flex gap-2 mt-4"><button class="btn btn-primary btn-sm">Save</button></div></div></div></form>
<div class="card bg-base-100 shadow mt-6"><div class="card-body">
<div class="flex items-center justify-between mb-2"><h2 class="card-title text-lg">Bays</h2>
<a href="/sesb-eam/bays/new?substation={id}" class="btn btn-primary btn-sm">New Bay</a></div>
<table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Verification</th></tr></thead><tbody>{bay_html}</tbody></table>
</div></div>
<div class="mt-6">{history}</div>
</div>"#,
        header = header, derived = derived, id = id, body = body, bay_html = bay_html, history = history);
    Html(page_shell(&sidebar, &format!("Substation {}", f.name), &content)).into_response()
}

async fn update_substation(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = SubForm::from_map(&form);
    let site_id = match f.site_id { Some(s) => s, None => return bad("Site is required") };
    if f.code.trim().is_empty() || f.name.trim().is_empty() { return bad("Code and name are required"); }
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_substation SET name=$1, code=$2, asset_id=$3, asset_type_id=$4, primary_voltage_kv=$5, site_id=$6, substation_type=$7, busbar_configuration=$8, substation_class=$9, source_from=$10, feeder=$11, customers_served=$12, substation_category=$13, automation_type=$14, site_size=$15, gps_latitude=$16, gps_longitude=$17, ownership=$18, commissioning_date=$19, design_life_years=$20, state=$21, notes=$22, active=$23, updated_by=$24 WHERE id=$25")
        .bind(&f.name).bind(&f.code).bind(opt_str(&form, "asset_id")).bind(f.asset_type_id)
        .bind(opt_dec(&form, "primary_voltage_kv")).bind(site_id)
        .bind(opt_str(&form, "substation_type")).bind(opt_str(&form, "busbar_configuration"))
        .bind(opt_str(&form, "substation_class")).bind(opt_str(&form, "source_from")).bind(opt_str(&form, "feeder"))
        .bind(opt_i32(&form, "customers_served").unwrap_or(0)).bind(opt_str(&form, "substation_category"))
        .bind(opt_str(&form, "automation_type")).bind(opt_str(&form, "site_size"))
        .bind(opt_str(&form, "gps_latitude")).bind(opt_str(&form, "gps_longitude"))
        .bind(form.get("ownership").map(|s| s.as_str()).unwrap_or("sesb"))
        .bind(opt_date(&form, "commissioning_date")).bind(opt_i32(&form, "design_life_years").unwrap_or(40))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(user.id).bind(id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "substation update failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/substations/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Bay
// ═════════════════════════════════════════════════════════════════════════

const BAY_TYPES: &[(&str, &str)] = &[
    ("incoming","Incoming"),("outgoing","Outgoing"),("bus_coupler","Bus Coupler"),("bus_section","Bus Section"),
    ("transformer","Transformer"),("capacitor","Capacitor"),("metering","Metering"),("auxiliary","Auxiliary"),("other","Other"),
];
const BAY_STATES: &[(&str, &str)] = &[
    ("available","Available"),("in_service","In Service"),("out_of_service","Out of Service"),("under_maintenance","Under Maintenance"),("reserved","Reserved"),
];

#[derive(Default)]
struct BayForm {
    code: String, name: String, bay_number: String, asset_id: String, substation_id: Option<Uuid>,
    bay_type: String, voltage_level_id: Option<Uuid>, busbar_configuration: String,
    rated_current_a: String, rated_fault_current_ka: String, feeder_name: String, feeder_number: String,
    destination: String, scada_point_group: String, sld_reference: String, state: String,
    notes: String, active: bool,
}

impl BayForm {
    fn defaults() -> Self { BayForm { bay_type: "outgoing".into(), state: "in_service".into(), active: true, ..Default::default() } }
    fn from_map(form: &HashMap<String, String>) -> Self {
        let g = |k: &str| form.get(k).cloned().unwrap_or_default();
        BayForm {
            code: g("code"), name: g("name"), bay_number: g("bay_number"), asset_id: g("asset_id"),
            substation_id: opt_uuid(form, "substation_id"), bay_type: g("bay_type"),
            voltage_level_id: opt_uuid(form, "voltage_level_id"), busbar_configuration: g("busbar_configuration"),
            rated_current_a: g("rated_current_a"), rated_fault_current_ka: g("rated_fault_current_ka"),
            feeder_name: g("feeder_name"), feeder_number: g("feeder_number"), destination: g("destination"),
            scada_point_group: g("scada_point_group"), sld_reference: g("sld_reference"), state: g("state"),
            notes: g("notes"), active: form.contains_key("active"),
        }
    }
}

async fn substation_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_substation WHERE active ORDER BY code", "-- Substation --", sel).await
}

async fn bay_body(db: &vortex_plugin_sdk::sqlx::PgPool, f: &BayForm, sub_preselect: Option<Uuid>, is_new: bool) -> String {
    let subs = substation_options(db, f.substation_id.or(sub_preselect)).await;
    let volts = voltage_options(db, f.voltage_level_id).await;
    let g = grid2(&format!("{}{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Code", "code", &f.code, true),
        text_field("Name", "name", &f.name, true),
        num_field("Bay Number", "bay_number", &f.bay_number, "1"),
        text_field("MNEC Asset ID", "asset_id", &f.asset_id, false),
        select_field("Substation *", "substation_id", &subs),
        select_field("Bay Type *", "bay_type", &enum_options(BAY_TYPES, &f.bay_type)),
        select_field("Voltage Level", "voltage_level_id", &volts),
        select_field("Busbar Configuration", "busbar_configuration", &enum_options(BUSBARS, &f.busbar_configuration)),
        num_field("Rated Current (A)", "rated_current_a", &f.rated_current_a, "0.01"),
        num_field("Rated Fault Current (kA)", "rated_fault_current_ka", &f.rated_fault_current_ka, "0.01"),
        text_field("Feeder Name", "feeder_name", &f.feeder_name, false),
        text_field("Feeder Number", "feeder_number", &f.feeder_number, false),
        text_field("Destination", "destination", &f.destination, false),
    ));
    let g2 = grid2(&format!("{}{}{}",
        text_field("SCADA Point Group", "scada_point_group", &f.scada_point_group, false),
        text_field("SLD Reference", "sld_reference", &f.sld_reference, false),
        select_field("State", "state", &enum_options(BAY_STATES, &f.state)),
    ));
    format!("{}{}{}{}", g, g2, textarea_field("Notes", "notes", &f.notes), active_field(f.active, is_new))
}

async fn new_bay(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.substations");
    let sub_pre = q.get("substation").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/substations", "Back to Substations", "New Bay");
    let body = bay_body(&db, &BayForm::defaults(), sub_pre, true).await;
    Html(page_shell(&sidebar, "New Bay", &wide_form_page("/sesb-eam/bays/create", &header, &body))).into_response()
}

async fn create_bay(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = BayForm::from_map(&form);
    let substation_id = match f.substation_id { Some(s) => s, None => return bad("Substation is required") };
    if f.code.trim().is_empty() || f.name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_bay (id, name, code, bay_number, asset_id, substation_id, bay_type, voltage_level_id, busbar_configuration, rated_current_a, rated_fault_current_ka, feeder_name, feeder_number, destination, scada_point_group, sld_reference, state, notes, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)")
        .bind(id).bind(&f.name).bind(&f.code).bind(opt_i32(&form, "bay_number"))
        .bind(opt_str(&form, "asset_id")).bind(substation_id)
        .bind(form.get("bay_type").map(|s| s.as_str()).unwrap_or("outgoing"))
        .bind(f.voltage_level_id).bind(opt_str(&form, "busbar_configuration"))
        .bind(opt_dec(&form, "rated_current_a")).bind(opt_dec(&form, "rated_fault_current_ka"))
        .bind(opt_str(&form, "feeder_name")).bind(opt_str(&form, "feeder_number")).bind(opt_str(&form, "destination"))
        .bind(opt_str(&form, "scada_point_group")).bind(opt_str(&form, "sld_reference"))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("in_service"))
        .bind(opt_str(&form, "notes")).bind(company_id).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "bay insert failed"); return bad(&format!("Failed: {e}")); }
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_bay", id.to_string()).with_resource_name(&f.name);
    let _ = state.audit.log(entry).await;
    Redirect::to(&format!("/sesb-eam/bays/{id}")).into_response()
}

async fn edit_bay(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.substations");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT b.code, b.name, b.bay_number, b.asset_id, b.substation_id, b.bay_type, b.voltage_level_id, b.busbar_configuration, b.rated_current_a::text AS rca, b.rated_fault_current_ka::text AS rfc, b.feeder_name, b.feeder_number, b.destination, b.scada_point_group, b.sld_reference, b.state, b.notes, b.active, b.verification_state, s.name AS sub_name FROM eam_bay b LEFT JOIN eam_substation s ON s.id = b.substation_id WHERE b.id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let gets = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let vstate: String = row.get("verification_state");
    let sub_name: Option<String> = row.try_get("sub_name").ok();
    let f = BayForm {
        code: row.get("code"), name: row.get("name"),
        bay_number: row.try_get::<Option<i32>, _>("bay_number").ok().flatten().map(|v| v.to_string()).unwrap_or_default(),
        asset_id: gets("asset_id"), substation_id: row.try_get("substation_id").ok(),
        bay_type: row.get("bay_type"), voltage_level_id: row.try_get("voltage_level_id").ok(),
        busbar_configuration: gets("busbar_configuration"), rated_current_a: gets("rca"), rated_fault_current_ka: gets("rfc"),
        feeder_name: gets("feeder_name"), feeder_number: gets("feeder_number"), destination: gets("destination"),
        scada_point_group: gets("scada_point_group"), sld_reference: gets("sld_reference"), state: row.get("state"),
        notes: gets("notes"), active: row.try_get("active").unwrap_or(true),
    };
    let back_url = f.substation_id.map(|s| format!("/sesb-eam/substations/{s}")).unwrap_or_else(|| "/sesb-eam/substations".into());
    let header = format!(
        r#"<a href="{back}" class="btn btn-ghost btn-sm mb-4">← Back{sub}</a>
<h1 class="text-2xl font-bold mb-2">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span> {badge}</h1>"#,
        back = back_url, sub = sub_name.map(|n| format!(" to {}", esc(&n))).unwrap_or_default(),
        name = esc(&f.name), code = esc(&f.code), badge = vstate_badge(&vstate));
    let body = bay_body(&db, &f, None, false).await;
    let history = vortex_plugin_sdk::framework::render_audit_trail(&db, "eam_bay", id).await;
    let content = format!("{}<div class=\"mt-6 max-w-4xl\">{}</div>",
        wide_form_page(&format!("/sesb-eam/bays/{id}"), &header, &body), history);
    Html(page_shell(&sidebar, &format!("Bay {}", f.name), &content)).into_response()
}

async fn update_bay(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = BayForm::from_map(&form);
    let substation_id = match f.substation_id { Some(s) => s, None => return bad("Substation is required") };
    if f.code.trim().is_empty() || f.name.trim().is_empty() { return bad("Code and name are required"); }
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_bay SET name=$1, code=$2, bay_number=$3, asset_id=$4, substation_id=$5, bay_type=$6, voltage_level_id=$7, busbar_configuration=$8, rated_current_a=$9, rated_fault_current_ka=$10, feeder_name=$11, feeder_number=$12, destination=$13, scada_point_group=$14, sld_reference=$15, state=$16, notes=$17, active=$18, updated_by=$19 WHERE id=$20")
        .bind(&f.name).bind(&f.code).bind(opt_i32(&form, "bay_number")).bind(opt_str(&form, "asset_id"))
        .bind(substation_id).bind(form.get("bay_type").map(|s| s.as_str()).unwrap_or("outgoing"))
        .bind(f.voltage_level_id).bind(opt_str(&form, "busbar_configuration"))
        .bind(opt_dec(&form, "rated_current_a")).bind(opt_dec(&form, "rated_fault_current_ka"))
        .bind(opt_str(&form, "feeder_name")).bind(opt_str(&form, "feeder_number")).bind(opt_str(&form, "destination"))
        .bind(opt_str(&form, "scada_point_group")).bind(opt_str(&form, "sld_reference"))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("in_service"))
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(user.id).bind(id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "bay update failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/bays/{id}")).into_response()
}
