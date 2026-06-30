//! Reference / master data CRUD — voltage levels, manufacturers, asset
//! classes and the asset-type acronym registry (§3.11).

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use vortex_plugin_sdk::framework::list::{
    execute_list, render_list, ListColumn, ListConfig, ListParams,
};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Voltage levels
        .route("/sesb-eam/voltage-levels", get(list_voltage))
        .route("/sesb-eam/voltage-levels/new", get(new_voltage))
        .route("/sesb-eam/voltage-levels/create", post(create_voltage))
        .route("/sesb-eam/voltage-levels/{id}", get(edit_voltage))
        .route("/sesb-eam/voltage-levels/{id}", post(update_voltage))
        // Manufacturers
        .route("/sesb-eam/manufacturers", get(list_mfr))
        .route("/sesb-eam/manufacturers/new", get(new_mfr))
        .route("/sesb-eam/manufacturers/create", post(create_mfr))
        .route("/sesb-eam/manufacturers/{id}", get(edit_mfr))
        .route("/sesb-eam/manufacturers/{id}", post(update_mfr))
        // Asset classes
        .route("/sesb-eam/asset-classes", get(list_class))
        .route("/sesb-eam/asset-classes/new", get(new_class))
        .route("/sesb-eam/asset-classes/create", post(create_class))
        .route("/sesb-eam/asset-classes/{id}", get(edit_class))
        .route("/sesb-eam/asset-classes/{id}", post(update_class))
        // Asset types
        .route("/sesb-eam/asset-types", get(list_type))
        .route("/sesb-eam/asset-types/new", get(new_type))
        .route("/sesb-eam/asset-types/create", post(create_type))
        .route("/sesb-eam/asset-types/{id}", get(edit_type))
        .route("/sesb-eam/asset-types/{id}", post(update_type))
}

// ─────────────────────────────────────────────────────────────────────────
// Voltage levels
// ─────────────────────────────────────────────────────────────────────────

const VTYPES: &[(&str, &str)] = &[("ac", "AC"), ("dc", "DC")];

async fn list_voltage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.voltage_levels");
    let config = ListConfig::new("Voltage Levels", "eam_voltage_level")
        .column(ListColumn::new("code", "Code").sortable().code())
        .column(ListColumn::new("name", "Name").sortable().searchable())
        .column(ListColumn::new("voltage_kv", "kV").sortable())
        .column(ListColumn::new("voltage_type", "Type").badge(&[("ac","AC","badge-info"),("dc","DC","badge-warning")]))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning"))
        .detail_url("/sesb-eam/voltage-levels/{id}")
        .create("New Voltage Level", "/sesb-eam/voltage-levels/new")
        .default_sort("voltage_kv");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error=%e, "voltage list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Voltage Levels", &render_list(&config, &result, &params, "/sesb-eam/voltage-levels"))).into_response()
}

fn voltage_body(code: &str, name: &str, kv: &str, vtype: &str, desc: &str, active: bool, is_new: bool) -> String {
    format!("{}{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        num_field("Voltage (kV)", "voltage_kv", kv, "0.0001"),
        select_field("Type", "voltage_type", &enum_options(VTYPES, vtype)),
        textarea_field("Description", "description", desc),
        active_field(active, is_new),
    )
}

async fn new_voltage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.voltage_levels");
    let _ = db;
    let header = form_header("/sesb-eam/voltage-levels", "Back to Voltage Levels", "New Voltage Level");
    let body = voltage_body("", "", "", "ac", "", true, true);
    Html(page_shell(&sidebar, "New Voltage Level", &form_page("/sesb-eam/voltage-levels/create", &header, &body))).into_response()
}

async fn create_voltage(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_voltage_level (id, name, code, voltage_kv, voltage_type, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code)
        .bind(opt_dec(&form, "voltage_kv"))
        .bind(form.get("voltage_type").map(|s| s.as_str()).unwrap_or("ac"))
        .bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "voltage insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/voltage-levels").into_response()
}

async fn edit_voltage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.voltage_levels");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT code, name, voltage_kv::text AS kv, voltage_type, description, active FROM eam_voltage_level WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let kv: Option<String> = row.try_get("kv").ok();
    let vtype: String = row.get("voltage_type");
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let header = form_header("/sesb-eam/voltage-levels", "Back to Voltage Levels", &format!("Edit {}", name));
    let body = voltage_body(&code, &name, kv.as_deref().unwrap_or(""), &vtype, desc.as_deref().unwrap_or(""), active, false);
    Html(page_shell(&sidebar, "Edit Voltage Level", &form_page(&format!("/sesb-eam/voltage-levels/{id}"), &header, &body))).into_response()
}

async fn update_voltage(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_voltage_level SET name=$1, code=$2, voltage_kv=$3, voltage_type=$4, description=$5, active=$6 WHERE id=$7")
        .bind(&name).bind(&code).bind(opt_dec(&form, "voltage_kv"))
        .bind(form.get("voltage_type").map(|s| s.as_str()).unwrap_or("ac"))
        .bind(opt_str(&form, "description")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/voltage-levels").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Manufacturers
// ─────────────────────────────────────────────────────────────────────────

async fn country_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM countries ORDER BY name", "-- Country --", sel).await
}

async fn list_mfr(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.manufacturers");
    let config = ListConfig::new("Manufacturers", "eam_manufacturer")
        .custom_from("eam_manufacturer m LEFT JOIN countries co ON co.id = m.country_id")
        .custom_select("m.id, m.code, m.name, co.name AS country, m.phone, m.email, m.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("m.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("m.name"))
        .column(ListColumn::new("country", "Country").sql_expr("co.name"))
        .column(ListColumn::new("phone", "Phone").sql_expr("m.phone"))
        .column(ListColumn::new("email", "Email").sql_expr("m.email"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning").sql_expr("m.active"))
        .detail_url("/sesb-eam/manufacturers/{id}")
        .create("New Manufacturer", "/sesb-eam/manufacturers/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "mfr list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Manufacturers", &render_list(&config, &result, &params, "/sesb-eam/manufacturers"))).into_response()
}

fn mfr_body(code: &str, name: &str, countries: &str, website: &str, phone: &str, email: &str, notes: &str, active: bool, is_new: bool) -> String {
    format!("{}{}{}{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        select_field("Country", "country_id", countries),
        text_field("Website", "website", website, false),
        text_field("Phone", "phone", phone, false),
        text_field("Email", "email", email, false),
        textarea_field("Notes", "notes", notes),
        active_field(active, is_new),
    )
}

async fn new_mfr(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.manufacturers");
    let countries = country_options(&db, None).await;
    let header = form_header("/sesb-eam/manufacturers", "Back to Manufacturers", "New Manufacturer");
    let body = mfr_body("", "", &countries, "", "", "", "", true, true);
    Html(page_shell(&sidebar, "New Manufacturer", &form_page("/sesb-eam/manufacturers/create", &header, &body))).into_response()
}

async fn create_mfr(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_manufacturer (id, name, code, country_id, website, phone, email, notes, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code).bind(opt_uuid(&form, "country_id"))
        .bind(opt_str(&form, "website")).bind(opt_str(&form, "phone")).bind(opt_str(&form, "email"))
        .bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "mfr insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/manufacturers").into_response()
}

async fn edit_mfr(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.manufacturers");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT code, name, country_id, website, phone, email, notes, active FROM eam_manufacturer WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let country_id: Option<Uuid> = row.try_get("country_id").ok();
    let website: Option<String> = row.try_get("website").ok();
    let phone: Option<String> = row.try_get("phone").ok();
    let email: Option<String> = row.try_get("email").ok();
    let notes: Option<String> = row.try_get("notes").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let countries = country_options(&db, country_id).await;
    let header = form_header("/sesb-eam/manufacturers", "Back to Manufacturers", &format!("Edit {}", name));
    let body = mfr_body(&code, &name, &countries, website.as_deref().unwrap_or(""), phone.as_deref().unwrap_or(""), email.as_deref().unwrap_or(""), notes.as_deref().unwrap_or(""), active, false);
    Html(page_shell(&sidebar, "Edit Manufacturer", &form_page(&format!("/sesb-eam/manufacturers/{id}"), &header, &body))).into_response()
}

async fn update_mfr(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_manufacturer SET name=$1, code=$2, country_id=$3, website=$4, phone=$5, email=$6, notes=$7, active=$8 WHERE id=$9")
        .bind(&name).bind(&code).bind(opt_uuid(&form, "country_id"))
        .bind(opt_str(&form, "website")).bind(opt_str(&form, "phone")).bind(opt_str(&form, "email"))
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/manufacturers").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Asset classes
// ─────────────────────────────────────────────────────────────────────────

const CLASS_TYPES: &[(&str, &str)] = &[("electrical", "Electrical"), ("non_electrical", "Non-Electrical")];
const CLASS_GROUPS: &[(&str, &str)] = &[
    ("", "—"), ("pencawang", "Pencawang"), ("primary", "Primary"), ("secondary", "Secondary"),
    ("building_exterior", "Building Exterior"), ("building_interior", "Building Interior"), ("access_door", "Access Door"),
];
const TIERS: &[(&str, &str)] = &[("", "—"), ("tier1", "Tier 1"), ("tier2", "Tier 2"), ("tier3", "Tier 3")];

async fn class_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_asset_class WHERE active ORDER BY sequence, name", "-- Parent Class --", sel).await
}

async fn list_class(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_classes");
    let config = ListConfig::new("Asset Classes", "eam_asset_class")
        .custom_from("eam_asset_class c LEFT JOIN eam_asset_class p ON p.id = c.parent_id")
        .custom_select("c.id, c.code, c.name, c.class_type, c.class_group, p.name AS parent_name, c.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("c.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("c.name"))
        .column(ListColumn::new("class_type", "Type")
            .filterable(&[("electrical","Electrical"),("non_electrical","Non-Electrical")])
            .badge(&[("electrical","Electrical","badge-info"),("non_electrical","Non-Electrical","badge-ghost")]).sql_expr("c.class_type"))
        .column(ListColumn::new("class_group", "Group").sql_expr("c.class_group"))
        .column(ListColumn::new("parent_name", "Parent").sql_expr("p.name"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning").sql_expr("c.active"))
        .detail_url("/sesb-eam/asset-classes/{id}")
        .create("New Asset Class", "/sesb-eam/asset-classes/new")
        .default_sort("code");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "class list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Asset Classes", &render_list(&config, &result, &params, "/sesb-eam/asset-classes"))).into_response()
}

#[allow(clippy::too_many_arguments)]
fn class_body(code: &str, name: &str, seq: &str, ctype: &str, cgroup: &str, parents: &str, tier: &str, t1: &str, t2: &str, dur: &str, scope: &str, desc: &str, active: bool, is_new: bool) -> String {
    format!("{}{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Code", "code", code, true),
        text_field("Name", "name", name, true),
        num_field("Sequence", "sequence", seq, "1"),
        select_field("Class Type", "class_type", &enum_options(CLASS_TYPES, ctype)),
        select_field("Class Group", "class_group", &enum_options(CLASS_GROUPS, cgroup)),
        select_field("Parent Class", "parent_id", parents),
        select_field("Default Maintenance Tier", "default_maintenance_tier", &enum_options(TIERS, tier)),
        num_field("Tier 1 Frequency (months)", "tier1_frequency_months", t1, "1"),
        num_field("Tier 2 Frequency (months)", "tier2_frequency_months", t2, "1"),
        num_field("Default Duration (hours)", "default_duration_hours", dur, "0.5"),
        textarea_field("Scope Notes", "scope_notes", scope),
        textarea_field("Description", "description", desc),
        active_field(active, is_new),
    )
}

async fn new_class(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_classes");
    let parents = class_options(&db, None).await;
    let header = form_header("/sesb-eam/asset-classes", "Back to Asset Classes", "New Asset Class");
    let body = class_body("", "", "0", "electrical", "", &parents, "", "", "", "", "", "", true, true);
    Html(page_shell(&sidebar, "New Asset Class", &form_page("/sesb-eam/asset-classes/create", &header, &body))).into_response()
}

async fn create_class(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset_class (id, name, code, sequence, class_type, class_group, parent_id, default_maintenance_tier, tier1_frequency_months, tier2_frequency_months, default_duration_hours, scope_notes, description, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code)
        .bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(form.get("class_type").map(|s| s.as_str()).unwrap_or("electrical"))
        .bind(opt_str(&form, "class_group")).bind(opt_uuid(&form, "parent_id"))
        .bind(opt_str(&form, "default_maintenance_tier"))
        .bind(opt_i32(&form, "tier1_frequency_months")).bind(opt_i32(&form, "tier2_frequency_months"))
        .bind(opt_dec(&form, "default_duration_hours"))
        .bind(opt_str(&form, "scope_notes")).bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "class insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/asset-classes").into_response()
}

async fn edit_class(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_classes");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, sequence, class_type, class_group, parent_id, default_maintenance_tier, \
                tier1_frequency_months, tier2_frequency_months, default_duration_hours::text AS dur, scope_notes, description, active \
         FROM eam_asset_class WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let seq: i32 = row.try_get("sequence").unwrap_or(0);
    let ctype: String = row.get("class_type");
    let cgroup: Option<String> = row.try_get("class_group").ok();
    let parent_id: Option<Uuid> = row.try_get("parent_id").ok();
    let tier: Option<String> = row.try_get("default_maintenance_tier").ok();
    let t1: Option<i32> = row.try_get("tier1_frequency_months").ok();
    let t2: Option<i32> = row.try_get("tier2_frequency_months").ok();
    let dur: Option<String> = row.try_get("dur").ok();
    let scope: Option<String> = row.try_get("scope_notes").ok();
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let parents = class_options(&db, parent_id).await;
    let header = form_header("/sesb-eam/asset-classes", "Back to Asset Classes", &format!("Edit {}", name));
    let body = class_body(&code, &name, &seq.to_string(), &ctype, cgroup.as_deref().unwrap_or(""), &parents,
        tier.as_deref().unwrap_or(""), &t1.map(|v| v.to_string()).unwrap_or_default(), &t2.map(|v| v.to_string()).unwrap_or_default(),
        dur.as_deref().unwrap_or(""), scope.as_deref().unwrap_or(""), desc.as_deref().unwrap_or(""), active, false);
    Html(page_shell(&sidebar, "Edit Asset Class", &form_page(&format!("/sesb-eam/asset-classes/{id}"), &header, &body))).into_response()
}

async fn update_class(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (code, name) = (form.get("code").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if code.trim().is_empty() || name.trim().is_empty() { return bad("Code and name are required"); }
    let parent_id = opt_uuid(&form, "parent_id").filter(|p| *p != id);
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset_class SET name=$1, code=$2, sequence=$3, class_type=$4, class_group=$5, parent_id=$6, \
         default_maintenance_tier=$7, tier1_frequency_months=$8, tier2_frequency_months=$9, default_duration_hours=$10, \
         scope_notes=$11, description=$12, active=$13 WHERE id=$14")
        .bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0))
        .bind(form.get("class_type").map(|s| s.as_str()).unwrap_or("electrical"))
        .bind(opt_str(&form, "class_group")).bind(parent_id)
        .bind(opt_str(&form, "default_maintenance_tier"))
        .bind(opt_i32(&form, "tier1_frequency_months")).bind(opt_i32(&form, "tier2_frequency_months"))
        .bind(opt_dec(&form, "default_duration_hours"))
        .bind(opt_str(&form, "scope_notes")).bind(opt_str(&form, "description"))
        .bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/asset-classes").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Asset types (acronym registry)
// ─────────────────────────────────────────────────────────────────────────

const TYPE_CATEGORIES: &[(&str, &str)] = &[
    ("switchgear_type", "Switchgear Type"), ("primary_equipment", "Primary Equipment"),
    ("online_monitoring", "Online Monitoring"), ("control_relay", "Control / Relay"),
    ("tower_equipment", "Tower Equipment"), ("ugc_equipment", "UGC Equipment"),
];
const ATTR_SCHEMAS: &[(&str, &str)] = &[
    ("transformer", "Transformer"), ("phase_primary", "Phase / Primary"), ("relay_control", "Relay / Control"),
    ("tower_hardware", "Tower Hardware"), ("ugc_accessory", "UGC Accessory"), ("generic", "Generic"),
];
const HLEVELS: &[(&str, &str)] = &[("", "—"), ("1", "1"), ("2", "2"), ("3", "3"), ("4", "4")];

async fn list_type(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_types");
    let config = ListConfig::new("Asset Types", "eam_asset_type")
        .column(ListColumn::new("acronym", "Acronym").sortable().code())
        .column(ListColumn::new("name", "Name").sortable().searchable())
        .column(ListColumn::new("category", "Category")
            .filterable(&[("switchgear_type","Switchgear"),("primary_equipment","Primary"),("online_monitoring","Online Monitoring"),("control_relay","Control/Relay"),("tower_equipment","Tower"),("ugc_equipment","UGC")]))
        .column(ListColumn::new("attribute_schema", "Schema"))
        .column(ListColumn::new("default_hierarchy_level", "Level"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning"))
        .detail_url("/sesb-eam/asset-types/{id}")
        .create("New Asset Type", "/sesb-eam/asset-types/new")
        .default_sort("acronym");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "type list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Asset Types", &render_list(&config, &result, &params, "/sesb-eam/asset-types"))).into_response()
}

fn type_body(acronym: &str, name: &str, category: &str, level: &str, schema: &str, desc: &str, active: bool, is_new: bool) -> String {
    format!("{}{}{}{}{}{}{}",
        text_field("Acronym", "acronym", acronym, true),
        text_field("Name", "name", name, true),
        select_field("Category", "category", &enum_options(TYPE_CATEGORIES, category)),
        select_field("Default Hierarchy Level", "default_hierarchy_level", &enum_options(HLEVELS, level)),
        select_field("Attribute Schema", "attribute_schema", &enum_options(ATTR_SCHEMAS, schema)),
        textarea_field("Description", "description", desc),
        active_field(active, is_new),
    )
}

async fn new_type(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_types");
    let _ = db;
    let header = form_header("/sesb-eam/asset-types", "Back to Asset Types", "New Asset Type");
    let body = type_body("", "", "primary_equipment", "", "generic", "", true, true);
    Html(page_shell(&sidebar, "New Asset Type", &form_page("/sesb-eam/asset-types/create", &header, &body))).into_response()
}

async fn create_type(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (acronym, name) = (form.get("acronym").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if acronym.trim().is_empty() || name.trim().is_empty() { return bad("Acronym and name are required"); }
    let company_id = default_company(&db).await;
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_asset_type (id, acronym, name, category, default_hierarchy_level, attribute_schema, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::now_v7()).bind(&acronym).bind(&name)
        .bind(form.get("category").map(|s| s.as_str()).unwrap_or("primary_equipment"))
        .bind(opt_i32(&form, "default_hierarchy_level"))
        .bind(form.get("attribute_schema").map(|s| s.as_str()).unwrap_or("generic"))
        .bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "type insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to("/sesb-eam/asset-types").into_response()
}

async fn edit_type(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.asset_types");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT acronym, name, category, default_hierarchy_level, attribute_schema, description, active FROM eam_asset_type WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let acronym: String = row.get("acronym");
    let name: String = row.get("name");
    let category: String = row.get("category");
    let level: Option<i32> = row.try_get("default_hierarchy_level").ok();
    let schema: String = row.get("attribute_schema");
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let header = form_header("/sesb-eam/asset-types", "Back to Asset Types", &format!("Edit {}", acronym));
    let body = type_body(&acronym, &name, &category, &level.map(|v| v.to_string()).unwrap_or_default(), &schema, desc.as_deref().unwrap_or(""), active, false);
    Html(page_shell(&sidebar, "Edit Asset Type", &form_page(&format!("/sesb-eam/asset-types/{id}"), &header, &body))).into_response()
}

async fn update_type(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (acronym, name) = (form.get("acronym").cloned().unwrap_or_default(), form.get("name").cloned().unwrap_or_default());
    if acronym.trim().is_empty() || name.trim().is_empty() { return bad("Acronym and name are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_asset_type SET acronym=$1, name=$2, category=$3, default_hierarchy_level=$4, attribute_schema=$5, description=$6, active=$7 WHERE id=$8")
        .bind(&acronym).bind(&name)
        .bind(form.get("category").map(|s| s.as_str()).unwrap_or("primary_equipment"))
        .bind(opt_i32(&form, "default_hierarchy_level"))
        .bind(form.get("attribute_schema").map(|s| s.as_str()).unwrap_or("generic"))
        .bind(opt_str(&form, "description")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to("/sesb-eam/asset-types").into_response()
}
