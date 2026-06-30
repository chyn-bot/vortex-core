//! Transmission / distribution / UGC network CRUD (§3.4–3.5):
//! transmission lines, towers (+ wayleave), spans, gantries, UGC lines,
//! distribution lines, cable segments and IR/PI cable tests.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use vortex_plugin_sdk::framework::list::{
    execute_list, render_list, ListColumn, ListConfig, ListParams,
};

const TL_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.transmission_line", "TL").with_padding(5);
const TWR_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.tower", "TWR").with_padding(6);
const SPN_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.span", "SPN").with_padding(6);
const GTR_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.gantry", "GTR").with_padding(5);
const DL_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.distribution_line", "DL").with_padding(5);
const UGC_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.ugc_line", "UGC").with_padding(5);
const CT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.cable_test", "CT").with_padding(5).yearly();

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Transmission lines
        .route("/sesb-eam/transmission-lines", get(list_tline))
        .route("/sesb-eam/transmission-lines/new", get(new_tline))
        .route("/sesb-eam/transmission-lines/create", post(create_tline))
        .route("/sesb-eam/transmission-lines/{id}", get(edit_tline))
        .route("/sesb-eam/transmission-lines/{id}", post(update_tline))
        // Towers
        .route("/sesb-eam/towers/new", get(new_tower))
        .route("/sesb-eam/towers/create", post(create_tower))
        .route("/sesb-eam/towers/{id}", get(edit_tower))
        .route("/sesb-eam/towers/{id}", post(update_tower))
        // Spans
        .route("/sesb-eam/spans/create", post(create_span))
        .route("/sesb-eam/spans/{id}/delete", post(delete_span))
        // Gantries
        .route("/sesb-eam/gantries/new", get(new_gantry))
        .route("/sesb-eam/gantries/create", post(create_gantry))
        .route("/sesb-eam/gantries/{id}", post(update_gantry))
        // Distribution lines
        .route("/sesb-eam/distribution-lines", get(list_dline))
        .route("/sesb-eam/distribution-lines/new", get(new_dline))
        .route("/sesb-eam/distribution-lines/create", post(create_dline))
        .route("/sesb-eam/distribution-lines/{id}", get(edit_dline))
        .route("/sesb-eam/distribution-lines/{id}", post(update_dline))
        // UGC lines
        .route("/sesb-eam/ugc-lines", get(list_ugc))
        .route("/sesb-eam/ugc-lines/new", get(new_ugc))
        .route("/sesb-eam/ugc-lines/create", post(create_ugc))
        .route("/sesb-eam/ugc-lines/{id}", get(edit_ugc))
        .route("/sesb-eam/ugc-lines/{id}", post(update_ugc))
        // Cable segments + tests
        .route("/sesb-eam/cable-segments/new", get(new_cseg))
        .route("/sesb-eam/cable-segments/create", post(create_cseg))
        .route("/sesb-eam/cable-segments/{id}", get(edit_cseg))
        .route("/sesb-eam/cable-segments/{id}", post(update_cseg))
        .route("/sesb-eam/cable-tests/create", post(create_ctest))
}

fn grid3(fields: &str) -> String { format!(r#"<div class="grid grid-cols-1 md:grid-cols-3 gap-x-4">{}</div>"#, fields) }

const LINE_STATES: &[(&str, &str)] = &[("planning","Planning"),("construction","Construction"),("operational","Operational"),("maintenance","Maintenance"),("decommissioned","Decommissioned")];
const OWNERSHIPS: &[(&str, &str)] = &[("sesb","SESB"),("ipp","IPP"),("shared","Shared")];

async fn substation_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_substation WHERE active ORDER BY code", "-- Substation --", sel).await
}

// ═════════════════════════════════════════════════════════════════════════
// Transmission line
// ═════════════════════════════════════════════════════════════════════════

const TL_COND: &[(&str, &str)] = &[("","—"),("acsr","ACSR"),("acar","ACAR"),("aaac","AAAC"),("aac","AAC"),("accc","ACCC"),("htls","HTLS")];

async fn list_tline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_lines");
    let config = ListConfig::new("Transmission Lines", "eam_transmission_line")
        .custom_from("eam_transmission_line t LEFT JOIN eam_region r ON r.id=t.region_id LEFT JOIN eam_voltage_level v ON v.id=t.voltage_level_id LEFT JOIN (SELECT transmission_line_id, COUNT(*) c FROM eam_transmission_tower GROUP BY transmission_line_id) tw ON tw.transmission_line_id=t.id")
        .custom_select("t.id, t.code, t.name, t.asset_id, r.name AS region_name, v.name AS voltage, COALESCE(tw.c,0)::text AS towers, t.state, t.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("t.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("t.name"))
        .column(ListColumn::new("asset_id", "MNEC Asset ID").searchable().sql_expr("t.asset_id"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("voltage", "Voltage").sql_expr("v.name"))
        .column(ListColumn::new("towers", "Towers").sql_expr("COALESCE(tw.c,0)"))
        .column(ListColumn::new("state", "State").badge(&[("operational","Operational","badge-success"),("maintenance","Maintenance","badge-warning"),("construction","Construction","badge-info"),("planning","Planning","badge-ghost"),("decommissioned","Decommissioned","badge-ghost")]).sql_expr("t.state"))
        .detail_url("/sesb-eam/transmission-lines/{id}")
        .create("New Transmission Line", "/sesb-eam/transmission-lines/new")
        .default_sort("code");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "tline list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Transmission Lines", &render_list(&config, &result, &params, "/sesb-eam/transmission-lines"))).into_response()
}

#[derive(Default)]
struct TLineForm {
    name: String, asset_id: String, region_id: Option<Uuid>, voltage_level_id: Option<Uuid>,
    from_substation_id: Option<Uuid>, to_substation_id: Option<Uuid>, line_length_km: String,
    conductor_type: String, conductor_size_mm2: String, number_of_circuits: String, earth_wire_type: String,
    rated_current_a: String, max_sag_m: String, state: String, commissioning_date: String,
    design_life_years: String, ownership: String, notes: String, active: bool,
}
impl TLineForm {
    fn defaults() -> Self { TLineForm { state: "operational".into(), ownership: "sesb".into(), active: true, ..Default::default() } }
    fn from_map(f: &HashMap<String, String>) -> Self {
        let g = |k: &str| f.get(k).cloned().unwrap_or_default();
        TLineForm { name: g("name"), asset_id: g("asset_id"), region_id: opt_uuid(f, "region_id"), voltage_level_id: opt_uuid(f, "voltage_level_id"),
            from_substation_id: opt_uuid(f, "from_substation_id"), to_substation_id: opt_uuid(f, "to_substation_id"), line_length_km: g("line_length_km"),
            conductor_type: g("conductor_type"), conductor_size_mm2: g("conductor_size_mm2"), number_of_circuits: g("number_of_circuits"), earth_wire_type: g("earth_wire_type"),
            rated_current_a: g("rated_current_a"), max_sag_m: g("max_sag_m"), state: g("state"), commissioning_date: g("commissioning_date"),
            design_life_years: g("design_life_years"), ownership: g("ownership"), notes: g("notes"), active: f.contains_key("active") }
    }
}

async fn tline_body(db: &PgPool, f: &TLineForm, is_new: bool) -> String {
    let regions = region_options(db, f.region_id).await;
    let volts = voltage_options(db, f.voltage_level_id).await;
    let froms = substation_opts(db, f.from_substation_id).await;
    let tos = substation_opts(db, f.to_substation_id).await;
    let g = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Name", "name", &f.name, true),
        text_field("MNEC Asset ID", "asset_id", &f.asset_id, false),
        select_field("Region *", "region_id", &regions),
        select_field("Voltage Level *", "voltage_level_id", &volts),
        select_field("From Substation", "from_substation_id", &froms),
        select_field("To Substation", "to_substation_id", &tos),
        num_field("Line Length (km)", "line_length_km", &f.line_length_km, "0.0001"),
        select_field("Conductor Type", "conductor_type", &enum_options(TL_COND, &f.conductor_type)),
        num_field("Conductor Size (mm²)", "conductor_size_mm2", &f.conductor_size_mm2, "0.01"),
        num_field("Number of Circuits", "number_of_circuits", &f.number_of_circuits, "1"),
        text_field("Earth Wire Type", "earth_wire_type", &f.earth_wire_type, false),
        num_field("Rated Current (A)", "rated_current_a", &f.rated_current_a, "0.01"),
        num_field("Max Sag (m)", "max_sag_m", &f.max_sag_m, "0.01"),
        num_field("Design Life (years)", "design_life_years", &f.design_life_years, "1"),
    ));
    let g2 = grid3(&format!("{}{}{}",
        date_field("Commissioning Date", "commissioning_date", &f.commissioning_date),
        select_field("State", "state", &enum_options(LINE_STATES, &f.state)),
        select_field("Ownership", "ownership", &enum_options(OWNERSHIPS, &f.ownership)),
    ));
    format!("{}{}{}{}", g, g2, textarea_field("Notes", "notes", &f.notes), active_field(f.active, is_new))
}

async fn new_tline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_lines");
    let header = form_header("/sesb-eam/transmission-lines", "Back to Transmission Lines", "New Transmission Line");
    let body = tline_body(&db, &TLineForm::defaults(), true).await;
    Html(page_shell(&sidebar, "New Transmission Line", &wide_form_page("/sesb-eam/transmission-lines/create", &header, &body))).into_response()
}

async fn create_tline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = TLineForm::from_map(&form);
    let region_id = match f.region_id { Some(r) => r, None => return bad("Region is required") };
    let voltage_id = match f.voltage_level_id { Some(v) => v, None => return bad("Voltage level is required") };
    if f.name.trim().is_empty() { return bad("Name is required"); }
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &TL_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_transmission_line (id, name, code, asset_id, hierarchy_level, region_id, voltage_level_id, from_substation_id, to_substation_id, line_length_km, conductor_type, conductor_size_mm2, number_of_circuits, earth_wire_type, rated_current_a, max_sag_m, state, commissioning_date, design_life_years, ownership, notes, company_id) \
         VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)")
        .bind(id).bind(&f.name).bind(&code).bind(opt_str(&form, "asset_id")).bind(region_id).bind(voltage_id)
        .bind(f.from_substation_id).bind(f.to_substation_id).bind(opt_dec(&form, "line_length_km"))
        .bind(opt_str(&form, "conductor_type")).bind(opt_dec(&form, "conductor_size_mm2")).bind(opt_i32(&form, "number_of_circuits"))
        .bind(opt_str(&form, "earth_wire_type")).bind(opt_dec(&form, "rated_current_a")).bind(opt_dec(&form, "max_sag_m"))
        .bind(&f.state).bind(opt_date(&form, "commissioning_date")).bind(opt_i32(&form, "design_life_years")).bind(&f.ownership)
        .bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "tline insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/transmission-lines/{id}")).into_response()
}

async fn edit_tline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_lines");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, asset_id, region_id, voltage_level_id, from_substation_id, to_substation_id, line_length_km::text AS llk, conductor_type, conductor_size_mm2::text AS cs, number_of_circuits, earth_wire_type, rated_current_a::text AS rc, max_sag_m::text AS ms, state, commissioning_date::text AS cd, design_life_years, ownership, notes, active FROM eam_transmission_line WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let gs = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let gi = |k: &str| -> String { row.try_get::<Option<i32>, _>(k).ok().flatten().map(|v| v.to_string()).unwrap_or_default() };
    let code: String = row.try_get::<Option<String>, _>("code").ok().flatten().unwrap_or_default();
    let f = TLineForm {
        name: row.get("name"), asset_id: gs("asset_id"), region_id: row.try_get("region_id").ok(), voltage_level_id: row.try_get("voltage_level_id").ok(),
        from_substation_id: row.try_get("from_substation_id").ok(), to_substation_id: row.try_get("to_substation_id").ok(), line_length_km: gs("llk"),
        conductor_type: gs("conductor_type"), conductor_size_mm2: gs("cs"), number_of_circuits: gi("number_of_circuits"), earth_wire_type: gs("earth_wire_type"),
        rated_current_a: gs("rc"), max_sag_m: gs("ms"), state: row.get("state"), commissioning_date: gs("cd"),
        design_life_years: gi("design_life_years"), ownership: row.get("ownership"), notes: gs("notes"), active: row.try_get("active").unwrap_or(true),
    };
    let body = tline_body(&db, &f, false).await;

    let towers = vortex_plugin_sdk::sqlx::query("SELECT id, code, tower_number, tower_type, condition_status FROM eam_transmission_tower WHERE transmission_line_id=$1 ORDER BY tower_number").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut twr_html = String::new();
    for r in &towers {
        let tid: Uuid = r.get("id");
        let tnum: i32 = r.try_get("tower_number").unwrap_or(0);
        let ttype: String = r.get("tower_type");
        let tcode: Option<String> = r.try_get("code").ok();
        twr_html.push_str(&format!(r#"<tr class="hover cursor-pointer" onclick="window.location='/sesb-eam/towers/{tid}'"><td class="font-mono">{tcode}</td><td>T{tnum}</td><td>{ttype}</td></tr>"#,
            tid = tid, tcode = esc(tcode.as_deref().unwrap_or("—")), tnum = tnum, ttype = esc(&ttype)));
    }
    if twr_html.is_empty() { twr_html.push_str(r#"<tr><td colspan="3" class="text-base-content/50">No towers</td></tr>"#); }

    let header = form_header("/sesb-eam/transmission-lines", "Back to Transmission Lines", &format!("{} · {}", f.name, code));
    let content = format!(
        r#"{form}<div class="max-w-4xl mt-6"><div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex items-center justify-between mb-2"><h2 class="card-title text-lg">Towers</h2>
<a href="/sesb-eam/towers/new?line={id}" class="btn btn-primary btn-sm">New Tower</a></div>
<table class="table table-sm"><thead><tr><th>Code</th><th>No</th><th>Type</th></tr></thead><tbody>{twr}</tbody></table></div></div></div>"#,
        form = wide_form_page(&format!("/sesb-eam/transmission-lines/{id}"), &header, &body), id = id, twr = twr_html);
    Html(page_shell(&sidebar, &format!("Line {}", f.name), &content)).into_response()
}

async fn update_tline(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = TLineForm::from_map(&form);
    let region_id = match f.region_id { Some(r) => r, None => return bad("Region is required") };
    let voltage_id = match f.voltage_level_id { Some(v) => v, None => return bad("Voltage level is required") };
    if f.name.trim().is_empty() { return bad("Name is required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_transmission_line SET name=$1, asset_id=$2, region_id=$3, voltage_level_id=$4, from_substation_id=$5, to_substation_id=$6, line_length_km=$7, conductor_type=$8, conductor_size_mm2=$9, number_of_circuits=$10, earth_wire_type=$11, rated_current_a=$12, max_sag_m=$13, state=$14, commissioning_date=$15, design_life_years=$16, ownership=$17, notes=$18, active=$19 WHERE id=$20")
        .bind(&f.name).bind(opt_str(&form, "asset_id")).bind(region_id).bind(voltage_id).bind(f.from_substation_id).bind(f.to_substation_id)
        .bind(opt_dec(&form, "line_length_km")).bind(opt_str(&form, "conductor_type")).bind(opt_dec(&form, "conductor_size_mm2")).bind(opt_i32(&form, "number_of_circuits"))
        .bind(opt_str(&form, "earth_wire_type")).bind(opt_dec(&form, "rated_current_a")).bind(opt_dec(&form, "max_sag_m")).bind(&f.state)
        .bind(opt_date(&form, "commissioning_date")).bind(opt_i32(&form, "design_life_years")).bind(&f.ownership).bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/transmission-lines/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Tower (full form with conductor/insulator/accessory/wayleave blocks)
// ═════════════════════════════════════════════════════════════════════════

const TOWER_TYPES: &[(&str, &str)] = &[("lattice_steel","Lattice Steel"),("tubular_steel","Tubular Steel"),("wood_pole","Wood Pole"),("concrete_pole","Concrete Pole"),("monopole","Monopole"),("h_frame","H-Frame")];
const TOWER_FUNCS: &[(&str, &str)] = &[("","—"),("suspension","Suspension"),("tension","Tension"),("angle","Angle"),("dead_end","Dead End"),("transposition","Transposition"),("junction","Junction")];
const INS_TYPES: &[(&str, &str)] = &[("","—"),("glass","Glass"),("porcelain","Porcelain"),("composite","Composite")];
const TTI: &[(&str, &str)] = &[("","—"),("tca","TCA (Critical)"),("tnca","TNCA (Non-Critical)")];
const ARR: &[(&str, &str)] = &[("","—"),("single","Single"),("double","Double")];
const YN: &[(&str, &str)] = &[("","—"),("yes","Yes"),("no","No"),("na","N/A")];
const CONDITIONS: &[(&str, &str)] = &[("excellent","Excellent"),("good","Good"),("fair","Fair"),("poor","Poor"),("critical","Critical")];
const OPSTAT: &[(&str, &str)] = &[("operational","Operational"),("standby","Standby"),("out_of_service","Out of Service"),("under_repair","Under Repair"),("decommissioned","Decommissioned")];

async fn line_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_transmission_line WHERE active ORDER BY code", "-- Transmission Line --", sel).await
}

async fn new_tower(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_lines");
    let line_pre = q.get("line").and_then(|s| s.parse::<Uuid>().ok());
    let back = line_pre.map(|l| format!("/sesb-eam/transmission-lines/{l}")).unwrap_or_else(|| "/sesb-eam/transmission-lines".into());
    let header = form_header(&back, "Back", "New Tower");
    let body = tower_form_body(&db, &HashMap::new(), line_pre, true).await;
    Html(page_shell(&sidebar, "New Tower", &wide_form_page("/sesb-eam/towers/create", &header, &body))).into_response()
}

/// Tower form body. Values come straight from a map (form repost or DB row
/// loaded into a map) keyed by column name.
async fn tower_form_body(db: &PgPool, v: &HashMap<String, String>, line_preselect: Option<Uuid>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let line_sel = v.get("transmission_line_id").and_then(|s| s.parse::<Uuid>().ok()).or(line_preselect);
    let lines = line_opts(db, line_sel).await;
    let volts = voltage_options(db, v.get("voltage_level_id").and_then(|s| s.parse().ok())).await;
    let atypes = asset_type_options(db, v.get("asset_type_id").and_then(|s| s.parse().ok())).await;
    let ident = grid3(&format!("{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), true),
        select_field("Transmission Line *", "transmission_line_id", &lines),
        num_field("Tower Number", "tower_number", g("tower_number"), "1"),
        text_field("MNEC Asset ID", "asset_id", g("asset_id"), false),
        select_field("Asset Type", "asset_type_id", &atypes),
        select_field("Voltage Level", "voltage_level_id", &volts),
    ));
    let phys = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}{}",
        select_field("Tower Type *", "tower_type", &enum_options(TOWER_TYPES, g("tower_type"))),
        select_field("Tower Function", "tower_function", &enum_options(TOWER_FUNCS, g("tower_function"))),
        num_field("Height (m)", "height_m", g("height_m"), "0.01"),
        num_field("Base Width (m)", "base_width_m", g("base_width_m"), "0.01"),
        num_field("Weight (kg)", "weight_kg", g("weight_kg"), "0.01"),
        text_field("Foundation Type", "foundation_type", g("foundation_type"), false),
        num_field("GPS Latitude", "gps_latitude", g("gps_latitude"), "0.0000001"),
        num_field("GPS Longitude", "gps_longitude", g("gps_longitude"), "0.0000001"),
        num_field("Elevation (m)", "elevation_m", g("elevation_m"), "0.01"),
        num_field("Ground Clearance (m)", "ground_clearance_m", g("ground_clearance_m"), "0.01"),
        num_field("Right of Way (m)", "right_of_way_m", g("right_of_way_m"), "0.01"),
        select_field("TTI Criticality", "tti_criticality", &enum_options(TTI, g("tti_criticality"))),
    ));
    let cond = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Tower Span (e.g. T1-T2)", "tower_span", g("tower_span"), false),
        num_field("Span Length (m)", "tower_span_length_m", g("tower_span_length_m"), "0.01"),
        text_field("Phasing Top", "phasing_top", g("phasing_top"), false),
        text_field("Phasing Middle", "phasing_middle", g("phasing_middle"), false),
        text_field("Phasing Bottom", "phasing_bottom", g("phasing_bottom"), false),
        text_field("Conductor Type", "conductor_type", g("conductor_type"), false),
        num_field("Conductor Size (mm²)", "conductor_size_mm2", g("conductor_size_mm2"), "0.01"),
        num_field("Conductor Rating @80°C (A)", "conductor_current_rating_a", g("conductor_current_rating_a"), "0.01"),
        select_field("Conductor Arrangement", "conductor_arrangement", &enum_options(ARR, g("conductor_arrangement"))),
        num_field("Conductor Year", "conductor_year", g("conductor_year"), "1"),
        text_field("Conductor Brand", "conductor_brand", g("conductor_brand"), false),
        text_field("Conductor Serial No", "conductor_serial_no", g("conductor_serial_no"), false),
    ));
    let insb = grid3(&format!("{}{}{}{}{}{}{}",
        select_field("Insulator Type", "insulator_type", &enum_options(INS_TYPES, g("insulator_type"))),
        num_field("Insulator Count", "insulator_count", g("insulator_count"), "1"),
        num_field("Discs per String", "insulator_disc_per_string", g("insulator_disc_per_string"), "1"),
        num_field("Insulator Year", "insulator_year", g("insulator_year"), "1"),
        text_field("Insulator Brand", "insulator_brand", g("insulator_brand"), false),
        text_field("Insulator Make", "insulator_make", g("insulator_make"), false),
        text_field("Insulator Serial No", "insulator_serial_no", g("insulator_serial_no"), false),
    ));
    let acc = grid3(&format!("{}{}{}{}{}{}",
        checkbox("accessory_awl", "Aircraft Warning Light (AWL)", g("accessory_awl") == "true"),
        checkbox("accessory_acws", "Aircraft Warning Sphere (ACWS)", g("accessory_acws") == "true"),
        checkbox("accessory_acd", "Anti-Climbing Device (ACD)", g("accessory_acd") == "true"),
        num_field("Accessory Year", "accessory_year", g("accessory_year"), "1"),
        text_field("Accessory Brand", "accessory_brand", g("accessory_brand"), false),
        text_field("Accessory Serial No", "accessory_serial_no", g("accessory_serial_no"), false),
    ));
    let way = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}",
        select_field("Span Rata (flat)", "span_rata", &enum_options(YN, g("span_rata"))),
        select_field("Span Bukit (hill)", "span_bukit", &enum_options(YN, g("span_bukit"))),
        select_field("Span Gaung (ravine)", "span_gaung", &enum_options(YN, g("span_gaung"))),
        text_field("Road Crossing", "road_crossing", g("road_crossing"), false),
        text_field("River Crossing", "river_crossing", g("river_crossing"), false),
        text_field("Locality", "locality", g("locality"), false),
        text_field("Landowner", "landowner", g("landowner"), false),
        text_field("Land Activity", "activity", g("activity"), false),
        select_field("Danger Tree", "danger_tree", &enum_options(YN, g("danger_tree"))),
        text_field("Occupational Permit (OP)", "occupational_permit", g("occupational_permit"), false),
        select_field("Safety Signage", "safety_signage", &enum_options(YN, g("safety_signage"))),
    ));
    let status = grid3(&format!("{}{}{}{}",
        select_field("Operational Status", "operational_status", &enum_options(OPSTAT, if g("operational_status").is_empty() { "operational" } else { g("operational_status") })),
        select_field("Condition", "condition_status", &enum_options(CONDITIONS, if g("condition_status").is_empty() { "good" } else { g("condition_status") })),
        date_field("Last Inspection", "last_inspection_date", g("last_inspection_date")),
        date_field("Next Inspection", "next_inspection_date", g("next_inspection_date")),
    ));
    let sec = |t: &str| format!(r#"<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">{}</h2>"#, t);
    format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
        sec("Identification"), ident, sec("Physical & Location"), phys, sec("Conductor Block"), cond,
        sec("Insulator Detail"), insb, sec("Accessories"), acc, sec("Wayleave"), way, sec("Status"), status,
        active_field(g("active") == "true" || is_new, is_new))
}

fn checkbox(name: &str, label: &str, checked: bool) -> String {
    format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="{name}" class="checkbox checkbox-sm" {c}/><span class="label-text">{label}</span></label></div>"#,
        name = name, label = label, c = if checked { "checked" } else { "" })
}

// Columns persisted for a tower (besides id/code/line/timestamps).
const TOWER_TEXT_COLS: &[&str] = &["name","asset_id","foundation_type","phase_configuration","tower_span","phasing_top","phasing_middle","phasing_bottom","conductor_type","conductor_brand","conductor_make","conductor_serial_no","insulator_brand","insulator_make","insulator_serial_no","accessory_brand","accessory_make","accessory_serial_no","road_crossing","river_crossing","locality","landowner","activity","occupational_permit","tower_type","tower_function","insulator_type","tti_criticality","conductor_arrangement","span_rata","span_bukit","span_gaung","danger_tree","safety_signage","operational_status","condition_status"];
const TOWER_NUM_COLS: &[&str] = &["height_m","base_width_m","weight_kg","span_to_next_m","span_to_previous_m","gps_latitude","gps_longitude","elevation_m","ground_clearance_m","right_of_way_m","tower_span_length_m","distance_from_pmu1_m","distance_from_pmu2_m","conductor_size_mm2","conductor_current_rating_a"];
const TOWER_INT_COLS: &[&str] = &["tower_number","insulator_count","conductor_year","insulator_disc_per_string","insulator_year","accessory_year"];
const TOWER_DATE_COLS: &[&str] = &["last_inspection_date","next_inspection_date"];
const TOWER_BOOL_COLS: &[&str] = &["earth_wire_attached","aviation_marking","accessory_awl","accessory_acws","accessory_acd"];

async fn create_tower(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let line_id = match opt_uuid(&form, "transmission_line_id") { Some(l) => l, None => return bad("Transmission line is required") };
    if form.get("name").map(|s| s.trim().is_empty()).unwrap_or(true) { return bad("Name is required"); }
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &TWR_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    // Auto-compose asset_id if absent: "{line.asset_id}-T{nnn}" (§4.9)
    let asset_id = match opt_str(&form, "asset_id") {
        Some(a) => Some(a.clone()),
        None => {
            let line_asset: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT asset_id FROM eam_transmission_line WHERE id=$1").bind(line_id).fetch_optional(&db).await.ok().flatten();
            line_asset.filter(|s| !s.is_empty()).map(|la| format!("{la}-T{:03}", opt_i32(&form, "tower_number").unwrap_or(0)))
        }
    };
    if let Err(e) = insert_tower_dynamic(&db, id, &code, line_id, asset_id.as_deref(), company_id, &form).await {
        error!(error=%e, "tower insert"); return bad(&format!("Failed: {e}"));
    }
    Redirect::to(&format!("/sesb-eam/towers/{id}")).into_response()
}

/// Build the tower INSERT dynamically from the column catalogues; values
/// cast in SQL, mirroring the spec-form approach.
async fn insert_tower_dynamic(db: &PgPool, id: Uuid, code: &str, line_id: Uuid, asset_id: Option<&str>, company_id: Option<Uuid>, form: &HashMap<String, String>) -> Result<(), vortex_plugin_sdk::sqlx::Error> {
    let mut cols = vec!["id".to_string(), "code".into(), "transmission_line_id".into(), "asset_id".into(), "company_id".into(), "hierarchy_level".into()];
    let mut ph = vec!["$1".to_string(), "$2".into(), "$3".into(), "$4".into(), "$5".into(), "2".into()];
    let mut binds: Vec<Option<String>> = Vec::new();
    let mut n = 6;
    let mut push = |col: &str, val: Option<String>, cast: &str| {
        cols.push(col.to_string());
        ph.push(format!("${n}{cast}", n = n, cast = cast));
        binds.push(val);
        n += 1;
    };
    for c in TOWER_TEXT_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), ""); }
    for c in TOWER_NUM_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), "::numeric"); }
    for c in TOWER_INT_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), "::int"); }
    for c in TOWER_DATE_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), "::date"); }
    for c in TOWER_BOOL_COLS { push(c, Some(if form.contains_key(*c) { "true".into() } else { "false".into() }), "::boolean"); }
    let sql = format!("INSERT INTO eam_transmission_tower ({}) VALUES ({})", cols.join(", "), ph.join(", "));
    let mut q = vortex_plugin_sdk::sqlx::query(&sql).bind(id).bind(code).bind(line_id).bind(asset_id).bind(company_id);
    for b in binds { q = q.bind(b); }
    q.execute(db).await.map(|_| ())
}

async fn update_tower_dynamic(db: &PgPool, id: Uuid, form: &HashMap<String, String>) -> Result<(), vortex_plugin_sdk::sqlx::Error> {
    let mut sets: Vec<String> = Vec::new();
    let mut binds: Vec<Option<String>> = Vec::new();
    let mut n = 1;
    if let Some(l) = opt_uuid(form, "transmission_line_id") { sets.push(format!("transmission_line_id = ${n}::uuid")); binds.push(Some(l.to_string())); n += 1; }
    let mut push = |col: &str, val: Option<String>, cast: &str| { sets.push(format!("{col} = ${n}{cast}", col = col, n = n, cast = cast)); binds.push(val); n += 1; };
    for c in TOWER_TEXT_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), ""); }
    for c in TOWER_NUM_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), "::numeric"); }
    for c in TOWER_INT_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), "::int"); }
    for c in TOWER_DATE_COLS { push(c, form.get(*c).filter(|s| !s.trim().is_empty()).cloned(), "::date"); }
    for c in TOWER_BOOL_COLS { push(c, Some(if form.contains_key(*c) { "true".into() } else { "false".into() }), "::boolean"); }
    push("active", Some(if form.contains_key("active") { "true".into() } else { "false".into() }), "::boolean");
    let sql = format!("UPDATE eam_transmission_tower SET {} WHERE id = ${n}::uuid", sets.join(", "));
    let mut q = vortex_plugin_sdk::sqlx::query(&sql);
    for b in binds { q = q.bind(b); }
    q = q.bind(id.to_string());
    q.execute(db).await.map(|_| ())
}

async fn edit_tower(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_lines");
    // Load row into a name→string map (text-cast everything).
    let mut cols: Vec<String> = vec!["transmission_line_id::text AS transmission_line_id".into(), "voltage_level_id::text AS voltage_level_id".into(), "asset_type_id::text AS asset_type_id".into(), "code".into(), "active::text AS active".into()];
    for c in TOWER_TEXT_COLS { cols.push(c.to_string()); }
    for c in TOWER_NUM_COLS { cols.push(format!("{c}::text AS {c}", c = c)); }
    for c in TOWER_INT_COLS { cols.push(format!("{c}::text AS {c}", c = c)); }
    for c in TOWER_DATE_COLS { cols.push(format!("{c}::text AS {c}", c = c)); }
    for c in TOWER_BOOL_COLS { cols.push(format!("{c}::text AS {c}", c = c)); }
    let sql = format!("SELECT {} FROM eam_transmission_tower WHERE id=$1", cols.join(", "));
    let row = match vortex_plugin_sdk::sqlx::query(&sql).bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for key in ["transmission_line_id","voltage_level_id","asset_type_id","active"].iter()
        .chain(TOWER_TEXT_COLS).chain(TOWER_NUM_COLS).chain(TOWER_INT_COLS).chain(TOWER_DATE_COLS).chain(TOWER_BOOL_COLS) {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(*key) { v.insert(key.to_string(), val); }
    }
    let code: Option<String> = row.try_get("code").ok();
    let name = v.get("name").cloned().unwrap_or_default();
    let body = tower_form_body(&db, &v, None, false).await;
    let back = v.get("transmission_line_id").map(|l| format!("/sesb-eam/transmission-lines/{l}")).unwrap_or_else(|| "/sesb-eam/transmission-lines".into());
    let header = form_header(&back, "Back to Line", &format!("{} · {}", name, code.unwrap_or_default()));
    let _ = user;
    Html(page_shell(&sidebar, &format!("Tower {}", name), &wide_form_page(&format!("/sesb-eam/towers/{id}"), &header, &body))).into_response()
}

async fn update_tower(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(e) = update_tower_dynamic(&db, id, &form).await { error!(error=%e, "tower update"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/towers/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Span (created inline from a line — between two of its towers)
// ═════════════════════════════════════════════════════════════════════════

async fn create_span(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let line_id = match opt_uuid(&form, "transmission_line_id") { Some(l) => l, None => return bad("Line required") };
    let from = match opt_uuid(&form, "from_tower_id") { Some(t) => t, None => return bad("From tower required") };
    let to = match opt_uuid(&form, "to_tower_id") { Some(t) => t, None => return bad("To tower required") };
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &SPN_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_transmission_span (id, code, name, transmission_line_id, from_tower_id, to_tower_id, from_tower_number, to_tower_number, length_m, company_id) \
         SELECT $1,$2, ('Span ' || ft.tower_number || '-' || tt.tower_number), $3, $4, $5, ft.tower_number, tt.tower_number, $6, $7 \
         FROM eam_transmission_tower ft, eam_transmission_tower tt WHERE ft.id=$4 AND tt.id=$5")
        .bind(Uuid::now_v7()).bind(&code).bind(line_id).bind(from).bind(to).bind(opt_dec(&form, "length_m")).bind(company_id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/transmission-lines/{line_id}")).into_response()
}

async fn delete_span(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let line: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT transmission_line_id FROM eam_transmission_span WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM eam_transmission_span WHERE id=$1").bind(id).execute(&db).await;
    Redirect::to(&line.map(|l| format!("/sesb-eam/transmission-lines/{l}")).unwrap_or_else(|| "/sesb-eam/transmission-lines".into())).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Gantry (bay ↔ line handshake)
// ═════════════════════════════════════════════════════════════════════════

const GANTRY_TYPES: &[(&str, &str)] = &[("","—"),("strain","Strain"),("dead_end","Dead End"),("portal","Portal"),("pole","Pole")];

async fn bay_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT b.id, (s.code || ' / ' || b.code) AS label FROM eam_bay b JOIN eam_substation s ON s.id=b.substation_id WHERE b.active ORDER BY s.code, b.code", "-- Bay --", sel).await
}

async fn new_gantry(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_lines");
    let bays = bay_opts(&db, None).await;
    let lines = line_opts(&db, None).await;
    let body = grid3(&format!("{}{}{}{}{}{}{}",
        text_field("Name", "name", "", true),
        select_field("Bay *", "bay_id", &bays),
        select_field("Transmission Line *", "transmission_line_id", &lines),
        select_field("Gantry Type", "gantry_type", &enum_options(GANTRY_TYPES, "")),
        num_field("Height (m)", "height_m", "", "0.01"),
        num_field("GPS Latitude", "gps_latitude", "", "0.0000001"),
        num_field("GPS Longitude", "gps_longitude", "", "0.0000001"),
    ));
    let header = form_header("/sesb-eam/transmission-lines", "Back", "New Gantry");
    Html(page_shell(&sidebar, "New Gantry", &wide_form_page("/sesb-eam/gantries/create", &header, &body))).into_response()
}

async fn create_gantry(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let bay_id = match opt_uuid(&form, "bay_id") { Some(b) => b, None => return bad("Bay required") };
    let line_id = match opt_uuid(&form, "transmission_line_id") { Some(l) => l, None => return bad("Line required") };
    if form.get("name").map(|s| s.trim().is_empty()).unwrap_or(true) { return bad("Name required"); }
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &GTR_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_gantry (id, name, code, bay_id, transmission_line_id, substation_id, gantry_type, height_m, gps_latitude, gps_longitude, company_id) \
         VALUES ($1,$2,$3,$4,$5,(SELECT substation_id FROM eam_bay WHERE id=$4),$6,$7,$8,$9,$10)")
        .bind(Uuid::now_v7()).bind(form.get("name")).bind(&code).bind(bay_id).bind(line_id)
        .bind(opt_str(&form, "gantry_type")).bind(opt_dec(&form, "height_m")).bind(opt_dec(&form, "gps_latitude")).bind(opt_dec(&form, "gps_longitude")).bind(company_id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/transmission-lines/{line_id}")).into_response()
}

async fn update_gantry(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_gantry SET name=$1, gantry_type=$2, height_m=$3 WHERE id=$4")
        .bind(form.get("name")).bind(opt_str(&form, "gantry_type")).bind(opt_dec(&form, "height_m")).bind(id).execute(&db).await;
    Redirect::to("/sesb-eam/transmission-lines").into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Distribution line
// ═════════════════════════════════════════════════════════════════════════

const DL_TYPES: &[(&str, &str)] = &[("overhead","Overhead"),("underground","Underground"),("mixed","Mixed")];
const DL_COND: &[(&str, &str)] = &[("","—"),("aac","AAC"),("aaac","AAAC"),("acsr","ACSR"),("abc","ABC"),("covered","Covered")];
const DL_STATES: &[(&str, &str)] = &[("planning","Planning"),("construction","Construction"),("operational","Operational"),("out_of_service","Out of Service"),("decommissioned","Decommissioned")];

async fn list_dline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.distribution_lines");
    let config = ListConfig::new("Distribution Lines", "eam_distribution_line")
        .custom_from("eam_distribution_line d LEFT JOIN eam_region r ON r.id=d.region_id")
        .custom_select("d.id, d.code, d.name, d.line_type, r.name AS region_name, d.route_length_km::text AS len, d.state, d.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("d.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("d.name"))
        .column(ListColumn::new("line_type", "Type").filterable(&[("overhead","Overhead"),("underground","Underground"),("mixed","Mixed")]).sql_expr("d.line_type"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("len", "Length (km)").sql_expr("d.route_length_km"))
        .column(ListColumn::new("state", "State").badge(&[("operational","Operational","badge-success"),("construction","Construction","badge-info"),("planning","Planning","badge-ghost"),("out_of_service","Out of Service","badge-warning"),("decommissioned","Decommissioned","badge-ghost")]).sql_expr("d.state"))
        .detail_url("/sesb-eam/distribution-lines/{id}")
        .create("New Distribution Line", "/sesb-eam/distribution-lines/new")
        .default_sort("code");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "dline list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Distribution Lines", &render_list(&config, &result, &params, "/sesb-eam/distribution-lines"))).into_response()
}

async fn dline_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let regions = region_options(db, v.get("region_id").and_then(|s| s.parse().ok())).await;
    let volts = voltage_options(db, v.get("voltage_level_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), true),
        select_field("Region *", "region_id", &regions),
        select_field("Line Type *", "line_type", &enum_options(DL_TYPES, if g("line_type").is_empty() { "overhead" } else { g("line_type") })),
        select_field("Voltage Level", "voltage_level_id", &volts),
        num_field("Route Length (km)", "route_length_km", g("route_length_km"), "0.0001"),
        num_field("Number of Circuits", "number_of_circuits", g("number_of_circuits"), "1"),
        select_field("Conductor Type", "conductor_type", &enum_options(DL_COND, g("conductor_type"))),
        num_field("Conductor Size (mm²)", "conductor_size_mm2", g("conductor_size_mm2"), "0.01"),
        select_field("State", "state", &enum_options(DL_STATES, if g("state").is_empty() { "operational" } else { g("state") })),
    ));
    format!("{}{}{}", grid, textarea_field("Notes", "notes", g("notes")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_dline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.distribution_lines");
    let header = form_header("/sesb-eam/distribution-lines", "Back to Distribution Lines", "New Distribution Line");
    let body = dline_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Distribution Line", &wide_form_page("/sesb-eam/distribution-lines/create", &header, &body))).into_response()
}

async fn create_dline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    if form.get("name").map(|s| s.trim().is_empty()).unwrap_or(true) { return bad("Name is required"); }
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &DL_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_distribution_line (id, name, code, region_id, line_type, voltage_level_id, route_length_km, number_of_circuits, conductor_type, conductor_size_mm2, state, notes, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(id).bind(form.get("name")).bind(&code).bind(region_id)
        .bind(form.get("line_type").map(|s| s.as_str()).unwrap_or("overhead")).bind(opt_uuid(&form, "voltage_level_id"))
        .bind(opt_dec(&form, "route_length_km")).bind(opt_i32(&form, "number_of_circuits")).bind(opt_str(&form, "conductor_type"))
        .bind(opt_dec(&form, "conductor_size_mm2")).bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational")).bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "dline insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/distribution-lines/{id}")).into_response()
}

async fn edit_dline(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.distribution_lines");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, region_id::text AS region_id, line_type, voltage_level_id::text AS voltage_level_id, route_length_km::text AS route_length_km, number_of_circuits::text AS number_of_circuits, conductor_type, conductor_size_mm2::text AS conductor_size_mm2, state, notes, active::text AS active FROM eam_distribution_line WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["name","region_id","line_type","voltage_level_id","route_length_km","number_of_circuits","conductor_type","conductor_size_mm2","state","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let code: Option<String> = row.try_get("code").ok();
    let name = v.get("name").cloned().unwrap_or_default();
    let body = dline_body(&db, &v, false).await;

    let segs = vortex_plugin_sdk::sqlx::query("SELECT id, code, name, condition FROM eam_cable_segment WHERE distribution_line_id=$1 ORDER BY sequence, code").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut seg_html = String::new();
    for r in &segs {
        let sid: Uuid = r.get("id");
        let scode: String = r.get("code");
        let sname: String = r.get("name");
        seg_html.push_str(&format!(r#"<tr class="hover cursor-pointer" onclick="window.location='/sesb-eam/cable-segments/{sid}'"><td class="font-mono">{scode}</td><td>{sname}</td></tr>"#, sid = sid, scode = esc(&scode), sname = esc(&sname)));
    }
    if seg_html.is_empty() { seg_html.push_str(r#"<tr><td colspan="2" class="text-base-content/50">No cable segments</td></tr>"#); }

    let header = form_header("/sesb-eam/distribution-lines", "Back to Distribution Lines", &format!("{} · {}", name, code.unwrap_or_default()));
    let content = format!(
        r#"{form}<div class="max-w-4xl mt-6"><div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex items-center justify-between mb-2"><h2 class="card-title text-lg">Cable Segments</h2>
<a href="/sesb-eam/cable-segments/new?line={id}" class="btn btn-primary btn-sm">New Segment</a></div>
<table class="table table-sm"><thead><tr><th>Code</th><th>Name</th></tr></thead><tbody>{seg}</tbody></table></div></div></div>"#,
        form = wide_form_page(&format!("/sesb-eam/distribution-lines/{id}"), &header, &body), id = id, seg = seg_html);
    Html(page_shell(&sidebar, &format!("Distribution Line {}", name), &content)).into_response()
}

async fn update_dline(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_distribution_line SET name=$1, region_id=$2, line_type=$3, voltage_level_id=$4, route_length_km=$5, number_of_circuits=$6, conductor_type=$7, conductor_size_mm2=$8, state=$9, notes=$10, active=$11 WHERE id=$12")
        .bind(form.get("name")).bind(region_id).bind(form.get("line_type").map(|s| s.as_str()).unwrap_or("overhead")).bind(opt_uuid(&form, "voltage_level_id"))
        .bind(opt_dec(&form, "route_length_km")).bind(opt_i32(&form, "number_of_circuits")).bind(opt_str(&form, "conductor_type")).bind(opt_dec(&form, "conductor_size_mm2"))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational")).bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/distribution-lines/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// UGC line
// ═════════════════════════════════════════════════════════════════════════

async fn list_ugc(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.ugc_lines");
    let config = ListConfig::new("UGC Lines", "eam_ugc_line")
        .custom_from("eam_ugc_line u LEFT JOIN eam_region r ON r.id=u.region_id LEFT JOIN eam_voltage_level v ON v.id=u.voltage_level_id")
        .custom_select("u.id, u.code, u.name, u.asset_id, r.name AS region_name, v.name AS voltage, u.distance_km::text AS dist, u.state, u.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("u.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("u.name"))
        .column(ListColumn::new("asset_id", "MNEC Asset ID").searchable().sql_expr("u.asset_id"))
        .column(ListColumn::new("region_name", "Region").sql_expr("r.name"))
        .column(ListColumn::new("voltage", "Voltage").sql_expr("v.name"))
        .column(ListColumn::new("dist", "Distance (km)").sql_expr("u.distance_km"))
        .column(ListColumn::new("state", "State").badge(&[("operational","Operational","badge-success"),("maintenance","Maintenance","badge-warning"),("construction","Construction","badge-info"),("planning","Planning","badge-ghost"),("decommissioned","Decommissioned","badge-ghost")]).sql_expr("u.state"))
        .detail_url("/sesb-eam/ugc-lines/{id}")
        .create("New UGC Line", "/sesb-eam/ugc-lines/new")
        .default_sort("code");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "ugc list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "UGC Lines", &render_list(&config, &result, &params, "/sesb-eam/ugc-lines"))).into_response()
}

async fn ugc_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let regions = region_options(db, v.get("region_id").and_then(|s| s.parse().ok())).await;
    let volts = voltage_options(db, v.get("voltage_level_id").and_then(|s| s.parse().ok())).await;
    let froms = substation_opts(db, v.get("from_substation_id").and_then(|s| s.parse().ok())).await;
    let tos = substation_opts(db, v.get("to_substation_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), true),
        text_field("MNEC Asset ID", "asset_id", g("asset_id"), false),
        select_field("Region *", "region_id", &regions),
        select_field("Voltage Level *", "voltage_level_id", &volts),
        select_field("From Substation", "from_substation_id", &froms),
        select_field("To Substation", "to_substation_id", &tos),
        num_field("Number of Circuits", "number_of_circuits", g("number_of_circuits"), "1"),
        num_field("MVA Rating (per circuit)", "mva_rating", g("mva_rating"), "0.0001"),
        num_field("Total MVA", "total_mva", g("total_mva"), "0.0001"),
        num_field("Distance (km)", "distance_km", g("distance_km"), "0.0001"),
        num_field("Length CCT-km 66kV", "length_cct_km_66", g("length_cct_km_66"), "0.0001"),
        num_field("Length CCT-km 132kV", "length_cct_km_132", g("length_cct_km_132"), "0.0001"),
    ));
    let g2 = grid3(&format!("{}{}{}{}",
        date_field("Commissioning Date", "commissioning_date", g("commissioning_date")),
        num_field("Design Life (years)", "design_life_years", if g("design_life_years").is_empty() { "40" } else { g("design_life_years") }, "1"),
        select_field("State", "state", &enum_options(LINE_STATES, if g("state").is_empty() { "operational" } else { g("state") })),
        select_field("Ownership", "ownership", &enum_options(OWNERSHIPS, if g("ownership").is_empty() { "sesb" } else { g("ownership") })),
    ));
    format!("{}{}{}{}", grid, g2, textarea_field("Notes", "notes", g("notes")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_ugc(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.ugc_lines");
    let header = form_header("/sesb-eam/ugc-lines", "Back to UGC Lines", "New UGC Line");
    let body = ugc_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New UGC Line", &wide_form_page("/sesb-eam/ugc-lines/create", &header, &body))).into_response()
}

async fn create_ugc(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    let voltage_id = match opt_uuid(&form, "voltage_level_id") { Some(v) => v, None => return bad("Voltage level is required") };
    if form.get("name").map(|s| s.trim().is_empty()).unwrap_or(true) { return bad("Name is required"); }
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &UGC_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_ugc_line (id, name, code, asset_id, hierarchy_level, region_id, voltage_level_id, from_substation_id, to_substation_id, number_of_circuits, mva_rating, total_mva, distance_km, length_cct_km_66, length_cct_km_132, commissioning_date, design_life_years, state, ownership, notes, company_id) \
         VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)")
        .bind(id).bind(form.get("name")).bind(&code).bind(opt_str(&form, "asset_id")).bind(region_id).bind(voltage_id)
        .bind(opt_uuid(&form, "from_substation_id")).bind(opt_uuid(&form, "to_substation_id")).bind(opt_i32(&form, "number_of_circuits"))
        .bind(opt_dec(&form, "mva_rating")).bind(opt_dec(&form, "total_mva")).bind(opt_dec(&form, "distance_km"))
        .bind(opt_dec(&form, "length_cct_km_66")).bind(opt_dec(&form, "length_cct_km_132")).bind(opt_date(&form, "commissioning_date"))
        .bind(opt_i32(&form, "design_life_years").unwrap_or(40)).bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
        .bind(form.get("ownership").map(|s| s.as_str()).unwrap_or("sesb")).bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "ugc insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/ugc-lines/{id}")).into_response()
}

async fn edit_ugc(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.ugc_lines");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, asset_id, region_id::text AS region_id, voltage_level_id::text AS voltage_level_id, from_substation_id::text AS from_substation_id, to_substation_id::text AS to_substation_id, number_of_circuits::text AS number_of_circuits, mva_rating::text AS mva_rating, total_mva::text AS total_mva, distance_km::text AS distance_km, length_cct_km_66::text AS length_cct_km_66, length_cct_km_132::text AS length_cct_km_132, commissioning_date::text AS commissioning_date, design_life_years::text AS design_life_years, state, ownership, notes, active::text AS active FROM eam_ugc_line WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["name","asset_id","region_id","voltage_level_id","from_substation_id","to_substation_id","number_of_circuits","mva_rating","total_mva","distance_km","length_cct_km_66","length_cct_km_132","commissioning_date","design_life_years","state","ownership","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let code: Option<String> = row.try_get("code").ok();
    let name = v.get("name").cloned().unwrap_or_default();
    let body = ugc_body(&db, &v, false).await;
    let header = form_header("/sesb-eam/ugc-lines", "Back to UGC Lines", &format!("{} · {}", name, code.unwrap_or_default()));
    Html(page_shell(&sidebar, &format!("UGC Line {}", name), &wide_form_page(&format!("/sesb-eam/ugc-lines/{id}"), &header, &body))).into_response()
}

async fn update_ugc(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let region_id = match opt_uuid(&form, "region_id") { Some(r) => r, None => return bad("Region is required") };
    let voltage_id = match opt_uuid(&form, "voltage_level_id") { Some(v) => v, None => return bad("Voltage level is required") };
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_ugc_line SET name=$1, asset_id=$2, region_id=$3, voltage_level_id=$4, from_substation_id=$5, to_substation_id=$6, number_of_circuits=$7, mva_rating=$8, total_mva=$9, distance_km=$10, length_cct_km_66=$11, length_cct_km_132=$12, commissioning_date=$13, design_life_years=$14, state=$15, ownership=$16, notes=$17, active=$18 WHERE id=$19")
        .bind(form.get("name")).bind(opt_str(&form, "asset_id")).bind(region_id).bind(voltage_id)
        .bind(opt_uuid(&form, "from_substation_id")).bind(opt_uuid(&form, "to_substation_id")).bind(opt_i32(&form, "number_of_circuits"))
        .bind(opt_dec(&form, "mva_rating")).bind(opt_dec(&form, "total_mva")).bind(opt_dec(&form, "distance_km"))
        .bind(opt_dec(&form, "length_cct_km_66")).bind(opt_dec(&form, "length_cct_km_132")).bind(opt_date(&form, "commissioning_date"))
        .bind(opt_i32(&form, "design_life_years").unwrap_or(40)).bind(form.get("state").map(|s| s.as_str()).unwrap_or("operational"))
        .bind(form.get("ownership").map(|s| s.as_str()).unwrap_or("sesb")).bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/ugc-lines/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Cable segment + IR/PI test
// ═════════════════════════════════════════════════════════════════════════

const CSEG_CABLE: &[(&str, &str)] = &[("","—"),("xlpe","XLPE"),("pilc","PILC"),("epr","EPR"),("other","Other")];
const CSEG_LAY: &[(&str, &str)] = &[("","—"),("direct_buried","Direct Buried"),("duct","Duct"),("tray","Tray"),("trench","Trench"),("submarine","Submarine")];
const CSEG_COND: &[(&str, &str)] = &[("","—"),("good","Good"),("medium","Medium"),("poor","Poor"),("very_poor","Very Poor")];
const CTEST_TYPES: &[(&str, &str)] = &[("ir","IR"),("hipot","HiPot"),("vlf","VLF"),("tandelta","Tan Delta"),("pd","PD")];

async fn dline_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_distribution_line WHERE active ORDER BY code", "-- Distribution Line --", sel).await
}

async fn cseg_body(db: &PgPool, v: &HashMap<String, String>, line_pre: Option<Uuid>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let lines = dline_opts(db, v.get("distribution_line_id").and_then(|s| s.parse().ok()).or(line_pre)).await;
    let volts = voltage_options(db, v.get("voltage_level_id").and_then(|s| s.parse().ok())).await;
    let starts = substation_opts(db, v.get("start_substation_id").and_then(|s| s.parse().ok())).await;
    let ends = substation_opts(db, v.get("end_substation_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), true),
        text_field("Code", "code", g("code"), true),
        num_field("Sequence", "sequence", g("sequence"), "1"),
        select_field("Distribution Line *", "distribution_line_id", &lines),
        select_field("Voltage Level", "voltage_level_id", &volts),
        select_field("Start Substation", "start_substation_id", &starts),
        select_field("End Substation", "end_substation_id", &ends),
        num_field("Start Chainage (m)", "start_chainage_m", g("start_chainage_m"), "0.01"),
        num_field("End Chainage (m)", "end_chainage_m", g("end_chainage_m"), "0.01"),
        select_field("Cable Type", "cable_type", &enum_options(CSEG_CABLE, g("cable_type"))),
        text_field("Conductor Size", "conductor_size", g("conductor_size"), false),
        select_field("Laying Method", "laying_method", &enum_options(CSEG_LAY, g("laying_method"))),
        select_field("Condition", "condition", &enum_options(CSEG_COND, g("condition"))),
    ));
    format!("{}{}{}", grid, textarea_field("Notes", "notes", g("notes")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_cseg(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.distribution_lines");
    let line_pre = q.get("line").and_then(|s| s.parse::<Uuid>().ok());
    let back = line_pre.map(|l| format!("/sesb-eam/distribution-lines/{l}")).unwrap_or_else(|| "/sesb-eam/distribution-lines".into());
    let header = form_header(&back, "Back", "New Cable Segment");
    let body = cseg_body(&db, &HashMap::new(), line_pre, true).await;
    Html(page_shell(&sidebar, "New Cable Segment", &wide_form_page("/sesb-eam/cable-segments/create", &header, &body))).into_response()
}

async fn create_cseg(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let line_id = match opt_uuid(&form, "distribution_line_id") { Some(l) => l, None => return bad("Distribution line is required") };
    let (name, code) = (form.get("name").cloned().unwrap_or_default(), form.get("code").cloned().unwrap_or_default());
    if name.trim().is_empty() || code.trim().is_empty() { return bad("Name and code are required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_cable_segment (id, name, code, sequence, distribution_line_id, voltage_level_id, start_substation_id, end_substation_id, start_chainage_m, end_chainage_m, cable_type, conductor_size, laying_method, condition, notes, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)")
        .bind(id).bind(&name).bind(&code).bind(opt_i32(&form, "sequence").unwrap_or(0)).bind(line_id)
        .bind(opt_uuid(&form, "voltage_level_id")).bind(opt_uuid(&form, "start_substation_id")).bind(opt_uuid(&form, "end_substation_id"))
        .bind(opt_dec(&form, "start_chainage_m")).bind(opt_dec(&form, "end_chainage_m")).bind(opt_str(&form, "cable_type"))
        .bind(opt_str(&form, "conductor_size")).bind(opt_str(&form, "laying_method")).bind(opt_str(&form, "condition")).bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "cseg insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/cable-segments/{id}")).into_response()
}

async fn edit_cseg(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.distribution_lines");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, code, sequence::text AS sequence, distribution_line_id::text AS distribution_line_id, voltage_level_id::text AS voltage_level_id, start_substation_id::text AS start_substation_id, end_substation_id::text AS end_substation_id, start_chainage_m::text AS start_chainage_m, end_chainage_m::text AS end_chainage_m, cable_type, conductor_size, laying_method, condition, notes, active::text AS active, distribution_line_id AS dline FROM eam_cable_segment WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["name","code","sequence","distribution_line_id","voltage_level_id","start_substation_id","end_substation_id","start_chainage_m","end_chainage_m","cable_type","conductor_size","laying_method","condition","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let dline: Option<Uuid> = row.try_get("dline").ok();
    let name = v.get("name").cloned().unwrap_or_default();
    let body = cseg_body(&db, &v, None, false).await;

    // Cable tests subtable + inline add form (computes PI/DAR per §4.7).
    let tests = vortex_plugin_sdk::sqlx::query("SELECT test_date::text AS td, test_type, polarization_index::text AS pi, dar_ratio::text AS dar, result FROM eam_cable_test WHERE segment_id=$1 ORDER BY test_date DESC").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut test_rows = String::new();
    for r in &tests {
        let td: Option<String> = r.try_get("td").ok();
        let tt: String = r.get("test_type");
        let pi: Option<String> = r.try_get("pi").ok();
        let dar: Option<String> = r.try_get("dar").ok();
        let res: Option<String> = r.try_get("result").ok();
        test_rows.push_str(&format!(r#"<tr><td>{td}</td><td>{tt}</td><td>{pi}</td><td>{dar}</td><td>{res}</td></tr>"#,
            td = esc(td.as_deref().unwrap_or("—")), tt = esc(&tt), pi = esc(pi.as_deref().unwrap_or("—")), dar = esc(dar.as_deref().unwrap_or("—")), res = esc(res.as_deref().unwrap_or("—"))));
    }
    if test_rows.is_empty() { test_rows.push_str(r#"<tr><td colspan="5" class="text-base-content/50">No tests</td></tr>"#); }
    let test_form = format!(
        r#"<form method="POST" action="/sesb-eam/cable-tests/create" class="grid grid-cols-2 md:grid-cols-6 gap-2 items-end mt-3">
<input type="hidden" name="segment_id" value="{id}"/>
<input name="test_date" type="date" class="input input-bordered input-sm" required/>
<select name="test_type" class="select select-bordered select-sm">{tt}</select>
<input name="ir_1min" type="number" step="0.0001" class="input input-bordered input-sm" placeholder="IR 1min"/>
<input name="ir_10min" type="number" step="0.0001" class="input input-bordered input-sm" placeholder="IR 10min"/>
<input name="ir_30s" type="number" step="0.0001" class="input input-bordered input-sm" placeholder="IR 30s"/>
<button class="btn btn-primary btn-sm">Add Test</button></form>
<div class="text-xs opacity-60 mt-1">PI = IR10min/IR1min, DAR = IR60s/IR30s computed automatically (§4.7).</div>"#,
        id = id, tt = enum_options(CTEST_TYPES, "ir"));

    let back = dline.map(|l| format!("/sesb-eam/distribution-lines/{l}")).unwrap_or_else(|| "/sesb-eam/distribution-lines".into());
    let header = form_header(&back, "Back to Line", &format!("Cable Segment {}", name));
    let content = format!(
        r#"{form}<div class="max-w-4xl mt-6"><div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-2">IR / PI Tests</h2>
<table class="table table-sm"><thead><tr><th>Date</th><th>Type</th><th>PI</th><th>DAR</th><th>Result</th></tr></thead><tbody>{tests}</tbody></table>
{test_form}</div></div></div>"#,
        form = wide_form_page(&format!("/sesb-eam/cable-segments/{id}"), &header, &body), tests = test_rows, test_form = test_form);
    Html(page_shell(&sidebar, &format!("Cable Segment {}", name), &content)).into_response()
}

async fn update_cseg(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let line_id = match opt_uuid(&form, "distribution_line_id") { Some(l) => l, None => return bad("Distribution line is required") };
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_cable_segment SET name=$1, code=$2, sequence=$3, distribution_line_id=$4, voltage_level_id=$5, start_substation_id=$6, end_substation_id=$7, start_chainage_m=$8, end_chainage_m=$9, cable_type=$10, conductor_size=$11, laying_method=$12, condition=$13, notes=$14, active=$15 WHERE id=$16")
        .bind(form.get("name")).bind(form.get("code")).bind(opt_i32(&form, "sequence").unwrap_or(0)).bind(line_id)
        .bind(opt_uuid(&form, "voltage_level_id")).bind(opt_uuid(&form, "start_substation_id")).bind(opt_uuid(&form, "end_substation_id"))
        .bind(opt_dec(&form, "start_chainage_m")).bind(opt_dec(&form, "end_chainage_m")).bind(opt_str(&form, "cable_type"))
        .bind(opt_str(&form, "conductor_size")).bind(opt_str(&form, "laying_method")).bind(opt_str(&form, "condition")).bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/cable-segments/{id}")).into_response()
}

async fn create_ctest(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let segment_id = match opt_uuid(&form, "segment_id") { Some(s) => s, None => return bad("Segment required") };
    let test_date = match opt_date(&form, "test_date") { Some(d) => d, None => return bad("Test date required") };
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &CT_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    // PI = IR10min/IR1min ; DAR = IR60s/IR30s (§4.7), computed in SQL with zero-guard.
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_cable_test (id, name, segment_id, test_date, test_type, ir_30s, ir_60s, ir_1min, ir_10min, polarization_index, dar_ratio, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, \
            CASE WHEN COALESCE($8,0) > 0 THEN $9/$8 END, \
            CASE WHEN COALESCE($6,0) > 0 THEN $7/$6 END, $10)")
        .bind(Uuid::now_v7()).bind(&code).bind(segment_id).bind(test_date)
        .bind(form.get("test_type").map(|s| s.as_str()).unwrap_or("ir"))
        .bind(opt_dec(&form, "ir_30s")).bind(opt_dec(&form, "ir_60s")).bind(opt_dec(&form, "ir_1min")).bind(opt_dec(&form, "ir_10min")).bind(company_id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/cable-segments/{segment_id}")).into_response()
}
