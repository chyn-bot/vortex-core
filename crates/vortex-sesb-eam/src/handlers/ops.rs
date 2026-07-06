//! Operational records — defects (§5.4 state machine), inspections,
//! condition monitoring (§4.7 diagnostics), line patrols, outages,
//! vegetation sections and Cerdik troubleshooting rules.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

const DEF_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.defect", "DEF").with_padding(5).yearly();
const INS_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.inspection", "INS").with_padding(5).yearly();
const CM_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.condition_monitoring", "CM").with_padding(5).yearly();
const LP_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.line_patrol", "LP").with_padding(5).yearly();
const OUT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.outage", "OUT").with_padding(5).yearly();
const MNT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.maintenance", "MNT").with_padding(5).yearly();

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Defects
        .route("/sesb-eam/defects", get(list_defect))
        .route("/sesb-eam/defects/new", get(new_defect))
        .route("/sesb-eam/defects/create", post(create_defect))
        .route("/sesb-eam/defects/{id}", get(edit_defect))
        .route("/sesb-eam/defects/{id}", post(update_defect))
        .route("/sesb-eam/defects/{id}/action/{action}", post(defect_action))
        // Inspections
        .route("/sesb-eam/inspections", get(list_inspection))
        .route("/sesb-eam/inspections/new", get(new_inspection))
        .route("/sesb-eam/inspections/create", post(create_inspection))
        .route("/sesb-eam/inspections/{id}", get(edit_inspection))
        .route("/sesb-eam/inspections/{id}", post(update_inspection))
        .route("/sesb-eam/inspections/{id}/action/{action}", post(inspection_action))
        .route("/sesb-eam/inspections/{id}/duplicate", post(duplicate_inspection))
        // Condition monitoring
        .route("/sesb-eam/condition-monitoring", get(list_cm))
        .route("/sesb-eam/condition-monitoring/new", get(new_cm))
        .route("/sesb-eam/condition-monitoring/create", post(create_cm))
        .route("/sesb-eam/condition-monitoring/{id}", get(edit_cm))
        .route("/sesb-eam/condition-monitoring/{id}", post(update_cm))
        // Line patrols
        .route("/sesb-eam/patrols", get(list_patrol))
        .route("/sesb-eam/patrols/new", get(new_patrol))
        .route("/sesb-eam/patrols/create", post(create_patrol))
        .route("/sesb-eam/patrols/{id}", get(edit_patrol))
        .route("/sesb-eam/patrols/{id}", post(update_patrol))
        // Outages
        .route("/sesb-eam/outages", get(list_outage))
        .route("/sesb-eam/outages/new", get(new_outage))
        .route("/sesb-eam/outages/create", post(create_outage))
        .route("/sesb-eam/outages/{id}", get(edit_outage))
        .route("/sesb-eam/outages/{id}", post(update_outage))
        // Vegetation
        .route("/sesb-eam/vegetation", get(list_veg))
        .route("/sesb-eam/vegetation/new", get(new_veg))
        .route("/sesb-eam/vegetation/create", post(create_veg))
        .route("/sesb-eam/vegetation/{id}", get(edit_veg))
        .route("/sesb-eam/vegetation/{id}", post(update_veg))
        // Troubleshooting rules
        .route("/sesb-eam/troubleshooting", get(list_tsr))
        .route("/sesb-eam/troubleshooting/new", get(new_tsr))
        .route("/sesb-eam/troubleshooting/create", post(create_tsr))
        .route("/sesb-eam/troubleshooting/{id}", get(edit_tsr))
        .route("/sesb-eam/troubleshooting/{id}", post(update_tsr))
}

async fn equipment_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_equipment WHERE active ORDER BY code", "-- Equipment --", sel).await
}
async fn user_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, username AS label FROM users ORDER BY username", "-- User --", sel).await
}

fn badge(s: &str, map: &[(&str, &str, &str)]) -> String {
    for (v, l, c) in map { if *v == s { return format!(r#"<span class="badge {c}">{l}</span>"#, c = c, l = l); } }
    format!(r#"<span class="badge badge-ghost">{}</span>"#, s)
}

// ═════════════════════════════════════════════════════════════════════════
// Defects (§5.4)
// ═════════════════════════════════════════════════════════════════════════

const SEVERITIES: &[(&str, &str)] = &[("minor","Minor"),("moderate","Moderate"),("major","Major"),("critical","Critical")];
const DEF_CATS: &[(&str, &str)] = &[("","—"),("electrical","Electrical"),("mechanical","Mechanical"),("structural","Structural"),("safety","Safety"),("housekeeping","Housekeeping"),("other","Other")];
const DEFECT_STATE_BADGES: &[(&str, &str, &str)] = &[("draft","Draft","badge-ghost"),("open","Open","badge-info"),("assigned","Assigned","badge-info"),("in_repair","In Repair","badge-warning"),("repaired","Repaired","badge-success"),("verified","Verified","badge-success"),("cancelled","Cancelled","badge-error")];

async fn list_defect(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.defects");
    let config = ListConfig::new("Defects", "eam_defect")
        .custom_from("eam_defect d LEFT JOIN eam_equipment e ON e.id=d.equipment_id")
        .custom_select("d.id, d.name, d.title, e.name AS equipment, d.severity, d.defect_category, d.state, d.discovered_date::text AS dd, d.active")
        .column(ListColumn::new("name", "Number").sortable().code().sql_expr("d.name"))
        .column(ListColumn::new("title", "Title").searchable().sql_expr("d.title"))
        .column(ListColumn::new("equipment", "Equipment").sql_expr("e.name"))
        .column(ListColumn::new("severity", "Severity").filterable(&[("minor","Minor"),("moderate","Moderate"),("major","Major"),("critical","Critical")])
            .badge(&[("minor","Minor","badge-ghost"),("moderate","Moderate","badge-info"),("major","Major","badge-warning"),("critical","Critical","badge-error")]).sql_expr("d.severity"))
        .column(ListColumn::new("state", "State").filterable(&[("open","Open"),("assigned","Assigned"),("in_repair","In Repair"),("repaired","Repaired"),("verified","Verified")])
            .badge(&[("draft","Draft","badge-ghost"),("open","Open","badge-info"),("assigned","Assigned","badge-info"),("in_repair","In Repair","badge-warning"),("repaired","Repaired","badge-success"),("verified","Verified","badge-success"),("cancelled","Cancelled","badge-error")]).sql_expr("d.state"))
        .detail_url("/sesb-eam/defects/{id}")
        .create("New Defect", "/sesb-eam/defects/new")
        .default_sort("name")
        .group_by_options(&[("state","State"),("severity","Severity")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "defect list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Defects", &render_list(&config, &result, &params, "/sesb-eam/defects"))).into_response()
}

async fn defect_body(db: &PgPool, v: &HashMap<String, String>, eq_pre: Option<Uuid>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let equips = equipment_opts(db, v.get("equipment_id").and_then(|s| s.parse().ok()).or(eq_pre)).await;
    let users = user_opts(db, v.get("assigned_to").and_then(|s| s.parse().ok())).await;
    let g2 = grid2(&format!("{}{}{}{}{}{}",
        text_field("Title", "title", g("title"), true),
        select_field("Equipment *", "equipment_id", &equips),
        select_field("Severity *", "severity", &enum_options(SEVERITIES, if g("severity").is_empty() { "moderate" } else { g("severity") })),
        select_field("Category", "defect_category", &enum_options(DEF_CATS, g("defect_category"))),
        date_field("Discovered Date", "discovered_date", g("discovered_date")),
        select_field("Assigned To", "assigned_to", &users)));
    format!("{}{}{}", g2, textarea_field("Description", "description", g("description")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_defect(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.defects");
    let eq_pre = q.get("equipment").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/defects", "Back to Defects", "Raise Defect");
    let body = defect_body(&db, &HashMap::new(), eq_pre, true).await;
    Html(page_shell(&sidebar, "Raise Defect", &wide_form_page("/sesb-eam/defects/create", &header, &body))).into_response()
}

async fn create_defect(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let equipment_id = match opt_uuid(&form, "equipment_id") { Some(e) => e, None => return bad("Equipment is required") };
    let title = form.get("title").cloned().unwrap_or_default();
    if title.trim().is_empty() { return bad("Title is required"); }
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &DEF_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_defect (id, name, title, description, equipment_id, bay_id, substation_id, region_id, kawasan_id, responsible_kawasan_id, responsible_region_id, discovered_date, discovered_by, severity, defect_category, assigned_to, state, company_id, created_by) \
         SELECT $1,$2,$3,$4,$5, e.bay_id, e.substation_id, \
            (SELECT si.region_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.kawasan_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.kawasan_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.region_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            COALESCE($6, NOW()), $7, $8, $9, $10, 'open', $11, $7 \
         FROM eam_equipment e WHERE e.id=$5")
        .bind(id).bind(&number).bind(&title).bind(opt_str(&form, "description")).bind(equipment_id)
        .bind(opt_date(&form, "discovered_date").map(|d| d.and_hms_opt(0,0,0).unwrap().and_utc())).bind(user.id)
        .bind(form.get("severity").map(|s| s.as_str()).unwrap_or("moderate")).bind(opt_str(&form, "defect_category"))
        .bind(opt_uuid(&form, "assigned_to")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "defect insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/defects/{id}")).into_response()
}

async fn edit_defect(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.defects");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, title, description, equipment_id::text AS equipment_id, severity, defect_category, assigned_to::text AS assigned_to, state, discovered_date::text AS discovered_date, repair_maintenance_id, repair_notes, active::text AS active FROM eam_defect WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["title","description","equipment_id","severity","defect_category","assigned_to","discovered_date","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let number: Option<String> = row.try_get("name").ok();
    let dstate: String = row.get("state");
    let repair_mid: Option<Uuid> = row.try_get("repair_maintenance_id").ok();
    let title = v.get("title").cloned().unwrap_or_default();
    let body = defect_body(&db, &v, None, false).await;
    let actions = defect_actions(&dstate, id, repair_mid);
    let history = vortex_plugin_sdk::framework::render_audit_trail(&db, "eam_defect", id).await;
    let header = format!(
        r#"<div class="flex items-center justify-between mb-3"><div>
<a href="/sesb-eam/defects" class="btn btn-ghost btn-sm mb-2">← Back to Defects</a>
<h1 class="text-2xl font-bold">{title} <span class="font-mono text-sm opacity-50">{num}</span> {badge}</h1></div></div>"#,
        title = esc(&title), num = esc(number.as_deref().unwrap_or("")), badge = badge(&dstate, DEFECT_STATE_BADGES));
    let content = format!("<div class=\"max-w-3xl\">{}{}{}<div class=\"mt-6\">{}</div></div>",
        header, actions, wide_form_page(&format!("/sesb-eam/defects/{id}"), "", &body), history);
    Html(page_shell(&sidebar, &format!("Defect {}", title), &content)).into_response()
}

fn defect_actions(s: &str, id: Uuid, repair_mid: Option<Uuid>) -> String {
    let btn = |action: &str, label: &str, cls: &str, extra: &str| format!(
        r#"<form method="POST" action="/sesb-eam/defects/{id}/action/{action}" class="inline">{extra}<button class="btn btn-sm {cls}">{label}</button></form>"#, id = id, action = action, cls = cls, label = label, extra = extra);
    let mut out = match s {
        "open" | "assigned" => vec![btn("create_repair_order", "Create Repair Order", "btn-primary", ""), btn("cancel", "Cancel", "btn-error btn-outline", "")],
        "in_repair" => vec![btn("mark_repaired", "Mark Repaired (needs after-photo)", "btn-success", "")],
        "repaired" => vec![btn("verify", "Verify", "btn-success", "")],
        _ => vec![],
    };
    if let Some(m) = repair_mid { out.push(format!(r#"<a href="/sesb-eam/maintenance/{m}" class="btn btn-sm btn-ghost">View Repair Order →</a>"#)); }
    if out.is_empty() { return String::new(); }
    format!(r#"<div class="flex flex-wrap gap-2 mb-4 items-center">{}</div>"#, out.join(""))
}

async fn update_defect(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let title = form.get("title").cloned().unwrap_or_default();
    if title.trim().is_empty() { return bad("Title is required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_defect SET title=$1, description=$2, severity=$3, defect_category=$4, assigned_to=$5, active=$6 WHERE id=$7")
        .bind(&title).bind(opt_str(&form, "description")).bind(form.get("severity").map(|s| s.as_str()).unwrap_or("moderate"))
        .bind(opt_str(&form, "defect_category")).bind(opt_uuid(&form, "assigned_to")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/defects/{id}")).into_response()
}

async fn defect_action(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path((id, action)): Path<(Uuid, String)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let now = vortex_plugin_sdk::chrono::Utc::now();
    match action.as_str() {
        "create_repair_order" => {
            // Map severity → priority (minor→0 … critical→3); create a cm work order.
            let row = vortex_plugin_sdk::sqlx::query("SELECT title, equipment_id, severity FROM eam_defect WHERE id=$1 AND state IN ('open','assigned')").bind(id).fetch_optional(&db).await.ok().flatten();
            let row = match row { Some(r) => r, None => return (StatusCode::CONFLICT, "Cannot create repair order from this state").into_response() };
            let title: String = row.get("title");
            let equipment_id: Uuid = row.get("equipment_id");
            let severity: String = row.get("severity");
            let priority = match severity.as_str() { "minor" => "0", "moderate" => "1", "major" => "2", _ => "3" };
            let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &MNT_SEQ).await.unwrap_or_default();
            let company_id = default_company(&db).await;
            let wo_id = Uuid::now_v7();
            let _ = vortex_plugin_sdk::sqlx::query(
                "INSERT INTO eam_maintenance (id, name, description, equipment_id, equipment_category, bay_id, substation_id, maintenance_type, priority, request_date, state, repair_for_defect_id, company_id, created_by) \
                 SELECT $1,$2,$3,$4, e.equipment_category, e.bay_id, e.substation_id, 'cm', $5, CURRENT_DATE, 'scheduled', $6, $7, $8 FROM eam_equipment e WHERE e.id=$4")
                .bind(wo_id).bind(&number).bind(format!("Repair: {title}")).bind(equipment_id).bind(priority).bind(id).bind(company_id).bind(user.id)
                .execute(&db).await;
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_defect SET state='in_repair', repair_maintenance_id=$2 WHERE id=$1").bind(id).bind(wo_id).execute(&db).await;
            Redirect::to(&format!("/sesb-eam/defects/{id}")).into_response()
        }
        "mark_repaired" => {
            // Requires an after-photo per §5.4. (Photo upload UI lands with the portal; we accept a flag here.)
            let has_photo: bool = vortex_plugin_sdk::sqlx::query_scalar("SELECT photo_after IS NOT NULL FROM eam_defect WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten().unwrap_or(false);
            if !has_photo && !form.contains_key("confirm_no_photo") {
                return (StatusCode::BAD_REQUEST, "An after-photo is required to mark a defect repaired (§5.4).").into_response();
            }
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_defect SET state='repaired', repaired_by=$2, repair_date=$3, repair_notes=$4 WHERE id=$1 AND state='in_repair'")
                .bind(id).bind(user.id).bind(now).bind(opt_str(&form, "repair_notes")).execute(&db).await;
            Redirect::to(&format!("/sesb-eam/defects/{id}")).into_response()
        }
        "verify" => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_defect SET state='verified', verified_by=$2, verification_date=$3 WHERE id=$1 AND state='repaired'").bind(id).bind(user.id).bind(now).execute(&db).await;
            Redirect::to(&format!("/sesb-eam/defects/{id}")).into_response()
        }
        "cancel" => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_defect SET state='cancelled' WHERE id=$1").bind(id).execute(&db).await;
            Redirect::to(&format!("/sesb-eam/defects/{id}")).into_response()
        }
        _ => (StatusCode::BAD_REQUEST, "Unknown action").into_response(),
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Inspection (§5.6)
// ═════════════════════════════════════════════════════════════════════════

const INSP_TYPES: &[(&str, &str)] = &[("routine","Routine"),("detailed","Detailed"),("visual","Visual"),("thermal","Thermal"),("ultrasonic","Ultrasonic"),("special","Special")];
const CONDITIONS: &[(&str, &str)] = &[("","—"),("excellent","Excellent"),("good","Good"),("fair","Fair"),("poor","Poor"),("critical","Critical")];
const INSP_STATE_BADGES: &[(&str, &str, &str)] = &[("draft","Draft","badge-ghost"),("in_progress","In Progress","badge-warning"),("completed","Completed","badge-success"),("approved","Approved","badge-success")];

async fn list_inspection(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.inspections");
    let config = ListConfig::new("Inspections", "eam_inspection")
        .custom_from("eam_inspection i LEFT JOIN eam_equipment e ON e.id=i.equipment_id")
        .custom_select("i.id, i.name, e.name AS equipment, i.inspection_type, i.inspection_date::text AS dt, i.overall_condition, i.state, i.active")
        .column(ListColumn::new("name", "Number").sortable().code().sql_expr("i.name"))
        .column(ListColumn::new("equipment", "Equipment").searchable().sql_expr("e.name"))
        .column(ListColumn::new("inspection_type", "Type").sql_expr("i.inspection_type"))
        .column(ListColumn::new("dt", "Date").sortable().sql_expr("i.inspection_date"))
        .column(ListColumn::new("overall_condition", "Condition").sql_expr("i.overall_condition"))
        .column(ListColumn::new("state", "State").badge(&[("draft","Draft","badge-ghost"),("in_progress","In Progress","badge-warning"),("completed","Completed","badge-success"),("approved","Approved","badge-success")]).sql_expr("i.state"))
        .detail_url("/sesb-eam/inspections/{id}")
        .create("New Inspection", "/sesb-eam/inspections/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "insp list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Inspections", &render_list(&config, &result, &params, "/sesb-eam/inspections"))).into_response()
}

async fn insp_body(db: &PgPool, v: &HashMap<String, String>, eq_pre: Option<Uuid>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let equips = equipment_opts(db, v.get("equipment_id").and_then(|s| s.parse().ok()).or(eq_pre)).await;
    let inspectors = user_opts(db, v.get("inspector_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}",
        select_field("Equipment *", "equipment_id", &equips),
        select_field("Inspection Type *", "inspection_type", &enum_options(INSP_TYPES, if g("inspection_type").is_empty() { "routine" } else { g("inspection_type") })),
        date_field("Inspection Date *", "inspection_date", g("inspection_date")),
        select_field("Inspector", "inspector_id", &inspectors),
        select_field("Overall Condition", "overall_condition", &enum_options(CONDITIONS, g("overall_condition"))),
        num_field("Condition Score (0-100)", "condition_score", g("condition_score"), "1"),
        checkbox("immediate_action_required", "Immediate Action Required", g("immediate_action_required") == "true")));
    format!("{}{}{}{}{}", grid, textarea_field("Findings", "findings", g("findings")), textarea_field("Defects Found", "defects_found", g("defects_found")), textarea_field("Recommendations", "recommendations", g("recommendations")), active_field(g("active") == "true" || is_new, is_new))
}

fn checkbox(name: &str, label: &str, checked: bool) -> String {
    format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="{name}" class="checkbox checkbox-sm" {c}/><span class="label-text">{label}</span></label></div>"#, name = name, label = label, c = if checked { "checked" } else { "" })
}
fn grid3(fields: &str) -> String { format!(r#"<div class="grid grid-cols-1 md:grid-cols-3 gap-x-4">{}</div>"#, fields) }

async fn new_inspection(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.inspections");
    let eq_pre = q.get("equipment").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/inspections", "Back to Inspections", "New Inspection");
    let body = insp_body(&db, &HashMap::new(), eq_pre, true).await;
    Html(page_shell(&sidebar, "New Inspection", &wide_form_page("/sesb-eam/inspections/create", &header, &body))).into_response()
}

async fn create_inspection(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let equipment_id = match opt_uuid(&form, "equipment_id") { Some(e) => e, None => return bad("Equipment is required") };
    let date = match opt_date(&form, "inspection_date") { Some(d) => d, None => return bad("Inspection date is required") };
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &INS_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_inspection (id, name, equipment_id, equipment_category, bay_id, substation_id, inspection_type, inspection_date, inspector_id, overall_condition, condition_score, immediate_action_required, findings, defects_found, recommendations, company_id) \
         SELECT $1,$2,$3, e.equipment_category, e.bay_id, e.substation_id, $4,$5,$6,$7,$8,$9,$10,$11,$12,$13 FROM eam_equipment e WHERE e.id=$3")
        .bind(id).bind(&number).bind(equipment_id)
        .bind(form.get("inspection_type").map(|s| s.as_str()).unwrap_or("routine")).bind(date)
        .bind(opt_uuid(&form, "inspector_id").or(Some(user.id))).bind(opt_str(&form, "overall_condition")).bind(opt_i32(&form, "condition_score"))
        .bind(form.contains_key("immediate_action_required")).bind(opt_str(&form, "findings")).bind(opt_str(&form, "defects_found")).bind(opt_str(&form, "recommendations")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "insp insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/inspections/{id}")).into_response()
}

async fn edit_inspection(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.inspections");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, equipment_id::text AS equipment_id, inspection_type, inspection_date::text AS inspection_date, inspector_id::text AS inspector_id, overall_condition, condition_score::text AS condition_score, immediate_action_required::text AS immediate_action_required, findings, defects_found, recommendations, state, active::text AS active FROM eam_inspection WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["equipment_id","inspection_type","inspection_date","inspector_id","overall_condition","condition_score","immediate_action_required","findings","defects_found","recommendations","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let number: Option<String> = row.try_get("name").ok();
    let istate: String = row.get("state");
    let body = insp_body(&db, &v, None, false).await;
    let actions = {
        let btn = |a: &str, l: &str, c: &str| format!(r#"<form method="POST" action="/sesb-eam/inspections/{id}/action/{a}" class="inline"><button class="btn btn-sm {c}">{l}</button></form>"#, id = id, a = a, c = c, l = l);
        match istate.as_str() {
            "draft" => btn("start", "Start", "btn-primary"),
            "in_progress" => btn("complete", "Complete (writes condition back)", "btn-success"),
            "completed" => btn("approve", "Approve", "btn-success"),
            _ => String::new(),
        }
    };
    let header = format!(r#"<a href="/sesb-eam/inspections" class="btn btn-ghost btn-sm mb-3">← Back to Inspections</a>
<h1 class="text-2xl font-bold mb-3">Inspection <span class="font-mono text-sm opacity-50">{num}</span> {badge}</h1>"#, num = esc(number.as_deref().unwrap_or("")), badge = badge(&istate, INSP_STATE_BADGES));
    let dup = duplicate_button(&format!("/sesb-eam/inspections/{id}/duplicate"));
    let actions_bar = format!(r#"<div class="flex gap-2 mb-4">{}{}</div>"#, actions, dup);
    let content = format!("<div class=\"max-w-4xl\">{}{}{}</div>", header, actions_bar, wide_form_page(&format!("/sesb-eam/inspections/{id}"), "", &body));
    Html(page_shell(&sidebar, "Inspection", &content)).into_response()
}

async fn update_inspection(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    if opt_uuid(&form, "equipment_id").is_none() { return bad("Equipment is required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_inspection SET inspection_type=$1, inspection_date=$2, inspector_id=$3, overall_condition=$4, condition_score=$5, immediate_action_required=$6, findings=$7, defects_found=$8, recommendations=$9, active=$10 WHERE id=$11")
        .bind(form.get("inspection_type").map(|s| s.as_str()).unwrap_or("routine")).bind(opt_date(&form, "inspection_date"))
        .bind(opt_uuid(&form, "inspector_id")).bind(opt_str(&form, "overall_condition")).bind(opt_i32(&form, "condition_score"))
        .bind(form.contains_key("immediate_action_required")).bind(opt_str(&form, "findings")).bind(opt_str(&form, "defects_found")).bind(opt_str(&form, "recommendations")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/inspections/{id}")).into_response()
}

async fn inspection_action(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path((id, action)): Path<(Uuid, String)>,
) -> Response {
    match action.as_str() {
        "start" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_inspection SET state='in_progress' WHERE id=$1 AND state='draft'").bind(id).execute(&db).await; }
        "complete" => {
            // §5.6: completing writes overall_condition back onto the equipment.
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_inspection SET state='completed' WHERE id=$1 AND state='in_progress'").bind(id).execute(&db).await;
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE eam_equipment e SET condition_status = i.overall_condition FROM eam_inspection i WHERE i.id=$1 AND i.equipment_id=e.id AND i.overall_condition IS NOT NULL")
                .bind(id).execute(&db).await;
        }
        "approve" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_inspection SET state='approved', approved_by=$2, approved_date=CURRENT_DATE WHERE id=$1 AND state='completed'").bind(id).bind(user.id).execute(&db).await; }
        _ => return (StatusCode::BAD_REQUEST, "Unknown action").into_response(),
    }
    Redirect::to(&format!("/sesb-eam/inspections/{id}")).into_response()
}

/// POST /sesb-eam/inspections/{id}/duplicate — copy an inspection into a
/// fresh draft dated today: new INS number, all recorded results/checks and
/// the approval cleared. The inspector is kept deliberately — a routine
/// inspection is re-run by the same inspector on the same equipment.
async fn duplicate_inspection(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &INS_SEQ).await {
        Ok(n) => n,
        Err(_) => return bad("Failed to generate number"),
    };
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    let spec = DuplicateSpec::new("eam_inspection")
        .set("name", json!(number))
        .set("inspection_date", json!(today.to_string()))
        // lifecycle → DB default: state 'draft'
        .skip("state")
        // recorded results / measurements
        .skip("overall_condition").skip("condition_score")
        .skip("visual_check").skip("cleanliness_check").skip("corrosion_check")
        .skip("oil_leak_check").skip("connection_check").skip("labeling_check")
        .skip("temperature_c").skip("humidity_percent").skip("noise_level_db")
        .skip("findings").skip("defects_found").skip("recommendations")
        .skip("immediate_action_required")
        // sign-off + source work-order link stay with the source
        .skip("approved_by").skip("approved_date").skip("maintenance_id");
    match spec.execute(&db, id, Some(user.id)).await {
        Ok(new_id) => {
            let entry = vortex_plugin_sdk::security::AuditEntry::new(
                vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
            ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
             .with_database(&db_ctx.db_name).with_resource("eam_inspection", new_id.to_string()).with_resource_name(&number)
             .with_details(json!({"duplicated_from": id, "number": number}));
            let _ = state.audit.log(entry).await;
            Redirect::to(&format!("/sesb-eam/inspections/{new_id}")).into_response()
        }
        Err(e) => {
            error!(error=%e, "inspection duplicate");
            (StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response()
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Condition monitoring (§4.7 diagnostics)
// ═════════════════════════════════════════════════════════════════════════

const CM_TYPES: &[(&str, &str)] = &[("dga","DGA"),("thermal","Thermal"),("pd","PD"),("oil_quality","Oil Quality"),("tan_delta","Tan Delta"),("winding_resistance","Winding Resistance"),("ir","IR"),("sf6","SF6"),("contact_resistance","Contact Resistance"),("battery","Battery"),("timing","Timing")];
const RESULT_STATUSES: &[(&str, &str)] = &[("","—"),("normal","Normal"),("caution","Caution"),("warning","Warning"),("critical","Critical")];

async fn list_cm(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.condition_monitoring");
    let config = ListConfig::new("Condition Monitoring", "eam_condition_monitoring")
        .custom_from("eam_condition_monitoring c LEFT JOIN eam_equipment e ON e.id=c.equipment_id")
        .custom_select("c.id, c.name, e.name AS equipment, c.test_type, c.test_date::text AS dt, c.result_status, c.state, c.active")
        .column(ListColumn::new("name", "Number").sortable().code().sql_expr("c.name"))
        .column(ListColumn::new("equipment", "Equipment").searchable().sql_expr("e.name"))
        .column(ListColumn::new("test_type", "Test").filterable(&[("dga","DGA"),("thermal","Thermal"),("pd","PD"),("oil_quality","Oil"),("ir","IR"),("sf6","SF6"),("battery","Battery")]).sql_expr("c.test_type"))
        .column(ListColumn::new("dt", "Date").sortable().sql_expr("c.test_date"))
        .column(ListColumn::new("result_status", "Result").badge(&[("normal","Normal","badge-success"),("caution","Caution","badge-info"),("warning","Warning","badge-warning"),("critical","Critical","badge-error")]).sql_expr("c.result_status"))
        .column(ListColumn::new("state", "State").sql_expr("c.state"))
        .detail_url("/sesb-eam/condition-monitoring/{id}")
        .create("New Test", "/sesb-eam/condition-monitoring/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "cm list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Condition Monitoring", &render_list(&config, &result, &params, "/sesb-eam/condition-monitoring"))).into_response()
}

async fn cm_body(db: &PgPool, v: &HashMap<String, String>, eq_pre: Option<Uuid>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let equips = equipment_opts(db, v.get("equipment_id").and_then(|s| s.parse().ok()).or(eq_pre)).await;
    let head = grid3(&format!("{}{}{}{}{}",
        select_field("Equipment *", "equipment_id", &equips),
        select_field("Test Type *", "test_type", &enum_options(CM_TYPES, if g("test_type").is_empty() { "dga" } else { g("test_type") })),
        date_field("Test Date *", "test_date", g("test_date")),
        select_field("Result Status", "result_status", &enum_options(RESULT_STATUSES, g("result_status"))),
        text_field("Test Lab", "test_lab", g("test_lab"), false)));
    // DGA gases + oil + thermal core inputs (the diagnostic-bearing ones, §4.7)
    let dga = grid3(&format!("{}{}{}{}{}{}",
        num_field("H₂", "dga_hydrogen_h2", g("dga_hydrogen_h2"), "0.01"),
        num_field("CH₄", "dga_methane_ch4", g("dga_methane_ch4"), "0.01"),
        num_field("C₂H₆", "dga_ethane_c2h6", g("dga_ethane_c2h6"), "0.01"),
        num_field("C₂H₄", "dga_ethylene_c2h4", g("dga_ethylene_c2h4"), "0.01"),
        num_field("C₂H₂", "dga_acetylene_c2h2", g("dga_acetylene_c2h2"), "0.01"),
        num_field("CO", "dga_carbon_monoxide_co", g("dga_carbon_monoxide_co"), "0.01")));
    let other = grid3(&format!("{}{}{}{}",
        num_field("Thermal Ambient °C", "thermal_ambient_temp_c", g("thermal_ambient_temp_c"), "0.1"),
        num_field("Thermal Max °C", "thermal_max_temp_c", g("thermal_max_temp_c"), "0.1"),
        num_field("IR 1min (MΩ)", "ir_1min_mohm", g("ir_1min_mohm"), "0.0001"),
        num_field("IR 10min (MΩ)", "ir_10min_mohm", g("ir_10min_mohm"), "0.0001")));
    let sec = |t: &str| format!(r#"<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">{}</h2>"#, t);
    format!("{}{}{}{}{}{}{}", head, sec("DGA Gases (ppm)"), dga, sec("Thermal / IR"), other, textarea_field("Result Summary", "result_summary", g("result_summary")), active_field(g("active") == "true" || is_new, is_new))
}

/// §4.7 diagnostic roll-up shown read-only on the CM detail page.
fn cm_diagnostics(v: &HashMap<String, String>) -> String {
    let n = |k: &str| v.get(k).and_then(|s| s.parse::<f64>().ok());
    let tdcg = ["dga_hydrogen_h2","dga_methane_ch4","dga_ethane_c2h6","dga_ethylene_c2h4","dga_acetylene_c2h2","dga_carbon_monoxide_co"].iter().filter_map(|k| n(k)).sum::<f64>();
    let tdg = tdcg + n("dga_carbon_dioxide_co2").unwrap_or(0.0);
    let delta_t = match (n("thermal_max_temp_c"), n("thermal_ambient_temp_c")) { (Some(mx), Some(am)) => Some(mx - am), _ => None };
    let thermal_band = delta_t.map(|d| if d < 10.0 { "normal" } else if d < 30.0 { "attention" } else if d < 60.0 { "intermediate" } else if d < 100.0 { "serious" } else { "critical" });
    let pi = match (n("ir_10min_mohm"), n("ir_1min_mohm")) { (Some(a), Some(b)) if b > 0.0 => Some(a / b), _ => None };
    let pi_band = pi.map(|p| if p > 1.4 { "good" } else if p >= 1.0 { "questionable" } else { "poor" });
    format!(
        r#"<div class="stats stats-vertical sm:stats-horizontal shadow w-full mb-4">
<div class="stat"><div class="stat-title">Total Combustible Gas</div><div class="stat-value text-xl">{tdcg:.1}</div><div class="stat-desc">TDG {tdg:.1}</div></div>
<div class="stat"><div class="stat-title">Thermal ΔT</div><div class="stat-value text-xl">{dt}</div><div class="stat-desc">{tb}</div></div>
<div class="stat"><div class="stat-title">Polarization Index</div><div class="stat-value text-xl">{pi}</div><div class="stat-desc">{pb}</div></div>
</div>"#,
        tdcg = tdcg, tdg = tdg,
        dt = delta_t.map(|d| format!("{d:.1}°C")).unwrap_or_else(|| "—".into()), tb = thermal_band.unwrap_or("—"),
        pi = pi.map(|p| format!("{p:.2}")).unwrap_or_else(|| "—".into()), pb = pi_band.unwrap_or("—"))
}

async fn new_cm(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.condition_monitoring");
    let eq_pre = q.get("equipment").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/condition-monitoring", "Back", "New Condition-Monitoring Test");
    let body = cm_body(&db, &HashMap::new(), eq_pre, true).await;
    Html(page_shell(&sidebar, "New CM Test", &wide_form_page("/sesb-eam/condition-monitoring/create", &header, &body))).into_response()
}

const CM_NUM_FIELDS: &[&str] = &["dga_hydrogen_h2","dga_methane_ch4","dga_ethane_c2h6","dga_ethylene_c2h4","dga_acetylene_c2h2","dga_carbon_monoxide_co","thermal_ambient_temp_c","thermal_max_temp_c","ir_1min_mohm","ir_10min_mohm"];

async fn create_cm(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let equipment_id = match opt_uuid(&form, "equipment_id") { Some(e) => e, None => return bad("Equipment is required") };
    let date = match opt_date(&form, "test_date") { Some(d) => d, None => return bad("Test date is required") };
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &CM_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    // Build dynamic insert over the numeric diagnostic fields + head.
    let mut cols = vec!["id".to_string(), "name".into(), "equipment_id".into(), "equipment_category".into(), "test_type".into(), "test_date".into(), "result_status".into(), "test_lab".into(), "result_summary".into(), "company_id".into()];
    let mut ph = vec!["$1".to_string(), "$2".into(), "$3".into(), "(SELECT equipment_category FROM eam_equipment WHERE id=$3)".into(), "$4".into(), "$5".into(), "$6".into(), "$7".into(), "$8".into(), "$9".into()];
    let mut n = 10;
    let mut nums: Vec<Option<vortex_plugin_sdk::rust_decimal::Decimal>> = Vec::new();
    for c in CM_NUM_FIELDS { cols.push(c.to_string()); ph.push(format!("${n}", n = n)); nums.push(opt_dec(&form, c)); n += 1; }
    let sql = format!("INSERT INTO eam_condition_monitoring ({}) VALUES ({})", cols.join(", "), ph.join(", "));
    let mut qx = vortex_plugin_sdk::sqlx::query(&sql).bind(id).bind(&number).bind(equipment_id)
        .bind(form.get("test_type").map(|s| s.as_str()).unwrap_or("dga")).bind(date)
        .bind(opt_str(&form, "result_status")).bind(opt_str(&form, "test_lab")).bind(opt_str(&form, "result_summary")).bind(company_id);
    for v in nums { qx = qx.bind(v); }
    if let Err(e) = qx.execute(&db).await { error!(error=%e, "cm insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/condition-monitoring/{id}")).into_response()
}

async fn edit_cm(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.condition_monitoring");
    let mut select_cols = vec!["name".to_string(), "equipment_id::text AS equipment_id".into(), "test_type".into(), "test_date::text AS test_date".into(), "result_status".into(), "test_lab".into(), "result_summary".into(), "active::text AS active".into()];
    for c in CM_NUM_FIELDS { select_cols.push(format!("{c}::text AS {c}", c = c)); }
    let sql = format!("SELECT {} FROM eam_condition_monitoring WHERE id=$1", select_cols.join(", "));
    let row = match vortex_plugin_sdk::sqlx::query(&sql).bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["equipment_id","test_type","test_date","result_status","test_lab","result_summary","active"].iter().chain(CM_NUM_FIELDS) {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(*k) { v.insert(k.to_string(), val); }
    }
    let number: Option<String> = row.try_get("name").ok();
    let diag = cm_diagnostics(&v);
    let body = cm_body(&db, &v, None, false).await;
    let header = format!(r#"<a href="/sesb-eam/condition-monitoring" class="btn btn-ghost btn-sm mb-3">← Back</a>
<h1 class="text-2xl font-bold mb-3">CM Test <span class="font-mono text-sm opacity-50">{}</span></h1>"#, esc(number.as_deref().unwrap_or("")));
    let content = format!("<div class=\"max-w-4xl\">{}{}{}</div>", header, diag, wide_form_page(&format!("/sesb-eam/condition-monitoring/{id}"), "", &body));
    Html(page_shell(&sidebar, "CM Test", &content)).into_response()
}

async fn update_cm(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut sets = vec!["test_type=$1".to_string(), "test_date=$2".into(), "result_status=$3".into(), "test_lab=$4".into(), "result_summary=$5".into(), "active=$6".into()];
    let mut n = 7;
    let mut nums: Vec<Option<vortex_plugin_sdk::rust_decimal::Decimal>> = Vec::new();
    for c in CM_NUM_FIELDS { sets.push(format!("{c}=${n}", c = c, n = n)); nums.push(opt_dec(&form, c)); n += 1; }
    let sql = format!("UPDATE eam_condition_monitoring SET {} WHERE id=${n}", sets.join(", "), n = n);
    let mut qx = vortex_plugin_sdk::sqlx::query(&sql)
        .bind(form.get("test_type").map(|s| s.as_str()).unwrap_or("dga")).bind(opt_date(&form, "test_date"))
        .bind(opt_str(&form, "result_status")).bind(opt_str(&form, "test_lab")).bind(opt_str(&form, "result_summary")).bind(form.contains_key("active"));
    for v in nums { qx = qx.bind(v); }
    qx = qx.bind(id);
    let _ = qx.execute(&db).await;
    Redirect::to(&format!("/sesb-eam/condition-monitoring/{id}")).into_response()
}

// ═════════════════════════════════════════════════════════════════════════
// Line patrol / Outage / Vegetation / Troubleshooting — list + create + edit
// ═════════════════════════════════════════════════════════════════════════

const PATROL_TYPES: &[(&str, &str)] = &[("routine","Routine"),("cbm","CBM"),("storm","Storm"),("vegetation","Vegetation"),("emergency","Emergency")];
const PATROL_METHODS: &[(&str, &str)] = &[("","—"),("ground","Ground"),("vehicle","Vehicle"),("uav","UAV"),("climbing","Climbing"),("helicopter","Helicopter")];

async fn list_patrol(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.patrols");
    let config = ListConfig::new("Line Patrols", "eam_line_patrol")
        .custom_select("id, name, patrol_type, patrol_date::text AS dt, patrol_method, anomalies_found, state, active")
        .column(ListColumn::new("name", "Number").sortable().code())
        .column(ListColumn::new("patrol_type", "Type").filterable(&[("routine","Routine"),("cbm","CBM"),("storm","Storm"),("vegetation","Vegetation"),("emergency","Emergency")]))
        .column(ListColumn::new("dt", "Date").sortable())
        .column(ListColumn::new("patrol_method", "Method"))
        .column(ListColumn::new("anomalies_found", "Anomalies"))
        .column(ListColumn::new("state", "State"))
        .detail_url("/sesb-eam/patrols/{id}")
        .create("New Patrol", "/sesb-eam/patrols/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "patrol list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Line Patrols", &render_list(&config, &result, &params, "/sesb-eam/patrols"))).into_response()
}

async fn tline_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_transmission_line WHERE active ORDER BY code", "-- Transmission Line --", sel).await
}
async fn dline_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_distribution_line WHERE active ORDER BY code", "-- Distribution Line --", sel).await
}

async fn patrol_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let tlines = tline_opts(db, v.get("transmission_line_id").and_then(|s| s.parse().ok())).await;
    let dlines = dline_opts(db, v.get("distribution_line_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}",
        select_field("Patrol Type *", "patrol_type", &enum_options(PATROL_TYPES, if g("patrol_type").is_empty() { "routine" } else { g("patrol_type") })),
        date_field("Patrol Date *", "patrol_date", g("patrol_date")),
        select_field("Method", "patrol_method", &enum_options(PATROL_METHODS, g("patrol_method"))),
        select_field("Transmission Line", "transmission_line_id", &tlines),
        select_field("Distribution Line", "distribution_line_id", &dlines),
        num_field("Anomalies Found", "anomalies_found", g("anomalies_found"), "1"),
        num_field("Vegetation Issues", "vegetation_issues", g("vegetation_issues"), "1"),
        num_field("Tower Issues", "tower_issues", g("tower_issues"), "1")));
    format!("{}{}{}", grid, textarea_field("Findings", "findings", g("findings")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_patrol(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.patrols");
    let header = form_header("/sesb-eam/patrols", "Back to Patrols", "New Line Patrol");
    let body = patrol_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Patrol", &wide_form_page("/sesb-eam/patrols/create", &header, &body))).into_response()
}

async fn create_patrol(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let date = match opt_date(&form, "patrol_date") { Some(d) => d, None => return bad("Patrol date is required") };
    let tl = opt_uuid(&form, "transmission_line_id");
    let dl = opt_uuid(&form, "distribution_line_id");
    if tl.is_some() == dl.is_some() { return bad("Specify exactly one of transmission or distribution line (§5.6)"); }
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &LP_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_line_patrol (id, name, patrol_type, patrol_date, patrol_method, transmission_line_id, distribution_line_id, anomalies_found, vegetation_issues, tower_issues, findings, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(id).bind(&number).bind(form.get("patrol_type").map(|s| s.as_str()).unwrap_or("routine")).bind(date)
        .bind(opt_str(&form, "patrol_method")).bind(tl).bind(dl).bind(opt_i32(&form, "anomalies_found")).bind(opt_i32(&form, "vegetation_issues")).bind(opt_i32(&form, "tower_issues"))
        .bind(opt_str(&form, "findings")).bind(company_id).execute(&db).await;
    Redirect::to(&format!("/sesb-eam/patrols/{id}")).into_response()
}

async fn edit_patrol(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.patrols");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, patrol_type, patrol_date::text AS patrol_date, patrol_method, transmission_line_id::text AS transmission_line_id, distribution_line_id::text AS distribution_line_id, anomalies_found::text AS anomalies_found, vegetation_issues::text AS vegetation_issues, tower_issues::text AS tower_issues, findings, active::text AS active FROM eam_line_patrol WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["patrol_type","patrol_date","patrol_method","transmission_line_id","distribution_line_id","anomalies_found","vegetation_issues","tower_issues","findings","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let number: Option<String> = row.try_get("name").ok();
    let body = patrol_body(&db, &v, false).await;
    let header = form_header("/sesb-eam/patrols", "Back to Patrols", &format!("Patrol {}", number.as_deref().unwrap_or("")));
    Html(page_shell(&sidebar, "Patrol", &wide_form_page(&format!("/sesb-eam/patrols/{id}"), &header, &body))).into_response()
}

async fn update_patrol(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_line_patrol SET patrol_type=$1, patrol_date=$2, patrol_method=$3, anomalies_found=$4, vegetation_issues=$5, tower_issues=$6, findings=$7, active=$8 WHERE id=$9")
        .bind(form.get("patrol_type").map(|s| s.as_str()).unwrap_or("routine")).bind(opt_date(&form, "patrol_date")).bind(opt_str(&form, "patrol_method"))
        .bind(opt_i32(&form, "anomalies_found")).bind(opt_i32(&form, "vegetation_issues")).bind(opt_i32(&form, "tower_issues")).bind(opt_str(&form, "findings")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/patrols/{id}")).into_response()
}

// ── Outage ──
const OUTAGE_TYPES: &[(&str, &str)] = &[("planned","Planned"),("unplanned","Unplanned"),("emergency","Emergency")];
const CAUSE_CATS: &[(&str, &str)] = &[("","—"),("equipment_failure","Equipment Failure"),("weather","Weather"),("vegetation","Vegetation"),("third_party","Third Party"),("animal","Animal"),("overload","Overload"),("human_error","Human Error"),("unknown","Unknown")];
const OUTAGE_STATES: &[(&str, &str)] = &[("ongoing","Ongoing"),("restored","Restored"),("cancelled","Cancelled")];

async fn substation_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_substation WHERE active ORDER BY code", "-- Substation --", sel).await
}

async fn list_outage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.outages");
    let config = ListConfig::new("Outages", "eam_outage")
        .custom_from("eam_outage o LEFT JOIN eam_substation s ON s.id=o.substation_id")
        .custom_select("o.id, o.name, s.name AS substation, o.outage_type, o.start_datetime::text AS st, o.customers_affected, o.state, \
            round(EXTRACT(EPOCH FROM (COALESCE(o.end_datetime, NOW()) - o.start_datetime))/60.0)::text AS dur_min")
        .column(ListColumn::new("name", "Number").sortable().code().sql_expr("o.name"))
        .column(ListColumn::new("substation", "Substation").searchable().sql_expr("s.name"))
        .column(ListColumn::new("outage_type", "Type").filterable(&[("planned","Planned"),("unplanned","Unplanned"),("emergency","Emergency")]).badge(&[("planned","Planned","badge-info"),("unplanned","Unplanned","badge-warning"),("emergency","Emergency","badge-error")]).sql_expr("o.outage_type"))
        .column(ListColumn::new("st", "Start").sortable().sql_expr("o.start_datetime"))
        .column(ListColumn::new("customers_affected", "Customers").sql_expr("o.customers_affected"))
        .column(ListColumn::new("dur_min", "Duration (min)").sql_expr("1"))
        .column(ListColumn::new("state", "State").badge(&[("ongoing","Ongoing","badge-error"),("restored","Restored","badge-success"),("cancelled","Cancelled","badge-ghost")]).sql_expr("o.state"))
        .detail_url("/sesb-eam/outages/{id}")
        .create("Log Outage", "/sesb-eam/outages/new")
        .default_sort("st");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "outage list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Outages", &render_list(&config, &result, &params, "/sesb-eam/outages"))).into_response()
}

async fn outage_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let subs = substation_opts(db, v.get("substation_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}",
        select_field("Substation *", "substation_id", &subs),
        text_field("Feeder", "feeder", g("feeder"), false),
        select_field("Outage Type *", "outage_type", &enum_options(OUTAGE_TYPES, if g("outage_type").is_empty() { "unplanned" } else { g("outage_type") })),
        select_field("Cause Category", "cause_category", &enum_options(CAUSE_CATS, g("cause_category"))),
        text_field("Start (ISO datetime) *", "start_datetime", g("start_datetime"), true),
        text_field("End (ISO datetime)", "end_datetime", g("end_datetime"), false),
        num_field("Customers Affected *", "customers_affected", g("customers_affected"), "1"),
        select_field("State *", "state", &enum_options(OUTAGE_STATES, if g("state").is_empty() { "ongoing" } else { g("state") }))));
    let mej = checkbox("is_major_event", "Major Event Day (excluded from normalised SAIDI/SAIFI)", g("is_major_event") == "true");
    format!("{}{}{}{}{}", grid, mej, textarea_field("Cause Detail", "cause_detail", g("cause_detail")), textarea_field("Description", "description", g("description")), if is_new { String::new() } else { String::new() })
}

async fn new_outage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.outages");
    let header = form_header("/sesb-eam/outages", "Back to Outages", "Log Outage");
    let body = outage_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "Log Outage", &wide_form_page("/sesb-eam/outages/create", &header, &body))).into_response()
}

async fn create_outage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let substation_id = match opt_uuid(&form, "substation_id") { Some(s) => s, None => return bad("Substation is required") };
    let start = match form.get("start_datetime").and_then(|s| parse_dt(s)) { Some(d) => d, None => return bad("Valid start datetime required (YYYY-MM-DD HH:MM)") };
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &OUT_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_outage (id, name, substation_id, feeder, region_id, zon_id, kawasan_id, outage_type, cause_category, cause_detail, start_datetime, end_datetime, customers_affected, state, is_major_event, description, company_id) \
         SELECT $1,$2,$3,$4, (SELECT si.region_id FROM eam_site si WHERE si.id=s.site_id), (SELECT si.zon_id FROM eam_site si WHERE si.id=s.site_id), (SELECT si.kawasan_id FROM eam_site si WHERE si.id=s.site_id), \
            $5,$6,$7,$8,$9,$10,$11,$12,$13,$14 FROM eam_substation s WHERE s.id=$3")
        .bind(id).bind(&number).bind(substation_id).bind(opt_str(&form, "feeder"))
        .bind(form.get("outage_type").map(|s| s.as_str()).unwrap_or("unplanned")).bind(opt_str(&form, "cause_category")).bind(opt_str(&form, "cause_detail"))
        .bind(start).bind(form.get("end_datetime").and_then(|s| parse_dt(s))).bind(opt_i32(&form, "customers_affected").unwrap_or(0))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("ongoing")).bind(form.contains_key("is_major_event")).bind(opt_str(&form, "description")).bind(company_id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/outages/{id}")).into_response()
}

fn parse_dt(s: &str) -> Option<vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>> {
    use vortex_plugin_sdk::chrono::{NaiveDateTime, TimeZone, Utc};
    let s = s.trim();
    for fmt in ["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) { return Some(Utc.from_utc_datetime(&ndt)); }
    }
    None
}

async fn edit_outage(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.outages");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, substation_id::text AS substation_id, feeder, outage_type, cause_category, cause_detail, to_char(start_datetime,'YYYY-MM-DD\"T\"HH24:MI') AS start_datetime, to_char(end_datetime,'YYYY-MM-DD\"T\"HH24:MI') AS end_datetime, customers_affected::text AS customers_affected, state, is_major_event::text AS is_major_event, description FROM eam_outage WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["substation_id","feeder","outage_type","cause_category","cause_detail","start_datetime","end_datetime","customers_affected","state","is_major_event","description"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let number: Option<String> = row.try_get("name").ok();
    let body = outage_body(&db, &v, false).await;
    let header = form_header("/sesb-eam/outages", "Back to Outages", &format!("Outage {}", number.as_deref().unwrap_or("")));
    Html(page_shell(&sidebar, "Outage", &wide_form_page(&format!("/sesb-eam/outages/{id}"), &header, &body))).into_response()
}

async fn update_outage(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_outage SET feeder=$1, outage_type=$2, cause_category=$3, cause_detail=$4, start_datetime=COALESCE($5, start_datetime), end_datetime=$6, customers_affected=$7, state=$8, is_major_event=$9, description=$10 WHERE id=$11")
        .bind(opt_str(&form, "feeder")).bind(form.get("outage_type").map(|s| s.as_str()).unwrap_or("unplanned")).bind(opt_str(&form, "cause_category")).bind(opt_str(&form, "cause_detail"))
        .bind(form.get("start_datetime").and_then(|s| parse_dt(s))).bind(form.get("end_datetime").and_then(|s| parse_dt(s))).bind(opt_i32(&form, "customers_affected").unwrap_or(0))
        .bind(form.get("state").map(|s| s.as_str()).unwrap_or("ongoing")).bind(form.contains_key("is_major_event")).bind(opt_str(&form, "description")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/outages/{id}")).into_response()
}

// ── Vegetation ──
const TERRAINS: &[(&str, &str)] = &[("","—"),("flat","Flat"),("hilly","Hilly"),("forest","Forest"),("swamp","Swamp"),("farmland","Farmland"),("urban","Urban")];
const DIVISIONS: &[(&str, &str)] = &[("distribution","Distribution"),("transmission","Transmission")];

async fn list_veg(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.vegetation");
    let config = ListConfig::new("Vegetation Sections", "eam_vegetation_section")
        .custom_select("id, name, division, terrain, required_clearance_m::text AS req, actual_clearance_m::text AS act, last_cleared_date::text AS lc, active")
        .column(ListColumn::new("name", "Name").searchable())
        .column(ListColumn::new("division", "Division").filterable(&[("transmission","Transmission"),("distribution","Distribution")]))
        .column(ListColumn::new("terrain", "Terrain"))
        .column(ListColumn::new("req", "Req Clearance (m)"))
        .column(ListColumn::new("act", "Actual (m)"))
        .column(ListColumn::new("lc", "Last Cleared"))
        .detail_url("/sesb-eam/vegetation/{id}")
        .create("New Section", "/sesb-eam/vegetation/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "veg list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Vegetation", &render_list(&config, &result, &params, "/sesb-eam/vegetation"))).into_response()
}

async fn veg_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let tlines = tline_opts(db, v.get("transmission_line_id").and_then(|s| s.parse().ok())).await;
    let dlines = dline_opts(db, v.get("distribution_line_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}{}",
        text_field("Name", "name", g("name"), false),
        select_field("Division *", "division", &enum_options(DIVISIONS, if g("division").is_empty() { "distribution" } else { g("division") })),
        select_field("Terrain", "terrain", &enum_options(TERRAINS, g("terrain"))),
        select_field("Transmission Line", "transmission_line_id", &tlines),
        select_field("Distribution Line", "distribution_line_id", &dlines),
        num_field("Length (m)", "length_m", g("length_m"), "0.1"),
        num_field("Required Clearance (m)", "required_clearance_m", g("required_clearance_m"), "0.1"),
        num_field("Actual Clearance (m)", "actual_clearance_m", g("actual_clearance_m"), "0.1"),
        date_field("Last Cleared", "last_cleared_date", g("last_cleared_date"))));
    format!("{}{}{}", grid, textarea_field("Notes", "notes", g("notes")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_veg(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.vegetation");
    let header = form_header("/sesb-eam/vegetation", "Back", "New Vegetation Section");
    let body = veg_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Vegetation Section", &wide_form_page("/sesb-eam/vegetation/create", &header, &body))).into_response()
}

async fn create_veg(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_vegetation_section (id, name, division, terrain, transmission_line_id, distribution_line_id, length_m, required_clearance_m, actual_clearance_m, last_cleared_date, notes, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(id).bind(opt_str(&form, "name")).bind(form.get("division").map(|s| s.as_str()).unwrap_or("distribution")).bind(opt_str(&form, "terrain"))
        .bind(opt_uuid(&form, "transmission_line_id")).bind(opt_uuid(&form, "distribution_line_id")).bind(opt_dec(&form, "length_m"))
        .bind(opt_dec(&form, "required_clearance_m")).bind(opt_dec(&form, "actual_clearance_m")).bind(opt_date(&form, "last_cleared_date")).bind(opt_str(&form, "notes")).bind(company_id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/vegetation/{id}")).into_response()
}

async fn edit_veg(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.vegetation");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, division, terrain, transmission_line_id::text AS transmission_line_id, distribution_line_id::text AS distribution_line_id, length_m::text AS length_m, required_clearance_m::text AS required_clearance_m, actual_clearance_m::text AS actual_clearance_m, last_cleared_date::text AS last_cleared_date, notes, active::text AS active FROM eam_vegetation_section WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["name","division","terrain","transmission_line_id","distribution_line_id","length_m","required_clearance_m","actual_clearance_m","last_cleared_date","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let body = veg_body(&db, &v, false).await;
    let header = form_header("/sesb-eam/vegetation", "Back to Vegetation", "Edit Vegetation Section");
    Html(page_shell(&sidebar, "Vegetation Section", &wide_form_page(&format!("/sesb-eam/vegetation/{id}"), &header, &body))).into_response()
}

async fn update_veg(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_vegetation_section SET name=$1, division=$2, terrain=$3, transmission_line_id=$4, distribution_line_id=$5, length_m=$6, required_clearance_m=$7, actual_clearance_m=$8, last_cleared_date=$9, notes=$10, active=$11 WHERE id=$12")
        .bind(opt_str(&form, "name")).bind(form.get("division").map(|s| s.as_str()).unwrap_or("distribution")).bind(opt_str(&form, "terrain"))
        .bind(opt_uuid(&form, "transmission_line_id")).bind(opt_uuid(&form, "distribution_line_id")).bind(opt_dec(&form, "length_m"))
        .bind(opt_dec(&form, "required_clearance_m")).bind(opt_dec(&form, "actual_clearance_m")).bind(opt_date(&form, "last_cleared_date")).bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/vegetation/{id}")).into_response()
}

// ── Troubleshooting rule ──
const TSR_PRIORITIES: &[(&str, &str)] = &[("0","Low"),("1","Normal"),("2","High")];
const TSR_CATS: &[(&str, &str)] = &[("","All categories"),("transformer","Transformer"),("switchgear","Switchgear"),("rmu","RMU"),("protection","Protection"),("scada","SCADA"),("battery","Battery"),("capacitor","Capacitor"),("ner","NER"),("feeder_pillar","Feeder Pillar"),("cable","Cable")];

async fn list_tsr(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.troubleshooting");
    let config = ListConfig::new("Troubleshooting Rules", "eam_troubleshooting_rule")
        .custom_select("id, name, priority, equipment_category, keywords, active")
        .column(ListColumn::new("name", "Name").searchable())
        .column(ListColumn::new("priority", "Priority").badge(&[("0","Low","badge-ghost"),("1","Normal","badge-info"),("2","High","badge-warning")]))
        .column(ListColumn::new("equipment_category", "Category"))
        .column(ListColumn::new("keywords", "Keywords").searchable())
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning"))
        .detail_url("/sesb-eam/troubleshooting/{id}")
        .create("New Rule", "/sesb-eam/troubleshooting/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "tsr list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Troubleshooting Rules", &render_list(&config, &result, &params, "/sesb-eam/troubleshooting"))).into_response()
}

fn tsr_body(name: &str, priority: &str, cat: &str, keywords: &str, guidance: &str, active: bool, is_new: bool) -> String {
    format!("{}{}{}{}{}{}",
        text_field("Name", "name", name, true),
        select_field("Priority", "priority", &enum_options(TSR_PRIORITIES, priority)),
        select_field("Equipment Category", "equipment_category", &enum_options(TSR_CATS, cat)),
        text_field("Keywords (comma/space-separated symptoms)", "keywords", keywords, false),
        textarea_field("Guidance (safety-first numbered steps)", "guidance", guidance),
        active_field(active, is_new))
}

async fn new_tsr(
    State(state): State<Arc<AppState>>, Db(_db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.troubleshooting");
    let header = form_header("/sesb-eam/troubleshooting", "Back", "New Troubleshooting Rule");
    let body = tsr_body("", "1", "", "", "", true, true);
    Html(page_shell(&sidebar, "New Rule", &form_page("/sesb-eam/troubleshooting/create", &header, &body))).into_response()
}

async fn create_tsr(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    let guidance = form.get("guidance").cloned().unwrap_or_default();
    if name.trim().is_empty() || guidance.trim().is_empty() { return bad("Name and guidance are required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_troubleshooting_rule (id, name, priority, equipment_category, keywords, guidance, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(id).bind(&name).bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1")).bind(opt_str(&form, "equipment_category"))
        .bind(opt_str(&form, "keywords")).bind(&guidance).bind(company_id).execute(&db).await;
    Redirect::to(&format!("/sesb-eam/troubleshooting/{id}")).into_response()
}

async fn edit_tsr(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.troubleshooting");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, priority, equipment_category, keywords, guidance, active FROM eam_troubleshooting_rule WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let name: String = row.get("name");
    let priority: String = row.get("priority");
    let cat: Option<String> = row.try_get("equipment_category").ok();
    let keywords: Option<String> = row.try_get("keywords").ok();
    let guidance: String = row.get("guidance");
    let active: bool = row.try_get("active").unwrap_or(true);
    let header = form_header("/sesb-eam/troubleshooting", "Back to Rules", &format!("Edit {}", name));
    let body = tsr_body(&name, &priority, cat.as_deref().unwrap_or(""), keywords.as_deref().unwrap_or(""), &guidance, active, false);
    Html(page_shell(&sidebar, "Edit Rule", &form_page(&format!("/sesb-eam/troubleshooting/{id}"), &header, &body))).into_response()
}

async fn update_tsr(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    let guidance = form.get("guidance").cloned().unwrap_or_default();
    if name.trim().is_empty() || guidance.trim().is_empty() { return bad("Name and guidance are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_troubleshooting_rule SET name=$1, priority=$2, equipment_category=$3, keywords=$4, guidance=$5, active=$6 WHERE id=$7")
        .bind(&name).bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1")).bind(opt_str(&form, "equipment_category"))
        .bind(opt_str(&form, "keywords")).bind(&guidance).bind(form.contains_key("active")).bind(id).execute(&db).await;
    Redirect::to(&format!("/sesb-eam/troubleshooting/{id}")).into_response()
}
