//! Checklist templates (config) + line instantiation and scoring (§4.8).

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
use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/checklist-templates", get(list_tpl))
        .route("/sesb-eam/checklist-templates/new", get(new_tpl))
        .route("/sesb-eam/checklist-templates/create", post(create_tpl))
        .route("/sesb-eam/checklist-templates/{id}", get(edit_tpl))
        .route("/sesb-eam/checklist-templates/{id}", post(update_tpl))
        .route("/sesb-eam/checklist-templates/{id}/items/add", post(add_item))
        .route("/sesb-eam/checklist-items/{id}/delete", post(delete_item))
}

pub(crate) const INPUT_TYPES: &[(&str, &str)] = &[
    ("pass_fail","Pass/Fail"),("yes_no","Yes/No"),("measurement","Measurement"),("text","Text"),("selection","Selection"),("rating","Rating"),
];
const EQUIP_CATS: &[(&str, &str)] = &[
    ("transformer","Transformer"),("switchgear","Switchgear"),("rmu","RMU"),("protection","Protection"),
    ("control_panel","Control Panel"),("scada","SCADA"),("battery","Battery"),("capacitor","Capacitor"),
    ("ner","NER"),("feeder_pillar","Feeder Pillar"),("cable","Cable"),("other","Other"),
];
const MAINT_TYPES: &[(&str, &str)] = &[
    ("pm","Preventive (PM)"),("cm","Corrective (CM)"),("emergency","Emergency"),("inspection","Inspection"),("testing","Testing"),("overhaul","Overhaul"),
];

async fn list_tpl(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.checklist_templates");
    let config = ListConfig::new("Checklist Templates", "eam_checklist_template")
        .custom_from("eam_checklist_template t LEFT JOIN (SELECT template_id, COUNT(*) c FROM eam_checklist_template_item GROUP BY template_id) i ON i.template_id=t.id")
        .custom_select("t.id, t.name, t.equipment_category, t.maintenance_type, t.version, COALESCE(i.c,0)::text AS items, t.active")
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("t.name"))
        .column(ListColumn::new("equipment_category", "Category").sql_expr("t.equipment_category"))
        .column(ListColumn::new("maintenance_type", "Type").sql_expr("t.maintenance_type"))
        .column(ListColumn::new("items", "Items").sql_expr("COALESCE(i.c,0)"))
        .column(ListColumn::new("version", "Ver").sql_expr("t.version"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Archived","badge-warning").sql_expr("t.active"))
        .detail_url("/sesb-eam/checklist-templates/{id}")
        .create("New Template", "/sesb-eam/checklist-templates/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "tpl list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Checklist Templates", &render_list(&config, &result, &params, "/sesb-eam/checklist-templates"))).into_response()
}

fn tpl_body(name: &str, cat: &str, mtype: &str, version: &str, desc: &str, active: bool, is_new: bool) -> String {
    format!("{}{}{}{}{}{}",
        text_field("Name", "name", name, true),
        select_field("Equipment Category *", "equipment_category", &enum_options(EQUIP_CATS, cat)),
        select_field("Maintenance Type *", "maintenance_type", &enum_options(MAINT_TYPES, mtype)),
        num_field("Version", "version", version, "1"),
        textarea_field("Description", "description", desc),
        active_field(active, is_new))
}

async fn new_tpl(
    State(state): State<Arc<AppState>>, Db(_db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.checklist_templates");
    let header = form_header("/sesb-eam/checklist-templates", "Back to Templates", "New Checklist Template");
    let body = tpl_body("", "transformer", "pm", "1", "", true, true);
    Html(page_shell(&sidebar, "New Template", &form_page("/sesb-eam/checklist-templates/create", &header, &body))).into_response()
}

async fn create_tpl(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Name is required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_checklist_template (id, name, equipment_category, maintenance_type, version, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(id).bind(&name).bind(form.get("equipment_category").map(|s| s.as_str()).unwrap_or("transformer"))
        .bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm")).bind(opt_i32(&form, "version").unwrap_or(1))
        .bind(opt_str(&form, "description")).bind(company_id).execute(&db).await;
    if let Err(e) = res { error!(error=%e, "tpl insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/checklist-templates/{id}")).into_response()
}

async fn edit_tpl(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.checklist_templates");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, equipment_category, maintenance_type, version, description, active FROM eam_checklist_template WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let name: String = row.get("name");
    let cat: String = row.get("equipment_category");
    let mtype: String = row.get("maintenance_type");
    let version: i32 = row.try_get("version").unwrap_or(1);
    let desc: Option<String> = row.try_get("description").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let body = tpl_body(&name, &cat, &mtype, &version.to_string(), desc.as_deref().unwrap_or(""), active, false);

    // Items
    let items = vortex_plugin_sdk::sqlx::query("SELECT id, name, section, input_type, is_required, is_critical, is_scored, weight::text AS weight FROM eam_checklist_template_item WHERE template_id=$1 ORDER BY sequence, name").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut item_rows = String::new();
    for r in &items {
        let iid: Uuid = r.get("id");
        let iname: String = r.get("name");
        let sec: Option<String> = r.try_get("section").ok();
        let itype: String = r.get("input_type");
        let req: bool = r.try_get("is_required").unwrap_or(false);
        let crit: bool = r.try_get("is_critical").unwrap_or(false);
        let flags = format!("{}{}", if req { "<span class=\"badge badge-xs badge-info\">req</span> " } else { "" }, if crit { "<span class=\"badge badge-xs badge-error\">critical</span>" } else { "" });
        item_rows.push_str(&format!(
            r#"<tr><td>{name}</td><td>{sec}</td><td>{itype}</td><td>{flags}</td><td><form method="POST" action="/sesb-eam/checklist-items/{iid}/delete" onsubmit="return confirm('Delete item?')"><button class="btn btn-ghost btn-xs text-error">✕</button></form></td></tr>"#,
            name = esc(&iname), sec = esc(sec.as_deref().unwrap_or("—")), itype = esc(&itype), flags = flags, iid = iid));
    }
    if item_rows.is_empty() { item_rows.push_str(r#"<tr><td colspan="5" class="text-base-content/50">No items</td></tr>"#); }
    let add_form = format!(
        r#"<form method="POST" action="/sesb-eam/checklist-templates/{id}/items/add" class="grid grid-cols-2 md:grid-cols-6 gap-2 items-end mt-3">
<input name="name" class="input input-bordered input-sm md:col-span-2" placeholder="Item / check description" required/>
<input name="section" class="input input-bordered input-sm" placeholder="Section"/>
<select name="input_type" class="select select-bordered select-sm">{itypes}</select>
<label class="label cursor-pointer gap-1"><input type="checkbox" name="is_required" class="checkbox checkbox-xs"/><span class="label-text text-xs">Req</span></label>
<label class="label cursor-pointer gap-1"><input type="checkbox" name="is_critical" class="checkbox checkbox-xs"/><span class="label-text text-xs">Critical</span></label>
<label class="label cursor-pointer gap-1"><input type="checkbox" name="is_scored" class="checkbox checkbox-xs"/><span class="label-text text-xs">Scored</span></label>
<button class="btn btn-primary btn-sm">Add Item</button></form>"#,
        id = id, itypes = enum_options(INPUT_TYPES, "pass_fail"));

    let header = form_header("/sesb-eam/checklist-templates", "Back to Templates", &format!("Edit {}", name));
    let content = format!(
        r#"{form}<div class="max-w-2xl mt-6"><div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-2">Items</h2>
<table class="table table-sm"><thead><tr><th>Name</th><th>Section</th><th>Type</th><th>Flags</th><th></th></tr></thead><tbody>{items}</tbody></table>
{add}</div></div></div>"#,
        form = form_page(&format!("/sesb-eam/checklist-templates/{id}"), &header, &body), items = item_rows, add = add_form);
    Html(page_shell(&sidebar, &format!("Template {}", name), &content)).into_response()
}

async fn update_tpl(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Name is required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_checklist_template SET name=$1, equipment_category=$2, maintenance_type=$3, version=$4, description=$5, active=$6 WHERE id=$7")
        .bind(&name).bind(form.get("equipment_category").map(|s| s.as_str()).unwrap_or("transformer"))
        .bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm")).bind(opt_i32(&form, "version").unwrap_or(1))
        .bind(opt_str(&form, "description")).bind(form.contains_key("active")).bind(id).execute(&db).await;
    Redirect::to(&format!("/sesb-eam/checklist-templates/{id}")).into_response()
}

async fn add_item(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Item name required"); }
    let seq: i32 = vortex_plugin_sdk::sqlx::query_scalar::<_, Option<i32>>("SELECT MAX(sequence)+1 FROM eam_checklist_template_item WHERE template_id=$1").bind(id).fetch_optional(&db).await.ok().flatten().flatten().unwrap_or(0);
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_checklist_template_item (id, template_id, name, section, sequence, input_type, is_required, is_critical, is_scored) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(Uuid::now_v7()).bind(id).bind(&name).bind(opt_str(&form, "section")).bind(seq)
        .bind(form.get("input_type").map(|s| s.as_str()).unwrap_or("pass_fail"))
        .bind(form.contains_key("is_required")).bind(form.contains_key("is_critical")).bind(form.contains_key("is_scored"))
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/checklist-templates/{id}")).into_response()
}

async fn delete_item(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let tpl: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT template_id FROM eam_checklist_template_item WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM eam_checklist_template_item WHERE id=$1").bind(id).execute(&db).await;
    Redirect::to(&tpl.map(|t| format!("/sesb-eam/checklist-templates/{t}")).unwrap_or_else(|| "/sesb-eam/checklist-templates".into())).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Instantiation + scoring (used by maintenance.rs)
// ─────────────────────────────────────────────────────────────────────────

/// Copy a template's items into checklist lines on a maintenance order.
pub async fn instantiate(db: &PgPool, maintenance_id: Uuid, template_id: Uuid) -> Result<(), vortex_plugin_sdk::sqlx::Error> {
    let items = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, description, sequence, section, input_type, measurement_unit, measurement_min, measurement_max, rating_scale_max, is_required, is_critical, is_scored, weight FROM eam_checklist_template_item WHERE template_id=$1 ORDER BY sequence")
        .bind(template_id).fetch_all(db).await?;
    for it in &items {
        let item_id: Uuid = it.get("id");
        // selection options serialized as "value|name" lines
        let opts: Vec<(String, String)> = vortex_plugin_sdk::sqlx::query("SELECT value, name FROM eam_checklist_selection_option WHERE template_item_id=$1 ORDER BY sequence")
            .bind(item_id).fetch_all(db).await.unwrap_or_default()
            .iter().map(|r| (r.get::<String, _>("value"), r.get::<String, _>("name"))).collect();
        let opts_text = opts.iter().map(|(v, n)| format!("{v}|{n}")).collect::<Vec<_>>().join("\n");
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO eam_checklist_line (id, maintenance_id, template_item_id, name, description, sequence, section, input_type, measurement_unit, measurement_min, measurement_max, selection_options, rating_scale_max, is_required, is_critical, is_scored, weight) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)")
            .bind(Uuid::now_v7()).bind(maintenance_id).bind(item_id)
            .bind(it.get::<String, _>("name")).bind(it.try_get::<Option<String>, _>("description").ok().flatten())
            .bind(it.get::<i32, _>("sequence")).bind(it.try_get::<Option<String>, _>("section").ok().flatten())
            .bind(it.get::<String, _>("input_type")).bind(it.try_get::<Option<String>, _>("measurement_unit").ok().flatten())
            .bind(it.try_get::<Option<vortex_plugin_sdk::rust_decimal::Decimal>, _>("measurement_min").ok().flatten())
            .bind(it.try_get::<Option<vortex_plugin_sdk::rust_decimal::Decimal>, _>("measurement_max").ok().flatten())
            .bind(if opts_text.is_empty() { None } else { Some(opts_text) })
            .bind(it.try_get::<Option<i32>, _>("rating_scale_max").ok().flatten())
            .bind(it.get::<bool, _>("is_required")).bind(it.get::<bool, _>("is_critical")).bind(it.get::<bool, _>("is_scored"))
            .bind(it.get::<vortex_plugin_sdk::rust_decimal::Decimal, _>("weight"))
            .execute(db).await?;
    }
    Ok(())
}

/// Computed checklist roll-up for an order (§4.8).
pub struct ChecklistRollup {
    pub total: i64,
    pub completed: i64,
    pub progress: f64,
    pub score: f64,
    pub has_critical_failure: bool,
    pub result: &'static str,
}

pub async fn rollup(db: &PgPool, maintenance_id: Uuid) -> ChecklistRollup {
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT input_type, is_critical, is_scored, weight::float8 AS weight, rating_scale_max, measurement_min::float8 AS mn, measurement_max::float8 AS mx, value_pass_fail, value_yes_no, value_measurement::float8 AS vm, value_text, value_selection, value_rating FROM eam_checklist_line WHERE maintenance_id=$1")
        .bind(maintenance_id).fetch_all(db).await.unwrap_or_default();
    let total = lines.len() as i64;
    let mut completed = 0i64;
    let mut score_sum = 0.0f64;
    let mut weight_sum = 0.0f64;
    let mut has_crit_fail = false;
    for l in &lines {
        let itype: String = l.get("input_type");
        let is_critical: bool = l.try_get("is_critical").unwrap_or(false);
        let is_scored: bool = l.try_get("is_scored").unwrap_or(false);
        let weight: f64 = l.try_get("weight").unwrap_or(1.0);
        let (has_value, line_score, is_failed) = score_line(l, &itype);
        if has_value { completed += 1; }
        if is_failed && is_critical { has_crit_fail = true; }
        if is_scored && has_value {
            score_sum += line_score * weight;
            weight_sum += weight;
        }
    }
    let progress = if total > 0 { completed as f64 / total as f64 * 100.0 } else { 0.0 };
    let score = if weight_sum > 0.0 { score_sum / weight_sum } else { 0.0 };
    let result = if completed == 0 { "not_started" }
        else if has_crit_fail || (weight_sum > 0.0 && score < 50.0) { "fail" }
        else if completed < total { "in_progress" }
        else if score >= 80.0 { "pass" }
        else { "pass_with_remarks" };
    ChecklistRollup { total, completed, progress, score, has_critical_failure: has_crit_fail, result }
}

/// (has_value, 0-100 score, is_failed) for a checklist line.
fn score_line(l: &vortex_plugin_sdk::sqlx::postgres::PgRow, itype: &str) -> (bool, f64, bool) {
    match itype {
        "pass_fail" => match l.try_get::<Option<String>, _>("value_pass_fail").ok().flatten().as_deref() {
            Some("pass") => (true, 100.0, false),
            Some("fail") => (true, 0.0, true),
            Some("na") => (true, 100.0, false),
            _ => (false, 0.0, false),
        },
        "yes_no" => match l.try_get::<Option<String>, _>("value_yes_no").ok().flatten().as_deref() {
            Some("yes") => (true, 100.0, false),
            Some("no") => (true, 0.0, true),
            _ => (false, 0.0, false),
        },
        "measurement" => match l.try_get::<Option<f64>, _>("vm").ok().flatten() {
            Some(v) => {
                let mn = l.try_get::<Option<f64>, _>("mn").ok().flatten();
                let mx = l.try_get::<Option<f64>, _>("mx").ok().flatten();
                let in_range = mn.map(|m| v >= m).unwrap_or(true) && mx.map(|m| v <= m).unwrap_or(true);
                (true, if in_range { 100.0 } else { 0.0 }, !in_range)
            }
            None => (false, 0.0, false),
        },
        "rating" => match l.try_get::<Option<i32>, _>("value_rating").ok().flatten() {
            Some(v) => {
                let max = l.try_get::<Option<i32>, _>("rating_scale_max").ok().flatten().unwrap_or(5).max(1);
                (true, (v as f64 / max as f64 * 100.0).min(100.0), false)
            }
            None => (false, 0.0, false),
        },
        "text" => (l.try_get::<Option<String>, _>("value_text").ok().flatten().is_some(), 100.0, false),
        "selection" => (l.try_get::<Option<String>, _>("value_selection").ok().flatten().is_some(), 100.0, false),
        _ => (false, 0.0, false),
    }
}
