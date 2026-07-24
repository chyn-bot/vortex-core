//! Equipment / Component / Part CRUD (§3.2) with the category-specific
//! detail forms (§3.3, via [`super::spec`]), MNEC asset-ID composition
//! (§4.9) and the health / age / action-plan formulas (§4.1).

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

use super::spec;
use super::*;
use vortex_plugin_sdk::framework::list::{
    execute_list, render_list, ListColumn, ListConfig, ListParams,
};

/// `EQP/000001`, `CMP/000001`, `PRT/000001`.
const EQP_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.equipment", "EQP").with_padding(6);
const CMP_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.component", "CMP").with_padding(6);
const PRT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.part", "PRT").with_padding(6);

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/equipment", get(list_equipment))
        .route("/sesb-eam/equipment/new", get(new_equipment))
        .route("/sesb-eam/equipment/create", post(create_equipment))
        .route("/sesb-eam/equipment/{id}", get(edit_equipment))
        .route("/sesb-eam/equipment/{id}", post(update_equipment))
        .route("/sesb-eam/equipment/{id}/delete", post(delete_equipment))
        // Components
        .route("/sesb-eam/components/new", get(new_component))
        .route("/sesb-eam/components/create", post(create_component))
        .route("/sesb-eam/components/{id}", get(edit_component))
        .route("/sesb-eam/components/{id}", post(update_component))
        .route("/sesb-eam/components/{id}/delete", post(delete_component))
        // Parts
        .route("/sesb-eam/parts/new", get(new_part))
        .route("/sesb-eam/parts/create", post(create_part))
        .route("/sesb-eam/parts/{id}", post(update_part))
        .route("/sesb-eam/parts/{id}/delete", post(delete_part))
}

const EQUIP_CATEGORIES: &[(&str, &str)] = &[
    ("transformer","Transformer"),("switchgear","Switchgear"),("rmu","RMU"),("motorised_rmu","Motorised RMU"),
    ("protection","Protection"),("control_panel","Control Panel"),("scada","SCADA"),("rtu","RTU"),
    ("battery","Battery"),("charger","Charger"),("capacitor","Capacitor"),("ner","NER"),
    ("feeder_pillar","Feeder Pillar"),("recloser","Recloser"),("sectionaliser","Sectionaliser"),
    ("metering","Metering"),("busbar","Busbar"),("isolator","Isolator"),("earthing","Earthing"),
    ("surge_arrester","Surge Arrester"),("cable","Cable"),("elb","ELB"),("cable_bridge","Cable Bridge"),
    ("auxiliary","Auxiliary"),("other","Other"),
];
const OP_STATUSES: &[(&str, &str)] = &[
    ("operational","Operational"),("standby","Standby"),("out_of_service","Out of Service"),("under_repair","Under Repair"),("decommissioned","Decommissioned"),
];
const CONDITIONS: &[(&str, &str)] = &[("excellent","Excellent"),("good","Good"),("fair","Fair"),("poor","Poor"),("critical","Critical")];
const RISKS: &[(&str, &str)] = &[("low","Low"),("medium","Medium"),("high","High"),("critical","Critical")];

fn vstate_badge(s: &str) -> String {
    let (label, cls) = match s {
        "draft" => ("Draft","badge-ghost"), "submitted" => ("Submitted","badge-info"),
        "verified" => ("Verified","badge-warning"), "approved" => ("Approved","badge-success"),
        "rejected" => ("Rejected","badge-error"), _ => (s,"badge-ghost"),
    };
    format!(r#"<span class="badge {cls}">{label}</span>"#, cls = cls, label = label)
}

// ─────────────────────────────────────────────────────────────────────────
// Computed values (§4.1)
// ─────────────────────────────────────────────────────────────────────────

struct Computed {
    health_index: f64,
    age_years: Option<i64>,
    useful_life_pct: Option<f64>,
    age_group: Option<&'static str>,
    end_of_life: Option<String>,
    action_plan: &'static str,
}

fn condition_score(c: &str) -> f64 {
    match c { "excellent" => 100.0, "good" => 80.0, "fair" => 60.0, "poor" => 40.0, "critical" => 20.0, _ => 50.0 }
}
fn operational_factor(s: &str) -> f64 {
    match s { "operational" => 1.0, "standby" => 0.95, "out_of_service" => 0.5, "under_repair" => 0.6, "decommissioned" => 0.0, _ => 1.0 }
}
fn age_group_of(age: i64) -> &'static str {
    if age <= 5 { "0-5" } else if age <= 15 { "6-15" } else if age <= 25 { "16-25" } else if age <= 35 { "26-35" } else { "36+" }
}

fn compute(condition: &str, op_status: &str, commissioning: Option<&str>, useful_life: Option<i32>, design_life: Option<i32>, risk: &str, failure_record: i32) -> Computed {
    let health = condition_score(condition) * operational_factor(op_status);
    let cdate = commissioning.and_then(|d| d.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok());
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    let age = cdate.map(|d| ((today - d).num_days() as f64 / 365.25).floor() as i64);
    let ulife = useful_life.filter(|v| *v > 0);
    let pct = age.zip(ulife).map(|(a, u)| a as f64 / u as f64 * 100.0);
    let eol = cdate.map(|d| {
        let dl = design_life.unwrap_or(25);
        (d + vortex_plugin_sdk::chrono::Duration::days((dl as f64 * 365.25) as i64)).to_string()
    });
    // action plan §4.1, first match wins
    let pct_v = pct.unwrap_or(0.0);
    let age_v = age.unwrap_or(0);
    let ul_v = ulife.unwrap_or(0) as i64;
    let action = if condition == "critical" || risk == "critical" {
        "Replace Immediately"
    } else if pct_v >= 100.0 || (ul_v > 0 && age_v >= ul_v) {
        "Replace Within 1 Year"
    } else if failure_record >= 3 {
        "Plan Replacement"
    } else if risk == "high" && pct_v >= 80.0 {
        "Plan Replacement"
    } else if matches!(risk, "medium" | "high") || matches!(condition, "poor" | "fair") {
        "Monitor Closely"
    } else {
        "No Action Required"
    };
    Computed { health_index: health, age_years: age, useful_life_pct: pct, age_group: age.map(age_group_of), end_of_life: eol, action_plan: action }
}

fn computed_stats(c: &Computed, condition: &str) -> String {
    let health_cls = if c.health_index >= 80.0 { "text-success" } else if c.health_index >= 50.0 { "text-warning" } else { "text-error" };
    let action_cls = match c.action_plan {
        "Replace Immediately" => "badge-error", "Replace Within 1 Year" => "badge-warning",
        "Plan Replacement" => "badge-warning", "Monitor Closely" => "badge-info", _ => "badge-success",
    };
    format!(
        r#"<div class="stats stats-vertical sm:stats-horizontal shadow w-full">
<div class="stat"><div class="stat-title">Health Index</div><div class="stat-value text-2xl {hc}">{health:.0}</div><div class="stat-desc">{cond}</div></div>
<div class="stat"><div class="stat-title">Age</div><div class="stat-value text-2xl">{age}</div><div class="stat-desc">{grp}</div></div>
<div class="stat"><div class="stat-title">Useful Life</div><div class="stat-value text-2xl">{pct}</div><div class="stat-desc">EOL {eol}</div></div>
<div class="stat"><div class="stat-title">Recommended Action</div><div class="stat-value"><span class="badge {ac} badge-lg">{action}</span></div></div>
</div>"#,
        hc = health_cls, health = c.health_index, cond = condition,
        age = c.age_years.map(|a| format!("{a}y")).unwrap_or_else(|| "—".into()),
        grp = c.age_group.unwrap_or("—"),
        pct = c.useful_life_pct.map(|p| format!("{p:.0}%")).unwrap_or_else(|| "—".into()),
        eol = c.end_of_life.as_deref().map(|e| &e[..e.len().min(10)]).unwrap_or("—"),
        ac = action_cls, action = c.action_plan,
    )
}

// ─────────────────────────────────────────────────────────────────────────
// List
// ─────────────────────────────────────────────────────────────────────────

async fn list_equipment(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.equipment");
    // health_index computed inline so it can be shown/sorted in the list.
    let config = ListConfig::new("Equipment", "eam_equipment")
        .scope_filter(division::division_predicate(&user, "e.division"))
        .custom_from(
            "eam_equipment e \
             LEFT JOIN eam_manufacturer m ON m.id = e.manufacturer_id \
             LEFT JOIN eam_bay b ON b.id = e.bay_id")
        .custom_select(
            "e.id, e.code, e.name, e.asset_id, e.equipment_category, m.name AS mfr, b.name AS bay_name, \
             e.condition_status, e.operational_status, e.risk_level, e.verification_state, e.active, \
             round( (CASE e.condition_status WHEN 'excellent' THEN 100 WHEN 'good' THEN 80 WHEN 'fair' THEN 60 WHEN 'poor' THEN 40 WHEN 'critical' THEN 20 ELSE 50 END) \
                  * (CASE e.operational_status WHEN 'operational' THEN 1.0 WHEN 'standby' THEN 0.95 WHEN 'out_of_service' THEN 0.5 WHEN 'under_repair' THEN 0.6 WHEN 'decommissioned' THEN 0.0 ELSE 1.0 END) )::text AS health")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("e.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("e.name"))
        .column(ListColumn::new("asset_id", "MNEC Asset ID").searchable().sql_expr("e.asset_id"))
        .column(ListColumn::new("equipment_category", "Category")
            .filterable(&[("transformer","Transformer"),("switchgear","Switchgear"),("rmu","RMU"),("protection","Protection"),("scada","SCADA"),("battery","Battery"),("capacitor","Capacitor"),("ner","NER"),("feeder_pillar","Feeder Pillar"),("cable","Cable"),("elb","ELB")]).sql_expr("e.equipment_category"))
        .column(ListColumn::new("bay_name", "Bay").sql_expr("b.name"))
        .column(ListColumn::new("mfr", "Manufacturer").sql_expr("m.name"))
        .column(ListColumn::new("health", "Health").sql_expr("1"))
        .column(ListColumn::new("condition_status", "Condition")
            .filterable(&[("excellent","Excellent"),("good","Good"),("fair","Fair"),("poor","Poor"),("critical","Critical")])
            .badge(&[("excellent","Excellent","badge-success"),("good","Good","badge-success"),("fair","Fair","badge-info"),("poor","Poor","badge-warning"),("critical","Critical","badge-error")]).sql_expr("e.condition_status"))
        .column(ListColumn::new("risk_level", "Risk")
            .filterable(&[("low","Low"),("medium","Medium"),("high","High"),("critical","Critical")])
            .badge(&[("low","Low","badge-ghost"),("medium","Medium","badge-info"),("high","High","badge-warning"),("critical","Critical","badge-error")]).sql_expr("e.risk_level"))
        .column(ListColumn::new("verification_state", "Verification")
            .badge(&[("draft","Draft","badge-ghost"),("submitted","Submitted","badge-info"),("verified","Verified","badge-warning"),("approved","Approved","badge-success"),("rejected","Rejected","badge-error")]).sql_expr("e.verification_state"))
        .detail_url("/sesb-eam/equipment/{id}")
        .create("New Equipment", "/sesb-eam/equipment/new")
        .default_sort("code")
        .group_by_options(&[("equipment_category","Category"),("condition_status","Condition"),("risk_level","Risk"),("verification_state","Verification")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r, Err(e) => { error!(error=%e, "equipment list failed"); return Html("<h1>Failed</h1>").into_response(); }
    };
    Html(page_shell(&sidebar, "Equipment", &render_list(&config, &result, &params, "/sesb-eam/equipment"))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Form model
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct EquipForm {
    name: String, asset_id: String, asset_type_id: Option<Uuid>, mnec_sequence: String,
    bay_id: Option<Uuid>, equipment_category: String, asset_class_id: Option<Uuid>, asset_tag: String,
    manufacturer_id: Option<Uuid>, model_number: String, serial_number: String,
    manufacture_date: String, installation_date: String, commissioning_date: String, warranty_expiry_date: String,
    design_life_years: String, commission_year: String, voltage_level_id: Option<Uuid>,
    rated_voltage_kv: String, rated_current_a: String, rated_power_kva: String, fuse_rating_a: String,
    operational_status: String, condition_status: String, nomenclature: String, rating: String,
    useful_life_years: String, failure_record: String, risk_level: String, target_replacement_year: String,
    ibr_budget_available: bool, ibr_year: String, notes: String, active: bool,
}

impl EquipForm {
    fn defaults() -> Self {
        EquipForm { equipment_category: "transformer".into(), operational_status: "operational".into(),
            condition_status: "good".into(), risk_level: "low".into(), design_life_years: "25".into(), active: true, ..Default::default() }
    }
    fn from_map(form: &HashMap<String, String>) -> Self {
        let g = |k: &str| form.get(k).cloned().unwrap_or_default();
        EquipForm {
            name: g("name"), asset_id: g("asset_id"), asset_type_id: opt_uuid(form, "asset_type_id"),
            mnec_sequence: g("mnec_sequence"), bay_id: opt_uuid(form, "bay_id"),
            equipment_category: g("equipment_category"), asset_class_id: opt_uuid(form, "asset_class_id"),
            asset_tag: g("asset_tag"), manufacturer_id: opt_uuid(form, "manufacturer_id"),
            model_number: g("model_number"), serial_number: g("serial_number"),
            manufacture_date: g("manufacture_date"), installation_date: g("installation_date"),
            commissioning_date: g("commissioning_date"), warranty_expiry_date: g("warranty_expiry_date"),
            design_life_years: g("design_life_years"), commission_year: g("commission_year"),
            voltage_level_id: opt_uuid(form, "voltage_level_id"), rated_voltage_kv: g("rated_voltage_kv"),
            rated_current_a: g("rated_current_a"), rated_power_kva: g("rated_power_kva"), fuse_rating_a: g("fuse_rating_a"),
            operational_status: g("operational_status"), condition_status: g("condition_status"),
            nomenclature: g("nomenclature"), rating: g("rating"), useful_life_years: g("useful_life_years"),
            failure_record: g("failure_record"), risk_level: g("risk_level"),
            target_replacement_year: g("target_replacement_year"), ibr_budget_available: form.contains_key("ibr_budget_available"),
            ibr_year: g("ibr_year"), notes: g("notes"), active: form.contains_key("active"),
        }
    }
}

async fn asset_class_options(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_asset_class WHERE active ORDER BY sequence, name", "-- Asset Class --", sel).await
}
async fn bay_options(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT b.id, (s.code || ' / ' || b.code || ' · ' || b.name) AS label FROM eam_bay b JOIN eam_substation s ON s.id = b.substation_id WHERE b.active ORDER BY s.code, b.code", "-- Bay --", sel).await
}
async fn mfr_options(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM eam_manufacturer WHERE active ORDER BY name", "-- Manufacturer --", sel).await
}

async fn equip_base_body(db: &PgPool, f: &EquipForm, bay_preselect: Option<Uuid>, is_new: bool) -> String {
    let bays = bay_options(db, f.bay_id.or(bay_preselect)).await;
    let atypes = asset_type_options(db, f.asset_type_id).await;
    let aclasses = asset_class_options(db, f.asset_class_id).await;
    let mfrs = mfr_options(db, f.manufacturer_id).await;
    let volts = voltage_options(db, f.voltage_level_id).await;
    let ident = grid3(&format!("{}{}{}{}{}{}",
        text_field("Name", "name", &f.name, true),
        select_field("Category *", "equipment_category", &enum_options(EQUIP_CATEGORIES, &f.equipment_category)),
        select_field("Bay", "bay_id", &bays),
        select_field("Asset Type (acronym)", "asset_type_id", &atypes),
        text_field("MNEC Asset ID (auto)", "asset_id", &f.asset_id, false),
        num_field("MNEC Sequence", "mnec_sequence", &f.mnec_sequence, "1"),
    ));
    let classify = grid3(&format!("{}{}{}",
        select_field("Asset Class", "asset_class_id", &aclasses),
        text_field("Asset Tag", "asset_tag", &f.asset_tag, false),
        select_field("Voltage Level", "voltage_level_id", &volts),
    ));
    let nameplate = grid3(&format!("{}{}{}{}{}{}{}{}{}{}",
        select_field("Manufacturer", "manufacturer_id", &mfrs),
        text_field("Model Number", "model_number", &f.model_number, false),
        text_field("Serial Number", "serial_number", &f.serial_number, false),
        date_field("Manufacture Date", "manufacture_date", &f.manufacture_date),
        date_field("Installation Date", "installation_date", &f.installation_date),
        date_field("Commissioning Date", "commissioning_date", &f.commissioning_date),
        date_field("Warranty Expiry", "warranty_expiry_date", &f.warranty_expiry_date),
        num_field("Commission Year", "commission_year", &f.commission_year, "1"),
        text_field("Nomenclature", "nomenclature", &f.nomenclature, false),
        text_field("Rating", "rating", &f.rating, false),
    ));
    let ratings = grid3(&format!("{}{}{}{}",
        num_field("Rated Voltage (kV)", "rated_voltage_kv", &f.rated_voltage_kv, "0.0001"),
        num_field("Rated Current (A)", "rated_current_a", &f.rated_current_a, "0.01"),
        num_field("Rated Power (kVA)", "rated_power_kva", &f.rated_power_kva, "0.01"),
        num_field("Fuse Rating (A)", "fuse_rating_a", &f.fuse_rating_a, "0.01"),
    ));
    let status = grid3(&format!("{}{}{}",
        select_field("Operational Status", "operational_status", &enum_options(OP_STATUSES, &f.operational_status)),
        select_field("Condition", "condition_status", &enum_options(CONDITIONS, &f.condition_status)),
        select_field("Risk Level", "risk_level", &enum_options(RISKS, &f.risk_level)),
    ));
    let life = grid3(&format!("{}{}{}{}{}{}",
        num_field("Design Life (years)", "design_life_years", &f.design_life_years, "1"),
        num_field("Useful Life (years)", "useful_life_years", &f.useful_life_years, "1"),
        num_field("Failure Record", "failure_record", &f.failure_record, "1"),
        num_field("Target Replacement Year", "target_replacement_year", &f.target_replacement_year, "1"),
        num_field("IBR Year", "ibr_year", &f.ibr_year, "1"),
        format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="ibr_budget_available" class="checkbox checkbox-sm" {c}/><span class="label-text">IBR Budget Available</span></label></div>"#, c = if f.ibr_budget_available { "checked" } else { "" }),
    ));
    format!(
        r#"<h2 class="font-semibold text-sm uppercase opacity-60 mt-1 mb-2">Identification</h2>{ident}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Classification</h2>{classify}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Nameplate</h2>{nameplate}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Ratings</h2>{ratings}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Status &amp; Condition</h2>{status}
<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">Lifecycle &amp; Risk</h2>{life}
{notes}{active}"#,
        ident = ident, classify = classify, nameplate = nameplate, ratings = ratings, status = status, life = life,
        notes = textarea_field("Notes", "notes", &f.notes), active = active_field(f.active, is_new),
    )
}

fn grid3(fields: &str) -> String {
    format!(r#"<div class="grid grid-cols-1 md:grid-cols-3 gap-x-4">{}</div>"#, fields)
}

// MNEC asset_id composition (§4.9): "{parent.asset_id}-{acronym}[-{seq:02d}]"
async fn compose_asset_id(db: &PgPool, bay_id: Option<Uuid>, asset_type_id: Option<Uuid>, mnec_sequence: Option<i32>) -> Option<String> {
    compose_equipment_asset_id(db, &[(bay_id, "eam_bay")], asset_type_id, mnec_sequence).await
}

/// Resolve an equipment MNEC id (§4.9) from whichever parent it hangs off.
/// `parents` is a priority-ordered list of `(id, table)` candidates —
/// bay | tower | gantry | span | ugc_line | distribution_line — and the first
/// with a non-empty `asset_id` wins. The pure composition is in [`super::mnec`].
async fn compose_equipment_asset_id(
    db: &PgPool,
    parents: &[(Option<Uuid>, &str)],
    asset_type_id: Option<Uuid>,
    mnec_sequence: Option<i32>,
) -> Option<String> {
    let mut parent: Option<String> = None;
    for (id, table) in parents {
        if let Some(pid) = id {
            // `table` is an author-supplied literal, never request input.
            let sql = format!("SELECT asset_id FROM {table} WHERE id=$1");
            let got: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(&sql)
                .bind(pid).fetch_optional(db).await.ok().flatten();
            if let Some(a) = got.filter(|s| !s.is_empty()) {
                parent = Some(a);
                break;
            }
        }
    }
    let parent = parent?;
    let acronym: Option<String> = match asset_type_id {
        Some(a) => vortex_plugin_sdk::sqlx::query_scalar("SELECT acronym FROM eam_asset_type WHERE id=$1").bind(a).fetch_optional(db).await.ok().flatten(),
        None => None,
    };
    let acronym = acronym?;
    Some(super::mnec::equipment_asset_id(&parent, &acronym, mnec_sequence))
}

async fn new_equipment(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.equipment");
    let bay_pre = q.get("bay").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/equipment", "Back to Equipment", "New Equipment");
    let f = EquipForm::defaults();
    let body = equip_base_body(&db, &f, bay_pre, true).await;
    let note = r#"<div class="alert alert-info text-sm mb-4"><span>Category-specific technical details can be entered after the equipment is created.</span></div>"#;
    Html(page_shell(&sidebar, "New Equipment", &wide_form_page("/sesb-eam/equipment/create", &format!("{header}{note}"), &body))).into_response()
}

async fn create_equipment(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = EquipForm::from_map(&form);
    if f.name.trim().is_empty() { return bad("Name is required"); }
    if f.equipment_category.trim().is_empty() { return bad("Category is required"); }
    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &EQP_SEQ).await {
        Ok(c) => c, Err(e) => { error!(error=%e, "eqp seq failed"); return bad("Failed to generate code"); }
    };
    // MNEC asset_id: explicit wins, else auto-compose from bay + acronym.
    let mnec_seq = opt_i32(&form, "mnec_sequence");
    let asset_id = if !f.asset_id.trim().is_empty() {
        Some(f.asset_id.clone())
    } else {
        compose_asset_id(&db, f.bay_id, f.asset_type_id, mnec_seq).await
    };
    // hierarchy_level from asset-type default, else 3 (equipment under bay)
    let hlevel: Option<i32> = match f.asset_type_id {
        Some(a) => vortex_plugin_sdk::sqlx::query_scalar("SELECT default_hierarchy_level FROM eam_asset_type WHERE id=$1").bind(a).fetch_optional(&db).await.ok().flatten(),
        None => None,
    };
    // substation derived from bay
    let substation_id: Option<Uuid> = match f.bay_id {
        Some(b) => vortex_plugin_sdk::sqlx::query_scalar("SELECT substation_id FROM eam_bay WHERE id=$1").bind(b).fetch_optional(&db).await.ok().flatten(),
        None => None,
    };
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_equipment (id, name, code, asset_id, asset_type_id, hierarchy_level, mnec_sequence, bay_id, substation_id, division, equipment_category, asset_class_id, asset_tag, manufacturer_id, model_number, serial_number, manufacture_date, installation_date, commissioning_date, warranty_expiry_date, design_life_years, commission_year, voltage_level_id, rated_voltage_kv, rated_current_a, rated_power_kva, fuse_rating_a, operational_status, condition_status, nomenclature, rating, useful_life_years, failure_record, risk_level, target_replacement_year, ibr_budget_available, ibr_year, notes, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, \
                 (SELECT r.division FROM eam_substation s JOIN eam_site si ON si.id = s.site_id JOIN eam_region r ON r.id = si.region_id WHERE s.id = $9), \
                 $10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39)")
        .bind(id).bind(&f.name).bind(&code).bind(asset_id.as_deref()).bind(f.asset_type_id).bind(hlevel)
        .bind(mnec_seq).bind(f.bay_id).bind(substation_id)
        .bind(&f.equipment_category).bind(f.asset_class_id).bind(opt_str(&form, "asset_tag")).bind(f.manufacturer_id)
        .bind(opt_str(&form, "model_number")).bind(opt_str(&form, "serial_number"))
        .bind(opt_date(&form, "manufacture_date")).bind(opt_date(&form, "installation_date"))
        .bind(opt_date(&form, "commissioning_date")).bind(opt_date(&form, "warranty_expiry_date"))
        .bind(opt_i32(&form, "design_life_years")).bind(opt_i32(&form, "commission_year")).bind(f.voltage_level_id)
        .bind(opt_dec(&form, "rated_voltage_kv")).bind(opt_dec(&form, "rated_current_a")).bind(opt_dec(&form, "rated_power_kva")).bind(opt_dec(&form, "fuse_rating_a"))
        .bind(&f.operational_status).bind(&f.condition_status).bind(opt_str(&form, "nomenclature")).bind(opt_str(&form, "rating"))
        .bind(opt_i32(&form, "useful_life_years")).bind(opt_i32(&form, "failure_record").unwrap_or(0)).bind(&f.risk_level)
        .bind(opt_i32(&form, "target_replacement_year")).bind(f.ibr_budget_available).bind(opt_i32(&form, "ibr_year"))
        .bind(opt_str(&form, "notes")).bind(company_id).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "equipment insert failed"); return bad(&format!("Failed: {e}")); }
    // propagate asset_class type/group denormalized
    if f.asset_class_id.is_some() {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_equipment e SET asset_class_type = c.class_type, asset_class_group = c.class_group FROM eam_asset_class c WHERE c.id = e.asset_class_id AND e.id = $1")
            .bind(id).execute(&db).await;
    }
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_equipment", id.to_string()).with_resource_name(&f.name)
     .with_details(json!({"code": code, "asset_id": asset_id}));
    let _ = state.audit.log(entry).await;
    info!(code=%code, "equipment created");
    Redirect::to(&format!("/sesb-eam/equipment/{id}")).into_response()
}

async fn edit_equipment(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_equipment", id).await { return resp; }
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.equipment");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, asset_id, asset_type_id, mnec_sequence, bay_id, equipment_category, asset_class_id, asset_tag, manufacturer_id, model_number, serial_number, manufacture_date::text AS md, installation_date::text AS instd, commissioning_date::text AS cd, warranty_expiry_date::text AS wd, design_life_years, commission_year, voltage_level_id, rated_voltage_kv::text AS rv, rated_current_a::text AS rc, rated_power_kva::text AS rp, fuse_rating_a::text AS fr, operational_status, condition_status, nomenclature, rating, useful_life_years, failure_record, risk_level, target_replacement_year, ibr_budget_available, ibr_year, notes, active, verification_state FROM eam_equipment WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let gs = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let gi = |k: &str| -> String { row.try_get::<Option<i32>, _>(k).ok().flatten().map(|v| v.to_string()).unwrap_or_default() };
    let code: String = row.get("code");
    let vstate: String = row.get("verification_state");
    let category: String = row.get("equipment_category");
    let condition: String = row.get("condition_status");
    let op_status: String = row.get("operational_status");
    let risk: String = row.get("risk_level");
    let f = EquipForm {
        name: row.get("name"), asset_id: gs("asset_id"), asset_type_id: row.try_get("asset_type_id").ok(),
        mnec_sequence: gi("mnec_sequence"), bay_id: row.try_get("bay_id").ok(), equipment_category: category.clone(),
        asset_class_id: row.try_get("asset_class_id").ok(), asset_tag: gs("asset_tag"),
        manufacturer_id: row.try_get("manufacturer_id").ok(), model_number: gs("model_number"), serial_number: gs("serial_number"),
        manufacture_date: gs("md"), installation_date: gs("instd"), commissioning_date: gs("cd"), warranty_expiry_date: gs("wd"),
        design_life_years: gi("design_life_years"), commission_year: gi("commission_year"), voltage_level_id: row.try_get("voltage_level_id").ok(),
        rated_voltage_kv: gs("rv"), rated_current_a: gs("rc"), rated_power_kva: gs("rp"), fuse_rating_a: gs("fr"),
        operational_status: op_status.clone(), condition_status: condition.clone(), nomenclature: gs("nomenclature"), rating: gs("rating"),
        useful_life_years: gi("useful_life_years"), failure_record: gi("failure_record"), risk_level: risk.clone(),
        target_replacement_year: gi("target_replacement_year"), ibr_budget_available: row.try_get("ibr_budget_available").unwrap_or(false),
        ibr_year: gi("ibr_year"), notes: gs("notes"), active: row.try_get("active").unwrap_or(true),
    };
    let comp = compute(&condition, &op_status, if f.commissioning_date.is_empty() { None } else { Some(f.commissioning_date.as_str()) },
        f.useful_life_years.parse().ok(), f.design_life_years.parse().ok(), &risk, f.failure_record.parse().unwrap_or(0));
    let stats = computed_stats(&comp, &condition);

    let base_body = equip_base_body(&db, &f, None, false).await;
    // Specialization detail card for this category
    let spec_section = match spec::spec_for(&category) {
        Some(sp) => {
            let inner = spec::render_spec(&db, sp, Some(id)).await;
            format!(r#"<div class="card bg-base-100 shadow mt-6"><div class="card-body"><form method="POST" action="/sesb-eam/equipment/{id}">
<input type="hidden" name="__spec_only" value="1"/>{inner}
<div class="mt-3"><button class="btn btn-primary btn-sm">Save Technical Details</button></div></form></div></div>"#, id = id, inner = inner)
        }
        None => String::new(),
    };

    // Components subtable
    let comps = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, component_type, condition_status FROM eam_component WHERE equipment_id=$1 ORDER BY code")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut comp_html = String::new();
    for r in &comps {
        let cid: Uuid = r.get("id");
        let ccode: Option<String> = r.try_get("code").ok();
        let cname: String = r.get("name");
        let ctype: String = r.get("component_type");
        comp_html.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/sesb-eam/components/{cid}'"><td class="font-mono">{ccode}</td><td>{cname}</td><td>{ctype}</td></tr>"#,
            cid = cid, ccode = esc(ccode.as_deref().unwrap_or("—")), cname = esc(&cname), ctype = esc(&ctype)));
    }
    if comp_html.is_empty() { comp_html.push_str(r#"<tr><td colspan="3" class="text-base-content/50">No components</td></tr>"#); }

    let history = vortex_plugin_sdk::framework::render_audit_trail(&db, "eam_equipment", id).await;
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("eam_equipment", id);
    let header = format!(
        r#"<div class="flex items-center justify-between mb-3"><div>
<a href="/sesb-eam/equipment" class="btn btn-ghost btn-sm mb-2">← Back to Equipment</a>
<h1 class="text-2xl font-bold">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span> {badge}</h1>
<div class="text-sm opacity-60 font-mono">{asset_id}</div></div>
<form method="POST" action="/sesb-eam/equipment/{id}/delete" onsubmit="return confirm('Archive this equipment?')"><button class="btn btn-error btn-sm btn-outline">Archive</button></form></div>"#,
        name = esc(&f.name), code = esc(&code), badge = vstate_badge(&vstate), asset_id = esc(&f.asset_id), id = id);
    let content = format!(
        r#"<div class="max-w-5xl">{header}{stats}
<form method="POST" action="/sesb-eam/equipment/{id}"><div class="card bg-base-100 shadow mt-4"><div class="card-body">{base_body}
<div class="flex gap-2 mt-4"><button class="btn btn-primary btn-sm">Save</button></div></div></div></form>
{spec_section}
<div class="card bg-base-100 shadow mt-6"><div class="card-body">
<div class="flex items-center justify-between mb-2"><h2 class="card-title text-lg">Components</h2>
<a href="/sesb-eam/components/new?equipment={id}" class="btn btn-primary btn-sm">New Component</a></div>
<table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Type</th></tr></thead><tbody>{comp_html}</tbody></table></div></div>
<div class="mt-6">{activity_panel}</div>
<div class="mt-6">{history}</div></div>"#,
        header = header, stats = stats, id = id, base_body = base_body, spec_section = spec_section, comp_html = comp_html, history = history, activity_panel = activity_panel);
    Html(page_shell(&sidebar, &format!("Equipment {}", f.name), &content)).into_response()
}

async fn update_equipment(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    // Spec-only submit: just UPSERT the specialization detail.
    if form.contains_key("__spec_only") {
        let category: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT equipment_category FROM eam_equipment WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
        if let Some(cat) = category {
            if let Some(sp) = spec::spec_for(&cat) {
                if let Err(e) = spec::save_spec(&db, sp, id, &form).await {
                    error!(error=%e, "spec save failed"); return bad(&format!("Failed: {e}"));
                }
            }
        }
        return Redirect::to(&format!("/sesb-eam/equipment/{id}")).into_response();
    }
    let f = EquipForm::from_map(&form);
    if f.name.trim().is_empty() { return bad("Name is required"); }
    let mnec_seq = opt_i32(&form, "mnec_sequence");
    let asset_id = if !f.asset_id.trim().is_empty() { Some(f.asset_id.clone()) } else { compose_asset_id(&db, f.bay_id, f.asset_type_id, mnec_seq).await };
    let substation_id: Option<Uuid> = match f.bay_id {
        Some(b) => vortex_plugin_sdk::sqlx::query_scalar("SELECT substation_id FROM eam_bay WHERE id=$1").bind(b).fetch_optional(&db).await.ok().flatten(),
        None => None,
    };
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_equipment SET name=$1, asset_id=$2, asset_type_id=$3, mnec_sequence=$4, bay_id=$5, substation_id=$6, equipment_category=$7, asset_class_id=$8, asset_tag=$9, manufacturer_id=$10, model_number=$11, serial_number=$12, manufacture_date=$13, installation_date=$14, commissioning_date=$15, warranty_expiry_date=$16, design_life_years=$17, commission_year=$18, voltage_level_id=$19, rated_voltage_kv=$20, rated_current_a=$21, rated_power_kva=$22, fuse_rating_a=$23, operational_status=$24, condition_status=$25, nomenclature=$26, rating=$27, useful_life_years=$28, failure_record=$29, risk_level=$30, target_replacement_year=$31, ibr_budget_available=$32, ibr_year=$33, notes=$34, active=$35, updated_by=$36 WHERE id=$37")
        .bind(&f.name).bind(asset_id.as_deref()).bind(f.asset_type_id).bind(mnec_seq).bind(f.bay_id).bind(substation_id)
        .bind(&f.equipment_category).bind(f.asset_class_id).bind(opt_str(&form, "asset_tag")).bind(f.manufacturer_id)
        .bind(opt_str(&form, "model_number")).bind(opt_str(&form, "serial_number"))
        .bind(opt_date(&form, "manufacture_date")).bind(opt_date(&form, "installation_date"))
        .bind(opt_date(&form, "commissioning_date")).bind(opt_date(&form, "warranty_expiry_date"))
        .bind(opt_i32(&form, "design_life_years")).bind(opt_i32(&form, "commission_year")).bind(f.voltage_level_id)
        .bind(opt_dec(&form, "rated_voltage_kv")).bind(opt_dec(&form, "rated_current_a")).bind(opt_dec(&form, "rated_power_kva")).bind(opt_dec(&form, "fuse_rating_a"))
        .bind(&f.operational_status).bind(&f.condition_status).bind(opt_str(&form, "nomenclature")).bind(opt_str(&form, "rating"))
        .bind(opt_i32(&form, "useful_life_years")).bind(opt_i32(&form, "failure_record").unwrap_or(0)).bind(&f.risk_level)
        .bind(opt_i32(&form, "target_replacement_year")).bind(f.ibr_budget_available).bind(opt_i32(&form, "ibr_year"))
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(user.id).bind(id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "equipment update failed"); return bad(&format!("Failed: {e}")); }
    if f.asset_class_id.is_some() {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_equipment e SET asset_class_type = c.class_type, asset_class_group = c.class_group FROM eam_asset_class c WHERE c.id = e.asset_class_id AND e.id = $1")
            .bind(id).execute(&db).await;
    }
    Redirect::to(&format!("/sesb-eam/equipment/{id}")).into_response()
}

async fn delete_equipment(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_equipment SET active=false, updated_by=$1 WHERE id=$2").bind(user.id).bind(id).execute(&db).await;
    Redirect::to("/sesb-eam/equipment").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Components
// ─────────────────────────────────────────────────────────────────────────

const COMPONENT_TYPES: &[(&str, &str)] = &[
    ("bushing","Bushing"),("winding","Winding"),("tap_changer","Tap Changer"),("cooling_fan","Cooling Fan"),
    ("oil_pump","Oil Pump"),("conservator","Conservator"),("relay","Relay"),("ct","CT"),("vt","VT"),
    ("insulator","Insulator"),("connector","Connector"),("terminal","Terminal"),("other","Other"),
];
const COMP_OP_STATUSES: &[(&str, &str)] = &[("operational","Operational"),("degraded","Degraded"),("failed","Failed"),("replaced","Replaced")];
const PHASES: &[(&str, &str)] = &[("","—"),("R","R"),("Y","Y"),("B","B"),("N","N")];

async fn equipment_options(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_equipment WHERE active ORDER BY code", "-- Equipment --", sel).await
}

#[derive(Default)]
struct CompForm {
    name: String, equipment_id: Option<Uuid>, component_type: String, asset_type_id: Option<Uuid>,
    phase: String, mnec_sequence: String, manufacturer_id: Option<Uuid>, model_number: String, serial_number: String,
    installation_date: String, condition_status: String, operational_status: String, position: String,
    specification: String, rating: String, brand: String, make_country: String, risk_level: String, notes: String, active: bool,
}
impl CompForm {
    fn defaults() -> Self { CompForm { component_type: "other".into(), condition_status: "good".into(), operational_status: "operational".into(), risk_level: "low".into(), active: true, ..Default::default() } }
    fn from_map(form: &HashMap<String, String>) -> Self {
        let g = |k: &str| form.get(k).cloned().unwrap_or_default();
        CompForm { name: g("name"), equipment_id: opt_uuid(form, "equipment_id"), component_type: g("component_type"),
            asset_type_id: opt_uuid(form, "asset_type_id"), phase: g("phase"), mnec_sequence: g("mnec_sequence"),
            manufacturer_id: opt_uuid(form, "manufacturer_id"), model_number: g("model_number"), serial_number: g("serial_number"),
            installation_date: g("installation_date"), condition_status: g("condition_status"), operational_status: g("operational_status"),
            position: g("position"), specification: g("specification"), rating: g("rating"), brand: g("brand"),
            make_country: g("make_country"), risk_level: g("risk_level"), notes: g("notes"), active: form.contains_key("active") }
    }
}

async fn comp_body(db: &PgPool, f: &CompForm, equip_preselect: Option<Uuid>, is_new: bool) -> String {
    let equips = equipment_options(db, f.equipment_id.or(equip_preselect)).await;
    let atypes = asset_type_options(db, f.asset_type_id).await;
    let mfrs = mfr_options(db, f.manufacturer_id).await;
    let g = grid3(&format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
        text_field("Name", "name", &f.name, true),
        select_field("Equipment *", "equipment_id", &equips),
        select_field("Component Type *", "component_type", &enum_options(COMPONENT_TYPES, &f.component_type)),
        select_field("Asset Type", "asset_type_id", &atypes),
        select_field("Phase", "phase", &enum_options(PHASES, &f.phase)),
        num_field("MNEC Sequence", "mnec_sequence", &f.mnec_sequence, "1"),
        select_field("Manufacturer", "manufacturer_id", &mfrs),
        text_field("Model Number", "model_number", &f.model_number, false),
        text_field("Serial Number", "serial_number", &f.serial_number, false),
        date_field("Installation Date", "installation_date", &f.installation_date),
        select_field("Condition", "condition_status", &enum_options(CONDITIONS, &f.condition_status)),
        select_field("Operational Status", "operational_status", &enum_options(COMP_OP_STATUSES, &f.operational_status)),
        select_field("Risk Level", "risk_level", &enum_options(RISKS, &f.risk_level)),
        text_field("Position", "position", &f.position, false),
        text_field("Rating", "rating", &f.rating, false),
    ));
    let g2 = grid3(&format!("{}{}",
        text_field("Brand", "brand", &f.brand, false),
        text_field("Make Country", "make_country", &f.make_country, false),
    ));
    format!("{}{}{}{}{}", g, g2, textarea_field("Specification", "specification", &f.specification), textarea_field("Notes", "notes", &f.notes), active_field(f.active, is_new))
}

async fn new_component(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.equipment");
    let eq_pre = q.get("equipment").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header(&eq_pre.map(|e| format!("/sesb-eam/equipment/{e}")).unwrap_or_else(|| "/sesb-eam/equipment".into()), "Back", "New Component");
    let body = comp_body(&db, &CompForm::defaults(), eq_pre, true).await;
    Html(page_shell(&sidebar, "New Component", &wide_form_page("/sesb-eam/components/create", &header, &body))).into_response()
}

async fn create_component(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = CompForm::from_map(&form);
    let equipment_id = match f.equipment_id { Some(e) => e, None => return bad("Equipment is required") };
    if f.name.trim().is_empty() { return bad("Name is required"); }
    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &CMP_SEQ).await { Ok(c) => c, Err(_) => return bad("Failed to generate code") };
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_component (id, name, code, equipment_id, component_type, asset_type_id, phase, mnec_sequence, manufacturer_id, model_number, serial_number, installation_date, condition_status, operational_status, position, specification, rating, brand, make_country, risk_level, notes, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)")
        .bind(id).bind(&f.name).bind(&code).bind(equipment_id).bind(&f.component_type).bind(f.asset_type_id)
        .bind(opt_str(&form, "phase")).bind(opt_i32(&form, "mnec_sequence")).bind(f.manufacturer_id)
        .bind(opt_str(&form, "model_number")).bind(opt_str(&form, "serial_number")).bind(opt_date(&form, "installation_date"))
        .bind(&f.condition_status).bind(&f.operational_status).bind(opt_str(&form, "position"))
        .bind(opt_str(&form, "specification")).bind(opt_str(&form, "rating")).bind(opt_str(&form, "brand")).bind(opt_str(&form, "make_country"))
        .bind(&f.risk_level).bind(opt_str(&form, "notes")).bind(company_id).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "component insert failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/components/{id}")).into_response()
}

async fn edit_component(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_component", id).await { return resp; }
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.equipment");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, equipment_id, component_type, asset_type_id, phase, mnec_sequence, manufacturer_id, model_number, serial_number, installation_date::text AS instd, condition_status, operational_status, position, specification, rating, brand, make_country, risk_level, notes, active FROM eam_component WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let gs = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let code: String = row.try_get::<Option<String>, _>("code").ok().flatten().unwrap_or_default();
    let f = CompForm {
        name: row.get("name"), equipment_id: row.try_get("equipment_id").ok(), component_type: row.get("component_type"),
        asset_type_id: row.try_get("asset_type_id").ok(), phase: gs("phase"),
        mnec_sequence: row.try_get::<Option<i32>, _>("mnec_sequence").ok().flatten().map(|v| v.to_string()).unwrap_or_default(),
        manufacturer_id: row.try_get("manufacturer_id").ok(), model_number: gs("model_number"), serial_number: gs("serial_number"),
        installation_date: gs("instd"), condition_status: row.get("condition_status"), operational_status: row.get("operational_status"),
        position: gs("position"), specification: gs("specification"), rating: gs("rating"), brand: gs("brand"),
        make_country: gs("make_country"), risk_level: row.get("risk_level"), notes: gs("notes"), active: row.try_get("active").unwrap_or(true),
    };
    let eqid = f.equipment_id;
    let body = comp_body(&db, &f, None, false).await;

    // Parts subtable
    let parts = vortex_plugin_sdk::sqlx::query("SELECT id, code, name, part_number, quantity, status FROM eam_part WHERE component_id=$1 ORDER BY code").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut part_rows = String::new();
    for r in &parts {
        let pid: Uuid = r.get("id");
        let pname: String = r.get("name");
        let pnum: Option<String> = r.try_get("part_number").ok();
        let qty: i32 = r.try_get("quantity").unwrap_or(0);
        let st: String = r.get("status");
        part_rows.push_str(&format!(
            r#"<tr><td>{pname}</td><td class="font-mono">{pnum}</td><td>{qty}</td><td>{st}</td><td><form method="POST" action="/sesb-eam/parts/{pid}/delete" onsubmit="return confirm('Remove part?')"><button class="btn btn-ghost btn-xs text-error">✕</button></form></td></tr>"#,
            pname = esc(&pname), pnum = esc(pnum.as_deref().unwrap_or("—")), qty = qty, st = esc(&st), pid = pid));
    }
    if part_rows.is_empty() { part_rows.push_str(r#"<tr><td colspan="5" class="text-base-content/50">No parts</td></tr>"#); }
    let part_form = format!(
        r#"<form method="POST" action="/sesb-eam/parts/create" class="grid grid-cols-1 md:grid-cols-5 gap-2 items-end mt-3">
<input type="hidden" name="component_id" value="{id}"/>
<input name="name" class="input input-bordered input-sm" placeholder="Part name" required/>
<input name="part_number" class="input input-bordered input-sm" placeholder="Part number"/>
<input name="quantity" type="number" class="input input-bordered input-sm" placeholder="Qty" value="1"/>
<input name="unit_of_measure" class="input input-bordered input-sm" placeholder="Unit"/>
<button class="btn btn-primary btn-sm">Add Part</button></form>"#, id = id);

    let header = format!(
        r#"<a href="{back}" class="btn btn-ghost btn-sm mb-4">← Back to Equipment</a>
<h1 class="text-2xl font-bold mb-2">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span></h1>"#,
        back = eqid.map(|e| format!("/sesb-eam/equipment/{e}")).unwrap_or_else(|| "/sesb-eam/equipment".into()),
        name = esc(&f.name), code = esc(&code));
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("eam_component", id);
    let content = format!(
        r#"{form}
<div class="max-w-4xl mt-6"><div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-2">Parts</h2>
<table class="table table-sm"><thead><tr><th>Name</th><th>Part No</th><th>Qty</th><th>Status</th><th></th></tr></thead><tbody>{parts}</tbody></table>
{part_form}</div></div></div>
<div class="max-w-4xl mt-6">{activity_panel}</div>"#,
        form = wide_form_page(&format!("/sesb-eam/components/{id}"), &header, &body), parts = part_rows, part_form = part_form);
    let _ = user;
    Html(page_shell(&sidebar, &format!("Component {}", f.name), &content)).into_response()
}

async fn update_component(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let f = CompForm::from_map(&form);
    let equipment_id = match f.equipment_id { Some(e) => e, None => return bad("Equipment is required") };
    if f.name.trim().is_empty() { return bad("Name is required"); }
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_component SET name=$1, equipment_id=$2, component_type=$3, asset_type_id=$4, phase=$5, mnec_sequence=$6, manufacturer_id=$7, model_number=$8, serial_number=$9, installation_date=$10, condition_status=$11, operational_status=$12, position=$13, specification=$14, rating=$15, brand=$16, make_country=$17, risk_level=$18, notes=$19, active=$20, updated_by=$21 WHERE id=$22")
        .bind(&f.name).bind(equipment_id).bind(&f.component_type).bind(f.asset_type_id).bind(opt_str(&form, "phase")).bind(opt_i32(&form, "mnec_sequence"))
        .bind(f.manufacturer_id).bind(opt_str(&form, "model_number")).bind(opt_str(&form, "serial_number")).bind(opt_date(&form, "installation_date"))
        .bind(&f.condition_status).bind(&f.operational_status).bind(opt_str(&form, "position")).bind(opt_str(&form, "specification"))
        .bind(opt_str(&form, "rating")).bind(opt_str(&form, "brand")).bind(opt_str(&form, "make_country")).bind(&f.risk_level)
        .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(user.id).bind(id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "component update failed"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/components/{id}")).into_response()
}

async fn delete_component(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let eqid: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT equipment_id FROM eam_component WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM eam_component WHERE id=$1").bind(id).execute(&db).await;
    Redirect::to(&eqid.map(|e| format!("/sesb-eam/equipment/{e}")).unwrap_or_else(|| "/sesb-eam/equipment".into())).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Parts (inline create/delete from the component page)
// ─────────────────────────────────────────────────────────────────────────

async fn new_part() -> Response { Redirect::to("/sesb-eam/equipment").into_response() }

async fn create_part(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let component_id = match opt_uuid(&form, "component_id") { Some(c) => c, None => return bad("Component is required") };
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Name is required"); }
    let code = vortex_plugin_sdk::orm::sequence::next(&state.pool, &PRT_SEQ).await.unwrap_or_default();
    let equipment_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT equipment_id FROM eam_component WHERE id=$1").bind(component_id).fetch_optional(&db).await.ok().flatten();
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_part (id, name, code, component_id, equipment_id, part_number, quantity, unit_of_measure, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(Uuid::now_v7()).bind(&name).bind(&code).bind(component_id).bind(equipment_id)
        .bind(opt_str(&form, "part_number")).bind(opt_i32(&form, "quantity").unwrap_or(1)).bind(opt_str(&form, "unit_of_measure")).bind(company_id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/components/{component_id}")).into_response()
}

async fn update_part(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_part SET name=$1, part_number=$2, quantity=$3 WHERE id=$4")
        .bind(form.get("name")).bind(opt_str(&form, "part_number")).bind(opt_i32(&form, "quantity").unwrap_or(1)).bind(id).execute(&db).await;
    let cid: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT component_id FROM eam_part WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    Redirect::to(&cid.map(|c| format!("/sesb-eam/components/{c}")).unwrap_or_else(|| "/sesb-eam/equipment".into())).into_response()
}

async fn delete_part(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let cid: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT component_id FROM eam_part WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM eam_part WHERE id=$1").bind(id).execute(&db).await;
    Redirect::to(&cid.map(|c| format!("/sesb-eam/components/{c}")).unwrap_or_else(|| "/sesb-eam/equipment".into())).into_response()
}
