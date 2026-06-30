//! Maintenance plans (§3.6 / §5.3) — recurring schedules, the order
//! generator that rolls forward across the planning horizon, and the
//! admin-only frequency-change control.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::chrono::{Months, NaiveDate};
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use super::checklist;
use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

const PLAN_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.plan", "PLAN").with_padding(5).yearly();
const MNT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.maintenance", "MNT").with_padding(5).yearly();

const PLAN_TYPES: &[(&str, &str)] = &[("pm","Preventive"),("cm","Corrective"),("inspection","Inspection"),("testing","Testing"),("overhaul","Overhaul")];
const PRIORITIES: &[(&str, &str)] = &[("0","Low"),("1","Normal"),("2","High"),("3","Critical")];
const TIERS: &[(&str, &str)] = &[("","—"),("tier_1","Tier 1"),("tier_2","Tier 2"),("tier_3","Tier 3")];
const FREQ_UNITS: &[(&str, &str)] = &[("day","Day(s)"),("week","Week(s)"),("month","Month(s)"),("year","Year(s)")];
const PLAN_STATE_BADGES: &[(&str, &str, &str)] = &[("draft","Draft","badge-ghost"),("active","Active","badge-success"),("done","Done","badge-info"),("cancelled","Cancelled","badge-error")];

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/plans", get(list_plan))
        .route("/sesb-eam/plans/new", get(new_plan))
        .route("/sesb-eam/plans/create", post(create_plan))
        .route("/sesb-eam/plans/{id}", get(edit_plan))
        .route("/sesb-eam/plans/{id}", post(update_plan))
        .route("/sesb-eam/plans/{id}/action/{action}", post(plan_action))
}

async fn equipment_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_equipment WHERE active ORDER BY code", "-- Equipment --", sel).await
}
async fn template_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM eam_checklist_template WHERE active ORDER BY name", "-- Checklist Template --", sel).await
}

async fn list_plan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.plans");
    let config = ListConfig::new("Maintenance Plans", "eam_maintenance_plan")
        .custom_from("eam_maintenance_plan p LEFT JOIN eam_equipment e ON e.id=p.equipment_id")
        .custom_select("p.id, p.name, e.name AS equipment, p.maintenance_type, p.risk_tier, (p.frequency_interval::text||' '||p.frequency_unit) AS freq, p.next_maintenance_date::text AS nmd, p.state, p.active")
        .column(ListColumn::new("name", "Number").sortable().code().sql_expr("p.name"))
        .column(ListColumn::new("equipment", "Equipment").searchable().sql_expr("e.name"))
        .column(ListColumn::new("maintenance_type", "Type").filterable(&[("pm","Preventive"),("cm","Corrective"),("inspection","Inspection"),("testing","Testing"),("overhaul","Overhaul")]).sql_expr("p.maintenance_type"))
        .column(ListColumn::new("risk_tier", "Tier").sql_expr("p.risk_tier"))
        .column(ListColumn::new("freq", "Frequency").sql_expr("1"))
        .column(ListColumn::new("nmd", "Next Date").sortable().sql_expr("p.next_maintenance_date"))
        .column(ListColumn::new("state", "State").filterable(&[("draft","Draft"),("active","Active"),("done","Done"),("cancelled","Cancelled")])
            .badge(&[("draft","Draft","badge-ghost"),("active","Active","badge-success"),("done","Done","badge-info"),("cancelled","Cancelled","badge-error")]).sql_expr("p.state"))
        .detail_url("/sesb-eam/plans/{id}")
        .create("New Plan", "/sesb-eam/plans/new")
        .default_sort("nmd");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "plan list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Maintenance Plans", &render_list(&config, &result, &params, "/sesb-eam/plans"))).into_response()
}

/// The plan form. `locked` controls whether the frequency fields are editable
/// (an active plan only unlocks them when an Admin sets `frequency_unlocked`).
async fn plan_body(db: &PgPool, v: &HashMap<String, String>, eq_pre: Option<Uuid>, is_new: bool, freq_locked: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let equips = equipment_opts(db, v.get("equipment_id").and_then(|s| s.parse().ok()).or(eq_pre)).await;
    let tpls = template_opts(db, v.get("checklist_template_id").and_then(|s| s.parse().ok())).await;
    let users = user_options(db, v.get("assigned_to").and_then(|s| s.parse().ok())).await;
    let head = grid3(&format!("{}{}{}{}{}{}",
        select_field("Equipment *", "equipment_id", &equips),
        select_field("Maintenance Type *", "maintenance_type", &enum_options(PLAN_TYPES, if g("maintenance_type").is_empty() { "pm" } else { g("maintenance_type") })),
        select_field("Priority", "priority", &enum_options(PRIORITIES, if g("priority").is_empty() { "1" } else { g("priority") })),
        select_field("Risk Tier", "risk_tier", &enum_options(TIERS, g("risk_tier"))),
        select_field("Checklist Template", "checklist_template_id", &tpls),
        select_field("Assigned To", "assigned_to", &users)));
    let lock_attr = if freq_locked { "disabled" } else { "" };
    let freq = format!(
        r#"<div class="grid grid-cols-1 md:grid-cols-4 gap-x-4">
{si}
<div class="form-control mb-3"><label class="label"><span class="label-text">Every {lk}</span></label><input name="frequency_interval" type="number" min="1" class="input input-bordered input-sm" value="{fi}" {la}/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Frequency Unit</span></label><select name="frequency_unit" class="select select-bordered select-sm" {la}>{fu}</select></div>
{nmd}
</div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-x-4">
<div class="form-control mb-3"><label class="label"><span class="label-text">Planning Horizon</span></label><input name="planning_horizon_interval" type="number" min="1" class="input input-bordered input-sm" value="{phi}"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Horizon Unit</span></label><select name="planning_horizon_unit" class="select select-bordered select-sm">{phu}</select></div>
</div>"#,
        si = date_field("Start Date *", "start_date", g("start_date")),
        nmd = date_field("Next Maintenance Date *", "next_maintenance_date", g("next_maintenance_date")),
        fi = if g("frequency_interval").is_empty() { "1" } else { g("frequency_interval") },
        fu = enum_options(FREQ_UNITS, if g("frequency_unit").is_empty() { "month" } else { g("frequency_unit") }),
        phi = if g("planning_horizon_interval").is_empty() { "1" } else { g("planning_horizon_interval") },
        phu = enum_options(FREQ_UNITS, if g("planning_horizon_unit").is_empty() { "year" } else { g("planning_horizon_unit") }),
        la = lock_attr, lk = if freq_locked { "🔒" } else { "" });
    let extras = grid2(&format!("{}{}",
        text_field("Procedure Reference", "procedure_reference", g("procedure_reference"), false),
        num_field("Planned Duration (h)", "planned_duration_hours", g("planned_duration_hours"), "0.5")));
    format!("{}{}{}{}{}", head, freq, extras, textarea_field("Notes", "notes", g("notes")), active_field(g("active") == "true" || is_new, is_new))
}

fn grid3(fields: &str) -> String { format!(r#"<div class="grid grid-cols-1 md:grid-cols-3 gap-x-4">{}</div>"#, fields) }

async fn new_plan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.plans");
    let eq_pre = q.get("equipment").and_then(|s| s.parse::<Uuid>().ok());
    let header = form_header("/sesb-eam/plans", "Back to Plans", "New Maintenance Plan");
    let body = plan_body(&db, &HashMap::new(), eq_pre, true, false).await;
    Html(page_shell(&sidebar, "New Plan", &wide_form_page("/sesb-eam/plans/create", &header, &body))).into_response()
}

async fn create_plan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let equipment_id = match opt_uuid(&form, "equipment_id") { Some(e) => e, None => return bad("Equipment is required") };
    let start = opt_date(&form, "start_date").unwrap_or_else(|| vortex_plugin_sdk::chrono::Utc::now().date_naive());
    let nmd = opt_date(&form, "next_maintenance_date").unwrap_or(start);
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &PLAN_SEQ).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_maintenance_plan (id, name, equipment_id, equipment_category, substation_id, site_id, region_id, kawasan_id, asset_class_id, maintenance_type, priority, risk_tier, procedure_reference, planned_duration_hours, assigned_to, checklist_template_id, start_date, next_maintenance_date, frequency_interval, frequency_unit, planning_horizon_interval, planning_horizon_unit, notes, company_id, created_by) \
         SELECT $1,$2,$3, e.equipment_category, e.substation_id, \
            (SELECT site_id FROM eam_substation WHERE id=e.substation_id), \
            (SELECT si.region_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.kawasan_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            e.asset_class_id, $4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19 \
         FROM eam_equipment e WHERE e.id=$3")
        .bind(id).bind(&number).bind(equipment_id)
        .bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm"))
        .bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1"))
        .bind(opt_str(&form, "risk_tier")).bind(opt_str(&form, "procedure_reference"))
        .bind(opt_dec(&form, "planned_duration_hours")).bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "checklist_template_id"))
        .bind(start).bind(nmd)
        .bind(opt_i32(&form, "frequency_interval").unwrap_or(1)).bind(form.get("frequency_unit").map(|s| s.as_str()).unwrap_or("month"))
        .bind(opt_i32(&form, "planning_horizon_interval").unwrap_or(1)).bind(form.get("planning_horizon_unit").map(|s| s.as_str()).unwrap_or("year"))
        .bind(opt_str(&form, "notes")).bind(company_id).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "plan insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/plans/{id}")).into_response()
}

async fn edit_plan(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.plans");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, equipment_id::text AS equipment_id, maintenance_type, priority, risk_tier, procedure_reference, planned_duration_hours::text AS planned_duration_hours, assigned_to::text AS assigned_to, checklist_template_id::text AS checklist_template_id, start_date::text AS start_date, next_maintenance_date::text AS next_maintenance_date, frequency_interval::text AS frequency_interval, frequency_unit, planning_horizon_interval::text AS planning_horizon_interval, planning_horizon_unit, frequency_unlocked, frequency_change_count::text AS frequency_change_count, state, notes, active::text AS active, \
            (SELECT COUNT(*) FROM eam_maintenance m WHERE m.plan_id=p.id)::text AS order_count FROM eam_maintenance_plan p WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["equipment_id","maintenance_type","priority","risk_tier","procedure_reference","planned_duration_hours","assigned_to","checklist_template_id","start_date","next_maintenance_date","frequency_interval","frequency_unit","planning_horizon_interval","planning_horizon_unit","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let number: Option<String> = row.try_get("name").ok();
    let pstate: String = row.get("state");
    let freq_unlocked: bool = row.try_get("frequency_unlocked").unwrap_or(false);
    let freq_locked = pstate == "active" && !freq_unlocked;
    let order_count: String = row.try_get("order_count").ok().flatten().unwrap_or_default();
    let fchanges: String = row.try_get("frequency_change_count").ok().flatten().unwrap_or_default();
    let is_admin = user.roles.iter().any(|r| r == "EAM Admin" || r == "System Administrator");

    let stats = format!(
        r#"<div class="stats stats-vertical sm:stats-horizontal shadow w-full mb-4">
<div class="stat"><div class="stat-title">State</div><div class="stat-value"><span class="badge {sc} badge-lg">{state}</span></div></div>
<div class="stat"><div class="stat-title">Orders Generated</div><div class="stat-value text-2xl">{oc}</div></div>
<div class="stat"><div class="stat-title">Frequency</div><div class="stat-value text-xl">{fi} {fu}</div><div class="stat-desc">changed {fc}× · {lock}</div></div>
</div>"#,
        sc = PLAN_STATE_BADGES.iter().find(|(v,_,_)| *v==pstate).map(|(_,_,c)| *c).unwrap_or("badge-ghost"), state = pstate,
        oc = order_count, fi = v.get("frequency_interval").map(|s| s.as_str()).unwrap_or("1"), fu = v.get("frequency_unit").map(|s| s.as_str()).unwrap_or("month"),
        fc = fchanges, lock = if freq_locked { "🔒 locked" } else { "🔓 editable" });

    let actions = plan_actions(&pstate, id, freq_unlocked, is_admin);
    let body = plan_body(&db, &v, None, false, freq_locked).await;
    let header = format!(r#"<a href="/sesb-eam/plans" class="btn btn-ghost btn-sm mb-3">← Back to Plans</a>
<h1 class="text-2xl font-bold mb-3">Plan <span class="font-mono text-sm opacity-50">{}</span></h1>"#, esc(number.as_deref().unwrap_or("")));
    let content = format!("<div class=\"max-w-4xl\">{}{}{}{}</div>", header, stats, actions, wide_form_page(&format!("/sesb-eam/plans/{id}"), "", &body));
    Html(page_shell(&sidebar, "Maintenance Plan", &content)).into_response()
}

fn plan_actions(s: &str, id: Uuid, freq_unlocked: bool, is_admin: bool) -> String {
    let btn = |a: &str, l: &str, c: &str, extra: &str| format!(
        r#"<form method="POST" action="/sesb-eam/plans/{id}/action/{a}" class="inline">{extra}<button class="btn btn-sm {c}">{l}</button></form>"#, id = id, a = a, c = c, l = l, extra = extra);
    let mut out: Vec<String> = match s {
        "draft" => vec![btn("activate", "Activate", "btn-primary", ""), btn("cancel", "Cancel", "btn-error btn-outline", "")],
        "active" => vec![
            btn("generate_orders", "Generate Orders", "btn-primary", ""),
            btn("done", "Mark Done", "btn-ghost", ""),
            btn("cancel", "Cancel", "btn-error btn-outline", ""),
        ],
        "cancelled" => vec![btn("reset_draft", "Reset to Draft", "btn-ghost", "")],
        _ => vec![],
    };
    // Frequency unlock (admin-only) on active plans
    if s == "active" {
        if freq_unlocked {
            out.push(btn("relock_frequency", "Re-lock Frequency", "btn-warning btn-outline", ""));
        } else if is_admin {
            let reason = r#"<input name="reason" class="input input-bordered input-xs mr-1" placeholder="unlock reason" required/>"#;
            out.push(btn("unlock_frequency", "Unlock Frequency", "btn-warning btn-outline", reason));
        }
    }
    if out.is_empty() { return String::new(); }
    format!(r#"<div class="flex flex-wrap gap-2 mb-4 items-center">{}</div>"#, out.join(""))
}

async fn update_plan(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    // Guard frequency edits on active+locked plans (§5.3).
    let row = vortex_plugin_sdk::sqlx::query("SELECT state, frequency_unlocked, frequency_interval, frequency_unit FROM eam_maintenance_plan WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let (pstate, unlocked, cur_fi, cur_fu): (String, bool, i32, String) = match row {
        Some(r) => (r.get("state"), r.try_get("frequency_unlocked").unwrap_or(false), r.get("frequency_interval"), r.get("frequency_unit")),
        None => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let new_fi = opt_i32(&form, "frequency_interval").unwrap_or(cur_fi);
    let new_fu = form.get("frequency_unit").cloned().unwrap_or_else(|| cur_fu.clone());
    let freq_locked = pstate == "active" && !unlocked;
    let freq_changed = new_fi != cur_fi || new_fu != cur_fu;
    if freq_locked && freq_changed {
        return (StatusCode::CONFLICT, "Frequency is locked on an active plan — an Admin must unlock it first (§5.3).").into_response();
    }
    // Apply update. If a frequency change went through (unlocked active plan), bump
    // the counter and auto-relock.
    if pstate == "active" && unlocked && freq_changed {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_maintenance_plan SET maintenance_type=$1, priority=$2, risk_tier=$3, procedure_reference=$4, planned_duration_hours=$5, assigned_to=$6, checklist_template_id=$7, next_maintenance_date=$8, planning_horizon_interval=$9, planning_horizon_unit=$10, notes=$11, active=$12, frequency_interval=$13, frequency_unit=$14, frequency_unlocked=FALSE, frequency_change_count=frequency_change_count+1 WHERE id=$15")
            .bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm")).bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1"))
            .bind(opt_str(&form, "risk_tier")).bind(opt_str(&form, "procedure_reference")).bind(opt_dec(&form, "planned_duration_hours"))
            .bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "checklist_template_id")).bind(opt_date(&form, "next_maintenance_date"))
            .bind(opt_i32(&form, "planning_horizon_interval").unwrap_or(1)).bind(form.get("planning_horizon_unit").map(|s| s.as_str()).unwrap_or("year"))
            .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(new_fi).bind(&new_fu).bind(id)
            .execute(&db).await;
    } else {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_maintenance_plan SET maintenance_type=$1, priority=$2, risk_tier=$3, procedure_reference=$4, planned_duration_hours=$5, assigned_to=$6, checklist_template_id=$7, start_date=$8, next_maintenance_date=$9, frequency_interval=$10, frequency_unit=$11, planning_horizon_interval=$12, planning_horizon_unit=$13, notes=$14, active=$15 WHERE id=$16")
            .bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm")).bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1"))
            .bind(opt_str(&form, "risk_tier")).bind(opt_str(&form, "procedure_reference")).bind(opt_dec(&form, "planned_duration_hours"))
            .bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "checklist_template_id"))
            .bind(opt_date(&form, "start_date")).bind(opt_date(&form, "next_maintenance_date"))
            .bind(new_fi).bind(&new_fu)
            .bind(opt_i32(&form, "planning_horizon_interval").unwrap_or(1)).bind(form.get("planning_horizon_unit").map(|s| s.as_str()).unwrap_or("year"))
            .bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
            .execute(&db).await;
    }
    Redirect::to(&format!("/sesb-eam/plans/{id}")).into_response()
}

/// Add `interval` of `unit` to a date (months/years via chrono Months).
fn add_interval(d: NaiveDate, interval: i32, unit: &str) -> Option<NaiveDate> {
    let n = interval.max(1) as u32;
    match unit {
        "day" => d.checked_add_days(vortex_plugin_sdk::chrono::Days::new(n as u64)),
        "week" => d.checked_add_days(vortex_plugin_sdk::chrono::Days::new((n * 7) as u64)),
        "month" => d.checked_add_months(Months::new(n)),
        "year" => d.checked_add_months(Months::new(n * 12)),
        _ => None,
    }
}

async fn plan_action(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path((id, action)): Path<(Uuid, String)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    match action.as_str() {
        "activate" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET state='active' WHERE id=$1 AND state='draft'").bind(id).execute(&db).await; }
        "done" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET state='done' WHERE id=$1 AND state='active'").bind(id).execute(&db).await; }
        "cancel" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET state='cancelled' WHERE id=$1").bind(id).execute(&db).await; }
        "reset_draft" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET state='draft' WHERE id=$1 AND state='cancelled'").bind(id).execute(&db).await; }
        "unlock_frequency" => {
            let is_admin = user.roles.iter().any(|r| r == "EAM Admin" || r == "System Administrator");
            if !is_admin { return (StatusCode::FORBIDDEN, "Only an EAM Admin may unlock plan frequency (§5.3)").into_response(); }
            let reason = match opt_str(&form, "reason") { Some(r) => r.clone(), None => return bad("An unlock reason is required") };
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET frequency_unlocked=TRUE, frequency_change_reason=$2, frequency_change_approved_by=$3, frequency_change_approved_date=NOW() WHERE id=$1 AND state='active'")
                .bind(id).bind(&reason).bind(user.id).execute(&db).await;
        }
        "relock_frequency" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET frequency_unlocked=FALSE WHERE id=$1").bind(id).execute(&db).await; }
        "generate_orders" => {
            return generate_orders(&state, &db, &user, &db_ctx, id).await;
        }
        _ => return (StatusCode::BAD_REQUEST, "Unknown action").into_response(),
    }
    Redirect::to(&format!("/sesb-eam/plans/{id}")).into_response()
}

/// §5.3: roll forward from next_maintenance_date across the planning horizon at
/// the configured frequency, skipping dates that already have an order, then
/// advance next_maintenance_date past the horizon.
async fn generate_orders(
    state: &Arc<AppState>, db: &PgPool, user: &AuthUser, db_ctx: &DatabaseContext, id: Uuid,
) -> Response {
    let p = match vortex_plugin_sdk::sqlx::query(
        "SELECT equipment_id, equipment_category, substation_id, site_id, region_id, kawasan_id, maintenance_type, priority, planned_duration_hours, assigned_to, checklist_template_id, description, next_maintenance_date, frequency_interval, frequency_unit, planning_horizon_interval, planning_horizon_unit FROM eam_maintenance_plan WHERE id=$1 AND state='active'")
        .bind(id).fetch_optional(db).await { Ok(Some(r)) => r, _ => return (StatusCode::CONFLICT, "Plan must be active to generate orders").into_response() };
    let equipment_id: Uuid = p.get("equipment_id");
    let freq_i: i32 = p.get("frequency_interval");
    let freq_u: String = p.get("frequency_unit");
    let hor_i: i32 = p.get("planning_horizon_interval");
    let hor_u: String = p.get("planning_horizon_unit");
    let mut nmd: NaiveDate = p.get("next_maintenance_date");
    let horizon_end = match add_interval(nmd, hor_i, &hor_u) { Some(d) => d, None => return bad("Invalid planning horizon") };
    let template_id: Option<Uuid> = p.try_get("checklist_template_id").ok();
    let company_id = default_company(db).await;

    let mut created = 0i32;
    let mut date = nmd;
    let mut guard = 0;
    while date <= horizon_end && guard < 1000 {
        guard += 1;
        let exists: bool = vortex_plugin_sdk::sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM eam_maintenance WHERE plan_id=$1 AND scheduled_date=$2)")
            .bind(id).bind(date).fetch_one(db).await.unwrap_or(false);
        if !exists {
            let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &MNT_SEQ).await.unwrap_or_default();
            let wo_id = Uuid::now_v7();
            let res = vortex_plugin_sdk::sqlx::query(
                "INSERT INTO eam_maintenance (id, name, description, equipment_id, equipment_category, substation_id, site_id, region_id, kawasan_id, responsible_kawasan_id, responsible_region_id, maintenance_type, priority, request_date, scheduled_date, planned_duration_hours, assigned_to, checklist_template_id, plan_id, state, company_id, created_by) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$8,$10,$11,$15,$15,$12,$13,$14,$16,'scheduled',$17,$18)")
                .bind(wo_id).bind(&number)
                .bind(p.try_get::<Option<String>,_>("description").ok().flatten().unwrap_or_else(|| "Planned maintenance".into()))
                .bind(equipment_id).bind(p.try_get::<Option<String>,_>("equipment_category").ok().flatten())
                .bind(p.try_get::<Option<Uuid>,_>("substation_id").ok().flatten()).bind(p.try_get::<Option<Uuid>,_>("site_id").ok().flatten())
                .bind(p.try_get::<Option<Uuid>,_>("region_id").ok().flatten()).bind(p.try_get::<Option<Uuid>,_>("kawasan_id").ok().flatten())
                .bind(p.get::<String,_>("maintenance_type")).bind(p.get::<String,_>("priority"))
                .bind(p.try_get::<Option<vortex_plugin_sdk::rust_decimal::Decimal>,_>("planned_duration_hours").ok().flatten())
                .bind(p.try_get::<Option<Uuid>,_>("assigned_to").ok().flatten()).bind(template_id)
                .bind(date).bind(id).bind(company_id).bind(user.id)
                .execute(db).await;
            match res {
                Ok(_) => {
                    if let Some(tpl) = template_id { let _ = checklist::instantiate(db, wo_id, tpl).await; }
                    created += 1;
                }
                Err(e) => { error!(error=%e, "generate order insert"); }
            }
        }
        match add_interval(date, freq_i, &freq_u) { Some(d) => date = d, None => break }
    }
    // Advance next_maintenance_date to the first slot beyond the horizon.
    nmd = date;
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance_plan SET next_maintenance_date=$2, last_generated_date=CURRENT_DATE WHERE id=$1").bind(id).bind(nmd).execute(db).await;

    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_maintenance_plan", id.to_string())
     .with_details(json!({"action": "generate_orders", "created": created}));
    let _ = state.audit.log(entry).await;
    info!(plan=%id, created, "generated maintenance orders");
    Redirect::to(&format!("/sesb-eam/plans/{id}")).into_response()
}
