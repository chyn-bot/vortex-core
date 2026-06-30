//! Maintenance work orders — §5.2 state machine, checklist lines,
//! part lines, and computed values (§4.8).

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

use super::checklist;
use super::*;
use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

const MNT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.maintenance", "MNT").with_padding(5).yearly();

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/maintenance", get(list_wo))
        .route("/sesb-eam/maintenance/new", get(new_wo))
        .route("/sesb-eam/maintenance/create", post(create_wo))
        .route("/sesb-eam/maintenance/{id}", get(edit_wo))
        .route("/sesb-eam/maintenance/{id}", post(update_wo))
        .route("/sesb-eam/maintenance/{id}/action/{action}", post(wo_action))
        .route("/sesb-eam/maintenance/{id}/parts/add", post(add_part_line))
        .route("/sesb-eam/maintenance/{id}/parts/{line_id}/delete", post(del_part_line))
}

const MTYPES: &[(&str, &str)] = &[("pm","Preventive"),("cm","Corrective"),("emergency","Emergency"),("inspection","Inspection"),("testing","Testing"),("overhaul","Overhaul")];
const PRIORITIES: &[(&str, &str)] = &[("0","Low"),("1","Normal"),("2","High"),("3","Urgent")];

fn state_badge(s: &str) -> String {
    let (l, c) = match s {
        "draft" => ("Draft","badge-ghost"), "scheduled" => ("Scheduled","badge-info"),
        "assigned" => ("Assigned","badge-info"), "in_progress" => ("In Progress","badge-warning"),
        "on_hold" => ("On Hold","badge-warning"), "completed" => ("Completed","badge-success"),
        "verified" => ("Verified","badge-success"), "cancelled" => ("Cancelled","badge-error"),
        _ => (s, "badge-ghost"),
    };
    format!(r#"<span class="badge {c}">{l}</span>"#, c = c, l = l)
}

async fn list_wo(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.maintenance");
    let config = ListConfig::new("Work Orders", "eam_maintenance")
        .custom_from("eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id LEFT JOIN users u ON u.id=m.assigned_to")
        .custom_select("m.id, m.name, m.description, e.name AS equipment, m.maintenance_type, m.priority, m.scheduled_date::text AS sched, u.username AS assignee, m.state, \
            (CASE WHEN m.state NOT IN ('completed','verified','cancelled') AND m.scheduled_date < CURRENT_DATE THEN 'Y' ELSE '' END) AS overdue")
        .column(ListColumn::new("name", "Number").sortable().code().sql_expr("m.name"))
        .column(ListColumn::new("description", "Description").searchable().sql_expr("m.description"))
        .column(ListColumn::new("equipment", "Equipment").sql_expr("e.name"))
        .column(ListColumn::new("maintenance_type", "Type").filterable(&[("pm","PM"),("cm","CM"),("emergency","Emergency"),("inspection","Inspection"),("testing","Testing"),("overhaul","Overhaul")]).sql_expr("m.maintenance_type"))
        .column(ListColumn::new("priority", "Priority").badge(&[("0","Low","badge-ghost"),("1","Normal","badge-info"),("2","High","badge-warning"),("3","Urgent","badge-error")]).sql_expr("m.priority"))
        .column(ListColumn::new("sched", "Scheduled").sortable().sql_expr("m.scheduled_date"))
        .column(ListColumn::new("assignee", "Assignee").sql_expr("u.username"))
        .column(ListColumn::new("state", "State").filterable(&[("draft","Draft"),("scheduled","Scheduled"),("assigned","Assigned"),("in_progress","In Progress"),("on_hold","On Hold"),("completed","Completed"),("verified","Verified"),("cancelled","Cancelled")])
            .badge(&[("draft","Draft","badge-ghost"),("scheduled","Scheduled","badge-info"),("assigned","Assigned","badge-info"),("in_progress","In Progress","badge-warning"),("on_hold","On Hold","badge-warning"),("completed","Completed","badge-success"),("verified","Verified","badge-success"),("cancelled","Cancelled","badge-error")]).sql_expr("m.state"))
        .detail_url("/sesb-eam/maintenance/{id}")
        .create("New Work Order", "/sesb-eam/maintenance/new")
        .default_sort("name")
        .group_by_options(&[("state","State"),("maintenance_type","Type"),("priority","Priority")]);
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "wo list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Work Orders", &render_list(&config, &result, &params, "/sesb-eam/maintenance"))).into_response()
}

async fn equipment_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(code,'') || ' · ' || name) AS label FROM eam_equipment WHERE active ORDER BY code", "-- Equipment --", sel).await
}
async fn user_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, username AS label FROM users ORDER BY username", "-- Unassigned --", sel).await
}
async fn template_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM eam_checklist_template WHERE active ORDER BY name", "-- No Checklist --", sel).await
}

async fn new_wo(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.maintenance");
    let eq_pre = q.get("equipment").and_then(|s| s.parse::<Uuid>().ok());
    let equips = equipment_opts(&db, eq_pre).await;
    let users = user_opts(&db, None).await;
    let templates = template_opts(&db, None).await;
    let body = format!("{}{}{}",
        grid2(&format!("{}{}{}{}{}{}{}{}",
            text_field("Description", "description", "", true),
            select_field("Equipment *", "equipment_id", &equips),
            select_field("Type", "maintenance_type", &enum_options(MTYPES, "pm")),
            select_field("Priority", "priority", &enum_options(PRIORITIES, "1")),
            date_field("Request Date", "request_date", ""),
            date_field("Scheduled Date", "scheduled_date", ""),
            num_field("Planned Duration (h)", "planned_duration_hours", "", "0.5"),
            select_field("Assigned To", "assigned_to", &users))),
        select_field("Checklist Template", "checklist_template_id", &templates),
        textarea_field("Work Description", "work_description", ""));
    let header = form_header("/sesb-eam/maintenance", "Back to Work Orders", "New Work Order");
    Html(page_shell(&sidebar, "New Work Order", &wide_form_page("/sesb-eam/maintenance/create", &header, &body))).into_response()
}

async fn create_wo(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let equipment_id = match opt_uuid(&form, "equipment_id") { Some(e) => e, None => return bad("Equipment is required") };
    let desc = form.get("description").cloned().unwrap_or_default();
    if desc.trim().is_empty() { return bad("Description is required"); }
    let number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &MNT_SEQ).await { Ok(n) => n, Err(_) => return bad("Failed to generate number") };
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    // denormalize location + category from the equipment + its bay
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_maintenance (id, name, description, equipment_id, equipment_category, bay_id, substation_id, site_id, region_id, kawasan_id, responsible_kawasan_id, responsible_region_id, maintenance_type, priority, request_date, scheduled_date, planned_duration_hours, assigned_to, checklist_template_id, work_description, company_id, created_by) \
         SELECT $1,$2,$3,$4, e.equipment_category, e.bay_id, e.substation_id, \
            (SELECT site_id FROM eam_substation WHERE id=e.substation_id), \
            (SELECT si.region_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.kawasan_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.kawasan_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            (SELECT si.region_id FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.id=e.substation_id), \
            $5,$6,$7,$8,$9,$10,$11,$12,$13,$14 \
         FROM eam_equipment e WHERE e.id=$4")
        .bind(id).bind(&number).bind(&desc).bind(equipment_id)
        .bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm"))
        .bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1"))
        .bind(opt_date(&form, "request_date").unwrap_or_else(|| vortex_plugin_sdk::chrono::Utc::now().date_naive()))
        .bind(opt_date(&form, "scheduled_date")).bind(opt_dec(&form, "planned_duration_hours"))
        .bind(opt_uuid(&form, "assigned_to")).bind(opt_uuid(&form, "checklist_template_id"))
        .bind(opt_str(&form, "work_description")).bind(company_id).bind(user.id)
        .execute(&db).await;
    if let Err(e) = res { error!(error=%e, "wo insert"); return bad(&format!("Failed: {e}")); }
    // Instantiate checklist lines if a template was chosen.
    if let Some(tpl) = opt_uuid(&form, "checklist_template_id") {
        if let Err(e) = checklist::instantiate(&db, id, tpl).await { error!(error=%e, "checklist instantiate"); }
    }
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_maintenance", id.to_string()).with_resource_name(&number);
    let _ = state.audit.log(entry).await;
    info!(number=%number, "work order created");
    Redirect::to(&format!("/sesb-eam/maintenance/{id}")).into_response()
}

async fn edit_wo(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.maintenance");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT m.name, m.description, m.equipment_id, e.name AS equipment_name, m.maintenance_type, m.priority, m.state, m.request_date::text AS rd, m.scheduled_date::text AS sd, m.planned_duration_hours::text AS pdh, m.assigned_to, m.work_description, m.findings, m.actions_taken, m.recommendations, m.labor_cost::text AS labor, m.materials_cost::text AS mat, m.total_cost::text AS tot, m.rejection_reason, m.verification_rating, m.verification_notes, m.start_date::text AS st, m.end_date::text AS et FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id WHERE m.id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let gs = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let number: String = row.try_get::<Option<String>, _>("name").ok().flatten().unwrap_or_default();
    let wstate: String = row.get("state");
    let desc: String = row.get("description");
    let equipment_name: Option<String> = row.try_get("equipment_name").ok();
    let assigned_to: Option<Uuid> = row.try_get("assigned_to").ok();
    let users = user_opts(&db, assigned_to).await;

    // Computed cost + checklist rollup
    let rollup = checklist::rollup(&db, id).await;
    let labor: f64 = gs("labor").parse().unwrap_or(0.0);
    let mat: f64 = gs("mat").parse().unwrap_or(0.0);
    let stats = format!(
        r#"<div class="stats stats-vertical sm:stats-horizontal shadow w-full mb-4">
<div class="stat"><div class="stat-title">Checklist</div><div class="stat-value text-xl">{done}/{total}</div><div class="stat-desc">{prog:.0}% · score {score:.0}</div></div>
<div class="stat"><div class="stat-title">Result</div><div class="stat-value"><span class="badge {rc} badge-lg">{result}</span></div></div>
<div class="stat"><div class="stat-title">Materials</div><div class="stat-value text-xl">{mat:.2}</div></div>
<div class="stat"><div class="stat-title">Total Cost</div><div class="stat-value text-xl">{tot:.2}</div></div>
</div>"#,
        done = rollup.completed, total = rollup.total, prog = rollup.progress, score = rollup.score,
        rc = match rollup.result { "fail" => "badge-error", "pass" => "badge-success", "pass_with_remarks" => "badge-warning", "in_progress" => "badge-info", _ => "badge-ghost" },
        result = rollup.result, mat = mat, tot = labor + mat);

    // Base form (read-only-ish fields editable in draft/scheduled)
    let base = format!("{}{}{}",
        grid2(&format!("{}{}{}{}{}{}",
            text_field("Description", "description", &esc(&desc), true),
            select_field("Type", "maintenance_type", &enum_options(MTYPES, &row.get::<String,_>("maintenance_type"))),
            select_field("Priority", "priority", &enum_options(PRIORITIES, &row.get::<String,_>("priority"))),
            date_field("Scheduled Date", "scheduled_date", &gs("sd")),
            num_field("Planned Duration (h)", "planned_duration_hours", &gs("pdh"), "0.5"),
            select_field("Assigned To", "assigned_to", &users))),
        grid2(&format!("{}{}",
            num_field("Labor Cost", "labor_cost", &gs("labor"), "0.01"),
            text_field("", "spacer", "", false))),
        format!("{}{}{}{}",
            textarea_field("Work Description", "work_description", &esc(&gs("work_description"))),
            textarea_field("Findings", "findings", &esc(&gs("findings"))),
            textarea_field("Actions Taken", "actions_taken", &esc(&gs("actions_taken"))),
            textarea_field("Recommendations", "recommendations", &esc(&gs("recommendations")))));

    // Checklist lines (editable values)
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, section, input_type, measurement_unit, rating_scale_max, selection_options, is_critical, value_pass_fail, value_yes_no, value_measurement::text AS vm, value_text, value_selection, value_rating, note FROM eam_checklist_line WHERE maintenance_id=$1 ORDER BY sequence, name")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut cl_html = String::new();
    for l in &lines {
        let lid: Uuid = l.get("id");
        let lname: String = l.get("name");
        let itype: String = l.get("input_type");
        let crit: bool = l.try_get("is_critical").unwrap_or(false);
        let input = checklist_input(l, &itype, lid);
        cl_html.push_str(&format!(
            r#"<tr><td>{name}{crit}</td><td>{input}</td><td><input name="note__{lid}" class="input input-bordered input-xs w-full" value="{note}" placeholder="note"/></td></tr>"#,
            name = esc(&lname), crit = if crit { r#" <span class="badge badge-xs badge-error">critical</span>"# } else { "" },
            input = input, lid = lid, note = esc(&l.try_get::<Option<String>,_>("note").ok().flatten().unwrap_or_default())));
    }
    let checklist_card = if lines.is_empty() { String::new() } else {
        format!(r#"<div class="card bg-base-100 shadow mt-6"><div class="card-body"><h2 class="card-title text-lg mb-2">Checklist</h2>
<form method="POST" action="/sesb-eam/maintenance/{id}"><input type="hidden" name="__checklist_only" value="1"/>
<table class="table table-sm"><thead><tr><th>Item</th><th>Result</th><th>Note</th></tr></thead><tbody>{rows}</tbody></table>
<div class="mt-3"><button class="btn btn-primary btn-sm">Save Checklist</button></div></form></div></div>"#, id = id, rows = cl_html)
    };

    // Part lines
    let parts = vortex_plugin_sdk::sqlx::query("SELECT id, name, part_number, quantity::text AS qty, unit, unit_cost::text AS uc, cost::text AS cost FROM eam_maintenance_part_line WHERE maintenance_id=$1 ORDER BY sequence").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut part_rows = String::new();
    for r in &parts {
        let pid: Uuid = r.get("id");
        let pname: String = r.get("name");
        let pnum: Option<String> = r.try_get("part_number").ok();
        let qty: Option<String> = r.try_get("qty").ok();
        let cost: Option<String> = r.try_get("cost").ok();
        part_rows.push_str(&format!(r#"<tr><td>{n}</td><td class="font-mono">{pn}</td><td>{q}</td><td>{c}</td><td><form method="POST" action="/sesb-eam/maintenance/{id}/parts/{pid}/delete"><button class="btn btn-ghost btn-xs text-error">✕</button></form></td></tr>"#,
            n = esc(&pname), pn = esc(pnum.as_deref().unwrap_or("—")), q = esc(qty.as_deref().unwrap_or("")), c = esc(cost.as_deref().unwrap_or("")), id = id, pid = pid));
    }
    if part_rows.is_empty() { part_rows.push_str(r#"<tr><td colspan="5" class="text-base-content/50">No parts</td></tr>"#); }
    let part_card = format!(
        r#"<div class="card bg-base-100 shadow mt-6"><div class="card-body"><h2 class="card-title text-lg mb-2">Parts Used</h2>
<table class="table table-sm"><thead><tr><th>Name</th><th>Part No</th><th>Qty</th><th>Cost</th><th></th></tr></thead><tbody>{rows}</tbody></table>
<form method="POST" action="/sesb-eam/maintenance/{id}/parts/add" class="grid grid-cols-2 md:grid-cols-5 gap-2 items-end mt-3">
<input name="name" class="input input-bordered input-sm" placeholder="Part name" required/>
<input name="part_number" class="input input-bordered input-sm" placeholder="Part number"/>
<input name="quantity" type="number" step="0.0001" class="input input-bordered input-sm" placeholder="Qty" value="1"/>
<input name="unit_cost" type="number" step="0.0001" class="input input-bordered input-sm" placeholder="Unit cost"/>
<button class="btn btn-primary btn-sm">Add Part</button></form></div></div>"#, rows = part_rows, id = id);

    let actions = state_actions(&wstate, id);
    let history = vortex_plugin_sdk::framework::render_audit_trail(&db, "eam_maintenance", id).await;
    let header = format!(
        r#"<div class="flex items-center justify-between mb-3"><div>
<a href="/sesb-eam/maintenance" class="btn btn-ghost btn-sm mb-2">← Back to Work Orders</a>
<h1 class="text-2xl font-bold">{num} {badge}</h1><div class="text-sm opacity-60">{eq}</div></div></div>"#,
        num = esc(&number), badge = state_badge(&wstate), eq = esc(equipment_name.as_deref().unwrap_or("")));
    let content = format!(
        r#"<div class="max-w-5xl">{header}{stats}{actions}
<form method="POST" action="/sesb-eam/maintenance/{id}"><div class="card bg-base-100 shadow"><div class="card-body">{base}
<div class="mt-3"><button class="btn btn-primary btn-sm">Save</button></div></div></div></form>
{checklist}{parts}
<div class="mt-6">{history}</div></div>"#,
        header = header, stats = stats, actions = actions, id = id, base = base, checklist = checklist_card, parts = part_card, history = history);
    Html(page_shell(&sidebar, &format!("WO {}", number), &content)).into_response()
}

/// One editable input for a checklist line, by input type.
fn checklist_input(l: &vortex_plugin_sdk::sqlx::postgres::PgRow, itype: &str, lid: Uuid) -> String {
    let name = format!("cl__{}", lid);
    let g = |k: &str| -> String { l.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    match itype {
        "pass_fail" => {
            let v = g("value_pass_fail");
            format!(r#"<select name="{n}" class="select select-bordered select-xs">{}</select>"#, super::enum_options(&[("","—"),("pass","Pass"),("fail","Fail"),("na","N/A")], &v), n = name)
        }
        "yes_no" => {
            let v = g("value_yes_no");
            format!(r#"<select name="{n}" class="select select-bordered select-xs">{}</select>"#, super::enum_options(&[("","—"),("yes","Yes"),("no","No")], &v), n = name)
        }
        "measurement" => {
            let unit: String = l.try_get::<Option<String>, _>("measurement_unit").ok().flatten().unwrap_or_default();
            format!(r#"<input name="{n}" type="number" step="0.0001" class="input input-bordered input-xs w-28" value="{v}"/> <span class="text-xs opacity-60">{u}</span>"#, n = name, v = esc(&g("vm")), u = esc(&unit))
        }
        "rating" => {
            let max = l.try_get::<Option<i32>, _>("rating_scale_max").ok().flatten().unwrap_or(5);
            format!(r#"<input name="{n}" type="number" min="0" max="{max}" class="input input-bordered input-xs w-20" value="{v}"/> <span class="text-xs opacity-60">/ {max}</span>"#, n = name, max = max, v = esc(&g("value_rating")))
        }
        "selection" => {
            let opts_raw = g("selection_options");
            let mut opts = vec![("".to_string(), "—".to_string())];
            for line in opts_raw.lines() {
                if let Some((v, nm)) = line.split_once('|') { opts.push((v.to_string(), nm.to_string())); }
            }
            let cur = g("value_selection");
            let rendered: String = opts.iter().map(|(v, nm)| format!(r#"<option value="{v}"{s}>{nm}</option>"#, v = esc(v), s = if *v == cur { " selected" } else { "" }, nm = esc(nm))).collect();
            format!(r#"<select name="{n}" class="select select-bordered select-xs">{rendered}</select>"#, n = name, rendered = rendered)
        }
        _ => format!(r#"<input name="{n}" class="input input-bordered input-xs w-full" value="{v}"/>"#, n = name, v = esc(&g("value_text"))),
    }
}

/// State-machine action buttons for the current state (§5.2).
fn state_actions(s: &str, id: Uuid) -> String {
    let btn = |action: &str, label: &str, cls: &str, extra: &str| format!(
        r#"<form method="POST" action="/sesb-eam/maintenance/{id}/action/{action}" class="inline">{extra}<button class="btn btn-sm {cls}">{label}</button></form>"#,
        id = id, action = action, cls = cls, label = label, extra = extra);
    let reason = r#"<input name="reason" class="input input-bordered input-xs mr-1" placeholder="reason"/>"#;
    let rating = r#"<select name="rating" class="select select-bordered select-xs mr-1"><option value="good">Good</option><option value="excellent">Excellent</option><option value="fair">Fair</option><option value="poor">Poor</option></select>"#;
    let buttons = match s {
        "draft" => vec![btn("schedule", "Schedule", "btn-primary", "")],
        "scheduled" => vec![btn("assign", "Assign", "btn-primary", ""), btn("accept", "Accept & Start", "btn-success", ""), btn("cancel", "Cancel", "btn-error btn-outline", "")],
        "assigned" => vec![btn("accept", "Accept & Start", "btn-success", ""), btn("reject", "Reject", "btn-warning", reason), btn("cancel", "Cancel", "btn-error btn-outline", "")],
        "in_progress" => vec![btn("hold", "Hold", "btn-warning", ""), btn("complete", "Complete", "btn-success", "")],
        "on_hold" => vec![btn("resume", "Resume", "btn-primary", ""), btn("complete", "Complete", "btn-success", "")],
        "completed" => vec![btn("verify", "Verify", "btn-success", rating), btn("return_for_rework", "Return for Rework", "btn-warning", reason)],
        "verified" => vec![btn("cancel", "Cancel", "btn-error btn-outline", "")],
        "cancelled" => vec![btn("reset_draft", "Reset to Draft", "btn-ghost", "")],
        _ => vec![],
    };
    if buttons.is_empty() { return String::new(); }
    format!(r#"<div class="flex flex-wrap gap-2 mb-4 items-end">{}</div>"#, buttons.join(""))
}

async fn update_wo(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    if form.contains_key("__checklist_only") {
        save_checklist(&db, id, &form).await;
        return Redirect::to(&format!("/sesb-eam/maintenance/{id}")).into_response();
    }
    let desc = form.get("description").cloned().unwrap_or_default();
    if desc.trim().is_empty() { return bad("Description is required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_maintenance SET description=$1, maintenance_type=$2, priority=$3, scheduled_date=$4, planned_duration_hours=$5, assigned_to=$6, labor_cost=$7, work_description=$8, findings=$9, actions_taken=$10, recommendations=$11, total_cost=$7+materials_cost WHERE id=$12")
        .bind(&desc).bind(form.get("maintenance_type").map(|s| s.as_str()).unwrap_or("pm")).bind(form.get("priority").map(|s| s.as_str()).unwrap_or("1"))
        .bind(opt_date(&form, "scheduled_date")).bind(opt_dec(&form, "planned_duration_hours")).bind(opt_uuid(&form, "assigned_to"))
        .bind(opt_dec(&form, "labor_cost").unwrap_or(vortex_plugin_sdk::rust_decimal::Decimal::ZERO))
        .bind(opt_str(&form, "work_description")).bind(opt_str(&form, "findings")).bind(opt_str(&form, "actions_taken")).bind(opt_str(&form, "recommendations")).bind(id)
        .execute(&db).await;
    Redirect::to(&format!("/sesb-eam/maintenance/{id}")).into_response()
}

async fn save_checklist(db: &PgPool, id: Uuid, form: &HashMap<String, String>) {
    let lines = vortex_plugin_sdk::sqlx::query("SELECT id, input_type FROM eam_checklist_line WHERE maintenance_id=$1").bind(id).fetch_all(db).await.unwrap_or_default();
    for l in &lines {
        let lid: Uuid = l.get("id");
        let itype: String = l.get("input_type");
        let val = form.get(&format!("cl__{}", lid)).filter(|s| !s.is_empty());
        let note = form.get(&format!("note__{}", lid)).filter(|s| !s.is_empty());
        let col = match itype.as_str() {
            "pass_fail" => "value_pass_fail", "yes_no" => "value_yes_no", "measurement" => "value_measurement",
            "rating" => "value_rating", "selection" => "value_selection", _ => "value_text",
        };
        let cast = match itype.as_str() { "measurement" => "::numeric", "rating" => "::int", _ => "" };
        let sql = format!("UPDATE eam_checklist_line SET {col} = $1{cast}, note = $2 WHERE id = $3", col = col, cast = cast);
        let _ = vortex_plugin_sdk::sqlx::query(&sql).bind(val).bind(note).bind(lid).execute(db).await;
    }
}

async fn wo_action(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path((id, action)): Path<(Uuid, String)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let cur: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM eam_maintenance WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let cur = match cur { Some(c) => c, None => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let now = vortex_plugin_sdk::chrono::Utc::now();
    let res: Result<&str, &str> = match (action.as_str(), cur.as_str()) {
        ("schedule", "draft") => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='scheduled' WHERE id=$1").bind(id).execute(&db).await;
            Ok("scheduled")
        }
        ("assign", "scheduled") => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='assigned' WHERE id=$1 AND assigned_to IS NOT NULL").bind(id).execute(&db).await;
            Ok("assigned")
        }
        ("accept", "scheduled") | ("accept", "assigned") => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='in_progress', accepted_by=$2, acceptance_date=$3, start_date=COALESCE(start_date,$3) WHERE id=$1")
                .bind(id).bind(user.id).bind(now).execute(&db).await;
            Ok("in_progress")
        }
        ("reject", "scheduled") | ("reject", "assigned") => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='scheduled', assigned_to=NULL, rejected_by=$2, rejection_date=$3, rejection_reason=$4, rejection_count=rejection_count+1 WHERE id=$1")
                .bind(id).bind(user.id).bind(now).bind(opt_str(&form, "reason")).execute(&db).await;
            Ok("scheduled")
        }
        ("hold", "in_progress") => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='on_hold' WHERE id=$1").bind(id).execute(&db).await; Ok("on_hold") }
        ("resume", "on_hold") => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='in_progress' WHERE id=$1").bind(id).execute(&db).await; Ok("in_progress") }
        ("complete", "in_progress") | ("complete", "on_hold") => {
            // Validate required checklist items have a value.
            let missing: i64 = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT COUNT(*) FROM eam_checklist_line WHERE maintenance_id=$1 AND is_required AND value_pass_fail IS NULL AND value_yes_no IS NULL AND value_measurement IS NULL AND value_text IS NULL AND value_selection IS NULL AND value_rating IS NULL")
                .bind(id).fetch_one(&db).await.unwrap_or(0);
            if missing > 0 { return bad(&format!("{missing} required checklist item(s) not completed")); }
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE eam_maintenance SET state='completed', end_date=$2, needs_rework=false, \
                 actual_duration_hours = CASE WHEN start_date IS NOT NULL THEN EXTRACT(EPOCH FROM ($2 - start_date))/3600.0 END WHERE id=$1")
                .bind(id).bind(now).execute(&db).await;
            Ok("completed")
        }
        ("verify", "completed") => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='verified', verified_by=$2, verification_date=$3, verification_rating=$4, verification_notes=$5 WHERE id=$1")
                .bind(id).bind(user.id).bind(now).bind(form.get("rating").map(|s| s.as_str()).unwrap_or("good")).bind(opt_str(&form, "notes")).execute(&db).await;
            Ok("verified")
        }
        ("return_for_rework", "completed") => {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='in_progress', needs_rework=true, rework_notes=$2, rework_count=rework_count+1, end_date=NULL WHERE id=$1")
                .bind(id).bind(opt_str(&form, "reason")).execute(&db).await;
            Ok("in_progress")
        }
        ("cancel", _) => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='cancelled' WHERE id=$1").bind(id).execute(&db).await; Ok("cancelled") }
        ("reset_draft", "cancelled") => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_maintenance SET state='draft' WHERE id=$1").bind(id).execute(&db).await; Ok("draft") }
        _ => Err("Illegal transition"),
    };
    match res {
        Ok(to) => {
            let entry = vortex_plugin_sdk::security::AuditEntry::new(
                vortex_plugin_sdk::security::AuditAction::RecordUpdated, vortex_plugin_sdk::security::AuditSeverity::Info,
            ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
             .with_database(&db_ctx.db_name).with_resource("eam_maintenance", id.to_string())
             .with_details(json!({"action": action, "from": cur, "to": to}));
            let _ = state.audit.log(entry).await;
            Redirect::to(&format!("/sesb-eam/maintenance/{id}")).into_response()
        }
        Err(msg) => (StatusCode::CONFLICT, format!("{msg}: cannot {action} from {cur}")).into_response(),
    }
}

async fn add_part_line(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Part name required"); }
    let company_id = default_company(&db).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_maintenance_part_line (id, maintenance_id, name, part_number, quantity, unit_cost, cost) \
         VALUES ($1,$2,$3,$4,$5,$6, COALESCE($5,1)*COALESCE($6,0))")
        .bind(Uuid::now_v7()).bind(id).bind(&name).bind(opt_str(&form, "part_number"))
        .bind(opt_dec(&form, "quantity")).bind(opt_dec(&form, "unit_cost")).execute(&db).await;
    let _ = company_id;
    recompute_costs(&db, id).await;
    Redirect::to(&format!("/sesb-eam/maintenance/{id}")).into_response()
}

async fn del_part_line(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path((id, line_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM eam_maintenance_part_line WHERE id=$1").bind(line_id).execute(&db).await;
    recompute_costs(&db, id).await;
    Redirect::to(&format!("/sesb-eam/maintenance/{id}")).into_response()
}

async fn recompute_costs(db: &PgPool, id: Uuid) {
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_maintenance SET materials_cost = COALESCE((SELECT SUM(cost) FROM eam_maintenance_part_line WHERE maintenance_id=$1),0), \
         total_cost = labor_cost + COALESCE((SELECT SUM(cost) FROM eam_maintenance_part_line WHERE maintenance_id=$1),0) WHERE id=$1")
        .bind(id).execute(db).await;
}
