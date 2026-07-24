//! Workforce / field agents (§3.8) — agents, groups (crews) and leave,
//! with the leave approval actions and per-agent kawasan coverage that the
//! §5.5 boundary-reassignment eligibility check relies on.

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

const AGENT_LEVELS: &[(&str, &str)] = &[("","—"),("tukang","Tukang"),("juruteknik","Juruteknik"),("jurutera","Jurutera"),("supervisor","Supervisor"),("manager","Manager")];
const SKILLS: &[(&str, &str)] = &[("","—"),("senggaraan_pencawang","Senggaraan Pencawang"),("talian_atas","Talian Atas"),("kabel_bawah_tanah","Kabel Bawah Tanah"),("primary","Primary"),("protection","Protection"),("telecontrol","Telecontrol")];
const GROUP_TYPES: &[(&str, &str)] = &[("crew","Crew"),("area","Area"),("skill","Skill")];
const LEAVE_TYPES: &[(&str, &str)] = &[("annual","Annual"),("medical","Medical"),("emergency","Emergency"),("training","Training"),("unpaid","Unpaid"),("other","Other")];
const LEAVE_STATE_BADGES: &[(&str, &str, &str)] = &[("draft","Draft","badge-ghost"),("submitted","Submitted","badge-info"),("approved","Approved","badge-success"),("rejected","Rejected","badge-error"),("cancelled","Cancelled","badge-ghost")];

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/agents", get(list_agent))
        .route("/sesb-eam/agents/new", get(new_agent))
        .route("/sesb-eam/agents/create", post(create_agent))
        .route("/sesb-eam/agents/{id}", get(edit_agent))
        .route("/sesb-eam/agents/{id}", post(update_agent))
        .route("/sesb-eam/agent-groups", get(list_group))
        .route("/sesb-eam/agent-groups/new", get(new_group))
        .route("/sesb-eam/agent-groups/create", post(create_group))
        .route("/sesb-eam/agent-groups/{id}", get(edit_group))
        .route("/sesb-eam/agent-groups/{id}", post(update_group))
        .route("/sesb-eam/leaves", get(list_leave))
        .route("/sesb-eam/leaves/new", get(new_leave))
        .route("/sesb-eam/leaves/create", post(create_leave))
        .route("/sesb-eam/leaves/{id}", get(edit_leave))
        .route("/sesb-eam/leaves/{id}", post(update_leave))
        .route("/sesb-eam/leaves/{id}/action/{action}", post(leave_action))
}

async fn group_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_field_agent_group WHERE active ORDER BY sequence, code", "-- Group --", sel).await
}
async fn agent_opts(db: &PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (COALESCE(employee_no,'') || ' ' || name) AS label FROM eam_field_agent WHERE active ORDER BY name", "-- Agent --", sel).await
}

/// Multi-checkbox kawasan picker (coverage), pre-checking `selected`.
async fn kawasan_checkboxes(db: &PgPool, selected: &[Uuid]) -> String {
    let rows = vortex_plugin_sdk::sqlx::query("SELECT id, (code || ' · ' || name) AS label FROM eam_kawasan WHERE active ORDER BY sequence, name").fetch_all(db).await.unwrap_or_default();
    let mut out = String::from(r#"<div class="form-control mb-3"><label class="label"><span class="label-text">Kawasan Coverage</span></label><div class="grid grid-cols-2 md:grid-cols-3 gap-1">"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let label: String = r.get("label");
        let checked = if selected.contains(&id) { "checked" } else { "" };
        out.push_str(&format!(r#"<label class="cursor-pointer label justify-start gap-2 py-0"><input type="checkbox" name="kawasan_ids" value="{id}" class="checkbox checkbox-xs" {c}/><span class="label-text text-xs">{l}</span></label>"#, id = id, c = checked, l = esc(&label)));
    }
    out.push_str("</div></div>");
    out
}

// ═════════════════════════════════════ Field Agent ═════════════════════════

async fn list_agent(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.agents");
    let config = ListConfig::new("Field Agents", "eam_field_agent")
        .scope_filter(division::division_predicate(&user, "a.division"))
        .custom_from("eam_field_agent a LEFT JOIN eam_region r ON r.id=a.region_id")
        .custom_select("a.id, a.name, a.employee_no, a.agent_level, a.skill_category, r.name AS region, a.is_supervisor, a.active, \
            (SELECT COUNT(*) FROM eam_maintenance m WHERE m.assigned_to=a.user_id AND m.state NOT IN ('completed','verified','cancelled'))::text AS active_jobs")
        .column(ListColumn::new("employee_no", "Emp No").sortable().code().sql_expr("a.employee_no"))
        .column(ListColumn::new("name", "Name").searchable().sql_expr("a.name"))
        .column(ListColumn::new("agent_level", "Level").filterable(&[("tukang","Tukang"),("juruteknik","Juruteknik"),("jurutera","Jurutera"),("supervisor","Supervisor")]).sql_expr("a.agent_level"))
        .column(ListColumn::new("skill_category", "Skill").sql_expr("a.skill_category"))
        .column(ListColumn::new("region", "Region").sql_expr("r.name"))
        .column(ListColumn::new("active_jobs", "Active Jobs").sql_expr("1"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Inactive","badge-ghost").sql_expr("a.active"))
        .detail_url("/sesb-eam/agents/{id}")
        .create("New Agent", "/sesb-eam/agents/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "agent list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Field Agents", &render_list(&config, &result, &params, "/sesb-eam/agents"))).into_response()
}

async fn agent_body(db: &PgPool, v: &HashMap<String, String>, cov: &[Uuid], is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let regions = region_options(db, v.get("region_id").and_then(|s| s.parse().ok())).await;
    let groups = group_opts(db, v.get("supervisor_group_id").and_then(|s| s.parse().ok())).await;
    let users = user_options(db, v.get("user_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}{}{}{}",
        text_field("Name *", "name", g("name"), true),
        text_field("Employee No", "employee_no", g("employee_no"), false),
        select_field("Linked User", "user_id", &users),
        select_field("Level", "agent_level", &enum_options(AGENT_LEVELS, g("agent_level"))),
        select_field("Skill", "skill_category", &enum_options(SKILLS, g("skill_category"))),
        select_field("Region", "region_id", &regions),
        select_field("Group", "supervisor_group_id", &groups),
        num_field("Max Concurrent Jobs", "max_concurrent_jobs", g("max_concurrent_jobs"), "1")));
    let grid2x = grid2(&format!("{}{}",
        text_field("Phone", "phone", g("phone"), false),
        text_field("Emergency Contact", "emergency_contact", g("emergency_contact"), false)));
    let sup = checkbox("is_supervisor", "Is Supervisor", g("is_supervisor") == "true");
    let cov_picker = kawasan_checkboxes(db, cov).await;
    format!("{}{}{}{}{}{}", grid, grid2x, sup, cov_picker, textarea_field("Notes", "notes", g("notes")), active_field(g("active") == "true" || is_new, is_new))
}

fn checkbox(name: &str, label: &str, checked: bool) -> String {
    format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="{name}" class="checkbox checkbox-sm" {c}/><span class="label-text">{label}</span></label></div>"#, name = name, label = label, c = if checked { "checked" } else { "" })
}
fn grid3(fields: &str) -> String { format!(r#"<div class="grid grid-cols-1 md:grid-cols-3 gap-x-4">{}</div>"#, fields) }

async fn new_agent(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.agents");
    let header = form_header("/sesb-eam/agents", "Back to Agents", "New Field Agent");
    let body = agent_body(&db, &HashMap::new(), &[], true).await;
    Html(page_shell(&sidebar, "New Agent", &wide_form_page("/sesb-eam/agents/create", &header, &body))).into_response()
}

/// Build a last-wins map from urlencoded key/value pairs.
fn pairs_map(pairs: &[(String, String)]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (k, v) in pairs { m.insert(k.clone(), v.clone()); }
    m
}
/// Collect repeated checkbox values (e.g. `kawasan_ids`) as UUIDs.
fn multi_uuids(pairs: &[(String, String)], key: &str) -> Vec<Uuid> {
    pairs.iter().filter(|(k, _)| k == key).filter_map(|(_, v)| v.parse::<Uuid>().ok()).collect()
}

async fn create_agent(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let form = pairs_map(&pairs);
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Name is required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_field_agent (id, name, employee_no, user_id, agent_level, is_supervisor, skill_category, region_id, supervisor_group_id, phone, emergency_contact, max_concurrent_jobs, notes, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
        .bind(id).bind(&name).bind(opt_str(&form, "employee_no")).bind(opt_uuid(&form, "user_id"))
        .bind(opt_str(&form, "agent_level")).bind(form.contains_key("is_supervisor")).bind(opt_str(&form, "skill_category"))
        .bind(opt_uuid(&form, "region_id")).bind(opt_uuid(&form, "supervisor_group_id")).bind(opt_str(&form, "phone")).bind(opt_str(&form, "emergency_contact"))
        .bind(opt_i32(&form, "max_concurrent_jobs")).bind(opt_str(&form, "notes")).bind(company_id).execute(&db).await;
    if let Err(e) = res { error!(error=%e, "agent insert"); return bad(&format!("Failed: {e}")); }
    for kid in multi_uuids(&pairs, "kawasan_ids") {
        let _ = vortex_plugin_sdk::sqlx::query("INSERT INTO eam_field_agent_kawasan_rel (agent_id, kawasan_id) VALUES ($1,$2) ON CONFLICT DO NOTHING").bind(id).bind(kid).execute(&db).await;
    }
    if let Some(gid) = opt_uuid(&form, "supervisor_group_id") {
        let _ = vortex_plugin_sdk::sqlx::query("INSERT INTO eam_field_agent_group_rel (agent_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING").bind(id).bind(gid).execute(&db).await;
    }
    Redirect::to(&format!("/sesb-eam/agents/{id}")).into_response()
}

async fn edit_agent(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_field_agent", id).await { return resp; }
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.agents");
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, employee_no, user_id::text AS user_id, agent_level, is_supervisor::text AS is_supervisor, skill_category, region_id::text AS region_id, supervisor_group_id::text AS supervisor_group_id, phone, emergency_contact, max_concurrent_jobs::text AS max_concurrent_jobs, notes, active::text AS active FROM eam_field_agent WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["name","employee_no","user_id","agent_level","is_supervisor","skill_category","region_id","supervisor_group_id","phone","emergency_contact","max_concurrent_jobs","notes","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let cov: Vec<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT kawasan_id FROM eam_field_agent_kawasan_rel WHERE agent_id=$1").bind(id).fetch_all(&db).await.unwrap_or_default();
    let body = agent_body(&db, &v, &cov, false).await;
    let header = form_header("/sesb-eam/agents", "Back to Agents", &format!("Agent · {}", v.get("name").cloned().unwrap_or_default()));
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("eam_agent", id);
    let content = format!("{}<div class=\"max-w-4xl mt-6\">{activity_panel}</div>", wide_form_page(&format!("/sesb-eam/agents/{id}"), &header, &body));
    Html(page_shell(&sidebar, "Field Agent", &content)).into_response()
}

async fn update_agent(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let form = pairs_map(&pairs);
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() { return bad("Name is required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_field_agent SET name=$1, employee_no=$2, user_id=$3, agent_level=$4, is_supervisor=$5, skill_category=$6, region_id=$7, supervisor_group_id=$8, phone=$9, emergency_contact=$10, max_concurrent_jobs=$11, notes=$12, active=$13 WHERE id=$14")
        .bind(&name).bind(opt_str(&form, "employee_no")).bind(opt_uuid(&form, "user_id")).bind(opt_str(&form, "agent_level"))
        .bind(form.contains_key("is_supervisor")).bind(opt_str(&form, "skill_category")).bind(opt_uuid(&form, "region_id")).bind(opt_uuid(&form, "supervisor_group_id"))
        .bind(opt_str(&form, "phone")).bind(opt_str(&form, "emergency_contact")).bind(opt_i32(&form, "max_concurrent_jobs")).bind(opt_str(&form, "notes")).bind(form.contains_key("active")).bind(id)
        .execute(&db).await;
    // Replace kawasan coverage.
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM eam_field_agent_kawasan_rel WHERE agent_id=$1").bind(id).execute(&db).await;
    for kid in multi_uuids(&pairs, "kawasan_ids") {
        let _ = vortex_plugin_sdk::sqlx::query("INSERT INTO eam_field_agent_kawasan_rel (agent_id, kawasan_id) VALUES ($1,$2) ON CONFLICT DO NOTHING").bind(id).bind(kid).execute(&db).await;
    }
    Redirect::to(&format!("/sesb-eam/agents/{id}")).into_response()
}

// ═════════════════════════════════════ Agent Group ═════════════════════════

async fn list_group(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.agent_groups");
    let config = ListConfig::new("Field Agent Groups", "eam_field_agent_group")
        .custom_select("id, code, name, group_type, skill_category, active, (SELECT COUNT(*) FROM eam_field_agent_group_rel r WHERE r.group_id=eam_field_agent_group.id)::text AS members")
        .column(ListColumn::new("code", "Code").sortable().code())
        .column(ListColumn::new("name", "Name").searchable())
        .column(ListColumn::new("group_type", "Type").filterable(&[("crew","Crew"),("area","Area"),("skill","Skill")]))
        .column(ListColumn::new("skill_category", "Skill"))
        .column(ListColumn::new("members", "Members").sql_expr("1"))
        .column(ListColumn::new("active", "Status").bool_badge("Active","badge-success","Inactive","badge-ghost"))
        .detail_url("/sesb-eam/agent-groups/{id}")
        .create("New Group", "/sesb-eam/agent-groups/new")
        .default_sort("code");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "group list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Agent Groups", &render_list(&config, &result, &params, "/sesb-eam/agent-groups"))).into_response()
}

async fn group_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let sups = user_options(db, v.get("supervisor_user_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}{}",
        text_field("Name *", "name", g("name"), true),
        text_field("Code *", "code", g("code"), true),
        select_field("Type *", "group_type", &enum_options(GROUP_TYPES, if g("group_type").is_empty() { "crew" } else { g("group_type") })),
        select_field("Skill", "skill_category", &enum_options(SKILLS, g("skill_category"))),
        select_field("Supervisor", "supervisor_user_id", &sups)));
    format!("{}{}{}", grid, textarea_field("Description", "description", g("description")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_group(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.agent_groups");
    let header = form_header("/sesb-eam/agent-groups", "Back to Groups", "New Agent Group");
    let body = group_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Group", &wide_form_page("/sesb-eam/agent-groups/create", &header, &body))).into_response()
}

async fn create_group(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    let code = form.get("code").cloned().unwrap_or_default();
    if name.trim().is_empty() || code.trim().is_empty() { return bad("Name and code are required"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_field_agent_group (id, name, code, group_type, skill_category, supervisor_user_id, description, company_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(&name).bind(&code).bind(form.get("group_type").map(|s| s.as_str()).unwrap_or("crew"))
        .bind(opt_str(&form, "skill_category")).bind(opt_uuid(&form, "supervisor_user_id")).bind(opt_str(&form, "description")).bind(company_id).execute(&db).await;
    if let Err(e) = res { error!(error=%e, "group insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/agent-groups/{id}")).into_response()
}

async fn edit_group(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.agent_groups");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, code, group_type, skill_category, supervisor_user_id::text AS supervisor_user_id, description, active::text AS active FROM eam_field_agent_group WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["name","code","group_type","skill_category","supervisor_user_id","description","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    // Member roster
    let members = vortex_plugin_sdk::sqlx::query("SELECT a.name, a.employee_no FROM eam_field_agent_group_rel r JOIN eam_field_agent a ON a.id=r.agent_id WHERE r.group_id=$1 ORDER BY a.name").bind(id).fetch_all(&db).await.unwrap_or_default();
    let roster = if members.is_empty() { "<p class=\"opacity-60 text-sm\">No members yet — set this group on an agent.</p>".to_string() } else {
        let items: String = members.iter().map(|m| format!("<li>{} <span class=\"opacity-50 font-mono text-xs\">{}</span></li>", esc(&m.get::<String,_>("name")), esc(&m.try_get::<Option<String>,_>("employee_no").ok().flatten().unwrap_or_default()))).collect();
        format!("<ul class=\"list-disc ml-5 text-sm\">{}</ul>", items)
    };
    let body = group_body(&db, &v, false).await;
    let header = form_header("/sesb-eam/agent-groups", "Back to Groups", &format!("Group · {}", v.get("name").cloned().unwrap_or_default()));
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("eam_group", id);
    let content = format!("<div class=\"max-w-4xl\">{}{}<div class=\"card bg-base-100 shadow mt-4\"><div class=\"card-body\"><h2 class=\"font-semibold\">Members</h2>{}</div></div><div class=\"mt-6\">{activity_panel}</div></div>",
        header, wide_form_page(&format!("/sesb-eam/agent-groups/{id}"), "", &body), roster);
    Html(page_shell(&sidebar, "Agent Group", &content)).into_response()
}

async fn update_group(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    let code = form.get("code").cloned().unwrap_or_default();
    if name.trim().is_empty() || code.trim().is_empty() { return bad("Name and code are required"); }
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_field_agent_group SET name=$1, code=$2, group_type=$3, skill_category=$4, supervisor_user_id=$5, description=$6, active=$7 WHERE id=$8")
        .bind(&name).bind(&code).bind(form.get("group_type").map(|s| s.as_str()).unwrap_or("crew")).bind(opt_str(&form, "skill_category"))
        .bind(opt_uuid(&form, "supervisor_user_id")).bind(opt_str(&form, "description")).bind(form.contains_key("active")).bind(id).execute(&db).await;
    Redirect::to(&format!("/sesb-eam/agent-groups/{id}")).into_response()
}

// ═════════════════════════════════════ Leave ═══════════════════════════════

async fn list_leave(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.leaves");
    let config = ListConfig::new("Agent Leave", "eam_field_agent_leave")
        .custom_from("eam_field_agent_leave l LEFT JOIN eam_field_agent a ON a.id=l.agent_id")
        .custom_select("l.id, a.name AS agent, l.leave_type, l.date_from::text AS df, l.date_to::text AS dt, (l.date_to - l.date_from + 1)::text AS days, l.state, l.active")
        .column(ListColumn::new("agent", "Agent").searchable().sql_expr("a.name"))
        .column(ListColumn::new("leave_type", "Type").filterable(&[("annual","Annual"),("medical","Medical"),("emergency","Emergency"),("training","Training")]).sql_expr("l.leave_type"))
        .column(ListColumn::new("df", "From").sortable().sql_expr("l.date_from"))
        .column(ListColumn::new("dt", "To").sql_expr("l.date_to"))
        .column(ListColumn::new("days", "Days").sql_expr("1"))
        .column(ListColumn::new("state", "State").filterable(&[("submitted","Submitted"),("approved","Approved"),("rejected","Rejected")])
            .badge(&[("draft","Draft","badge-ghost"),("submitted","Submitted","badge-info"),("approved","Approved","badge-success"),("rejected","Rejected","badge-error"),("cancelled","Cancelled","badge-ghost")]).sql_expr("l.state"))
        .detail_url("/sesb-eam/leaves/{id}")
        .create("New Leave", "/sesb-eam/leaves/new")
        .default_sort("df");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await { Ok(r) => r, Err(e) => { error!(error=%e, "leave list"); return Html("<h1>Failed</h1>").into_response(); } };
    Html(page_shell(&sidebar, "Agent Leave", &render_list(&config, &result, &params, "/sesb-eam/leaves"))).into_response()
}

async fn leave_body(db: &PgPool, v: &HashMap<String, String>, is_new: bool) -> String {
    let g = |k: &str| v.get(k).map(|s| s.as_str()).unwrap_or("");
    let agents = agent_opts(db, v.get("agent_id").and_then(|s| s.parse().ok())).await;
    let grid = grid3(&format!("{}{}{}{}",
        select_field("Agent *", "agent_id", &agents),
        select_field("Leave Type *", "leave_type", &enum_options(LEAVE_TYPES, if g("leave_type").is_empty() { "annual" } else { g("leave_type") })),
        date_field("From *", "date_from", g("date_from")),
        date_field("To *", "date_to", g("date_to"))));
    format!("{}{}{}", grid, textarea_field("Reason", "reason", g("reason")), active_field(g("active") == "true" || is_new, is_new))
}

async fn new_leave(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.leaves");
    let header = form_header("/sesb-eam/leaves", "Back to Leave", "New Leave Request");
    let body = leave_body(&db, &HashMap::new(), true).await;
    Html(page_shell(&sidebar, "New Leave", &wide_form_page("/sesb-eam/leaves/create", &header, &body))).into_response()
}

async fn create_leave(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let agent_id = match opt_uuid(&form, "agent_id") { Some(a) => a, None => return bad("Agent is required") };
    let date_from = match opt_date(&form, "date_from") { Some(d) => d, None => return bad("From date is required") };
    let date_to = match opt_date(&form, "date_to") { Some(d) => d, None => return bad("To date is required") };
    if date_to < date_from { return bad("To date must be on/after From date"); }
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_field_agent_leave (id, agent_id, user_id, leave_type, date_from, date_to, reason, state, company_id) \
         SELECT $1,$2, a.user_id, $3,$4,$5,$6,'submitted',$7 FROM eam_field_agent a WHERE a.id=$2")
        .bind(id).bind(agent_id).bind(form.get("leave_type").map(|s| s.as_str()).unwrap_or("annual"))
        .bind(date_from).bind(date_to).bind(opt_str(&form, "reason")).bind(company_id).execute(&db).await;
    if let Err(e) = res { error!(error=%e, "leave insert"); return bad(&format!("Failed: {e}")); }
    Redirect::to(&format!("/sesb-eam/leaves/{id}")).into_response()
}

async fn edit_leave(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.leaves");
    let row = match vortex_plugin_sdk::sqlx::query("SELECT agent_id::text AS agent_id, leave_type, date_from::text AS date_from, date_to::text AS date_to, reason, state, rejection_reason, active::text AS active FROM eam_field_agent_leave WHERE id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v: HashMap<String, String> = HashMap::new();
    for k in ["agent_id","leave_type","date_from","date_to","reason","active"] {
        if let Ok(Some(val)) = row.try_get::<Option<String>, _>(k) { v.insert(k.to_string(), val); }
    }
    let lstate: String = row.get("state");
    let body = leave_body(&db, &v, false).await;
    let btn = |a: &str, l: &str, c: &str, extra: &str| format!(r#"<form method="POST" action="/sesb-eam/leaves/{id}/action/{a}" class="inline">{extra}<button class="btn btn-sm {c}">{l}</button></form>"#, id = id, a = a, c = c, l = l, extra = extra);
    let actions = match lstate.as_str() {
        "submitted" => format!("{}{}", btn("approve", "Approve", "btn-success", ""), btn("reject", "Reject", "btn-error btn-outline", r#"<input name="reason" class="input input-bordered input-xs mr-1" placeholder="reason" required/>"#)),
        "approved" | "rejected" => btn("reset", "Reset to Draft", "btn-ghost", ""),
        _ => btn("submit", "Submit", "btn-primary", ""),
    };
    let header = format!(r#"<a href="/sesb-eam/leaves" class="btn btn-ghost btn-sm mb-3">← Back to Leave</a>
<h1 class="text-2xl font-bold mb-3">Leave Request {badge}</h1><div class="flex gap-2 mb-4">{actions}</div>"#,
        badge = LEAVE_STATE_BADGES.iter().find(|(v,_,_)| *v==lstate).map(|(_,l,c)| format!(r#"<span class="badge {c}">{l}</span>"#, c=c, l=l)).unwrap_or_default(), actions = actions);
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("eam_leave", id);
    let content = format!("<div class=\"max-w-4xl\">{}{}<div class=\"mt-6\">{activity_panel}</div></div>", header, wide_form_page(&format!("/sesb-eam/leaves/{id}"), "", &body));
    Html(page_shell(&sidebar, "Leave Request", &content)).into_response()
}

async fn update_leave(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    if opt_uuid(&form, "agent_id").is_none() { return bad("Agent is required"); }
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_field_agent_leave SET leave_type=$1, date_from=$2, date_to=$3, reason=$4, active=$5 WHERE id=$6")
        .bind(form.get("leave_type").map(|s| s.as_str()).unwrap_or("annual")).bind(opt_date(&form, "date_from")).bind(opt_date(&form, "date_to"))
        .bind(opt_str(&form, "reason")).bind(form.contains_key("active")).bind(id).execute(&db).await;
    Redirect::to(&format!("/sesb-eam/leaves/{id}")).into_response()
}

async fn leave_action(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path((id, action)): Path<(Uuid, String)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    match action.as_str() {
        "submit" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_field_agent_leave SET state='submitted' WHERE id=$1 AND state='draft'").bind(id).execute(&db).await; }
        "approve" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_field_agent_leave SET state='approved', approved_by=$2, approval_date=NOW() WHERE id=$1 AND state='submitted'").bind(id).bind(user.id).execute(&db).await; }
        "reject" => {
            let reason = match opt_str(&form, "reason") { Some(r) => r.clone(), None => return bad("Rejection reason is required") };
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_field_agent_leave SET state='rejected', rejection_reason=$2 WHERE id=$1 AND state='submitted'").bind(id).bind(&reason).execute(&db).await;
        }
        "reset" => { let _ = vortex_plugin_sdk::sqlx::query("UPDATE eam_field_agent_leave SET state='draft' WHERE id=$1").bind(id).execute(&db).await; }
        _ => return (StatusCode::BAD_REQUEST, "Unknown action").into_response(),
    }
    Redirect::to(&format!("/sesb-eam/leaves/{id}")).into_response()
}
