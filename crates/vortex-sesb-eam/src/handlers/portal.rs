//! Field technician portal (§8) under `/sesb-eam/my/*` — a mobile-first,
//! server-rendered surface for assigned work: personal KPIs, today's jobs, a
//! work-order detail with the live checklist + action buttons, location
//! sharing and the "Cerdik" troubleshooting assistant (offline fallback).

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::axum::Json;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use super::{api, checklist};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/my", get(home))
        .route("/sesb-eam/my/dashboard", get(dashboard))
        .route("/sesb-eam/my/today", get(today))
        .route("/sesb-eam/my/maintenance", get(my_maintenance))
        .route("/sesb-eam/my/maintenance/{id}", get(my_wo))
        .route("/sesb-eam/my/maintenance/{id}/action", post(my_wo_action))
        .route("/sesb-eam/my/maintenance/{id}/checklist/save", post(my_checklist_save))
        .route("/sesb-eam/my/location/update", post(location_update))
        .route("/sesb-eam/my/ai/troubleshoot", post(troubleshoot))
}

/// Minimal mobile shell (self-contained; reuses the daisyUI CDN like the rest).
fn portal_shell(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><meta charset="utf-8"><title>{title} · Field</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=12" rel="stylesheet"/>
<script src="/static/vortex.js?v=12" defer></script>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="navbar bg-base-100 shadow sticky top-0 z-30">
<a href="/sesb-eam/my/dashboard" class="btn btn-ghost text-lg"><span class="text-success">SESB</span> Field</a>
<div class="flex-1"></div>
<a href="/sesb-eam/my/today" class="btn btn-ghost btn-sm">Today</a>
<a href="/sesb-eam/my/maintenance" class="btn btn-ghost btn-sm">Jobs</a>
</div>
<main class="p-3 max-w-2xl mx-auto">{body}</main></body></html>"#,
        title = esc(title), body = body)
}

fn pkpi(title: &str, value: &str, cls: &str) -> String {
    format!(r#"<div class="stat bg-base-100 rounded-box shadow p-3"><div class="stat-title text-xs">{t}</div><div class="stat-value text-xl {c}">{v}</div></div>"#, t = esc(title), v = esc(value), c = cls)
}

async fn home() -> Response { Redirect::to("/sesb-eam/my/dashboard").into_response() }

async fn dashboard(
    Db(db): Db, Extension(user): Extension<AuthUser>,
) -> Response {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT \
           COUNT(*) FILTER (WHERE state NOT IN ('completed','verified','cancelled'))::bigint AS open, \
           COUNT(*) FILTER (WHERE state NOT IN ('completed','verified','cancelled') AND scheduled_date < CURRENT_DATE)::bigint AS overdue, \
           COUNT(*) FILTER (WHERE scheduled_date = CURRENT_DATE)::bigint AS today, \
           COUNT(*) FILTER (WHERE state='in_progress')::bigint AS in_progress, \
           COUNT(*) FILTER (WHERE state IN ('completed','verified'))::bigint AS completed \
         FROM eam_maintenance WHERE assigned_to=$1")
        .bind(user.id).fetch_one(&db).await.ok();
    let g = |k: &str| row.as_ref().and_then(|r| r.try_get::<i64,_>(k).ok()).unwrap_or(0);
    let defects: i64 = vortex_plugin_sdk::sqlx::query_scalar("SELECT COUNT(*)::bigint FROM eam_defect WHERE discovered_by=$1").bind(user.id).fetch_one(&db).await.unwrap_or(0);
    let cards = format!("{}{}{}{}{}{}",
        pkpi("Open", &g("open").to_string(), ""),
        pkpi("Overdue", &g("overdue").to_string(), "text-error"),
        pkpi("Due Today", &g("today").to_string(), "text-warning"),
        pkpi("In Progress", &g("in_progress").to_string(), "text-info"),
        pkpi("Completed", &g("completed").to_string(), "text-success"),
        pkpi("Defects Raised", &defects.to_string(), ""));
    let body = format!(
        r#"<h1 class="text-xl font-bold mb-3">Hi, {name}</h1>
<div class="grid grid-cols-2 gap-2 mb-4">{cards}</div>
<div class="flex gap-2"><a href="/sesb-eam/my/today" class="btn btn-primary btn-sm flex-1">Today's Jobs</a><a href="/sesb-eam/my/maintenance" class="btn btn-ghost btn-sm flex-1">All Jobs</a></div>"#,
        name = esc(user.full_name.as_deref().unwrap_or(&user.username)), cards = cards);
    Html(portal_shell("Dashboard", &body)).into_response()
}

async fn today(
    Db(db): Db, Extension(user): Extension<AuthUser>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT m.id, m.name, m.description, m.state, e.name AS equip, s.name AS sub, s.latitude::text AS lat, s.longitude::text AS lng \
         FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id LEFT JOIN eam_substation s ON s.id=m.substation_id \
         WHERE m.assigned_to=$1 AND m.scheduled_date <= CURRENT_DATE AND m.state NOT IN ('completed','verified','cancelled') ORDER BY m.scheduled_date")
        .bind(user.id).fetch_all(&db).await.unwrap_or_default();
    let body = if rows.is_empty() { "<p class=\"opacity-60\">No jobs due. 🎉</p>".to_string() } else {
        rows.iter().map(|r| {
            let id: Uuid = r.get("id");
            let nm: Option<String> = r.try_get("name").ok();
            let desc: String = r.get("description");
            let equip: Option<String> = r.try_get("equip").ok();
            let lat: Option<String> = r.try_get("lat").ok().flatten();
            let lng: Option<String> = r.try_get("lng").ok().flatten();
            let nav = match (lat, lng) { (Some(a), Some(o)) => format!(r#"<a href="https://www.google.com/maps/dir/?api=1&destination={a},{o}" target="_blank" rel="noopener" class="btn btn-xs btn-outline">Navigate</a>"#, a = a, o = o), _ => String::new() };
            format!(r#"<div class="card bg-base-100 shadow mb-2"><div class="card-body p-3">
<div class="flex justify-between items-start"><div><div class="font-mono text-xs opacity-50">{nm}</div><div class="font-semibold">{desc}</div><div class="text-sm opacity-70">{equip}</div></div><span class="badge badge-sm">{st}</span></div>
<div class="flex gap-2 mt-2"><a href="/sesb-eam/my/maintenance/{id}" class="btn btn-primary btn-xs flex-1">Open</a>{nav}</div></div></div>"#,
                nm = esc(nm.as_deref().unwrap_or("")), desc = esc(&desc), equip = esc(equip.as_deref().unwrap_or("")), st = esc(&r.get::<String,_>("state")), id = id, nav = nav)
        }).collect()
    };
    Html(portal_shell("Today", &format!("<h1 class=\"text-xl font-bold mb-3\">Today's Jobs</h1>{}", body))).into_response()
}

async fn my_maintenance(
    Db(db): Db, Extension(user): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let state_f = q.get("state").cloned().unwrap_or_default();
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT m.id, m.name, m.description, m.state, e.name AS equip FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id WHERE m.assigned_to=$1 AND ($2='' OR m.state=$2) ORDER BY m.scheduled_date NULLS LAST, m.created_at DESC LIMIT 100")
        .bind(user.id).bind(&state_f).fetch_all(&db).await.unwrap_or_default();
    let filters = ["", "scheduled", "assigned", "in_progress", "completed"].iter().map(|s| {
        let label = if s.is_empty() { "All" } else { *s };
        let cls = if *s == state_f { "btn-primary" } else { "btn-ghost" };
        format!(r#"<a href="/sesb-eam/my/maintenance?state={s}" class="btn btn-xs {c}">{l}</a>"#, s = s, c = cls, l = label)
    }).collect::<String>();
    let list = if rows.is_empty() { "<p class=\"opacity-60\">No jobs.</p>".to_string() } else {
        rows.iter().map(|r| {
            let id: Uuid = r.get("id");
            format!(r#"<a href="/sesb-eam/my/maintenance/{id}" class="card bg-base-100 shadow mb-2 block"><div class="card-body p-3 flex-row justify-between items-center"><div><div class="font-mono text-xs opacity-50">{nm}</div><div class="font-semibold">{desc}</div><div class="text-sm opacity-70">{equip}</div></div><span class="badge badge-sm">{st}</span></div></a>"#,
                id = id, nm = esc(&r.try_get::<Option<String>,_>("name").ok().flatten().unwrap_or_default()), desc = esc(&r.get::<String,_>("description")), equip = esc(&r.try_get::<Option<String>,_>("equip").ok().flatten().unwrap_or_default()), st = esc(&r.get::<String,_>("state")))
        }).collect()
    };
    Html(portal_shell("Jobs", &format!(r#"<h1 class="text-xl font-bold mb-2">My Jobs</h1><div class="flex flex-wrap gap-1 mb-3">{}</div>{}"#, filters, list))).into_response()
}

async fn my_wo(
    Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<Uuid>,
) -> Response {
    let m = vortex_plugin_sdk::sqlx::query(
        "SELECT m.name, m.description, m.state, e.name AS equip, e.id AS equip_id FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id WHERE m.id=$1 AND (m.assigned_to=$2 OR $3)")
        .bind(id).bind(user.id).bind(user.roles.iter().any(|r| r=="EAM Manager"||r=="EAM Officer"||r=="System Administrator"))
        .fetch_optional(&db).await.ok().flatten();
    let m = match m { Some(r) => r, None => return (StatusCode::NOT_FOUND, "Not found or not assigned to you").into_response() };
    let st: String = m.get("state");
    let equip_id: Option<Uuid> = m.try_get("equip_id").ok();
    let roll = checklist::rollup(&db, id).await;
    // checklist editor
    let lines = vortex_plugin_sdk::sqlx::query("SELECT id, name, input_type, is_required, value_pass_fail, value_yes_no, value_measurement::text AS vm, value_text, value_selection, value_rating::text AS vr, note FROM eam_checklist_line WHERE maintenance_id=$1 ORDER BY sequence").bind(id).fetch_all(&db).await.unwrap_or_default();
    let cl_body: String = lines.iter().map(|l| {
        let lid: Uuid = l.get("id");
        let it: String = l.get("input_type");
        let req = if l.try_get::<bool,_>("is_required").unwrap_or(false) { r#"<span class="text-error">*</span>"# } else { "" };
        let cur = match it.as_str() {
            "pass_fail" => l.try_get::<Option<String>,_>("value_pass_fail").ok().flatten(),
            "yes_no" => l.try_get::<Option<String>,_>("value_yes_no").ok().flatten(),
            "measurement" => l.try_get::<Option<String>,_>("vm").ok().flatten(),
            "rating" => l.try_get::<Option<String>,_>("vr").ok().flatten(),
            "selection" => l.try_get::<Option<String>,_>("value_selection").ok().flatten(),
            _ => l.try_get::<Option<String>,_>("value_text").ok().flatten(),
        }.unwrap_or_default();
        let input = match it.as_str() {
            "pass_fail" => select_in(&format!("cl__{lid}"), &[("","—"),("pass","Pass"),("fail","Fail"),("na","N/A")], &cur),
            "yes_no" => select_in(&format!("cl__{lid}"), &[("","—"),("yes","Yes"),("no","No")], &cur),
            "measurement" => format!(r#"<input name="cl__{lid}" type="number" step="any" value="{v}" class="input input-bordered input-sm w-32"/>"#, lid = lid, v = esc(&cur)),
            "rating" => format!(r#"<input name="cl__{lid}" type="number" min="0" value="{v}" class="input input-bordered input-sm w-24"/>"#, lid = lid, v = esc(&cur)),
            _ => format!(r#"<input name="cl__{lid}" value="{v}" class="input input-bordered input-sm w-full"/>"#, lid = lid, v = esc(&cur)),
        };
        format!(r#"<div class="mb-2"><label class="label py-0"><span class="label-text text-sm">{n}{req}</span></label>{input}</div>"#, n = esc(&l.get::<String,_>("name")), req = req, input = input)
    }).collect();
    let cl_form = if lines.is_empty() { "<p class=\"opacity-60 text-sm\">No checklist.</p>".to_string() } else {
        format!(r#"<form method="POST" action="/sesb-eam/my/maintenance/{id}/checklist/save"><div class="card bg-base-100 shadow mb-3"><div class="card-body p-3"><div class="flex justify-between items-center mb-2"><h2 class="font-semibold">Checklist</h2><span class="badge">{done}/{total} · {pct:.0}%</span></div>{body}<button class="btn btn-primary btn-sm mt-2 w-full">Save Checklist</button></div></div></form>"#,
            id = id, done = roll.completed, total = roll.total, pct = roll.progress, body = cl_body) };

    // action buttons by state
    let act = |a: &str, l: &str, c: &str| format!(r#"<form method="POST" action="/sesb-eam/my/maintenance/{id}/action" class="flex-1"><input type="hidden" name="action" value="{a}"/><button class="btn {c} btn-sm w-full">{l}</button></form>"#, id = id, a = a, c = c, l = l);
    let actions = match st.as_str() {
        "scheduled" | "assigned" => format!("{}{}", act("accept","Accept & Start","btn-success"), act("reject","Reject","btn-error btn-outline")),
        "in_progress" => format!("{}{}", act("hold","Hold","btn-warning btn-outline"), act("complete","Complete","btn-success")),
        "on_hold" => act("resume","Resume","btn-primary"),
        _ => String::new(),
    };
    let ai = equip_id.map(|eid| format!(r#"<a href="/sesb-eam/my/maintenance/{id}#ai" class="btn btn-ghost btn-sm w-full mt-2">🤖 Cerdik Assistant</a><div id="ai"></div><p class="text-xs opacity-50 mt-1">AI: POST /sesb-eam/my/ai/troubleshoot {{equipment_id={eid}, symptom}}</p>"#, id = id, eid = eid)).unwrap_or_default();
    let body = format!(
        r#"<a href="/sesb-eam/my/maintenance" class="btn btn-ghost btn-xs mb-2">← Jobs</a>
<div class="card bg-base-100 shadow mb-3"><div class="card-body p-3"><div class="flex justify-between"><div><div class="font-mono text-xs opacity-50">{nm}</div><h1 class="text-lg font-bold">{desc}</h1><div class="opacity-70 text-sm">{equip}</div></div><span class="badge">{st}</span></div></div></div>
<div class="flex gap-2 mb-3">{actions}</div>
{cl}{ai}"#,
        nm = esc(&m.try_get::<Option<String>,_>("name").ok().flatten().unwrap_or_default()), desc = esc(&m.get::<String,_>("description")),
        equip = esc(&m.try_get::<Option<String>,_>("equip").ok().flatten().unwrap_or_default()), st = esc(&st), actions = actions, cl = cl_form, ai = ai);
    Html(portal_shell("Work Order", &body)).into_response()
}

fn select_in(name: &str, opts: &[(&str, &str)], cur: &str) -> String {
    let o: String = opts.iter().map(|(v, l)| format!(r#"<option value="{v}"{s}>{l}</option>"#, v = v, l = l, s = if *v == cur { " selected" } else { "" })).collect();
    format!(r#"<select name="{name}" class="select select-bordered select-sm w-40">{o}</select>"#, name = name, o = o)
}

async fn my_wo_action(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    // Reuse the API state-machine, then redirect back to the portal page.
    let resp = api::maintenance_action(State(state), Db(db), Extension(user), Extension(db_ctx), Path(id), Form(form)).await;
    if resp.status().is_success() {
        Redirect::to(&format!("/sesb-eam/my/maintenance/{id}")).into_response()
    } else { resp }
}

async fn my_checklist_save(
    Db(db): Db, Extension(_u): Extension<AuthUser>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let lines = vortex_plugin_sdk::sqlx::query("SELECT id, input_type FROM eam_checklist_line WHERE maintenance_id=$1").bind(id).fetch_all(&db).await.unwrap_or_default();
    for l in &lines {
        let lid: Uuid = l.get("id");
        let it: String = l.get("input_type");
        let val = form.get(&format!("cl__{}", lid)).filter(|s| !s.is_empty());
        let (col, cast) = match it.as_str() {
            "pass_fail" => ("value_pass_fail", ""), "yes_no" => ("value_yes_no", ""),
            "measurement" => ("value_measurement", "::numeric"), "rating" => ("value_rating", "::int"),
            "selection" => ("value_selection", ""), _ => ("value_text", ""),
        };
        let sql = format!("UPDATE eam_checklist_line SET {col} = $1{cast} WHERE id = $2", col = col, cast = cast);
        let _ = vortex_plugin_sdk::sqlx::query(&sql).bind(val).bind(lid).execute(&db).await;
    }
    Redirect::to(&format!("/sesb-eam/my/maintenance/{id}")).into_response()
}

async fn location_update(
    Db(db): Db, Extension(user): Extension<AuthUser>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let lat = form.get("lat").and_then(|s| s.parse::<f64>().ok());
    let lng = form.get("lng").and_then(|s| s.parse::<f64>().ok());
    if lat.is_none() || lng.is_none() { return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "lat/lng required"}))).into_response(); }
    let dec = |k: &str| form.get(k).and_then(|s| s.parse::<vortex_plugin_sdk::rust_decimal::Decimal>().ok());
    let status = form.get("status").map(|s| s.as_str()).unwrap_or("available");
    match api::upsert_location(&db, user.id, lat, lng, dec("accuracy_m"), dec("speed_kmh"), dec("heading"), opt_i32(&form, "battery"), status, "portal").await {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": e.to_string()}))).into_response(),
    }
}

// ── Cerdik troubleshooting assistant (online Anthropic + offline fallback) ───

async fn troubleshoot(
    Db(db): Db, Extension(_u): Extension<AuthUser>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let symptom = form.get("symptom").cloned().unwrap_or_default();
    let equipment_id = opt_uuid(&form, "equipment_id");
    // Asset context for rule matching + the AI prompt.
    let ctx = if let Some(eid) = equipment_id { asset_context(&db, eid).await } else { None };
    let category = ctx.as_ref().and_then(|c| c.category.clone());

    // §8 — call the Anthropic Claude messages API when a key is configured
    // (vault-provided env, never the DB). Any failure falls back to offline.
    if let Some(key) = cerdik_api_key() {
        let rules = matching_rules(&db, category.as_deref(), &symptom).await;
        if let Some(answer) = online_answer(&key, &ctx, &rules, &symptom).await {
            return Json(json!({"ok": true, "source": "online", "answer": answer})).into_response();
        }
    }
    let answer = offline_answer(&db, category.as_deref(), &symptom).await;
    Json(json!({"ok": true, "source": "offline", "answer": answer})).into_response()
}

/// Asset context (category, manufacturer, condition, health, age) for the prompt.
struct AssetCtx { name: String, category: Option<String>, manufacturer: Option<String>, model: Option<String>, condition: Option<String>, op_status: Option<String>, health: Option<i32>, age_years: Option<i32> }

async fn asset_context(db: &vortex_plugin_sdk::sqlx::PgPool, eid: vortex_plugin_sdk::uuid::Uuid) -> Option<AssetCtx> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT e.name, e.equipment_category, e.condition_status, e.operational_status, e.model_number, \
           m.name AS manufacturer, \
           EXTRACT(YEAR FROM AGE(NOW(), COALESCE(e.commissioning_date, e.installation_date)))::int AS age_years, \
           round(CASE e.condition_status WHEN 'excellent' THEN 100 WHEN 'good' THEN 80 WHEN 'fair' THEN 60 WHEN 'poor' THEN 40 WHEN 'critical' THEN 20 ELSE 50 END \
             * CASE e.operational_status WHEN 'operational' THEN 1.0 WHEN 'standby' THEN 0.95 WHEN 'out_of_service' THEN 0.5 WHEN 'under_repair' THEN 0.6 WHEN 'decommissioned' THEN 0.0 ELSE 1.0 END)::int AS health \
         FROM eam_equipment e LEFT JOIN eam_manufacturer m ON m.id=e.manufacturer_id WHERE e.id=$1")
        .bind(eid).fetch_optional(db).await.ok().flatten()?;
    Some(AssetCtx {
        name: row.try_get("name").unwrap_or_default(),
        category: row.try_get::<Option<String>, _>("equipment_category").ok().flatten(),
        manufacturer: row.try_get::<Option<String>, _>("manufacturer").ok().flatten(),
        model: row.try_get::<Option<String>, _>("model_number").ok().flatten(),
        condition: row.try_get::<Option<String>, _>("condition_status").ok().flatten(),
        op_status: row.try_get::<Option<String>, _>("operational_status").ok().flatten(),
        health: row.try_get::<Option<i32>, _>("health").ok().flatten(),
        age_years: row.try_get::<Option<i32>, _>("age_years").ok().flatten(),
    })
}

/// Library rules matched by category + symptom keywords (for the AI prompt).
async fn matching_rules(db: &vortex_plugin_sdk::sqlx::PgPool, category: Option<&str>, symptom: &str) -> Vec<(String, String)> {
    let sym = symptom.to_lowercase();
    let rules = vortex_plugin_sdk::sqlx::query(
        "SELECT name, guidance, keywords FROM eam_troubleshooting_rule WHERE active AND (equipment_category IS NULL OR equipment_category = $1) ORDER BY priority DESC, sequence LIMIT 20")
        .bind(category).fetch_all(db).await.unwrap_or_default();
    let mut out = Vec::new();
    for r in &rules {
        let kw: String = r.try_get::<Option<String>, _>("keywords").ok().flatten().unwrap_or_default();
        let hit = kw.split([',', ' ']).filter(|k| !k.trim().is_empty()).any(|k| sym.contains(&k.trim().to_lowercase()));
        if hit || sym.is_empty() {
            out.push((r.get::<String, _>("name"), r.get::<String, _>("guidance")));
            if out.len() >= 5 { break; }
        }
    }
    out
}

/// Anthropic API key from the deployment's secret vault (env), never the DB (§8/§0).
fn cerdik_api_key() -> Option<String> {
    std::env::var("VORTEX_CERDIK_API_KEY").ok()
        .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
        .filter(|k| !k.trim().is_empty())
}

/// Call the Anthropic Claude messages API. Returns None on any error → offline.
async fn online_answer(key: &str, ctx: &Option<AssetCtx>, rules: &[(String, String)], symptom: &str) -> Option<String> {
    let model = std::env::var("VORTEX_CERDIK_MODEL").ok().filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| "claude-opus-4-8".to_string());

    let mut asset = String::from("Asset: (none specified)\n");
    if let Some(c) = ctx {
        asset = format!("Asset: {}\n", c.name);
        if let Some(v) = &c.category { asset.push_str(&format!("- Category: {}\n", v.replace('_', " "))); }
        if let Some(v) = &c.manufacturer { asset.push_str(&format!("- Manufacturer: {v}\n")); }
        if let Some(v) = &c.model { asset.push_str(&format!("- Model: {v}\n")); }
        if let Some(v) = &c.condition { asset.push_str(&format!("- Condition: {v}\n")); }
        if let Some(v) = &c.op_status { asset.push_str(&format!("- Operational status: {}\n", v.replace('_', " "))); }
        if let Some(v) = c.health { asset.push_str(&format!("- Health index: {v}%\n")); }
        if let Some(v) = c.age_years { asset.push_str(&format!("- Age: {v} years\n")); }
    }
    let rules_txt = if rules.is_empty() {
        "No matching library rules.".to_string()
    } else {
        rules.iter().map(|(n, g)| format!("• {n}\n{g}")).collect::<Vec<_>>().join("\n\n")
    };
    let sym = if symptom.trim().is_empty() { "(no symptom text provided — give a general inspection checklist)" } else { symptom };
    let user_prompt = format!(
        "{asset}\nReported symptom:\n{sym}\n\nRelevant library troubleshooting rules:\n{rules_txt}\n\nGive concise, safety-first numbered troubleshooting steps for the field technician.");

    let system = "You are Cerdik, a safety-first electrical-utility maintenance assistant for Sabah Electricity (SESB). \
        Reply with concise, numbered troubleshooting steps. ALWAYS lead with any safety precaution (isolation / LOTO / PPE) where relevant. \
        Be specific to the given asset and symptom and incorporate the supplied library rules. \
        Never invent equipment ratings or facts you were not given. Keep it field-actionable.";

    let body = json!({
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": user_prompt}],
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30)).build().ok()?;
    let resp = client.post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        let code = resp.status();
        vortex_plugin_sdk::tracing::warn!(status=%code, "Cerdik online call failed; falling back to offline");
        return None;
    }
    let v: vortex_plugin_sdk::serde_json::Value = resp.json().await.ok()?;
    // content is an array of blocks; concatenate the text blocks.
    let text: String = v.get("content")?.as_array()?.iter()
        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
        .collect::<Vec<_>>().join("\n");
    if text.trim().is_empty() { None } else { Some(text) }
}

/// Library rules (matched by category + keyword) plus keyword heuristics — it
/// never returns empty-handed (§8).
async fn offline_answer(db: &vortex_plugin_sdk::sqlx::PgPool, category: Option<&str>, symptom: &str) -> String {
    let sym = symptom.to_lowercase();
    let mut out = String::new();
    // Matching library rules
    let rules = vortex_plugin_sdk::sqlx::query(
        "SELECT name, guidance, keywords FROM eam_troubleshooting_rule WHERE active AND (equipment_category IS NULL OR equipment_category = $1) ORDER BY priority DESC, sequence LIMIT 20")
        .bind(category).fetch_all(db).await.unwrap_or_default();
    let mut matched = 0;
    for r in &rules {
        let kw: String = r.try_get::<Option<String>,_>("keywords").ok().flatten().unwrap_or_default();
        let hit = kw.split([',', ' ']).filter(|k| !k.trim().is_empty()).any(|k| sym.contains(&k.trim().to_lowercase()));
        if hit || sym.is_empty() {
            out.push_str(&format!("• {}\n{}\n\n", r.get::<String,_>("name"), r.get::<String,_>("guidance")));
            matched += 1;
            if matched >= 3 { break; }
        }
    }
    // Keyword heuristics
    let mut heur: Vec<&str> = Vec::new();
    if sym.contains("thermal") || sym.contains("hot") || sym.contains("temperature") {
        heur.push("Thermal: confirm with IR camera, compare against ambient (ΔT bands per §4.7), check load and connection torque; isolate before touching.");
    }
    if sym.contains("trip") || sym.contains("breaker") {
        heur.push("Trip/breaker: read protection relay targets/event log, inspect for faults downstream, do NOT reclose onto a suspected fault.");
    }
    if sym.contains("oil") || sym.contains("leak") {
        heur.push("Oil/leak: contain spill, check level/Buchholz, sample for DGA before energising; gassing alarm → treat as internal fault.");
    }
    if sym.contains("noise") || sym.contains("vibration") {
        heur.push("Noise/vibration: check core/winding tightness, cooling fans/pumps and loose hardware; trend with previous readings.");
    }
    if !heur.is_empty() {
        out.push_str("General guidance:\n");
        for (i, h) in heur.iter().enumerate() { out.push_str(&format!("{}. {}\n", i + 1, h)); }
    }
    if out.trim().is_empty() {
        out = "Safety first: isolate and apply LOTO before any intervention. No matching rule found — record the symptom, capture photos, and escalate to your supervisor or the protection desk.".to_string();
    }
    out
}
