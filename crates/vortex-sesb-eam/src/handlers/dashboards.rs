//! Management dashboards (§9.1) — EAM overview, Control Room (KPIs +
//! reliability), Asset Health & Risk (APM), Executive Summary and Predictive
//! Maintenance. Live Leaflet maps are layered on in Phase 7; these render the
//! KPI/analytics surfaces from [`super::analytics`].

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use super::analytics;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/dashboard", get(eam_dashboard))
        .route("/sesb-eam/apm", get(apm))
        .route("/sesb-eam/executive", get(executive))
        .route("/sesb-eam/predictive", get(predictive))
}

fn kpi(title: &str, value: &str, desc: &str) -> String {
    format!(r#"<div class="stat bg-base-100 rounded-box shadow"><div class="stat-title">{t}</div><div class="stat-value text-2xl">{v}</div><div class="stat-desc">{d}</div></div>"#, t = esc(title), v = esc(value), d = esc(desc))
}
fn kpi_grid(cards: &str) -> String { format!(r#"<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">{}</div>"#, cards) }

fn ytd() -> (String, String) {
    let now = vortex_plugin_sdk::chrono::Utc::now();
    let year = vortex_plugin_sdk::chrono::Datelike::year(&now);
    (format!("{year}-01-01T00:00:00Z"), now.to_rfc3339())
}

/// Region chips + parse `?region=`.
async fn region_chips(db: &PgPool, base: &str, sel: Option<Uuid>) -> String {
    let rows = vortex_plugin_sdk::sqlx::query("SELECT id, name FROM eam_region WHERE active ORDER BY sequence, name").fetch_all(db).await.unwrap_or_default();
    let mut out = String::from(r#"<div class="flex flex-wrap gap-1 mb-4">"#);
    let all_cls = if sel.is_none() { "btn-primary" } else { "btn-ghost" };
    out.push_str(&format!(r#"<a href="{base}" class="btn btn-xs {c}">All Regions</a>"#, base = base, c = all_cls));
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        let cls = if sel == Some(id) { "btn-primary" } else { "btn-ghost" };
        out.push_str(&format!(r#"<a href="{base}?region={id}" class="btn btn-xs {c}">{n}</a>"#, base = base, id = id, c = cls, n = esc(&name)));
    }
    out.push_str("</div>");
    out
}

fn region_param(q: &HashMap<String, String>) -> Option<Uuid> {
    q.get("region").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
}

// ═══════════════════════════════ EAM Dashboard ══════════════════════════════

async fn eam_dashboard(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.dashboard");
    let region = region_param(&q);
    let rc = if region.is_some() { "WHERE region_id=$1" } else { "" };
    // §6.3 elevated read: re-apply division scope. `dvw` picks WHERE vs AND.
    let scope = division::DivisionScope::for_user(&user);
    let dvw = |col: &str, has_where: bool| -> String {
        match scope.sql_predicate(col) {
            None => String::new(),
            Some(p) => if has_where { format!(" AND {p}") } else { format!(" WHERE {p}") },
        }
    };
    let scalar = |sql: String| {
        let db = db.clone();
        async move {
            let qx = vortex_plugin_sdk::sqlx::query_scalar::<_, i64>(&sql);
            let qx = if let Some(r) = region { qx.bind(r) } else { qx };
            qx.fetch_one(&db).await.unwrap_or(0)
        }
    };
    let equip = scalar(format!("SELECT COUNT(*)::bigint FROM eam_equipment {rc}{dv}", rc = if region.is_some() {"WHERE region_id=$1"} else {""}, dv = dvw("division", region.is_some()))).await;
    let open_wo = scalar(format!("SELECT COUNT(*)::bigint FROM eam_maintenance WHERE state NOT IN ('completed','verified','cancelled') {rc}{dv}", rc = if region.is_some() {"AND region_id=$1"} else {""}, dv = dvw("division", true))).await;
    let open_def = scalar(format!("SELECT COUNT(*)::bigint FROM eam_defect WHERE state NOT IN ('verified','cancelled') {rc}{dv}", rc = if region.is_some() {"AND region_id=$1"} else {""}, dv = dvw("division", true))).await;
    let active_plans = scalar(format!("SELECT COUNT(*)::bigint FROM eam_maintenance_plan WHERE state='active' {rc}{dv}", rc = if region.is_some() {"AND region_id=$1"} else {""}, dv = dvw("division", true))).await;
    let _ = rc;
    let cards = format!("{}{}{}{}",
        kpi("Equipment", &equip.to_string(), "registered assets"),
        kpi("Open Work Orders", &open_wo.to_string(), "not completed"),
        kpi("Open Defects", &open_def.to_string(), "awaiting repair/verify"),
        kpi("Active Plans", &active_plans.to_string(), "recurring schedules"));

    // Condition + status breakdowns
    let cond = breakdown(&db, "eam_equipment", "condition_status", region, "region_id", scope).await;
    let opstat = breakdown(&db, "eam_equipment", "operational_status", region, "region_id", scope).await;
    let wo_state = breakdown(&db, "eam_maintenance", "state", region, "region_id", scope).await;

    // Upcoming + recent orders
    let upcoming = order_list(&db, region, "state IN ('scheduled','assigned') AND scheduled_date >= CURRENT_DATE", "scheduled_date ASC", 8, scope).await;
    let recent = order_list(&db, region, "state IN ('completed','verified')", "COALESCE(end_date, updated_at) DESC", 8, scope).await;

    let chips = region_chips(&db, "/sesb-eam/dashboard", region).await;
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-3">EAM Dashboard</h1>{chips}{cards}
<div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold">Condition</h2>{cond}</div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold">Operational Status</h2>{opstat}</div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold">Work-Order States</h2>{wo}</div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold mb-2">Upcoming Orders</h2>{up}</div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold mb-2">Recently Completed</h2>{rec}</div></div>
</div>"#,
        chips = chips, cards = kpi_grid(&cards), cond = cond, opstat = opstat, wo = wo_state, up = upcoming, rec = recent);
    Html(page_shell(&sidebar, "EAM Dashboard", &content)).into_response()
}

async fn breakdown(db: &PgPool, table: &str, col: &str, region: Option<Uuid>, region_col: &str, scope: division::DivisionScope) -> String {
    let rc = if region.is_some() { format!("WHERE {region_col}=$1", region_col = region_col) } else { String::new() };
    let dv = match scope.sql_predicate("division") { None => String::new(), Some(p) => if region.is_some() { format!(" AND {p}") } else { format!(" WHERE {p}") } };
    let sql = format!("SELECT {col} AS k, COUNT(*)::bigint AS n FROM {table} {rc}{dv} GROUP BY {col} ORDER BY n DESC", col = col, table = table, rc = rc, dv = dv);
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    let rows = q.fetch_all(db).await.unwrap_or_default();
    if rows.is_empty() { return "<p class=\"opacity-50 text-sm\">No data.</p>".into(); }
    let total: i64 = rows.iter().map(|r| r.try_get::<i64,_>("n").unwrap_or(0)).sum();
    rows.iter().map(|r| {
        let k: Option<String> = r.try_get("k").ok();
        let n: i64 = r.try_get("n").unwrap_or(0);
        let pct = if total > 0 { n as f64 / total as f64 * 100.0 } else { 0.0 };
        format!(r#"<div class="flex items-center justify-between text-sm py-1"><span>{k}</span><span class="font-mono">{n} <span class="opacity-50">({pct:.0}%)</span></span></div>"#,
            k = esc(k.as_deref().unwrap_or("—")), n = n, pct = pct)
    }).collect()
}

async fn order_list(db: &PgPool, region: Option<Uuid>, where_extra: &str, order: &str, limit: i64, scope: division::DivisionScope) -> String {
    let rc = if region.is_some() { "AND m.region_id=$1" } else { "" };
    let dv = scope.sql_predicate("m.division").map(|p| format!(" AND {p}")).unwrap_or_default();
    let sql = format!(
        "SELECT m.id, m.name, m.description, e.name AS equip, m.scheduled_date::text AS sd, m.state FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id WHERE {we} {rc}{dv} ORDER BY {ord} LIMIT {lim}",
        we = where_extra, rc = rc, dv = dv, ord = order, lim = limit);
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    let rows = q.fetch_all(db).await.unwrap_or_default();
    if rows.is_empty() { return "<p class=\"opacity-50 text-sm\">Nothing here.</p>".into(); }
    let items: String = rows.iter().map(|r| {
        let id: Uuid = r.get("id");
        let name: Option<String> = r.try_get("name").ok();
        let equip: Option<String> = r.try_get("equip").ok();
        let sd: Option<String> = r.try_get("sd").ok();
        let st: String = r.get("state");
        format!(r#"<tr><td class="font-mono text-xs"><a class="link" href="/sesb-eam/maintenance/{id}">{nm}</a></td><td>{eq}</td><td>{sd}</td><td><span class="badge badge-sm">{st}</span></td></tr>"#,
            id = id, nm = esc(name.as_deref().unwrap_or("")), eq = esc(equip.as_deref().unwrap_or("")), sd = esc(sd.as_deref().unwrap_or("")), st = esc(&st))
    }).collect();
    format!(r#"<div class="overflow-x-auto"><table class="table table-xs"><thead><tr><th>No</th><th>Equipment</th><th>Date</th><th>State</th></tr></thead><tbody>{}</tbody></table></div>"#, items)
}

// ═══════════════════════════════════ APM ════════════════════════════════════

async fn apm(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.apm");
    let region = region_param(&q);
    let d = analytics::apm_data(&db, region, division::DivisionScope::for_user(&user)).await;
    let chips = region_chips(&db, "/sesb-eam/apm", region).await;
    let cards = format!("{}{}{}{}{}",
        kpi("Equipment", &d.total.to_string(), "in scope"),
        kpi("End of Life", &d.eol.to_string(), "useful-life ≥ 100%"),
        kpi("High Risk", &d.high_risk.to_string(), "risk high/critical"),
        kpi("Poor Condition", &d.poor_condition.to_string(), "poor/critical"),
        kpi("Avg Health", &format!("{:.0}", d.avg_health), "0–100"));

    // risk matrix condition×risk
    let mut matrix = String::from(r#"<table class="table table-xs"><thead><tr><th>Condition \ Risk</th>"#);
    for r in analytics::RISKS { matrix.push_str(&format!("<th class=\"capitalize\">{}</th>", r)); }
    matrix.push_str("</tr></thead><tbody>");
    for (ci, c) in analytics::CONDITIONS.iter().enumerate() {
        matrix.push_str(&format!(r#"<tr><td class="capitalize font-medium">{}</td>"#, c));
        for ri in 0..analytics::RISKS.len() {
            let n = d.matrix[ci][ri];
            let cls = if n == 0 { "opacity-30" } else if ri >= 2 && ci >= 3 { "text-error font-bold" } else { "" };
            matrix.push_str(&format!(r#"<td class="text-center {cls}">{n}</td>"#, cls = cls, n = n));
        }
        matrix.push_str("</tr>");
    }
    matrix.push_str("</tbody></table>");

    let repl: String = d.replacement_top.iter().enumerate().map(|(i, r)| format!(
        r#"<tr><td>{rank}</td><td class="font-mono text-xs"><a class="link" href="/sesb-eam/equipment/{id}">{code}</a></td><td>{name}</td><td class="capitalize">{cond}</td><td class="capitalize">{risk}</td><td class="text-right">{ul:.0}%</td><td class="text-right font-bold">{score:.1}</td></tr>"#,
        rank = i + 1, id = r.id, code = esc(r.code.as_deref().unwrap_or("")), name = esc(&r.name), cond = r.condition, risk = r.risk, ul = r.useful_life_pct, score = r.score)).collect();

    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-3">Asset Health & Risk (APM)</h1>{chips}{cards}
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold mb-2">Condition × Risk Matrix</h2><div class="overflow-x-auto">{matrix}</div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold mb-2">Replacement Priority (Top 15)</h2><div class="overflow-x-auto"><table class="table table-xs"><thead><tr><th>#</th><th>Code</th><th>Name</th><th>Cond</th><th>Risk</th><th class="text-right">Life</th><th class="text-right">Score</th></tr></thead><tbody>{repl}</tbody></table></div></div></div>
</div>"#,
        chips = chips, cards = kpi_grid(&cards), matrix = matrix, repl = repl);
    Html(page_shell(&sidebar, "APM", &content)).into_response()
}

// ═══════════════════════════════ Executive ══════════════════════════════════

async fn executive(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(_q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.executive");
    let (from, to) = ytd();
    // §6.3: a scoped user's executive rollup only iterates their own division's
    // regions, so out-of-division per-region rows never appear.
    let rdv = division::DivisionScope::for_user(&user)
        .sql_predicate("division").map(|p| format!(" AND {p}")).unwrap_or_default();
    let regions = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT id, name FROM eam_region WHERE active{rdv} ORDER BY sequence, name")).fetch_all(&db).await.unwrap_or_default();
    let mut rows = String::new();
    for r in &regions {
        let rid: Uuid = r.get("id");
        let rname: String = r.get("name");
        let pm = analytics::pm_compliance(&db, Some(rid), &from, &to, division::DivisionScope::for_user(&user)).await;
        let rel = analytics::reliability(&db, Some(rid), &from, &to, true, division::DivisionScope::for_user(&user)).await;
        let cost: f64 = vortex_plugin_sdk::sqlx::query_scalar::<_, Option<f64>>(
            "SELECT SUM(total_cost)::float8 FROM eam_maintenance WHERE region_id=$1 AND state IN ('completed','verified')")
            .bind(rid).fetch_one(&db).await.ok().flatten().unwrap_or(0.0);
        let health: f64 = vortex_plugin_sdk::sqlx::query_scalar::<_, Option<f64>>(
            "SELECT AVG(CASE condition_status WHEN 'excellent' THEN 100 WHEN 'good' THEN 80 WHEN 'fair' THEN 60 WHEN 'poor' THEN 40 WHEN 'critical' THEN 20 ELSE 50 END)::float8 FROM eam_equipment WHERE region_id=$1 AND active")
            .bind(rid).fetch_one(&db).await.ok().flatten().unwrap_or(0.0);
        rows.push_str(&format!(
            r#"<tr><td class="font-medium">{name}</td><td class="text-right">{comp:.1}%</td><td class="text-right">{compl:.1}%</td><td class="text-right">{overdue}</td><td class="text-right">RM {cost:.0}</td><td class="text-right">{health:.0}</td><td class="text-right">{saidi:.2}</td><td class="text-right">{saifi:.3}</td></tr>"#,
            name = esc(&rname), comp = pm.compliance_pct, compl = pm.completion_pct, overdue = pm.overdue_open, cost = cost, health = health, saidi = rel.saidi, saifi = rel.saifi));
    }
    if rows.is_empty() { rows = "<tr><td colspan=\"8\" class=\"opacity-50\">No regions.</td></tr>".into(); }
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Executive Summary</h1><p class="opacity-60 text-sm mb-4">Year-to-date per-region scorecards.</p>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Region</th><th class="text-right">PM Compliance</th><th class="text-right">Completion</th><th class="text-right">Overdue</th><th class="text-right">Cost</th><th class="text-right">Avg Health</th><th class="text-right">SAIDI</th><th class="text-right">SAIFI</th></tr></thead>
<tbody>{rows}</tbody></table></div></div></div>"#, rows = rows);
    Html(page_shell(&sidebar, "Executive Summary", &content)).into_response()
}

// ═══════════════════════════════ Predictive ═════════════════════════════════

async fn predictive(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.predictive");
    let region = region_param(&q);
    let d = analytics::predictive(&db, region, division::DivisionScope::for_user(&user)).await;
    let chips = region_chips(&db, "/sesb-eam/predictive", region).await;
    let cards = format!("{}{}{}{}{}",
        kpi("Tracked", &d.total.to_string(), "operational assets"),
        kpi("Overdue", &d.overdue.to_string(), "predicted < today"),
        kpi("Imminent", &d.imminent.to_string(), "≤ 30 days"),
        kpi("Soon", &d.soon.to_string(), "≤ 90 days"),
        kpi("High Risk", &d.high_risk.to_string(), "failure ≥ 60%"));
    let work: String = d.worklist.iter().map(|w| {
        let band_cls = match w.band { "overdue" => "badge-error", "imminent" => "badge-warning", "soon" => "badge-info", _ => "badge-ghost" };
        format!(r#"<tr><td class="font-mono text-xs"><a class="link" href="/sesb-eam/equipment/{id}">{code}</a></td><td>{name}</td><td><span class="badge badge-sm {bc}">{band}</span></td><td class="text-right">{days}</td><td>{pd}</td><td class="text-right">{risk}%</td></tr>"#,
            id = w.id, code = esc(w.code.as_deref().unwrap_or("")), name = esc(&w.name), bc = band_cls, band = w.band, days = w.days, pd = esc(&w.predicted_date), risk = w.failure_risk_pct)
    }).collect();
    let work = if work.is_empty() { "<tr><td colspan=\"6\" class=\"opacity-50\">No equipment in scope.</td></tr>".to_string() } else { work };
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Predictive Maintenance</h1><p class="opacity-60 text-sm mb-3">Hybrid MTBF × condition × risk (§4.5).</p>{chips}{cards}
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="font-semibold mb-2">Worklist (Top 25 by days-to-service)</h2><div class="overflow-x-auto"><table class="table table-xs">
<thead><tr><th>Code</th><th>Name</th><th>Band</th><th class="text-right">Days</th><th>Predicted</th><th class="text-right">Risk</th></tr></thead><tbody>{work}</tbody></table></div></div></div>"#,
        chips = chips, cards = kpi_grid(&cards), work = work);
    Html(page_shell(&sidebar, "Predictive Maintenance", &content)).into_response()
}
