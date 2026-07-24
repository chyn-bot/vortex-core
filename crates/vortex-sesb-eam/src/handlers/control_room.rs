//! Network Operations Control Room (§9.1) — a faithful server-rendered port of
//! the Odoo `get_control_room_data` + OWL `sesb_eam.ControlRoom` screen. Two
//! tabs (Live Ops / Analytics): live KPIs, IEEE-1366 reliability, a
//! health-coloured Leaflet map of substations + towers, and live feeds for
//! outages, maintenance, defects, critical equipment and SLA breaches.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::{json, Value};
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/sesb-eam/control-room", get(control_room))
}

const OPEN_MO: &str = "('draft','scheduled','assigned','in_progress','on_hold')";
const OPEN_DEF: &str = "('open','assigned','in_repair')";
const DONE_MO: &str = "('completed','verified')";

fn health_color(h: &str) -> &'static str {
    match h { "good" => "#28a745", "attention" => "#ffc107", "critical" => "#dc3545", _ => "#6c757d" }
}

// ── data structs (mirror the Odoo JSON payload) ─────────────────────────────

#[derive(Default)]
struct Kpis { open_mo: i64, overdue_mo: i64, emergency_mo: i64, open_defects: i64, critical_defects: i64, critical_assets: i64, substations: i64, towers: i64 }

struct Asset {
    id: Uuid, model: &'static str, kind: &'static str, name: String, code: String,
    lat: Option<f64>, lng: Option<f64>, equipment_count: i64,
    open_mo: i64, overdue_mo: i64, open_defects: i64, health: &'static str,
}

#[derive(Default)]
struct Reliability2 { saidi: f64, saifi: f64, caidi: f64, total_customers: i64, customers_interrupted: i64, ongoing_count: i64, outage_count: i64 }

async fn control_room(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.control_room");
    let region = q.get("region").filter(|s| !s.is_empty()).and_then(|s| s.parse::<Uuid>().ok());
    let tab = match q.get("tab").map(|s| s.as_str()) { Some("analytics") => "analytics", _ => "live" };

    let content = match render_control_room(&db, region, tab, division::DivisionScope::for_user(&user)).await {
        Ok(html) => html,
        Err(e) => { error!(error=%e, "control room"); "<h1>Failed to load control room</h1>".to_string() }
    };
    Html(page_shell(&sidebar, "Control Room", &content)).into_response()
}

/// region filter clause helper (binds $1 when present).
fn rc(region: Option<Uuid>, col: &str) -> String {
    if region.is_some() { format!("AND {col} = $1", col = col) } else { String::new() }
}
/// Division-boundary fragment (§6.3): elevated dashboard aggregates bypass row
/// rules, so re-apply the caller's scope by hand. Constants only, no bind param.
fn dv(scope: division::DivisionScope, col: &str) -> String {
    scope.sql_predicate(col).map(|p| format!("AND {p}")).unwrap_or_default()
}
async fn scalar_i64(db: &PgPool, sql: &str, region: Option<Uuid>) -> i64 {
    let q = vortex_plugin_sdk::sqlx::query_scalar::<_, i64>(sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    q.fetch_one(db).await.unwrap_or(0)
}

async fn render_control_room(db: &PgPool, region: Option<Uuid>, tab: &str, scope: division::DivisionScope) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    // ─── KPIs ───────────────────────────────────────────────────────────────
    let k = Kpis {
        open_mo: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_maintenance m WHERE m.state IN {OPEN_MO} {} {}", rc(region, "m.region_id"), dv(scope, "m.division")), region).await,
        overdue_mo: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_maintenance m WHERE m.state IN {OPEN_MO} AND m.scheduled_date < CURRENT_DATE {} {}", rc(region, "m.region_id"), dv(scope, "m.division")), region).await,
        emergency_mo: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_maintenance m WHERE m.state IN {OPEN_MO} AND m.maintenance_type='emergency' {} {}", rc(region, "m.region_id"), dv(scope, "m.division")), region).await,
        open_defects: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_defect d WHERE d.state IN {OPEN_DEF} {} {}", rc(region, "d.region_id"), dv(scope, "d.division")), region).await,
        critical_defects: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_defect d WHERE d.state IN {OPEN_DEF} AND d.severity='critical' {} {}", rc(region, "d.region_id"), dv(scope, "d.division")), region).await,
        critical_assets: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_equipment e WHERE e.condition_status IN ('poor','critical') {} {}", rc(region, "e.region_id"), dv(scope, "e.division")), region).await,
        substations: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.active {} {}", rc(region, "si.region_id"), dv(scope, "s.division")), region).await,
        towers: scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_transmission_tower t WHERE t.active {} {}", rc(region, "t.region_id"), dv(scope, "t.division")), region).await,
    };

    // ─── Reliability (YTD) ───────────────────────────────────────────────────
    let now = vortex_plugin_sdk::chrono::Utc::now();
    let year = vortex_plugin_sdk::chrono::Datelike::year(&now);
    let ytd_from = format!("{year}-01-01T00:00:00Z");
    let base = super::analytics::reliability(db, region, &ytd_from, &now.to_rfc3339(), true, scope).await;
    let ci = scalar_i64(db, &format!("SELECT COALESCE(SUM(customers_affected),0)::bigint FROM eam_outage o WHERE o.start_datetime >= '{ytd_from}'::timestamptz AND NOT o.is_major_event {} {}", rc(region, "o.region_id"), dv(scope, "o.division")), region).await;
    let ongoing = scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_outage o WHERE o.state='ongoing' {} {}", rc(region, "o.region_id"), dv(scope, "o.division")), region).await;
    let rel = Reliability2 { saidi: base.saidi, saifi: base.saifi, caidi: base.caidi, total_customers: base.total_customers, customers_interrupted: ci, ongoing_count: ongoing, outage_count: base.outage_count };

    // ─── Per-asset incident map ──────────────────────────────────────────────
    let assets = gather_assets(db, region, scope).await;

    // ─── feeds ───────────────────────────────────────────────────────────────
    let outages = feed_outages(db, region, scope).await;
    let work_orders = feed_work_orders(db, region, scope).await;
    let defects = feed_defects(db, region, scope).await;
    let condition = feed_condition(db, region, scope).await;
    let overdue = feed_overdue(db, region, scope).await;

    // ─── analytics ───────────────────────────────────────────────────────────
    let analytics = gather_analytics(db, region, scope).await;

    // ─── region chips ────────────────────────────────────────────────────────
    let regions = vortex_plugin_sdk::sqlx::query("SELECT id, COALESCE(code, name) AS code FROM eam_region WHERE active ORDER BY sequence, name").fetch_all(db).await.unwrap_or_default();

    Ok(build_html(&k, &rel, &assets, &outages, &work_orders, &defects, &condition, &overdue, &analytics, &regions, region, tab, &now))
}

// ────────────────────────────── data gatherers ──────────────────────────────

const HEALTH_SQL: &str = "(CASE condition_status WHEN 'excellent' THEN 100 WHEN 'good' THEN 80 WHEN 'fair' THEN 60 WHEN 'poor' THEN 40 WHEN 'critical' THEN 20 ELSE 50 END * CASE operational_status WHEN 'operational' THEN 1.0 WHEN 'standby' THEN 0.95 WHEN 'out_of_service' THEN 0.5 WHEN 'under_repair' THEN 0.6 WHEN 'decommissioned' THEN 0.0 ELSE 1.0 END)";

async fn gather_assets(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Vec<Asset> {
    let mut out = Vec::new();
    // Substations
    let sub_sql = format!(
        "SELECT s.id, s.code, s.name, s.state, \
           COALESCE(s.latitude, CASE WHEN s.gps_latitude ~ '^-?[0-9.]+$' THEN s.gps_latitude::numeric END)::float8 AS lat, \
           COALESCE(s.longitude, CASE WHEN s.gps_longitude ~ '^-?[0-9.]+$' THEN s.gps_longitude::numeric END)::float8 AS lng, \
           (SELECT COUNT(*) FROM eam_equipment e WHERE e.substation_id=s.id)::bigint AS eqc, \
           (SELECT COUNT(*) FROM eam_maintenance m WHERE m.substation_id=s.id AND m.state IN {OPEN_MO})::bigint AS omo, \
           (SELECT COUNT(*) FROM eam_maintenance m WHERE m.substation_id=s.id AND m.state IN {OPEN_MO} AND m.scheduled_date < CURRENT_DATE)::bigint AS ovr, \
           (SELECT COUNT(*) FROM eam_defect d WHERE d.substation_id=s.id AND d.state IN {OPEN_DEF})::bigint AS odf, \
           (SELECT COUNT(*) FROM eam_defect d WHERE d.substation_id=s.id AND d.state IN {OPEN_DEF} AND d.severity='critical')::bigint AS cdf \
         FROM eam_substation s JOIN eam_site si ON si.id=s.site_id WHERE s.active {rc} {dv} ORDER BY s.code LIMIT 500",
        rc = rc(region, "si.region_id"), dv = dv(scope, "s.division"));
    let q = vortex_plugin_sdk::sqlx::query(&sub_sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    for row in q.fetch_all(db).await.unwrap_or_default() {
        let state: String = row.get("state");
        let omo: i64 = row.try_get("omo").unwrap_or(0);
        let ovr: i64 = row.try_get("ovr").unwrap_or(0);
        let odf: i64 = row.try_get("odf").unwrap_or(0);
        let cdf: i64 = row.try_get("cdf").unwrap_or(0);
        let health = if state == "decommissioned" { "no_data" }
            else if ovr > 0 || cdf > 0 || state == "maintenance" { "critical" }
            else if omo > 0 || odf > 0 { "attention" } else { "good" };
        out.push(Asset {
            id: row.get("id"), model: "substation", kind: "substation",
            name: row.try_get("name").ok().unwrap_or_default(), code: row.try_get("code").ok().flatten().unwrap_or_default(),
            lat: row.try_get("lat").ok().flatten(), lng: row.try_get("lng").ok().flatten(),
            equipment_count: row.try_get("eqc").unwrap_or(0), open_mo: omo, overdue_mo: ovr, open_defects: odf, health,
        });
    }
    // Towers
    let tw_sql = format!(
        "SELECT t.id, t.code, t.name, t.condition_status, t.operational_status, \
           t.gps_latitude::float8 AS lat, t.gps_longitude::float8 AS lng, \
           (SELECT COUNT(*) FROM eam_equipment e WHERE e.tower_id=t.id)::bigint AS eqc, \
           (SELECT COUNT(*) FROM eam_maintenance m JOIN eam_equipment e ON e.id=m.equipment_id WHERE e.tower_id=t.id AND m.state IN {OPEN_MO})::bigint AS omo, \
           (SELECT COUNT(*) FROM eam_maintenance m JOIN eam_equipment e ON e.id=m.equipment_id WHERE e.tower_id=t.id AND m.state IN {OPEN_MO} AND m.scheduled_date < CURRENT_DATE)::bigint AS ovr, \
           (SELECT COUNT(*) FROM eam_defect d JOIN eam_equipment e ON e.id=d.equipment_id WHERE e.tower_id=t.id AND d.state IN {OPEN_DEF})::bigint AS odf \
         FROM eam_transmission_tower t WHERE t.active {rc} {dv} ORDER BY t.code LIMIT 500",
        rc = rc(region, "t.region_id"), dv = dv(scope, "t.division"));
    let q = vortex_plugin_sdk::sqlx::query(&tw_sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    for row in q.fetch_all(db).await.unwrap_or_default() {
        let cond: String = row.get("condition_status");
        let op: String = row.get("operational_status");
        let omo: i64 = row.try_get("omo").unwrap_or(0);
        let ovr: i64 = row.try_get("ovr").unwrap_or(0);
        let odf: i64 = row.try_get("odf").unwrap_or(0);
        let health = if op == "decommissioned" { "no_data" }
            else if cond == "critical" || op == "out_of_service" || op == "under_repair" || ovr > 0 { "critical" }
            else if cond == "poor" || omo > 0 || odf > 0 { "attention" } else { "good" };
        out.push(Asset {
            id: row.get("id"), model: "tower", kind: "tower",
            name: row.try_get("name").ok().unwrap_or_default(), code: row.try_get("code").ok().flatten().unwrap_or_default(),
            lat: row.try_get("lat").ok().flatten(), lng: row.try_get("lng").ok().flatten(),
            equipment_count: row.try_get("eqc").unwrap_or(0), open_mo: omo, overdue_mo: ovr, open_defects: odf, health,
        });
    }
    out
}

async fn feed_work_orders(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Vec<Value> {
    let sql = format!(
        "SELECT m.id, m.name, m.description, m.maintenance_type, m.priority, m.state, e.name AS equip, \
           COALESCE(s.name, e.name) AS asset_name, u.username AS assignee, \
           (m.scheduled_date < CURRENT_DATE) AS is_overdue \
         FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id LEFT JOIN eam_substation s ON s.id=m.substation_id LEFT JOIN users u ON u.id=m.assigned_to \
         WHERE m.state IN {OPEN_MO} {rc} {dv} ORDER BY m.priority DESC, m.scheduled_date ASC NULLS LAST, m.id DESC LIMIT 12",
        rc = rc(region, "m.region_id"), dv = dv(scope, "m.division"));
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    q.fetch_all(db).await.unwrap_or_default().iter().map(|m| {
        let pr: String = m.get("priority");
        json!({
            "id": m.get::<Uuid,_>("id"),
            "name": m.try_get::<Option<String>,_>("name").ok().flatten().unwrap_or_default(),
            "title": m.get::<String,_>("description"),
            "type_label": type_label(&m.get::<String,_>("maintenance_type")),
            "priority_label": prio_label(&pr), "priority_color": prio_color(&pr),
            "state_label": state_label(&m.get::<String,_>("state")),
            "asset_name": m.try_get::<Option<String>,_>("asset_name").ok().flatten().unwrap_or_default(),
            "equipment": m.try_get::<Option<String>,_>("equip").ok().flatten().unwrap_or_default(),
            "assignee": m.try_get::<Option<String>,_>("assignee").ok().flatten().unwrap_or_default(),
            "is_overdue": m.try_get::<bool,_>("is_overdue").unwrap_or(false),
        })
    }).collect()
}

async fn feed_overdue(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Vec<Value> {
    let sql = format!(
        "SELECT m.id, m.name, m.description, COALESCE(s.name, e.name) AS asset_name, (CURRENT_DATE - m.scheduled_date) AS days \
         FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id LEFT JOIN eam_substation s ON s.id=m.substation_id \
         WHERE m.state IN {OPEN_MO} AND m.scheduled_date < CURRENT_DATE {rc} {dv} ORDER BY (CURRENT_DATE - m.scheduled_date) DESC LIMIT 10",
        rc = rc(region, "m.region_id"), dv = dv(scope, "m.division"));
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    q.fetch_all(db).await.unwrap_or_default().iter().map(|m| json!({
        "id": m.get::<Uuid,_>("id"),
        "name": m.try_get::<Option<String>,_>("name").ok().flatten().unwrap_or_default(),
        "title": m.get::<String,_>("description"),
        "asset_name": m.try_get::<Option<String>,_>("asset_name").ok().flatten().unwrap_or_default(),
        "days_overdue": m.try_get::<i32,_>("days").unwrap_or(0),
    })).collect()
}

async fn feed_defects(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Vec<Value> {
    let sql = format!(
        "SELECT d.id, d.name, d.title, d.severity, d.state, e.name AS equip, COALESCE(s.name, e.name) AS asset_name \
         FROM eam_defect d LEFT JOIN eam_equipment e ON e.id=d.equipment_id LEFT JOIN eam_substation s ON s.id=d.substation_id \
         WHERE d.state IN {OPEN_DEF} {rc} {dv} ORDER BY CASE d.severity WHEN 'critical' THEN 4 WHEN 'major' THEN 3 WHEN 'moderate' THEN 2 ELSE 1 END DESC, d.discovered_date DESC NULLS LAST, d.id DESC LIMIT 12",
        rc = rc(region, "d.region_id"), dv = dv(scope, "d.division"));
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    q.fetch_all(db).await.unwrap_or_default().iter().map(|d| {
        let sev: String = d.get("severity");
        json!({
            "id": d.get::<Uuid,_>("id"),
            "title": d.get::<String,_>("title"),
            "severity": sev, "severity_label": sev_label(&sev), "severity_color": sev_color(&sev),
            "state_label": def_state_label(&d.get::<String,_>("state")),
            "asset_name": d.try_get::<Option<String>,_>("asset_name").ok().flatten().unwrap_or_default(),
            "equipment": d.try_get::<Option<String>,_>("equip").ok().flatten().unwrap_or_default(),
        })
    }).collect()
}

async fn feed_condition(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Vec<Value> {
    let sql = format!(
        "SELECT e.id, e.name, e.equipment_category, e.condition_status, COALESCE(s.name, t.name) AS location, \
           round({HEALTH_SQL})::int AS hi \
         FROM eam_equipment e LEFT JOIN eam_substation s ON s.id=e.substation_id LEFT JOIN eam_transmission_tower t ON t.id=e.tower_id \
         WHERE e.condition_status IN ('poor','critical') {rc} {dv} ORDER BY round({HEALTH_SQL}) ASC LIMIT 12",
        rc = rc(region, "e.region_id"), dv = dv(scope, "e.division"));
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    q.fetch_all(db).await.unwrap_or_default().iter().map(|e| json!({
        "id": e.get::<Uuid,_>("id"),
        "name": e.get::<String,_>("name"),
        "category": e.try_get::<Option<String>,_>("equipment_category").ok().flatten().unwrap_or_default(),
        "condition": e.get::<String,_>("condition_status"),
        "health_index": e.try_get::<i32,_>("hi").unwrap_or(0),
        "location": e.try_get::<Option<String>,_>("location").ok().flatten().unwrap_or_default(),
    })).collect()
}

async fn feed_outages(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Vec<Value> {
    let sql = format!(
        "SELECT o.id, o.name, o.outage_type, o.cause_category, o.state, o.customers_affected, o.is_major_event, s.name AS sub, \
           round(EXTRACT(EPOCH FROM (COALESCE(o.end_datetime,NOW())-o.start_datetime))/60.0)::bigint AS dur_min \
         FROM eam_outage o LEFT JOIN eam_substation s ON s.id=o.substation_id \
         WHERE o.state <> 'cancelled' {rc} {dv} ORDER BY (o.state='ongoing') DESC, o.start_datetime DESC LIMIT 12",
        rc = rc(region, "o.region_id"), dv = dv(scope, "o.division"));
    let q = vortex_plugin_sdk::sqlx::query(&sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    q.fetch_all(db).await.unwrap_or_default().iter().map(|o| {
        let dur: i64 = o.try_get("dur_min").unwrap_or(0);
        let dur_disp = if dur >= 60 { format!("{}h {}m", dur / 60, dur % 60) } else { format!("{}m", dur) };
        json!({
            "id": o.get::<Uuid,_>("id"),
            "name": o.try_get::<Option<String>,_>("name").ok().flatten().unwrap_or_default(),
            "substation": o.try_get::<Option<String>,_>("sub").ok().flatten().unwrap_or_default(),
            "cause": cause_label(&o.try_get::<Option<String>,_>("cause_category").ok().flatten().unwrap_or_default()),
            "state": o.get::<String,_>("state"), "state_label": outage_state_label(&o.get::<String,_>("state")),
            "customers": o.try_get::<i32,_>("customers_affected").unwrap_or(0),
            "duration": dur_disp,
            "is_major": o.try_get::<bool,_>("is_major_event").unwrap_or(false),
        })
    }).collect()
}

async fn gather_analytics(db: &PgPool, region: Option<Uuid>, scope: division::DivisionScope) -> Value {
    // mo by state / type over open orders
    let by = |col: &'static str| {
        let sql = format!("SELECT {col} AS k, COUNT(*)::bigint AS n FROM eam_maintenance m WHERE m.state IN {OPEN_MO} {rc} {dv} GROUP BY {col} ORDER BY n DESC", col = col, rc = rc(region, "m.region_id"), dv = dv(scope, "m.division"));
        let db = db.clone();
        async move {
            let q = vortex_plugin_sdk::sqlx::query(&sql);
            let q = if let Some(r) = region { q.bind(r) } else { q };
            q.fetch_all(&db).await.unwrap_or_default().iter().map(|r| {
                let k: String = r.get("k");
                (k, r.try_get::<i64,_>("n").unwrap_or(0))
            }).collect::<Vec<_>>()
        }
    };
    let mo_by_state: Vec<Value> = by("m.state").await.into_iter().map(|(k, n)| json!({"key": k, "label": state_label(&k), "count": n})).collect();
    let mo_by_type: Vec<Value> = by("m.maintenance_type").await.into_iter().map(|(k, n)| json!({"key": k, "label": type_label(&k), "count": n})).collect();

    let month_start = format!("{}-{:02}-01", vortex_plugin_sdk::chrono::Datelike::year(&vortex_plugin_sdk::chrono::Utc::now()), vortex_plugin_sdk::chrono::Datelike::month(&vortex_plugin_sdk::chrono::Utc::now()));
    let done_month = scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_maintenance m WHERE m.state IN {DONE_MO} AND m.end_date >= '{month_start}'::date {} {}", rc(region, "m.region_id"), dv(scope, "m.division")), region).await;
    let done_30d = scalar_i64(db, &format!("SELECT COUNT(*)::bigint FROM eam_maintenance m WHERE m.state IN {DONE_MO} AND m.end_date >= NOW() - INTERVAL '30 days' {} {}", rc(region, "m.region_id"), dv(scope, "m.division")), region).await;
    let avg_dur: f64 = {
        let sql = format!("SELECT COALESCE(AVG(actual_duration_hours),0)::float8 FROM eam_maintenance m WHERE m.state IN {DONE_MO} AND m.end_date >= NOW() - INTERVAL '30 days' AND m.actual_duration_hours IS NOT NULL {} {}", rc(region, "m.region_id"), dv(scope, "m.division"));
        let q = vortex_plugin_sdk::sqlx::query_scalar::<_, f64>(&sql);
        let q = if let Some(r) = region { q.bind(r) } else { q };
        (q.fetch_one(db).await.unwrap_or(0.0) * 10.0).round() / 10.0
    };
    let sev = |s: &'static str| {
        let region = region;
        let sql = format!("SELECT COUNT(*)::bigint FROM eam_defect d WHERE d.state IN {OPEN_DEF} AND d.severity='{s}' {} {}", rc(region, "d.region_id"), dv(scope, "d.division"));
        let db = db.clone();
        async move { scalar_i64(&db, &sql, region).await }
    };
    let severity_mix = json!({"minor": sev("minor").await, "moderate": sev("moderate").await, "major": sev("major").await, "critical": sev("critical").await});

    let lh_sql = format!(
        "SELECT e.id, e.name, e.equipment_category, e.condition_status, COALESCE(s.name, t.name) AS location, round({HEALTH_SQL})::int AS hi \
         FROM eam_equipment e LEFT JOIN eam_substation s ON s.id=e.substation_id LEFT JOIN eam_transmission_tower t ON t.id=e.tower_id \
         WHERE e.active {rc} {dv} ORDER BY round({HEALTH_SQL}) ASC LIMIT 8", rc = rc(region, "e.region_id"), dv = dv(scope, "e.division"));
    let q = vortex_plugin_sdk::sqlx::query(&lh_sql);
    let q = if let Some(r) = region { q.bind(r) } else { q };
    let least_healthy: Vec<Value> = q.fetch_all(db).await.unwrap_or_default().iter().map(|e| json!({
        "id": e.get::<Uuid,_>("id"), "name": e.get::<String,_>("name"),
        "category": e.try_get::<Option<String>,_>("equipment_category").ok().flatten().unwrap_or_default(),
        "location": e.try_get::<Option<String>,_>("location").ok().flatten().unwrap_or_default(),
        "condition": e.get::<String,_>("condition_status"),
        "health_index": e.try_get::<i32,_>("hi").unwrap_or(0),
    })).collect();

    json!({
        "mo_by_state": mo_by_state, "mo_by_type": mo_by_type,
        "done_this_month": done_month, "done_30d": done_30d, "avg_duration_h": avg_dur,
        "severity_mix": severity_mix, "least_healthy": least_healthy,
    })
}

// ── enum label/colour helpers (mirror the Odoo selection labels) ────────────
fn type_label(s: &str) -> &'static str { match s { "pm" => "Preventive", "cm" => "Corrective", "emergency" => "Emergency", "inspection" => "Inspection", "testing" => "Testing", "overhaul" => "Overhaul", _ => "—" } }
fn state_label(s: &str) -> &'static str { match s { "draft" => "Draft", "scheduled" => "Scheduled", "assigned" => "Assigned", "in_progress" => "In Progress", "on_hold" => "On Hold", "completed" => "Completed", "verified" => "Verified", "cancelled" => "Cancelled", _ => s_static(s) } }
fn prio_label(s: &str) -> &'static str { match s { "0" => "Low", "1" => "Normal", "2" => "High", "3" => "Critical", _ => "—" } }
fn prio_color(s: &str) -> &'static str { match s { "0" => "#6c757d", "1" => "#0d6efd", "2" => "#fd7e14", "3" => "#dc3545", _ => "#888" } }
fn sev_label(s: &str) -> &'static str { match s { "minor" => "Minor", "moderate" => "Moderate", "major" => "Major", "critical" => "Critical", _ => "—" } }
fn sev_color(s: &str) -> &'static str { match s { "minor" => "#0d6efd", "moderate" => "#fd7e14", "major" => "#fd7e14", "critical" => "#dc3545", _ => "#888" } }
fn def_state_label(s: &str) -> &'static str { match s { "draft" => "Draft", "open" => "Open", "assigned" => "Assigned", "in_repair" => "In Repair", "repaired" => "Repaired", "verified" => "Verified", "cancelled" => "Cancelled", _ => "—" } }
fn cause_label(s: &str) -> &'static str { match s { "equipment_failure" => "Equipment Failure", "weather" => "Weather", "vegetation" => "Vegetation", "third_party" => "Third Party", "animal" => "Animal", "overload" => "Overload", "human_error" => "Human Error", "unknown" => "Unknown", _ => "—" } }
fn outage_state_label(s: &str) -> &'static str { match s { "ongoing" => "Ongoing", "restored" => "Restored", "cancelled" => "Cancelled", _ => "—" } }
fn s_static(_s: &str) -> &'static str { "—" }

// ─────────────────────────────── HTML render ────────────────────────────────

include!("control_room_html.rs");
