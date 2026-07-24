//! Leaflet maps (§9.3) — server-rendered ports of the Odoo/OWL map screens.
//!
//!  * Tower Map (`tower_map_action`) — transmission towers by GPS, voltage-coloured
//!    triangle markers, line polylines; filters by region / voltage / line.
//!  * Technician Map (`technician_map_action`) — live field-agent positions from
//!    `get_active_locations`, status-coloured pins (solid = real GPS, dashed = job-
//!    derived), 10-second polling, side roster.
//!  * Site Map (`site_map_action`) — distribution sites by type; filters by
//!    type / region / state.
//!
//! Data is gathered server-side and embedded as JSON; Leaflet (jsdelivr CDN,
//! already in the CSP allow-list) renders + filters client-side. OSM tiles are
//! permitted via the `img-src https://*.tile.openstreetmap.org` CSP directive.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::{json, Value};
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

const HEALTH_SQL: &str = "round(CASE condition_status WHEN 'excellent' THEN 100 WHEN 'good' THEN 80 WHEN 'fair' THEN 60 WHEN 'poor' THEN 40 WHEN 'critical' THEN 20 ELSE 50 END * CASE operational_status WHEN 'operational' THEN 1.0 WHEN 'standby' THEN 0.95 WHEN 'out_of_service' THEN 0.5 WHEN 'under_repair' THEN 0.6 WHEN 'decommissioned' THEN 0.0 ELSE 1.0 END)::int";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/tower-map", get(tower_map))
        .route("/sesb-eam/site-map", get(site_map))
        .route("/sesb-eam/technician-map", get(technician_map))
        .route("/sesb-eam/technician-map/locations", get(technician_locations))
}

const LEAFLET_HEAD: &str = r#"<link rel="stylesheet" href="/static/vendor/leaflet/leaflet.css"/>
<script src="/static/vendor/leaflet/leaflet.js"></script>"#;

fn map_css() -> &'static str {
    r#"<style>
.eam-map-view { display:flex; flex-direction:column; min-height: calc(100vh - 64px); background:#f0f2f5; }
.eam-map-toolbar { background:#fff; border-bottom:1px solid #dee2e6; padding:10px 16px; display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.eam-map-toolbar h4 { margin:0; font-size:16px; font-weight:600; white-space:nowrap; color:#212529; }
.eam-map-toolbar select { min-width:150px; padding:4px 8px; border:1px solid #ced4da; border-radius:6px; font-size:13px; color:#212529; background:#fff; }
.eam-map-spacer { flex:1; }
.eam-map-count { font-size:13px; color:#495057; font-weight:600; }
.eam-map-legend { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.eam-map-legend-item { display:flex; align-items:center; gap:4px; font-size:11px; color:#6c757d; white-space:nowrap; }
.eam-map-legend-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
.eam-map-body { flex:1; display:flex; min-height:0; }
.eam-map { flex:1; min-height: calc(100vh - 130px); z-index:0; }
.eam-map-roster { width:300px; background:#fff; border-left:1px solid #dee2e6; overflow-y:auto; max-height: calc(100vh - 130px); }
.eam-roster-head { padding:10px 14px; font-weight:700; font-size:13px; color:#212529; border-bottom:1px solid #dee2e6; position:sticky; top:0; background:#fff; display:flex; justify-content:space-between; }
.eam-roster-row { padding:8px 14px; border-bottom:1px solid #f0f2f5; cursor:pointer; font-size:12px; }
.eam-roster-row:hover { background:#f8f9fa; }
.eam-roster-name { font-weight:600; color:#212529; }
.eam-roster-meta { color:#6c757d; font-size:11px; margin-top:2px; }
.eam-roster-badge { display:inline-block; color:#fff; font-size:9px; font-weight:700; padding:1px 6px; border-radius:8px; text-transform:uppercase; }
.eam-map-empty { color:#6c757d; padding:20px; text-align:center; font-size:13px; }
</style>"#
}

fn voltage_color(kv: f64) -> &'static str {
    if kv >= 400.0 { "#dc3545" } else if kv >= 200.0 { "#fd7e14" } else if kv >= 100.0 { "#0d6efd" } else { "#198754" }
}
fn title_words(s: &str) -> String {
    s.split('_').map(|w| { let mut c = w.chars(); match c.next() { Some(f) => f.to_uppercase().collect::<String>() + c.as_str(), None => String::new() } }).collect::<Vec<_>>().join(" ")
}
fn jstr(v: &[Value]) -> String { vortex_plugin_sdk::serde_json::to_string(v).unwrap_or_else(|_| "[]".into()) }

// ═══════════════════════════════════ TOWER MAP ══════════════════════════════

async fn tower_map(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.tower_map");
    let content = match render_tower_map(&db, division::DivisionScope::for_user(&user)).await {
        Ok(h) => h, Err(e) => { error!(error=%e, "tower map"); "<h1>Failed to load tower map</h1>".into() }
    };
    Html(page_shell(&sidebar, "Tower Map", &content)).into_response()
}

async fn render_tower_map(db: &PgPool, scope: division::DivisionScope) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    // Elevated read (§6.3): row rules don't apply here, so re-apply the caller's
    // division scope by hand. Towers are transmission-constant, so a DAMS-only
    // user's map comes back empty rather than leaking.
    let dv = scope.sql_predicate("t.division").map(|p| format!(" AND {p}")).unwrap_or_default();
    let rows = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT t.id, t.name, t.code, t.tower_number, t.tower_type, t.height_m, \
           t.gps_latitude::float8 AS lat, t.gps_longitude::float8 AS lng, \
           t.transmission_line_id AS line_id, l.name AS line_name, t.region_id, \
           t.voltage_level_id AS vl_id, COALESCE(v.voltage_kv,132)::float8 AS kv, \
           t.operational_status, t.condition_status, {HEALTH_SQL} AS hi, \
           (SELECT COUNT(*) FROM eam_equipment e WHERE e.tower_id=t.id)::int AS equip_count \
         FROM eam_transmission_tower t \
         LEFT JOIN eam_transmission_line l ON l.id=t.transmission_line_id \
         LEFT JOIN eam_voltage_level v ON v.id=t.voltage_level_id \
         WHERE t.active AND t.gps_latitude IS NOT NULL AND t.gps_longitude IS NOT NULL \
           AND t.gps_latitude <> 0 AND t.gps_longitude <> 0{dv}"))
        .fetch_all(db).await?;
    let towers: Vec<Value> = rows.iter().map(|t| json!({
        "id": t.get::<Uuid,_>("id"), "name": t.try_get::<String,_>("name").unwrap_or_default(),
        "code": t.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default(),
        "tower_number": t.try_get::<Option<i32>,_>("tower_number").ok().flatten(),
        "tower_type": title_words(&t.try_get::<Option<String>,_>("tower_type").ok().flatten().unwrap_or_default()),
        "height_m": t.try_get::<Option<f64>,_>("height_m").ok().flatten(),
        "lat": t.try_get::<Option<f64>,_>("lat").ok().flatten(), "lng": t.try_get::<Option<f64>,_>("lng").ok().flatten(),
        "line_id": t.try_get::<Option<Uuid>,_>("line_id").ok().flatten().map(|u| u.to_string()).unwrap_or_default(),
        "line_name": t.try_get::<Option<String>,_>("line_name").ok().flatten().unwrap_or_else(|| "-".into()),
        "region_id": t.try_get::<Option<Uuid>,_>("region_id").ok().flatten().map(|u| u.to_string()).unwrap_or_default(),
        "vl_id": t.try_get::<Option<Uuid>,_>("vl_id").ok().flatten().map(|u| u.to_string()).unwrap_or_default(),
        "kv": t.try_get::<f64,_>("kv").unwrap_or(132.0),
        "op_status": title_words(&t.try_get::<Option<String>,_>("operational_status").ok().flatten().unwrap_or_default()),
        "cond_status": title_words(&t.try_get::<Option<String>,_>("condition_status").ok().flatten().unwrap_or_default()),
        "health": t.try_get::<i32,_>("hi").unwrap_or(0),
        "equip_count": t.try_get::<i32,_>("equip_count").unwrap_or(0),
    })).collect();

    let regions = options_from(db, "SELECT id, name FROM eam_region WHERE active AND division='transmission' ORDER BY name").await;
    let voltages = options_from(db, "SELECT id, name FROM eam_voltage_level WHERE voltage_kv >= 66 ORDER BY voltage_kv DESC").await;
    let lines = options_from(db, "SELECT id, COALESCE(code, name) AS name FROM eam_transmission_line WHERE active ORDER BY name").await;

    Ok(format!(r#"<div class="eam-map-view">{css}{leaflet}
<div class="eam-map-toolbar"><span style="font-size:18px">🗼</span><h4>Tower Map</h4>
  <select id="f-region" onchange="render()"><option value="">All Regions</option>{regions}</select>
  <select id="f-voltage" onchange="render()"><option value="">All Voltages</option>{voltages}</select>
  <select id="f-line" onchange="render()"><option value="">All Lines</option>{lines}</select>
  <span class="eam-map-count" id="count"></span>
  <div class="eam-map-spacer"></div>
  <div class="eam-map-legend">
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#dc3545"></span>≥400kV</span>
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#fd7e14"></span>≥275kV</span>
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#0d6efd"></span>≥132kV</span>
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#198754"></span>≤66kV</span>
  </div>
</div>
<div class="eam-map-body"><div id="map" class="eam-map"></div></div>
<script>
(function(){{
  var TOWERS = {towers_json};
  function vcolor(kv){{ return kv>=400?'#dc3545':kv>=200?'#fd7e14':kv>=100?'#0d6efd':'#198754'; }}
  function esc(s){{return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
  var map, layers=[];
  function init(){{
    if(!window.L){{return;}}
    map=L.map('map').setView([5.3,116.5],8);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{attribution:'© OpenStreetMap',maxZoom:19}}).addTo(map);
    window.render=render; render();
  }}
  function render(){{
    if(!map)return;
    layers.forEach(function(l){{map.removeLayer(l);}}); layers=[];
    var fr=document.getElementById('f-region').value, fv=document.getElementById('f-voltage').value, fl=document.getElementById('f-line').value;
    var ts=TOWERS.filter(function(t){{return t.lat&&t.lng&&(!fr||t.region_id===fr)&&(!fv||t.vl_id===fv)&&(!fl||t.line_id===fl);}});
    document.getElementById('count').textContent=ts.length+' towers';
    // polylines per line
    var byLine={{}};
    ts.forEach(function(t){{ if(t.line_id){{(byLine[t.line_id]=byLine[t.line_id]||[]).push(t);}} }});
    Object.keys(byLine).forEach(function(lid){{
      var lt=byLine[lid].slice().sort(function(a,b){{return (a.tower_number||0)-(b.tower_number||0);}});
      if(lt.length>=2){{ var pl=L.polyline(lt.map(function(t){{return [t.lat,t.lng];}}),{{color:vcolor(lt[0].kv),weight:3,opacity:0.7}}).addTo(map); layers.push(pl); }}
    }});
    var bounds=[];
    ts.forEach(function(t){{
      var color=vcolor(t.kv); bounds.push([t.lat,t.lng]);
      var icon=L.divIcon({{className:'',html:'<div style="width:0;height:0;border-left:8px solid transparent;border-right:8px solid transparent;border-bottom:14px solid '+color+';filter:drop-shadow(0 1px 2px rgba(0,0,0,.3))"></div>',iconSize:[16,14],iconAnchor:[8,14],popupAnchor:[0,-14]}});
      var p='<div style="min-width:200px"><strong>'+esc(t.name)+'</strong><br/><small>['+esc(t.code)+']</small><hr style="margin:4px 0"/>'+
        '<b>Line:</b> '+esc(t.line_name)+'<br/><b>Tower #:</b> '+esc(t.tower_number)+'<br/><b>Type:</b> '+esc(t.tower_type)+'<br/>'+
        '<b>Height:</b> '+(t.height_m||'-')+'m<br/><b>Status:</b> '+esc(t.op_status)+'<br/><b>Condition:</b> '+esc(t.cond_status)+'<br/>'+
        '<b>Health:</b> '+t.health+'%<br/><b>Equipment:</b> '+t.equip_count+'<br/><b>Coords:</b> '+t.lat.toFixed(6)+', '+t.lng.toFixed(6)+
        '<hr style="margin:4px 0"/><a href="/sesb-eam/towers/'+t.id+'" style="font-weight:bold">View Details →</a></div>';
      var m=L.marker([t.lat,t.lng],{{icon:icon}}).addTo(map).bindPopup(p); layers.push(m);
    }});
    if(bounds.length) map.fitBounds(bounds,{{padding:[30,30]}});
  }}
  if(document.readyState!=='loading') setTimeout(init,0); else document.addEventListener('DOMContentLoaded',init);
}})();
</script></div>"#,
        css = map_css(), leaflet = LEAFLET_HEAD, towers_json = jstr(&towers)))
}

// ═══════════════════════════════════ SITE MAP ═══════════════════════════════

async fn site_map(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.site_map");
    let content = match render_site_map(&db, division::DivisionScope::for_user(&user)).await {
        Ok(h) => h, Err(e) => { error!(error=%e, "site map"); "<h1>Failed to load site map</h1>".into() }
    };
    Html(page_shell(&sidebar, "Site Map", &content)).into_response()
}

const SITE_TYPES: &[(&str, &str, &str)] = &[
    ("pmu", "PMU", "#6f42c1"), ("ppu", "PPU", "#dc3545"), ("ssu_33kv", "SSU 33kV", "#0d6efd"),
    ("ssu_11kv", "SSU 11kV", "#0dcaf0"), ("pp", "PP", "#198754"), ("pe", "PE", "#ffc107"),
    ("ss", "SS", "#fd7e14"), ("isolation", "Isolation", "#20c997"), ("other", "Other", "#6c757d"),
];

async fn render_site_map(db: &PgPool, scope: division::DivisionScope) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    let dv = scope.sql_predicate("s.division").map(|p| format!(" AND {p}")).unwrap_or_default();
    let rows = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT s.id, s.name, s.code, s.site_type, s.state, \
           s.gps_latitude::float8 AS lat, s.gps_longitude::float8 AS lng, \
           s.region_id, r.name AS region_name, \
           (SELECT COUNT(*) FROM eam_substation su WHERE su.site_id=s.id)::int AS sub_count, \
           (SELECT COUNT(*) FROM eam_equipment e JOIN eam_substation su ON su.id=e.substation_id WHERE su.site_id=s.id)::int AS equip_count \
         FROM eam_site s LEFT JOIN eam_region r ON r.id=s.region_id \
         WHERE s.active AND s.gps_latitude IS NOT NULL AND s.gps_longitude IS NOT NULL \
           AND s.gps_latitude <> 0 AND s.gps_longitude <> 0{dv}"))
        .fetch_all(db).await?;
    let sites: Vec<Value> = rows.iter().map(|s| {
        let st: String = s.try_get("site_type").ok().flatten().unwrap_or_default();
        let (label, color) = SITE_TYPES.iter().find(|(k, _, _)| *k == st).map(|(_, l, c)| (*l, *c)).unwrap_or((st.as_str(), "#6c757d"));
        json!({
            "id": s.get::<Uuid,_>("id"), "name": s.try_get::<String,_>("name").unwrap_or_default(),
            "code": s.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default(),
            "site_type": st, "type_label": label, "color": color,
            "state": s.try_get::<Option<String>,_>("state").ok().flatten().unwrap_or_default(),
            "lat": s.try_get::<Option<f64>,_>("lat").ok().flatten(), "lng": s.try_get::<Option<f64>,_>("lng").ok().flatten(),
            "region_id": s.try_get::<Option<Uuid>,_>("region_id").ok().flatten().map(|u| u.to_string()).unwrap_or_default(),
            "region_name": s.try_get::<Option<String>,_>("region_name").ok().flatten().unwrap_or_else(|| "-".into()),
            "sub_count": s.try_get::<i32,_>("sub_count").unwrap_or(0),
            "equip_count": s.try_get::<i32,_>("equip_count").unwrap_or(0),
        })
    }).collect();

    let regions = options_from(db, "SELECT id, name FROM eam_region WHERE active ORDER BY name").await;
    let type_opts: String = SITE_TYPES.iter().map(|(k, l, _)| format!(r#"<option value="{k}">{l}</option>"#)).collect();
    // distinct states present
    let state_rows = vortex_plugin_sdk::sqlx::query("SELECT DISTINCT state FROM eam_site WHERE active AND state IS NOT NULL ORDER BY state").fetch_all(db).await.unwrap_or_default();
    let state_opts: String = state_rows.iter().map(|r| { let s: String = r.try_get("state").ok().flatten().unwrap_or_default(); format!(r#"<option value="{s}">{l}</option>"#, l = esc(&title_words(&s))) }).collect();

    Ok(format!(r#"<div class="eam-map-view">{css}{leaflet}
<div class="eam-map-toolbar"><span style="font-size:18px">🏢</span><h4>Site Map</h4>
  <select id="f-type" onchange="render()"><option value="">All Types</option>{type_opts}</select>
  <select id="f-region" onchange="render()"><option value="">All Regions</option>{regions}</select>
  <select id="f-state" onchange="render()"><option value="">All States</option>{state_opts}</select>
  <span class="eam-map-count" id="count"></span>
  <div class="eam-map-spacer"></div>
  <div class="eam-map-legend">{legend}</div>
</div>
<div class="eam-map-body"><div id="map" class="eam-map"></div></div>
<script>
(function(){{
  var SITES = {sites_json};
  function esc(s){{return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
  var map, layers=[];
  function init(){{
    if(!window.L)return;
    map=L.map('map').setView([5.3,116.5],8);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{attribution:'© OpenStreetMap',maxZoom:19}}).addTo(map);
    window.render=render; render();
  }}
  function render(){{
    if(!map)return;
    layers.forEach(function(l){{map.removeLayer(l);}}); layers=[];
    var ft=document.getElementById('f-type').value, fr=document.getElementById('f-region').value, fs=document.getElementById('f-state').value;
    var ss=SITES.filter(function(s){{return s.lat&&s.lng&&(!ft||s.site_type===ft)&&(!fr||s.region_id===fr)&&(!fs||s.state===fs);}});
    document.getElementById('count').textContent=ss.length+' sites';
    var bounds=[];
    ss.forEach(function(s){{
      bounds.push([s.lat,s.lng]);
      var icon=L.divIcon({{className:'',html:'<div style="background:'+s.color+';width:14px;height:14px;border-radius:50%;border:2px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,.4)"></div>',iconSize:[14,14],iconAnchor:[7,7],popupAnchor:[0,-10]}});
      var p='<div style="min-width:180px"><strong>'+esc(s.name)+'</strong><br/><small>['+esc(s.code)+']</small><hr style="margin:4px 0"/>'+
        '<b>Type:</b> '+esc(s.type_label)+'<br/><b>Region:</b> '+esc(s.region_name)+'<br/><b>Substations:</b> '+s.sub_count+'<br/>'+
        '<b>Equipment:</b> '+s.equip_count+'<br/><b>Coords:</b> '+s.lat.toFixed(6)+', '+s.lng.toFixed(6)+
        '<hr style="margin:4px 0"/><a href="/sesb-eam/sites/'+s.id+'" style="font-weight:bold">View Details →</a></div>';
      var m=L.marker([s.lat,s.lng],{{icon:icon}}).addTo(map).bindPopup(p); layers.push(m);
    }});
    if(bounds.length) map.fitBounds(bounds,{{padding:[30,30]}});
  }}
  if(document.readyState!=='loading') setTimeout(init,0); else document.addEventListener('DOMContentLoaded',init);
}})();
</script></div>"#,
        css = map_css(), leaflet = LEAFLET_HEAD,
        legend = SITE_TYPES.iter().map(|(_, l, c)| format!(r#"<span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:{c}"></span>{l}</span>"#)).collect::<String>(),
        sites_json = jstr(&sites)))
}

// ═══════════════════════════════ TECHNICIAN MAP ═════════════════════════════

async fn technician_map(
    State(state): State<Arc<AppState>>, Db(_db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.technician_map");
    let content = render_technician_map();
    Html(page_shell(&sidebar, "Technician Map", &content)).into_response()
}

/// Active field-agent locations (mirrors `get_active_locations`). JSON for polling.
async fn technician_locations(Db(db): Db, Extension(user): Extension<AuthUser>) -> Response {
    // The live technician map is an elevated read that §6.3 explicitly flags as
    // having leaked across divisions until the filter was re-applied by hand.
    // Positions are scoped by the agent's home division.
    let dv = division::DivisionScope::for_user(&user)
        .sql_predicate("a.division").map(|p| format!(" AND {p}")).unwrap_or_default();
    let rows = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT loc.id, loc.user_id, COALESCE(a.name, u.username, loc.name) AS agent, \
           loc.lat::float8 AS lat, loc.lng::float8 AS lng, loc.speed_kmh::float8 AS speed, \
           loc.battery_pct, loc.status, loc.source, r.name AS region, \
           m.description AS job, m.id AS job_id, to_char(loc.last_seen, 'HH24:MI:SS') AS last_seen \
         FROM eam_field_agent_location loc \
         LEFT JOIN eam_field_agent a ON a.id=loc.agent_id \
         LEFT JOIN users u ON u.id=loc.user_id \
         LEFT JOIN eam_region r ON r.id=loc.region_id \
         LEFT JOIN eam_maintenance m ON m.id=loc.maintenance_id \
         WHERE loc.is_active AND loc.last_seen >= NOW() - INTERVAL '15 minutes' AND loc.lat <> 0{dv}"))
        .fetch_all(&db).await.unwrap_or_default();
    let techs: Vec<Value> = rows.iter().map(|t| json!({
        "id": t.get::<Uuid,_>("id"),
        "agent": t.try_get::<Option<String>,_>("agent").ok().flatten().unwrap_or_default(),
        "lat": t.try_get::<Option<f64>,_>("lat").ok().flatten(),
        "lng": t.try_get::<Option<f64>,_>("lng").ok().flatten(),
        "speed_kmh": t.try_get::<Option<f64>,_>("speed").ok().flatten().unwrap_or(0.0),
        "battery_pct": t.try_get::<Option<i32>,_>("battery_pct").ok().flatten().unwrap_or(0),
        "status": t.try_get::<Option<String>,_>("status").ok().flatten().unwrap_or_default(),
        "source": t.try_get::<Option<String>,_>("source").ok().flatten().unwrap_or_default(),
        "region": t.try_get::<Option<String>,_>("region").ok().flatten().unwrap_or_default(),
        "job": t.try_get::<Option<String>,_>("job").ok().flatten().unwrap_or_default(),
        "job_id": t.try_get::<Option<Uuid>,_>("job_id").ok().flatten().map(|u| u.to_string()).unwrap_or_default(),
        "last_seen": t.try_get::<Option<String>,_>("last_seen").ok().flatten().unwrap_or_default(),
    })).collect();
    vortex_plugin_sdk::axum::Json(Value::Array(techs)).into_response()
}

fn render_technician_map() -> String {
    format!(r#"<div class="eam-map-view">{css}{leaflet}
<div class="eam-map-toolbar"><span style="font-size:18px">📍</span><h4>Technician Map</h4>
  <span class="eam-map-count" id="count"></span>
  <div class="eam-map-spacer"></div>
  <span class="eam-map-legend">
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#28a745"></span>Available</span>
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#007bff"></span>En Route</span>
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#fd7e14"></span>On Site</span>
    <span class="eam-map-legend-item"><span class="eam-map-legend-dot" style="background:#6c757d"></span>Off Duty</span>
  </span>
  <span class="eam-map-count" id="updated" style="color:#6c757d;font-weight:400"></span>
</div>
<div class="eam-map-body"><div id="map" class="eam-map"></div>
  <div class="eam-map-roster"><div class="eam-roster-head"><span>Field Agents</span><span id="rcount"></span></div><div id="roster"></div></div>
</div>
<script>
(function(){{
  var SC={{available:'#28a745',en_route:'#007bff',on_site:'#fd7e14',off_duty:'#6c757d'}};
  var SL={{available:'Available',en_route:'En Route',on_site:'On Site',off_duty:'Off Duty'}};
  var SRC={{device:'Device GPS',portal:'Portal',api:'API',derived:'From Job'}};
  function esc(s){{return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
  var map, markers={{}};
  function pin(color,derived){{
    var ring=derived?'border:3px dashed white;':'border:3px solid white;';
    return L.divIcon({{className:'',html:'<div style="width:32px;height:32px;border-radius:50%;background:'+color+';'+ring+'box-shadow:0 2px 6px rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center"><svg viewBox=\'0 0 24 24\' width=\'15\' height=\'15\' fill=\'white\'><path d=\'M12 2a5 5 0 0 0-5 5c0 1.7 1 3.4 3 5.2V21a2 2 0 0 0 4 0v-8.8c2-1.8 3-3.5 3-5.2a5 5 0 0 0-5-5zm0 7a2 2 0 1 1 0-4 2 2 0 0 1 0 4z\'/></svg></div>',iconSize:[32,32],iconAnchor:[16,32],popupAnchor:[0,-34]}});
  }}
  function popup(t,color){{
    return '<div style="min-width:190px"><strong>'+esc(t.agent)+'</strong><br/>'+
      '<span style="background:'+color+';color:#fff;padding:1px 7px;border-radius:8px;font-size:11px">'+esc(SL[t.status]||t.status)+'</span> '+
      '<span style="color:#888;font-size:11px">'+esc(SRC[t.source]||t.source)+'</span><br/>'+
      (t.region?'📍 '+esc(t.region)+'<br/>':'')+(t.job?'🔧 '+esc(t.job)+'<br/>':'')+
      (t.speed_kmh>0?'Speed: '+t.speed_kmh.toFixed(1)+' km/h<br/>':'')+(t.battery_pct>0?'Battery: '+t.battery_pct+'%<br/>':'')+
      '<small style="color:#888">Updated '+esc(t.last_seen)+'</small></div>';
  }}
  function roster(techs){{
    document.getElementById('rcount').textContent=techs.length;
    if(!techs.length){{document.getElementById('roster').innerHTML='<div class="eam-map-empty">No active field agents in the last 15 minutes.</div>';return;}}
    document.getElementById('roster').innerHTML=techs.map(function(t){{
      var c=SC[t.status]||'#6c757d';
      return '<div class="eam-roster-row" data-id="'+t.id+'"><div class="eam-roster-name">'+esc(t.agent)+' <span class="eam-roster-badge" style="background:'+c+'">'+esc(SL[t.status]||t.status)+'</span></div>'+
        '<div class="eam-roster-meta">'+(t.region?esc(t.region)+' · ':'')+esc(SRC[t.source]||t.source)+(t.job?' · '+esc(t.job):'')+'</div></div>';
    }}).join('');
    Array.prototype.forEach.call(document.querySelectorAll('.eam-roster-row'),function(el){{
      el.addEventListener('click',function(){{var m=markers[el.dataset.id]; if(m){{map.setView(m.getLatLng(),14); m.openPopup();}}}});
    }});
  }}
  function renderMarkers(techs){{
    var active={{}}; techs.forEach(function(t){{active[t.id]=1;}});
    Object.keys(markers).forEach(function(id){{ if(!active[id]){{map.removeLayer(markers[id]); delete markers[id];}} }});
    var coords=[];
    techs.forEach(function(t){{
      if(!t.lat&&!t.lng)return;
      var color=SC[t.status]||'#6c757d', derived=t.source==='derived', p=popup(t,color), ic=pin(color,derived);
      coords.push([t.lat,t.lng]);
      if(markers[t.id]){{markers[t.id].setLatLng([t.lat,t.lng]).setPopupContent(p).setIcon(ic);}}
      else{{markers[t.id]=L.marker([t.lat,t.lng],{{icon:ic}}).addTo(map).bindPopup(p);}}
    }});
    if(coords.length) map.fitBounds(coords,{{padding:[50,50],maxZoom:13}});
  }}
  function poll(){{
    fetch('/sesb-eam/technician-map/locations',{{headers:{{'Accept':'application/json'}}}}).then(function(r){{return r.json();}}).then(function(techs){{
      document.getElementById('count').textContent=techs.length+' active';
      document.getElementById('updated').textContent='Updated '+new Date().toLocaleTimeString();
      if(map) renderMarkers(techs); roster(techs);
    }}).catch(function(){{}});
  }}
  function init(){{
    if(!window.L)return;
    map=L.map('map').setView([5.4,117.0],7);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{attribution:'© OpenStreetMap',maxZoom:18}}).addTo(map);
    poll(); setInterval(poll,10000);
  }}
  if(document.readyState!=='loading') setTimeout(init,0); else document.addEventListener('DOMContentLoaded',init);
}})();
</script></div>"#, css = map_css(), leaflet = LEAFLET_HEAD)
}

// ── shared ──────────────────────────────────────────────────────────────────

async fn options_from(db: &PgPool, sql: &str) -> String {
    vortex_plugin_sdk::sqlx::query(sql).fetch_all(db).await.unwrap_or_default().iter().map(|r| {
        let id: Uuid = r.get("id");
        let name: String = r.try_get("name").ok().flatten().unwrap_or_default();
        format!(r#"<option value="{id}">{n}</option>"#, n = esc(&name))
    }).collect()
}
