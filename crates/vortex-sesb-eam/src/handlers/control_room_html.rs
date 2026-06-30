// HTML renderer for the Control Room — included into control_room.rs.
// Ports the OWL template (control_room_view.xml), the Leaflet map JS, and
// the dark control_room.css into a single server-rendered page.

const CONTROL_ROOM_CSS: &str = include_str!("control_room.css");

// small JSON field accessors
fn vs<'a>(v: &'a Value, k: &str) -> &'a str { v.get(k).and_then(|x| x.as_str()).unwrap_or("") }
fn vi(v: &Value, k: &str) -> i64 { v.get(k).and_then(|x| x.as_i64()).unwrap_or(0) }
fn vb(v: &Value, k: &str) -> bool { v.get(k).and_then(|x| x.as_bool()).unwrap_or(false) }
fn vid(v: &Value, k: &str) -> String { v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string() }

#[allow(clippy::too_many_arguments)]
fn build_html(
    k: &Kpis, rel: &Reliability2, assets: &[Asset],
    outages: &[Value], work_orders: &[Value], defects: &[Value], condition: &[Value], overdue: &[Value],
    analytics: &Value, regions: &[vortex_plugin_sdk::sqlx::postgres::PgRow],
    region: Option<Uuid>, tab: &str, now: &vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>,
) -> String {
    let reg_q = region.map(|r| format!("&region={r}")).unwrap_or_default();
    let updated = now.format("%Y-%m-%d %H:%M UTC").to_string();

    // ── header + tabs + region chips ─────────────────────────────────────────
    let mut chips = format!(
        r#"<a class="cr_chip {act}" href="/sesb-eam/control-room?tab={tab}">All</a>"#,
        act = if region.is_none() { "active" } else { "" });
    for r in regions {
        let id: Uuid = r.get("id");
        let code: String = r.try_get("code").unwrap_or_default();
        let active = region == Some(id);
        chips.push_str(&format!(
            r#"<a class="cr_chip {act}" href="/sesb-eam/control-room?tab={tab}&region={id}">{code}</a>"#,
            act = if active { "active" } else { "" }, code = esc(&code)));
    }

    let body = if tab == "analytics" {
        render_analytics(analytics, assets)
    } else {
        render_live(k, rel, assets, outages, work_orders, defects, condition, overdue, &reg_q)
    };

    // ── map bootstrap (live tab only) ────────────────────────────────────────
    let map_assets: Vec<Value> = assets.iter()
        .filter(|a| a.lat.is_some() && a.lng.is_some())
        .map(|a| json!({
            "id": a.id, "model": a.model, "kind": a.kind, "name": a.name, "code": a.code,
            "lat": a.lat, "lng": a.lng, "health": a.health, "equipment_count": a.equipment_count,
            "open_mo": a.open_mo, "overdue_mo": a.overdue_mo, "open_defects": a.open_defects,
        })).collect();
    let map_script = if tab == "live" {
        let assets_json = vortex_plugin_sdk::serde_json::to_string(&map_assets).unwrap_or_else(|_| "[]".into());
        format!(r#"
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
(function(){{
  var ASSETS = {assets_json};
  var COLORS = {{good:'#28a745',attention:'#ffc107',critical:'#dc3545',no_data:'#6c757d'}};
  function esc(s){{return (''+(s==null?'':s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
  function init(){{
    var el = document.getElementById('cr_map');
    if(!el || !window.L) return;
    var map = L.map(el).setView([5.4,117.0],7);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{attribution:'© OpenStreetMap',maxZoom:19}}).addTo(map);
    var pts=[];
    ASSETS.forEach(function(a){{
      if(a.lat==null||a.lng==null) return;
      var color=COLORS[a.health]||'#888', m;
      if(a.kind==='tower'){{
        m=L.marker([a.lat,a.lng],{{icon:L.divIcon({{className:'cr_tower_icon',html:'<span class=\"cr_tower_mark\" style=\"background:'+color+'\"></span>',iconSize:[14,14],iconAnchor:[7,7]}})}}).addTo(map);
      }} else {{
        m=L.circleMarker([a.lat,a.lng],{{radius:9+Math.min(9,(a.equipment_count||0)*0.5),color:color,fillColor:color,fillOpacity:0.65,weight:3}}).addTo(map);
      }}
      var kl=a.kind==='tower'?'Tower':'Substation';
      m.bindTooltip('<strong>'+esc(a.name)+'</strong><br/><small>'+kl+' · '+esc(a.code)+'</small><br/>Equipment: '+a.equipment_count+' · Open MO: '+a.open_mo+'<br/>Overdue: '+a.overdue_mo+' · Defects: '+a.open_defects,{{sticky:true}});
      var url=(a.kind==='tower'?'/sesb-eam/towers/':'/sesb-eam/substations/')+a.id;
      m.on('click',function(){{window.location.href=url;}});
      pts.push([a.lat,a.lng]);
    }});
    if(pts.length) map.fitBounds(L.latLngBounds(pts).pad(0.3));
  }}
  if(document.readyState!=='loading') setTimeout(init,0); else document.addEventListener('DOMContentLoaded',init);
}})();
</script>"#)
    } else { String::new() };

    format!(r#"<div class="eam_control_room">
<style>{css}
.eam_control_room {{ min-height: calc(100vh - 64px); height: auto; }}
.eam_control_room a.cr_tab, .eam_control_room a.cr_chip {{ text-decoration: none; }}
</style>
<div class="cr_header">
  <h1 class="cr_title">⚡ Network Operations Control Room</h1>
  <div class="cr_tabs">
    <a class="cr_tab {live_act}" href="/sesb-eam/control-room?tab=live{reg_q}">⚡ Live Ops</a>
    <a class="cr_tab {ana_act}" href="/sesb-eam/control-room?tab=analytics{reg_q}">📊 Analytics</a>
  </div>
  <div class="cr_actions">
    <a class="cr_tab" href="/sesb-eam/control-room?tab={tab}{reg_q}">↻ Refresh</a>
    <span class="cr_refresh_label">Updated {updated}</span>
  </div>
</div>
<div class="cr_filter_bar">
  <span class="cr_filter_label">Region:</span>
  {chips}
</div>
<div class="cr_body">{body}</div>
</div>
{map_script}"#,
        css = CONTROL_ROOM_CSS,
        live_act = if tab == "live" { "active" } else { "" },
        ana_act = if tab == "analytics" { "active" } else { "" },
    )
}

#[allow(clippy::too_many_arguments)]
fn render_live(
    k: &Kpis, rel: &Reliability2, assets: &[Asset],
    outages: &[Value], work_orders: &[Value], defects: &[Value], condition: &[Value], overdue: &[Value],
    _reg_q: &str,
) -> String {
    // KPI cards
    let kpi = |label: &str, val: i64, cls: &str| format!(
        r#"<div class="cr_kpi {cls}"><div class="kpi_label">{label}</div><div class="kpi_value">{val}</div></div>"#);
    let kpis = format!("{}{}{}{}{}{}{}{}",
        kpi("Open Maintenance", k.open_mo, ""),
        kpi("Overdue", k.overdue_mo, if k.overdue_mo > 0 { "kpi_danger" } else { "" }),
        kpi("Emergency MO", k.emergency_mo, if k.emergency_mo > 0 { "kpi_danger" } else { "" }),
        kpi("Open Defects", k.open_defects, if k.open_defects > 0 { "kpi_warning" } else { "" }),
        kpi("Critical Defects", k.critical_defects, if k.critical_defects > 0 { "kpi_danger" } else { "" }),
        kpi("Critical Assets", k.critical_assets, if k.critical_assets > 0 { "kpi_warning" } else { "" }),
        kpi("Substations", k.substations, ""),
        kpi("Towers", k.towers, ""),
    );

    // Reliability strip
    let rk = |val: String, lbl: &str, alert: bool| format!(
        r#"<div class="cr_rel_kpi {a}"><div class="rel_val">{val}</div><div class="rel_lbl">{lbl}</div></div>"#,
        a = if alert { "rel_alert" } else { "" });
    let reliability = format!(
        r#"<div class="cr_reliability"><div class="cr_rel_title">Reliability <span class="cr_rel_sub">IEEE-1366 · YTD · excl. major events</span></div><div class="cr_rel_grid">{}{}{}{}{}{}{}</div></div>"#,
        rk(format!("{:.1}", rel.saidi), "SAIDI (min)", rel.saidi > 100.0),
        rk(format!("{:.2}", rel.saifi), "SAIFI", rel.saifi > 1.0),
        rk(format!("{:.1}", rel.caidi), "CAIDI (min)", false),
        rk(rel.ongoing_count.to_string(), "Ongoing", rel.ongoing_count > 0),
        rk(fmt_thousands(rel.customers_interrupted), "Cust. Interrupted", false),
        rk(rel.outage_count.to_string(), "Outages (YTD)", false),
        rk(fmt_thousands(rel.total_customers), "Total Customers", false),
    );

    // Asset table
    let mut rows = String::new();
    for a in assets {
        let (kind_cls, kind_lbl, url) = if a.kind == "tower" {
            ("kind_tower", "Tower", format!("/sesb-eam/towers/{}", a.id))
        } else {
            ("kind_sub", "Sub", format!("/sesb-eam/substations/{}", a.id))
        };
        rows.push_str(&format!(
            r#"<tr class="cr_clickable" onclick="location.href='{url}'"><td>{name}<br><span class="muted">{code}</span></td><td><span class="cr_kind_pill {kind_cls}">{kind_lbl}</span></td><td>{eq}</td><td>{mo}</td><td>{ov}</td><td>{df}</td><td><span class="cr_health_pill" style="background:{hc}">{h}</span></td></tr>"#,
            name = esc(&a.name), code = esc(&a.code), eq = a.equipment_count, mo = a.open_mo, ov = a.overdue_mo, df = a.open_defects,
            hc = health_color(a.health), h = a.health));
    }
    let asset_table = if rows.is_empty() {
        r#"<div class="cr_empty">No assets in scope</div>"#.to_string()
    } else {
        format!(r#"<table class="cr_outlet_table"><thead><tr><th>Asset</th><th>Type</th><th>Eq</th><th>MO</th><th>Ovr</th><th>Def</th><th>Health</th></tr></thead><tbody>{rows}</tbody></table>"#)
    };

    // Feeds
    let outages_feed = feed_section("🔌 Supply Interruptions", &render_outages(outages), outages.is_empty(), "No active interruptions");
    let wo_feed = feed_section("🔧 Latest Open Maintenance", &render_work_orders(work_orders), work_orders.is_empty(), "No open maintenance");
    let def_feed = feed_section("🛠️ Open Defects", &render_defects(defects), defects.is_empty(), "No open defects");
    let cond_feed = feed_section("🌡️ Critical Condition Equipment", &render_condition(condition), condition.is_empty(), "All equipment healthy");
    let overdue_feed = feed_section("🔥 SLA Overdue Maintenance", &render_overdue(overdue), overdue.is_empty(), "No SLA breaches");

    format!(r#"
<div class="cr_kpis">{kpis}</div>
{reliability}
<div class="cr_split">
  <div class="cr_map_wrap">
    <div class="cr_panel_title">Network Status Map</div>
    <div id="cr_map" class="cr_map"></div>
    <div class="cr_map_legend">
      <span class="lg_chip"><span class="lg_dot lg_round" style="background:#28a745"></span>Good</span>
      <span class="lg_chip"><span class="lg_dot lg_round" style="background:#ffc107"></span>Attention</span>
      <span class="lg_chip"><span class="lg_dot lg_round" style="background:#dc3545"></span>Critical</span>
      <span class="lg_chip"><span class="lg_dot lg_round" style="background:#6c757d"></span>No data</span>
      <span class="lg_chip"><span class="lg_dot lg_square" style="background:#6f42c1"></span>Tower</span>
    </div>
    {asset_table}
  </div>
  <div class="cr_feeds">
    {outages_feed}{wo_feed}{def_feed}{cond_feed}{overdue_feed}
  </div>
</div>"#)
}

fn feed_section(title: &str, inner: &str, empty: bool, empty_msg: &str) -> String {
    let scroll = if empty {
        let good = if title.contains("Overdue") || title.contains("Condition") || title.contains("Supply") { "cr_empty_good" } else { "" };
        format!(r#"<div class="cr_empty {good}">{}</div>"#, esc(empty_msg))
    } else {
        format!(r#"<div class="cr_feed_scroll">{inner}</div>"#)
    };
    format!(r#"<div class="cr_feed_section"><div class="cr_panel_title">{}</div>{scroll}</div>"#, esc(title))
}

fn render_work_orders(items: &[Value]) -> String {
    items.iter().map(|m| format!(
        r#"<div class="cr_wo_row {breach}" onclick="location.href='/sesb-eam/maintenance/{id}'"><span class="wo_priority" style="background:{pc}">{pl}</span><div class="wo_body"><div class="wo_top"><span class="wo_state">{sl}</span>{ov}<span class="muted">{tl}</span></div><div class="wo_title">{title}</div><div class="wo_meta muted">{asset} · {assignee}</div></div></div>"#,
        breach = if vb(m, "is_overdue") { "is_breach" } else { "" },
        id = vid(m, "id"), pc = vs(m, "priority_color"), pl = esc(vs(m, "priority_label")),
        sl = esc(vs(m, "state_label")),
        ov = if vb(m, "is_overdue") { r#"<span class="wo_breach">OVERDUE</span>"# } else { "" },
        tl = esc(vs(m, "type_label")), title = esc(vs(m, "title")),
        asset = esc(vs(m, "asset_name")),
        assignee = { let a = vs(m, "assignee"); if a.is_empty() { "Unassigned".into() } else { esc(a) } },
    )).collect()
}

fn render_defects(items: &[Value]) -> String {
    items.iter().map(|d| format!(
        r#"<div class="cr_wo_row" onclick="location.href='/sesb-eam/defects/{id}'"><span class="wo_priority" style="background:{sc}">{sl}</span><div class="wo_body"><div class="wo_top"><span class="wo_state">{st}</span></div><div class="wo_title">{title}</div><div class="wo_meta muted">{asset} · {equip}</div></div></div>"#,
        id = vid(d, "id"), sc = vs(d, "severity_color"), sl = esc(vs(d, "severity_label")),
        st = esc(vs(d, "state_label")), title = esc(vs(d, "title")),
        asset = esc(vs(d, "asset_name")), equip = esc(vs(d, "equipment")),
    )).collect()
}

fn render_outages(items: &[Value]) -> String {
    items.iter().map(|o| {
        let st = vs(o, "state");
        let color = if st == "ongoing" { "#dc3545" } else if st == "restored" { "#28a745" } else { "#6c757d" };
        format!(
        r#"<div class="cr_log_row" onclick="location.href='/sesb-eam/outages/{id}'"><span class="log_status" style="background:{color}">{sl}</span><div class="log_body"><div class="wo_top"><strong>{name}</strong>{major}</div><div class="log_meta muted">{sub} · {cause} · {cust} cust · {dur}</div></div></div>"#,
        id = vid(o, "id"), sl = esc(vs(o, "state_label")), name = esc(vs(o, "name")),
        major = if vb(o, "is_major") { r#" <span class="wo_breach">MAJOR</span>"# } else { "" },
        sub = esc(vs(o, "substation")), cause = esc(vs(o, "cause")),
        cust = fmt_thousands(vi(o, "customers")), dur = esc(vs(o, "duration")))
    }).collect()
}

fn render_condition(items: &[Value]) -> String {
    items.iter().map(|e| {
        let cond = vs(e, "condition");
        let breach = if cond == "critical" { "is_breach" } else { "" };
        let hi = vi(e, "health_index");
        let hc = if hi < 30 { "#dc3545" } else if hi < 50 { "#ffc107" } else { "#28a745" };
        format!(
        r#"<div class="cr_sensor_row {breach}" onclick="location.href='/sesb-eam/equipment/{id}'"><div class="sensor_body"><div class="sensor_top"><span>{name}</span><span class="sensor_reading" style="color:{hc}">{hi}</span></div><div class="sensor_meta muted">{cat} · {loc} · {cond}</div></div></div>"#,
        id = vid(e, "id"), name = esc(vs(e, "name")), cat = esc(vs(e, "category")),
        loc = esc(vs(e, "location")), cond = esc(cond))
    }).collect()
}

fn render_overdue(items: &[Value]) -> String {
    items.iter().map(|m| format!(
        r#"<div class="cr_breach_row" onclick="location.href='/sesb-eam/maintenance/{id}'">{title} <span class="muted">— {asset}</span><span class="breach_overdue">{days}d overdue</span></div>"#,
        id = vid(m, "id"), title = esc(vs(m, "title")), asset = esc(vs(m, "asset_name")), days = vi(m, "days_overdue"),
    )).collect()
}

// ─────────────────────────────── analytics tab ──────────────────────────────

fn render_analytics(a: &Value, assets: &[Asset]) -> String {
    let done_month = a.get("done_this_month").and_then(|x| x.as_i64()).unwrap_or(0);
    let done_30d = a.get("done_30d").and_then(|x| x.as_i64()).unwrap_or(0);
    let avg_dur = a.get("avg_duration_h").and_then(|x| x.as_f64()).unwrap_or(0.0);

    let throughput = format!(
        r#"<div class="cr_card"><div class="cr_panel_title">Maintenance Throughput</div><div class="cr_stat_row"><div class="cr_stat"><div class="cr_stat_value text-success">{dm}</div><div class="cr_stat_label">Completed this month</div></div><div class="cr_stat"><div class="cr_stat_value">{d30}</div><div class="cr_stat_label">Completed (30d)</div></div><div class="cr_stat"><div class="cr_stat_value">{avg:.1}h</div><div class="cr_stat_label">Avg duration (30d)</div></div></div></div>"#,
        dm = done_month, d30 = done_30d, avg = avg_dur);

    // severity mix
    let sev = a.get("severity_mix").cloned().unwrap_or(json!({}));
    let seg = |n: i64, lbl: &str, color: &str| format!(
        r#"<div class="cond_seg"><span class="cond_num" style="color:{color}">{n}</span><span class="cond_lbl">{lbl}</span></div>"#);
    let severity = format!(
        r#"<div class="cr_card"><div class="cr_panel_title">Open Defects by Severity</div><div class="cr_cond_mix">{}{}{}{}</div></div>"#,
        seg(sev.get("minor").and_then(|x| x.as_i64()).unwrap_or(0), "Minor", "#0d6efd"),
        seg(sev.get("moderate").and_then(|x| x.as_i64()).unwrap_or(0), "Moderate", "#fd7e14"),
        seg(sev.get("major").and_then(|x| x.as_i64()).unwrap_or(0), "Major", "#fd7e14"),
        seg(sev.get("critical").and_then(|x| x.as_i64()).unwrap_or(0), "Critical", "#dc3545"));

    let by_state = bar_card("Open Maintenance by State", a.get("mo_by_state"), true);
    let by_type = bar_card("Open Maintenance by Type", a.get("mo_by_type"), false);

    // least healthy table
    let empty_lh = a.get("least_healthy").and_then(|x| x.as_array()).map(|v| v.is_empty()).unwrap_or(true);
    let mut lh_rows = String::new();
    if let Some(arr) = a.get("least_healthy").and_then(|x| x.as_array()) {
        for e in arr {
            let hi = vi(e, "health_index");
            let hc = if hi < 30 { "#dc3545" } else if hi < 50 { "#ffc107" } else { "#28a745" };
            lh_rows.push_str(&format!(
                r#"<tr class="cr_clickable" onclick="location.href='/sesb-eam/equipment/{id}'"><td>{name}</td><td>{cat}</td><td>{loc}</td><td>{cond}</td><td style="color:{hc};font-weight:700">{hi}</td></tr>"#,
                id = vid(e, "id"), name = esc(vs(e, "name")), cat = esc(vs(e, "category")),
                loc = esc(vs(e, "location")), cond = esc(vs(e, "condition"))));
        }
    }
    let least_healthy = format!(
        r#"<div class="cr_card cr_card_wide"><div class="cr_panel_title">Least Healthy Equipment</div>{}</div>"#,
        if empty_lh { r#"<div class="cr_empty">No equipment data</div>"#.to_string() }
        else { format!(r#"<table class="cr_mini_table"><thead><tr><th>Equipment</th><th>Category</th><th>Location</th><th>Condition</th><th>Health</th></tr></thead><tbody>{lh_rows}</tbody></table>"#) });

    // asset health snapshot
    let mut good = 0; let mut att = 0; let mut crit = 0; let mut nd = 0;
    for a in assets { match a.health { "good" => good += 1, "attention" => att += 1, "critical" => crit += 1, _ => nd += 1 } }
    let snapshot = format!(
        r#"<div class="cr_card cr_card_wide"><div class="cr_panel_title">Asset Health Snapshot</div><div class="cr_cond_mix">{}{}{}{}</div></div>"#,
        seg(good, "Good", "#28a745"), seg(att, "Attention", "#ffc107"),
        seg(crit, "Critical", "#dc3545"), seg(nd, "No data", "#6c757d"));

    format!(r#"<div class="cr_analytics_grid">{throughput}{severity}{by_state}{by_type}{least_healthy}{snapshot}</div>"#)
}

fn bar_card(title: &str, data: Option<&Value>, state_style: bool) -> String {
    let arr = data.and_then(|x| x.as_array()).cloned().unwrap_or_default();
    if arr.is_empty() {
        return format!(r#"<div class="cr_card"><div class="cr_panel_title">{}</div><div class="cr_empty">No open orders</div></div>"#, esc(title));
    }
    let max = arr.iter().map(|i| vi(i, "count")).max().unwrap_or(1).max(1);
    let fill = if state_style { "bar_fill state_fill" } else { "bar_fill" };
    let rows: String = arr.iter().map(|i| {
        let n = vi(i, "count");
        let w = ((n as f64 / max as f64) * 100.0).round().min(100.0);
        format!(r#"<div class="cr_bar_row"><span class="bar_label">{lbl}</span><span class="bar_track"><span class="{fill}" style="width:{w}%"></span></span><span class="bar_value">{n}</span></div>"#,
            lbl = esc(vs(i, "label")))
    }).collect();
    format!(r#"<div class="cr_card"><div class="cr_panel_title">{}</div>{rows}</div>"#, esc(title))
}

fn fmt_thousands(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    let rev: String = out.chars().rev().collect();
    if n < 0 { format!("-{rev}") } else { rev }
}
