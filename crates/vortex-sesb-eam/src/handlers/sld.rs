//! Single Line Diagrams (§9.2) — server-rendered ports of the Odoo/OWL SLD views.
//!
//!  * Substation SLD (DAMS, `sld_view_action`) — IEC-style busbar/bay/equipment
//!    topology for a selected substation; voltage-coloured busbars, IEC symbols,
//!    status-coloured equipment, click-through.
//!  * Transmission SLD (TMS, `transmission_sld_action`) — a network view (grid of
//!    substations + voltage-coloured line edges) and a per-line view (line →
//!    towers → spans with 3-phase catenary conductors and tower-type symbols).
//!
//! The original used absolute-positioned HTML + inline SVG with the layout math
//! computed in JS; this reproduces the exact same layout algorithm in Rust and
//! emits the identical DOM + the original CSS (copied into the crate).

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

const SLD_CSS: &str = include_str!("sld_view.css");
const TSLD_CSS: &str = include_str!("transmission.css");

// health expression: condition score × operational factor (matches analytics)
const HEALTH_SQL: &str = "round(CASE condition_status WHEN 'excellent' THEN 100 WHEN 'good' THEN 80 WHEN 'fair' THEN 60 WHEN 'poor' THEN 40 WHEN 'critical' THEN 20 ELSE 50 END * CASE operational_status WHEN 'operational' THEN 1.0 WHEN 'standby' THEN 0.95 WHEN 'out_of_service' THEN 0.5 WHEN 'under_repair' THEN 0.6 WHEN 'decommissioned' THEN 0.0 ELSE 1.0 END)::int";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/sld", get(substation_sld))
        .route("/sesb-eam/transmission-sld", get(transmission_sld))
}

// ── shared palettes ─────────────────────────────────────────────────────────
const STATUS_COLORS: &[(&str, &str)] = &[
    ("operational", "#198754"), ("standby", "#ffc107"), ("out_of_service", "#dc3545"),
    ("under_repair", "#fd7e14"), ("decommissioned", "#6c757d"),
];
fn status_color(s: &str) -> &'static str {
    STATUS_COLORS.iter().find(|(k, _)| *k == s).map(|(_, v)| *v).unwrap_or("#198754")
}
const VOLTAGE_PALETTE: &[&str] = &["#dc3545", "#0d6efd", "#198754", "#fd7e14", "#6f42c1", "#0dcaf0"];

fn fmt_words(s: &str) -> String { s.replace('_', " ") }
fn title_words(s: &str) -> String {
    s.split('_').map(|w| { let mut c = w.chars(); match c.next() { Some(f) => f.to_uppercase().collect::<String>() + c.as_str(), None => String::new() } }).collect::<Vec<_>>().join(" ")
}

include!("sld_symbols.rs");

// ═══════════════════════════════ SUBSTATION SLD ═════════════════════════════

struct Vl { id: Uuid, name: String, kv: f64, color: String }
struct Bay {
    id: Uuid, name: String, bay_type: String, vl_id: Option<Uuid>,
    feeder_name: String, destination: String, state: String,
}
struct Equip {
    id: Uuid, name: String, code: String, category: String, op_status: String,
    health: i32, rated_kv: Option<f64>, rated_a: Option<f64>, rated_kva: Option<f64>,
}
struct Column { bay_idx: usize, col_index: usize, vl_id: Option<Uuid> }

// layout constants (mirror LAYOUT in sld_view.js)
const COL_WIDTH: i32 = 160;
const COL_CONTENT_W: i32 = 140;
const LEFT_MARGIN: i32 = 80;
const BUSBAR_FIRST_Y: i32 = 50;
const BUSBAR_H: i32 = 6;
const GAP_BUSBAR_HEADER: i32 = 14;
const HEADER_HEIGHT: i32 = 90;
const GAP_HEADER_EQUIP: i32 = 6;
const EQUIP_ITEM_H: i32 = 44;
const EQUIP_GAP: i32 = 8;
const GAP_SECTION_BOTTOM: i32 = 40;

fn equip_stack_height(count: usize) -> i32 {
    if count == 0 { 0 } else { count as i32 * EQUIP_ITEM_H + (count as i32 - 1) * EQUIP_GAP }
}

const EQUIP_RENDER_ORDER: &[&str] = &[
    "switchgear", "rmu", "isolator", "ct_vt", "transformer", "surge_arrester", "cable",
    "protection", "battery", "scada", "busbar", "earthing", "feeder_pillar", "other",
];
fn render_rank(cat: &str) -> usize {
    EQUIP_RENDER_ORDER.iter().position(|c| *c == cat).unwrap_or(13)
}

async fn substation_sld(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.sld");
    let sel = q.get("substation").filter(|s| !s.is_empty()).and_then(|s| s.parse::<Uuid>().ok());
    let content = match render_substation_sld(&db, sel).await {
        Ok(html) => html,
        Err(e) => { error!(error=%e, "substation sld"); "<h1>Failed to load SLD</h1>".into() }
    };
    Html(page_shell(&sidebar, "Single Line Diagram", &content)).into_response()
}

async fn render_substation_sld(db: &PgPool, sel: Option<Uuid>) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    // substation dropdown
    let subs = vortex_plugin_sdk::sqlx::query(
        "SELECT s.id, s.name, s.code FROM eam_substation s WHERE s.active ORDER BY s.name")
        .fetch_all(db).await.unwrap_or_default();
    let mut options = String::from(r#"<option value="">— Select Substation —</option>"#);
    for s in &subs {
        let id: Uuid = s.get("id");
        let name: String = s.try_get("name").unwrap_or_default();
        let code: Option<String> = s.try_get("code").ok().flatten();
        let selected = if sel == Some(id) { " selected" } else { "" };
        options.push_str(&format!(r#"<option value="{id}"{selected}>[{c}] {n}</option>"#,
            c = esc(code.as_deref().unwrap_or("")), n = esc(&name)));
    }

    let canvas = match sel {
        None => r#"<div class="sld-empty-state"><div style="font-size:42px">🗺️</div><p>Select a substation to view its Single Line Diagram</p></div>"#.to_string(),
        Some(id) => build_substation_canvas(db, id).await?,
    };

    Ok(format!(r#"<div class="sld-view"><style>{css}
.sld-view {{ min-height: calc(100vh - 64px); }}
.sld-view select {{ color:#212529; }}</style>
<div class="sld-toolbar">
  <span style="font-size:18px">🔌</span><h4>Single Line Diagram</h4>
  <select class="form-select form-select-sm" style="min-width:240px;padding:4px 8px;border:1px solid #ced4da;border-radius:6px"
     onchange="if(this.value)location.href='/sesb-eam/sld?substation='+this.value;else location.href='/sesb-eam/sld'">{options}</select>
  <div class="sld-toolbar-spacer"></div>
  <div class="sld-status-legend">
    <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#198754"></span>Oper.</span>
    <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#ffc107"></span>Standby</span>
    <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#dc3545"></span>OOS</span>
    <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#fd7e14"></span>Repair</span>
  </div>
</div>
<div class="sld-canvas-wrapper">{canvas}</div>
</div>"#, css = SLD_CSS))
}

async fn build_substation_canvas(db: &PgPool, id: Uuid) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    // substation header
    let sub = vortex_plugin_sdk::sqlx::query(
        "SELECT s.name, s.code, s.busbar_configuration, si.name AS site, \
           (SELECT COUNT(*) FROM eam_bay b WHERE b.substation_id=s.id AND b.active)::bigint AS bay_count, \
           (SELECT COUNT(*) FROM eam_equipment e WHERE e.substation_id=s.id AND e.active)::bigint AS equip_count \
         FROM eam_substation s LEFT JOIN eam_site si ON si.id=s.site_id WHERE s.id=$1")
        .bind(id).fetch_optional(db).await?;
    let Some(sub) = sub else { return Ok(r#"<div class="sld-empty-state"><p>Substation not found</p></div>"#.into()); };
    let sub_name: String = sub.try_get("name").unwrap_or_default();
    let sub_code: Option<String> = sub.try_get("code").ok().flatten();
    let busbar_cfg: Option<String> = sub.try_get("busbar_configuration").ok().flatten();
    let site: Option<String> = sub.try_get("site").ok().flatten();
    let bay_count: i64 = sub.try_get("bay_count").unwrap_or(0);
    let equip_count: i64 = sub.try_get("equip_count").unwrap_or(0);

    // bays
    let bay_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, bay_type, voltage_level_id, feeder_name, destination, state \
         FROM eam_bay WHERE substation_id=$1 AND active ORDER BY bay_number ASC NULLS LAST, name")
        .bind(id).fetch_all(db).await?;
    let bays: Vec<Bay> = bay_rows.iter().map(|b| Bay {
        id: b.get("id"), name: b.try_get("name").unwrap_or_default(),
        bay_type: b.try_get("bay_type").ok().flatten().unwrap_or_else(|| "other".into()),
        vl_id: b.try_get("voltage_level_id").ok().flatten(),
        feeder_name: b.try_get("feeder_name").ok().flatten().unwrap_or_default(),
        destination: b.try_get("destination").ok().flatten().unwrap_or_default(),
        state: b.try_get("state").ok().flatten().unwrap_or_default(),
    }).collect();

    // voltage levels present on this substation's bays, sorted desc by kv
    let vl_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT DISTINCT v.id, v.name, v.voltage_kv FROM eam_voltage_level v \
         JOIN eam_bay b ON b.voltage_level_id=v.id WHERE b.substation_id=$1 AND b.active \
         ORDER BY v.voltage_kv DESC")
        .bind(id).fetch_all(db).await?;
    let mut vls: Vec<Vl> = vl_rows.iter().enumerate().map(|(i, v)| Vl {
        id: v.get("id"), name: v.try_get("name").unwrap_or_default(),
        kv: v.try_get::<Option<f64>, _>("voltage_kv").ok().flatten().unwrap_or(0.0),
        color: VOLTAGE_PALETTE[i % VOLTAGE_PALETTE.len()].to_string(),
    }).collect();
    if vls.is_empty() {
        // no VL-tagged bays — synthesise a single bucket so bays still render
        vls.push(Vl { id: Uuid::nil(), name: "Busbar".into(), kv: 0.0, color: VOLTAGE_PALETTE[0].into() });
    }

    // equipment grouped by bay
    let eq_rows = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT id, name, code, equipment_category, operational_status, bay_id, \
           rated_voltage_kv, rated_current_a, rated_power_kva, {HEALTH_SQL} AS hi \
         FROM eam_equipment WHERE bay_id = ANY($1) AND active"))
        .bind(bays.iter().map(|b| b.id).collect::<Vec<_>>())
        .fetch_all(db).await?;
    let mut by_bay: HashMap<Uuid, Vec<Equip>> = HashMap::new();
    for e in &eq_rows {
        let bid: Uuid = e.get("bay_id");
        by_bay.entry(bid).or_default().push(Equip {
            id: e.get("id"), name: e.try_get("name").unwrap_or_default(),
            code: e.try_get("code").ok().flatten().unwrap_or_default(),
            category: e.try_get("equipment_category").ok().flatten().unwrap_or_else(|| "other".into()),
            op_status: e.try_get("operational_status").ok().flatten().unwrap_or_else(|| "operational".into()),
            health: e.try_get("hi").unwrap_or(0),
            rated_kv: e.try_get("rated_voltage_kv").ok().flatten(),
            rated_a: e.try_get("rated_current_a").ok().flatten(),
            rated_kva: e.try_get("rated_power_kva").ok().flatten(),
        });
    }
    for list in by_bay.values_mut() { list.sort_by_key(|e| render_rank(&e.category)); }

    // ── classify bays into columns (mirror sldLayout) ───────────────────────
    let vl_index: HashMap<Uuid, usize> = vls.iter().enumerate().map(|(i, v)| (v.id, i)).collect();
    let first_vl = vls[0].id;
    let mut transformer_bays = Vec::new();
    let mut coupler_bays = Vec::new();
    // per-vl ordered buckets
    let mut vl_in: HashMap<Uuid, Vec<usize>> = HashMap::new();
    let mut vl_out: HashMap<Uuid, Vec<usize>> = HashMap::new();
    let mut vl_other: HashMap<Uuid, Vec<usize>> = HashMap::new();
    for (i, b) in bays.iter().enumerate() {
        let vl = b.vl_id.filter(|v| vl_index.contains_key(v)).unwrap_or(first_vl);
        match b.bay_type.as_str() {
            "transformer" => transformer_bays.push(i),
            "bus_coupler" | "bus_section" => coupler_bays.push(i),
            "incoming" => vl_in.entry(vl).or_default().push(i),
            "outgoing" => vl_out.entry(vl).or_default().push(i),
            _ => vl_other.entry(vl).or_default().push(i),
        }
    }
    let mut columns: Vec<Column> = Vec::new();
    let mut col_index = 0usize;
    for v in &vls {
        for bucket in [&vl_in, &vl_out, &vl_other] {
            if let Some(idxs) = bucket.get(&v.id) {
                for &bi in idxs { columns.push(Column { bay_idx: bi, col_index, vl_id: Some(v.id) }); col_index += 1; }
            }
        }
    }
    for &bi in &transformer_bays {
        let vl = bays[bi].vl_id.filter(|v| vl_index.contains_key(v)).unwrap_or(first_vl);
        columns.push(Column { bay_idx: bi, col_index, vl_id: Some(vl) }); col_index += 1;
    }
    for &bi in &coupler_bays {
        let vl = bays[bi].vl_id.filter(|v| vl_index.contains_key(v)).unwrap_or(first_vl);
        columns.push(Column { bay_idx: bi, col_index, vl_id: Some(vl) }); col_index += 1;
    }
    let total_columns = col_index.max(1);

    // ── busbar Y positions ──────────────────────────────────────────────────
    let mut busbar_y: HashMap<Uuid, i32> = HashMap::new();
    let mut current_y = BUSBAR_FIRST_Y;
    for v in &vls {
        busbar_y.insert(v.id, current_y);
        let max_eq = columns.iter().filter(|c| c.vl_id == Some(v.id))
            .map(|c| by_bay.get(&bays[c.bay_idx].id).map(|l| l.len()).unwrap_or(0)).max().unwrap_or(0);
        let section = BUSBAR_H + GAP_BUSBAR_HEADER + HEADER_HEIGHT + GAP_HEADER_EQUIP + equip_stack_height(max_eq) + GAP_SECTION_BOTTOM;
        current_y += section;
    }
    let canvas_height = current_y + 40;
    let canvas_width = total_columns as i32 * COL_WIDTH + LEFT_MARGIN + 40;

    // ── info bar ────────────────────────────────────────────────────────────
    let mut info = format!(
        r#"<div class="sld-info-bar"><div class="sld-info-item"><span class="sld-info-label">Substation:</span><a class="sld-substation-link" href="/sesb-eam/substations/{id}">{n}</a></div><div class="sld-info-item"><span class="sld-info-label">Code:</span><span class="sld-info-value">{c}</span></div><div class="sld-info-item"><span class="sld-info-label">Bays:</span><span class="sld-info-value">{bc}</span></div><div class="sld-info-item"><span class="sld-info-label">Equipment:</span><span class="sld-info-value">{ec}</span></div>"#,
        n = esc(&sub_name), c = esc(sub_code.as_deref().unwrap_or("")), bc = bay_count, ec = equip_count);
    if let Some(s) = &site { info.push_str(&format!(r#"<div class="sld-info-item"><span class="sld-info-label">Site:</span><span class="sld-info-value">{}</span></div>"#, esc(s))); }
    if let Some(cfg) = &busbar_cfg { info.push_str(&format!(r#"<div class="sld-info-item"><span class="sld-info-label">Busbar:</span><span class="sld-info-value" style="text-transform:capitalize">{}</span></div>"#, esc(&fmt_words(cfg)))); }
    info.push_str("</div>");

    // voltage legend
    let mut legend = String::from(r#"<div class="sld-legend" style="padding:6px 16px;background:#fff;border-bottom:1px solid #dee2e6"><span style="font-size:11px;color:#6c757d;font-weight:600">Voltage:</span>"#);
    for v in &vls {
        legend.push_str(&format!(r#"<span class="sld-legend-item"><span class="sld-legend-dot" style="background:{col}"></span>{n} ({kv}kV)</span>"#,
            col = v.color, n = esc(&v.name), kv = fmt_kv(v.kv)));
    }
    legend.push_str("</div>");

    if columns.is_empty() {
        return Ok(format!("{info}{legend}<div class=\"sld-empty-state\" style=\"margin-top:40px\"><div style=\"font-size:42px\">🔌</div><p>No bays found for this substation</p></div>"));
    }

    // ── canvas ──────────────────────────────────────────────────────────────
    let mut canvas = format!(r#"<div class="sld-canvas" style="min-width:{w}px;min-height:{h}px">"#, w = canvas_width, h = canvas_height);
    // busbars
    for v in &vls {
        let y = *busbar_y.get(&v.id).unwrap_or(&BUSBAR_FIRST_Y);
        canvas.push_str(&format!(
            r#"<div class="sld-busbar" style="top:{y}px;background:{col}"><div class="sld-busbar-label" style="background:{col}">{n} ({kv}kV)</div></div>"#,
            col = v.color, n = esc(&v.name), kv = fmt_kv(v.kv)));
    }
    // columns
    for col in &columns {
        let bay = &bays[col.bay_idx];
        let vl_id = col.vl_id.unwrap_or(first_vl);
        let by = *busbar_y.get(&vl_id).unwrap_or(&BUSBAR_FIRST_Y);
        let vl_color = vls.iter().find(|v| v.id == vl_id).map(|v| v.color.as_str()).unwrap_or("#adb5bd");
        let left = col.col_index as i32 * COL_WIDTH + LEFT_MARGIN;
        let header_top = by + BUSBAR_H + GAP_BUSBAR_HEADER;
        let stem_top = by + BUSBAR_H;
        let stack_top = by + BUSBAR_H + GAP_BUSBAR_HEADER + HEADER_HEIGHT + GAP_HEADER_EQUIP;

        canvas.push_str(&format!(r#"<div class="sld-bay-column" style="left:{left}px">"#));
        // stem
        canvas.push_str(&format!(r#"<div class="sld-bay-stem" style="position:absolute;left:69px;top:{stem_top}px;height:{gh}px;background:{vl_color}"></div>"#, gh = GAP_BUSBAR_HEADER));
        // header
        let feeder = if bay.feeder_name.is_empty() { String::new() } else { format!(r#"<div class="sld-bay-feeder">{}</div>"#, esc(&bay.feeder_name)) };
        let dest = if bay.destination.is_empty() { String::new() } else { format!(r#"<div class="sld-bay-destination" title="{d}">{d}</div>"#, d = esc(&bay.destination)) };
        let state_badge = if bay.state.is_empty() { String::new() } else { format!(r#"<span style="display:inline-block;font-size:8px;padding:1px 5px;border-radius:8px;margin-top:3px;background:#e2e3e5;color:#41464b;text-transform:capitalize">{}</span>"#, esc(&fmt_words(&bay.state))) };
        canvas.push_str(&format!(
            r#"<div class="sld-bay-header" style="position:absolute;width:{w}px;top:{header_top}px" onclick="location.href='/sesb-eam/bays/{bid}'"><div class="sld-bay-name">{name}</div><div class="sld-bay-type">{btype}</div>{feeder}{dest}{state_badge}</div>"#,
            w = COL_CONTENT_W, bid = bay.id, name = esc(&bay.name), btype = esc(&fmt_words(&bay.bay_type))));
        // equipment stack
        canvas.push_str(&format!(r#"<div class="sld-equipment-stack" style="position:absolute;width:{w}px;top:{stack_top}px">"#, w = COL_CONTENT_W));
        if let Some(list) = by_bay.get(&bay.id) {
            for (ei, eq) in list.iter().enumerate() {
                if ei > 0 { canvas.push_str(r#"<div class="sld-equipment-connector"></div>"#); }
                canvas.push_str(&render_equip_item(eq));
            }
        }
        canvas.push_str("</div>"); // stack
        canvas.push_str("</div>"); // column
    }
    canvas.push_str("</div>"); // canvas

    Ok(format!("{info}{legend}{canvas}"))
}

fn render_equip_item(eq: &Equip) -> String {
    let color = status_color(&eq.op_status);
    let svg = equip_svg(&eq.category, color);
    let mut tip = format!(
        r#"<div class="sld-tooltip-name">{n}</div><div class="sld-tooltip-code">{c}</div><div class="sld-tooltip-row"><span class="sld-tooltip-label">Category:</span><span class="sld-tooltip-value">{cat}</span></div><div class="sld-tooltip-row"><span class="sld-tooltip-label">Status:</span><span class="sld-tooltip-value">{st}</span></div><div class="sld-tooltip-row"><span class="sld-tooltip-label">Health:</span><span class="sld-tooltip-value">{h}%</span></div>"#,
        n = esc(&eq.name), c = esc(&eq.code), cat = esc(&fmt_words(&eq.category)), st = esc(&title_words(&eq.op_status)), h = eq.health);
    if let Some(v) = eq.rated_kv { tip.push_str(&format!(r#"<div class="sld-tooltip-row"><span class="sld-tooltip-label">Voltage:</span><span class="sld-tooltip-value">{}kV</span></div>"#, fmt_kv(v))); }
    if let Some(a) = eq.rated_a { tip.push_str(&format!(r#"<div class="sld-tooltip-row"><span class="sld-tooltip-label">Current:</span><span class="sld-tooltip-value">{}A</span></div>"#, fmt_kv(a))); }
    if let Some(p) = eq.rated_kva { tip.push_str(&format!(r#"<div class="sld-tooltip-row"><span class="sld-tooltip-label">Power:</span><span class="sld-tooltip-value">{}kVA</span></div>"#, fmt_kv(p))); }
    format!(
        r#"<div class="sld-equipment-item sld-status-{st}" onclick="location.href='/sesb-eam/equipment/{id}'">{svg}<div class="sld-tooltip">{tip}</div></div>"#,
        st = eq.op_status, id = eq.id)
}

fn fmt_kv(v: f64) -> String {
    if (v.fract()).abs() < 1e-9 { format!("{}", v as i64) } else { format!("{v}") }
}

include!("transmission_sld.rs");
