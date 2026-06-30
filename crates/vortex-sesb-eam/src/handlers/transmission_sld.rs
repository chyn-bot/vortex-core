// Transmission SLD (TMS) — network view (substations + line edges) and per-line
// view (line → towers → spans). Included into sld.rs.

fn voltage_color(kv: f64) -> &'static str {
    if kv >= 400.0 { "#dc3545" } else if kv >= 200.0 { "#fd7e14" } else if kv >= 100.0 { "#0d6efd" } else { "#198754" }
}

async fn transmission_sld(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.transmission_sld");
    let line = q.get("line").filter(|s| !s.is_empty()).and_then(|s| s.parse::<Uuid>().ok());
    let content = match render_transmission_sld(&db, line).await {
        Ok(html) => html,
        Err(e) => { error!(error=%e, "transmission sld"); "<h1>Failed to load Transmission SLD</h1>".into() }
    };
    Html(page_shell(&sidebar, "Transmission SLD", &content)).into_response()
}

async fn render_transmission_sld(db: &PgPool, line: Option<Uuid>) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    // voltage legend (lines' distinct voltages)
    let vl_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT DISTINCT v.name, v.voltage_kv FROM eam_voltage_level v \
         JOIN eam_transmission_line l ON l.voltage_level_id=v.id WHERE l.active ORDER BY v.voltage_kv DESC")
        .fetch_all(db).await.unwrap_or_default();
    let mut legend = String::new();
    if !vl_rows.is_empty() {
        legend.push_str(r#"<div class="tsld-legend"><span style="font-size:11px;color:#6c757d;font-weight:600">Voltage:</span>"#);
        for v in &vl_rows {
            let name: String = v.try_get("name").unwrap_or_default();
            let kv: f64 = v.try_get::<Option<f64>, _>("voltage_kv").ok().flatten().unwrap_or(0.0);
            legend.push_str(&format!(r#"<span class="tsld-legend-item"><span class="tsld-legend-dot" style="background:{c}"></span>{n}</span>"#,
                c = voltage_color(kv), n = esc(&name)));
        }
        legend.push_str("</div>");
    }

    let (header, body) = match line {
        Some(id) => build_line_view(db, id).await?,
        None => ("Transmission Network SLD".to_string(), build_network_view(db).await?),
    };
    let back = if line.is_some() {
        r#"<a class="btn-back" href="/sesb-eam/transmission-sld" style="background:#6c757d;color:#fff;border-radius:6px;padding:4px 10px;font-size:13px;text-decoration:none">← Back to Network</a> "#
    } else { "" };

    Ok(format!(r#"<div class="transmission-sld-view"><style>{css}
.transmission-sld-view {{ min-height: calc(100vh - 64px); }}</style>
<div class="tsld-toolbar">{back}<span style="font-size:18px">🗼</span><h4>{header}</h4><div class="tsld-toolbar-spacer"></div>{legend}</div>
{body}</div>"#, css = TSLD_CSS, header = esc(&header)))
}

// ── network view ────────────────────────────────────────────────────────────

const NODE_W: i32 = 140;
const NODE_H: i32 = 50;
const NET_PADDING: i32 = 80;

async fn build_network_view(db: &PgPool) -> Result<String, vortex_plugin_sdk::sqlx::Error> {
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.name, l.code, l.from_substation_id, l.to_substation_id, \
           (SELECT COUNT(*) FROM eam_transmission_tower t WHERE t.transmission_line_id=l.id)::int AS tower_count, \
           COALESCE(v.voltage_kv,0)::float8 AS kv \
         FROM eam_transmission_line l LEFT JOIN eam_voltage_level v ON v.id=l.voltage_level_id \
         WHERE l.active ORDER BY l.name")
        .fetch_all(db).await?;
    // endpoint substations
    let sub_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT DISTINCT s.id, s.name, s.code FROM eam_substation s WHERE s.id IN ( \
           SELECT from_substation_id FROM eam_transmission_line WHERE active AND from_substation_id IS NOT NULL \
           UNION SELECT to_substation_id FROM eam_transmission_line WHERE active AND to_substation_id IS NOT NULL) \
         ORDER BY s.name")
        .fetch_all(db).await?;

    if sub_rows.is_empty() && lines.is_empty() {
        return Ok(r#"<div class="tsld-canvas-wrapper"><div class="tsld-empty-state"><div style="font-size:42px">🗼</div><p>No transmission lines found. Create transmission lines with from/to substations to see the network diagram.</p></div></div>"#.into());
    }

    // grid positions
    let n = sub_rows.len();
    let cols = ((n as f64 * 1.5).sqrt().ceil() as i32).max(2);
    let space_x = NODE_W + 140;
    let space_y = NODE_H + 140;
    let mut pos: HashMap<Uuid, (i32, i32)> = HashMap::new();
    let mut names: HashMap<Uuid, (String, String)> = HashMap::new();
    for (i, s) in sub_rows.iter().enumerate() {
        let id: Uuid = s.get("id");
        let col = i as i32 % cols;
        let row = i as i32 / cols;
        let cx = NET_PADDING + col * space_x + NODE_W / 2;
        let cy = NET_PADDING + row * space_y + NODE_H / 2;
        pos.insert(id, (cx, cy));
        names.insert(id, (s.try_get("name").unwrap_or_default(), s.try_get("code").ok().flatten().unwrap_or_default()));
    }
    let mut max_x = 600; let mut max_y = 400;
    for (_, &(x, y)) in &pos {
        if x + NODE_W > max_x { max_x = x + NODE_W; }
        if y + NODE_H > max_y { max_y = y + NODE_H; }
    }
    max_x += NET_PADDING; max_y += NET_PADDING;

    // edges
    let mut edge_svg = String::new();
    let mut labels = String::new();
    for l in &lines {
        let from: Option<Uuid> = l.try_get("from_substation_id").ok().flatten();
        let to: Option<Uuid> = l.try_get("to_substation_id").ok().flatten();
        let (Some(f), Some(t)) = (from, to) else { continue };
        let (Some(&(x1, y1)), Some(&(x2, y2))) = (pos.get(&f), pos.get(&t)) else { continue };
        let kv: f64 = l.try_get("kv").unwrap_or(0.0);
        let color = voltage_color(kv);
        edge_svg.push_str(&format!(r#"<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="3" stroke-opacity="0.7"/>"#));
        let mid_x = (x1 + x2) as f64 / 2.0;
        let mid_y = (y1 + y2) as f64 / 2.0;
        let dx = (x2 - x1) as f64; let dy = (y2 - y1) as f64;
        let len = (dx * dx + dy * dy).sqrt().max(1.0);
        let lx = mid_x + (-dy / len) * 18.0 - 40.0;
        let ly = mid_y + (dx / len) * 18.0 - 12.0;
        let id: Uuid = l.get("id");
        let code: Option<String> = l.try_get("code").ok().flatten();
        let towers: i32 = l.try_get("tower_count").unwrap_or(0);
        labels.push_str(&format!(
            r#"<div class="tsld-line-label" style="left:{lx}px;top:{ly}px;border-left:3px solid {color}" onclick="location.href='/sesb-eam/transmission-sld?line={id}'">{code} ({towers} towers)</div>"#,
            lx = lx.round() as i32, ly = ly.round() as i32, code = esc(code.as_deref().unwrap_or(""))));
    }

    // nodes
    let mut nodes = String::new();
    for s in &sub_rows {
        let id: Uuid = s.get("id");
        let &(cx, cy) = pos.get(&id).unwrap();
        let (name, code) = names.get(&id).cloned().unwrap_or_default();
        nodes.push_str(&format!(
            r#"<div class="tsld-substation-node" style="left:{x}px;top:{y}px" onclick="location.href='/sesb-eam/substations/{id}'"><div class="tsld-substation-name">{n}</div><div class="tsld-substation-code">{c}</div></div>"#,
            x = cx - NODE_W / 2, y = cy - NODE_H / 2, n = esc(&name), c = esc(&code)));
    }

    Ok(format!(r#"<div class="tsld-canvas-wrapper"><div class="tsld-network-canvas" style="min-width:{w}px;min-height:{h}px">
<svg style="position:absolute;left:0;top:0;width:{w}px;height:{h}px;pointer-events:none;z-index:1" width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">{edge_svg}</svg>
{nodes}{labels}</div></div>"#, w = max_x, h = max_y))
}

// ── line view ───────────────────────────────────────────────────────────────

const TOWER_SPACING: i32 = 180;
const TOWER_Y: i32 = 100;
const ENDPOINT_Y: i32 = 115;
const EQUIP_START_Y: i32 = 260;
const TLINE_LEFT_MARGIN: i32 = 120;

struct TowerN {
    id: Uuid, name: String, number: Option<i32>, tower_type: String,
    height_m: Option<f64>, status: String, span_next: Option<f64>, x: i32,
    equipment: Vec<(Uuid, String, String, String)>, // id, name, category, op_status
}

async fn build_line_view(db: &PgPool, line_id: Uuid) -> Result<(String, String), vortex_plugin_sdk::sqlx::Error> {
    let line = vortex_plugin_sdk::sqlx::query(
        "SELECT l.name, l.code, l.line_length_km, l.number_of_circuits, \
           (SELECT COUNT(*) FROM eam_transmission_tower t WHERE t.transmission_line_id=l.id)::int AS tower_count, \
           COALESCE(v.voltage_kv,132)::float8 AS kv, v.name AS vname, \
           fs.name AS from_name, fs.id AS from_id, ts.name AS to_name, ts.id AS to_id \
         FROM eam_transmission_line l \
         LEFT JOIN eam_voltage_level v ON v.id=l.voltage_level_id \
         LEFT JOIN eam_substation fs ON fs.id=l.from_substation_id \
         LEFT JOIN eam_substation ts ON ts.id=l.to_substation_id \
         WHERE l.id=$1")
        .bind(line_id).fetch_optional(db).await?;
    let Some(line) = line else { return Ok(("Line not found".into(), r#"<div class="tsld-empty-state"><p>Transmission line not found</p></div>"#.into())); };
    let lname: String = line.try_get("name").unwrap_or_default();
    let lcode: Option<String> = line.try_get("code").ok().flatten();
    let length: Option<f64> = line.try_get("line_length_km").ok().flatten();
    let circuits: Option<i32> = line.try_get("number_of_circuits").ok().flatten();
    let tower_count: Option<i32> = line.try_get("tower_count").ok().flatten();
    let kv: f64 = line.try_get("kv").unwrap_or(132.0);
    let from_name: Option<String> = line.try_get("from_name").ok().flatten();
    let from_id: Option<Uuid> = line.try_get("from_id").ok().flatten();
    let to_name: Option<String> = line.try_get("to_name").ok().flatten();
    let to_id: Option<Uuid> = line.try_get("to_id").ok().flatten();
    let color = voltage_color(kv);

    // towers
    let tower_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, tower_number, tower_type, height_m, operational_status, span_to_next_m \
         FROM eam_transmission_tower WHERE transmission_line_id=$1 AND active ORDER BY tower_number ASC NULLS LAST")
        .bind(line_id).fetch_all(db).await?;
    let tower_ids: Vec<Uuid> = tower_rows.iter().map(|t| t.get::<Uuid, _>("id")).collect();

    // equipment per tower
    let eq_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, equipment_category, operational_status, tower_id FROM eam_equipment WHERE tower_id = ANY($1) AND active")
        .bind(&tower_ids).fetch_all(db).await?;
    let mut by_tower: HashMap<Uuid, Vec<(Uuid, String, String, String)>> = HashMap::new();
    for e in &eq_rows {
        let tid: Uuid = e.get("tower_id");
        by_tower.entry(tid).or_default().push((
            e.get("id"), e.try_get("name").unwrap_or_default(),
            e.try_get("equipment_category").ok().flatten().unwrap_or_else(|| "other".into()),
            e.try_get("operational_status").ok().flatten().unwrap_or_else(|| "operational".into()),
        ));
    }

    let total = tower_rows.len();
    let towers: Vec<TowerN> = tower_rows.iter().enumerate().map(|(i, t)| {
        let id: Uuid = t.get("id");
        TowerN {
            id, name: t.try_get("name").unwrap_or_default(),
            number: t.try_get("tower_number").ok().flatten(),
            tower_type: t.try_get("tower_type").ok().flatten().unwrap_or_else(|| "lattice_steel".into()),
            height_m: t.try_get("height_m").ok().flatten(),
            status: t.try_get("operational_status").ok().flatten().unwrap_or_else(|| "operational".into()),
            span_next: t.try_get("span_to_next_m").ok().flatten(),
            x: TLINE_LEFT_MARGIN + (i as i32 + 1) * TOWER_SPACING,
            equipment: by_tower.remove(&id).unwrap_or_default(),
        }
    }).collect();

    let canvas_w = TLINE_LEFT_MARGIN * 2 + (total as i32 + 1) * TOWER_SPACING + 160;
    let max_equip = towers.iter().map(|t| t.equipment.len()).max().unwrap_or(0);
    let canvas_h = EQUIP_START_Y + max_equip as i32 * 30 + 80;

    // endpoints
    let endpoint_from_x = TLINE_LEFT_MARGIN - 60;
    let endpoint_to_x = TLINE_LEFT_MARGIN + (total as i32 + 1) * TOWER_SPACING;

    // conductor attachment X points
    let mut cpoints: Vec<i32> = Vec::new();
    cpoints.push(endpoint_from_x + 70);
    for t in &towers { cpoints.push(t.x); }
    cpoints.push(endpoint_to_x + 10);

    // 3-phase catenary paths + earth wire
    let base_y = TOWER_Y + 28;
    let mut conductor_paths = String::new();
    for off in [-5, 0, 5] {
        let y0 = base_y + off;
        let mut d = format!("M{},{}", cpoints[0], y0);
        for w in cpoints.windows(2) {
            let (x1, x2) = (w[0], w[1]);
            let mid = (x1 + x2) / 2;
            let sag = (((x2 - x1) as f64) * 0.05).min(12.0).round() as i32;
            d.push_str(&format!(" Q{},{} {},{}", mid, y0 + sag, x2, y0));
        }
        conductor_paths.push_str(&format!(r#"<path d="{d}" fill="none" stroke="{color}" stroke-width="2.5" stroke-opacity="0.75"/>"#));
    }
    let earth_y = TOWER_Y + 4;
    let mut earth = format!("M{},{}", cpoints[0], earth_y);
    for w in cpoints.windows(2) {
        let (x1, x2) = (w[0], w[1]);
        let mid = (x1 + x2) / 2;
        let sag = (((x2 - x1) as f64) * 0.025).min(6.0).round() as i32;
        earth.push_str(&format!(" Q{},{} {},{}", mid, earth_y + sag, x2, earth_y));
    }
    // span labels
    let mut spans = String::new();
    for w in towers.windows(2) {
        if let Some(s) = w[0].span_next {
            let x = (w[0].x + w[1].x) / 2;
            spans.push_str(&format!(r##"<text x="{x}" y="{y}" text-anchor="middle" font-size="9" fill="#999">{s}m</text>"##, y = base_y + 22, s = fmt_kv(s)));
        }
    }

    // tower nodes
    let mut tower_html = String::new();
    for t in &towers {
        let icon = tower_svg(&t.tower_type, status_color(&t.status));
        let mut eq_html = String::new();
        for (eid, ename, cat, op) in &t.equipment {
            eq_html.push_str(&format!(
                r#"<div class="tsld-tower-equip-item" title="{title}" onclick="event.stopPropagation();location.href='/sesb-eam/equipment/{eid}'">{svg}</div>"#,
                title = esc(ename), svg = equip_svg_small(cat, status_color(op))));
        }
        let height = t.height_m.map(|h| format!("{}m", fmt_kv(h))).unwrap_or_default();
        tower_html.push_str(&format!(
            r#"<div class="tsld-tower-node" style="left:{lx}px;top:{ty}px" onclick="location.href='/sesb-eam/towers/{id}'"><div class="tsld-tower-icon">{icon}</div><div class="tsld-tower-label">{name}</div><div class="tsld-tower-number">#{num}</div><div class="tsld-tower-info"><span>{ttype}</span><span>{height}</span></div><div class="tsld-tower-equipment">{eq_html}</div></div>"#,
            lx = t.x - 36, ty = TOWER_Y, id = t.id, name = esc(&t.name),
            num = t.number.map(|n| n.to_string()).unwrap_or_default(),
            ttype = esc(&title_words(&t.tower_type)), height = esc(&height)));
    }

    // info bar
    let mut info = format!(r#"<div class="tsld-line-header"><div class="tsld-line-info-item"><span class="tsld-line-info-label">Code:</span><span class="tsld-line-info-value">{c}</span></div><div class="tsld-line-info-item"><span class="tsld-line-info-label">Towers:</span><span class="tsld-line-info-value">{tc}</span></div>"#,
        c = esc(lcode.as_deref().unwrap_or("")), tc = tower_count.unwrap_or(total as i32));
    if let Some(l) = length { info.push_str(&format!(r#"<div class="tsld-line-info-item"><span class="tsld-line-info-label">Length:</span><span class="tsld-line-info-value">{} km</span></div>"#, fmt_kv(l))); }
    if let Some(ci) = circuits { info.push_str(&format!(r#"<div class="tsld-line-info-item"><span class="tsld-line-info-label">Circuits:</span><span class="tsld-line-info-value">{ci}</span></div>"#)); }
    if let Some(f) = &from_name { info.push_str(&format!(r#"<div class="tsld-line-info-item"><span class="tsld-line-info-label">From:</span><span class="tsld-line-info-value">{}</span></div>"#, esc(f))); }
    if let Some(t) = &to_name { info.push_str(&format!(r#"<div class="tsld-line-info-item"><span class="tsld-line-info-label">To:</span><span class="tsld-line-info-value">{}</span></div>"#, esc(t))); }
    info.push_str("</div>");

    // endpoint nodes
    let from_click = from_id.map(|i| format!("location.href='/sesb-eam/substations/{i}'")).unwrap_or_default();
    let to_click = to_id.map(|i| format!("location.href='/sesb-eam/substations/{i}'")).unwrap_or_default();
    let endpoints = format!(
        r#"<div class="tsld-endpoint-node" style="left:{fx}px;top:{ey}px" onclick="{fc}"><div class="tsld-endpoint-sub">From</div><div class="tsld-endpoint-label">{fn_}</div></div><div class="tsld-endpoint-node" style="left:{tx}px;top:{ey}px" onclick="{tc}"><div class="tsld-endpoint-sub">To</div><div class="tsld-endpoint-label">{tn}</div></div>"#,
        fx = endpoint_from_x, tx = endpoint_to_x, ey = ENDPOINT_Y, fc = from_click, tc = to_click,
        fn_ = esc(from_name.as_deref().unwrap_or("Start")), tn = esc(to_name.as_deref().unwrap_or("End")));

    let empty = if towers.is_empty() {
        r#"<div class="tsld-empty-state" style="margin-top:80px"><div style="font-size:42px">🗼</div><p>No towers found for this transmission line</p></div>"#
    } else { "" };

    let body = format!(r##"{info}<div class="tsld-canvas-wrapper"><div class="tsld-line-canvas" style="min-width:{w}px;min-height:{h}px">
<svg class="tsld-conductor-svg" style="position:absolute;left:0;top:0;width:{w}px;height:{h}px;pointer-events:none;z-index:2" width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">
<path d="{earth}" fill="none" stroke="#888" stroke-width="1" stroke-dasharray="4,3"/>{conductor_paths}{spans}</svg>
{endpoints}{tower_html}{empty}</div></div>"##, w = canvas_w, h = canvas_h);

    let header = format!("Line SLD — {}", lname);
    Ok((header, body))
}
