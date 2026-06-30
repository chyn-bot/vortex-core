//! Printable reports (§10.3). Each renders a self-contained, print-optimised
//! HTML document; with `?format=pdf` and the platform's `pdf-chromium` feature
//! compiled in, the same HTML is rendered to a PDF download. Without the
//! feature it falls back to the printable HTML (browser "Print → Save as PDF").

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::http::{header, StatusCode};
use vortex_plugin_sdk::framework::pdf::{self, PdfOptions};
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;
use super::analytics;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/reports", get(hub))
        .route("/sesb-eam/reports/work-order/{id}", get(work_order))
        .route("/sesb-eam/reports/equipment/{id}", get(equipment_datasheet))
        .route("/sesb-eam/reports/asset-register/{id}", get(asset_register))
        .route("/sesb-eam/reports/reliability/{id}", get(reliability_report))
}

const REPORT_CSS: &str = r#"
*{box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;margin:0;padding:24px;font-size:12px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:14px;margin:18px 0 6px;border-bottom:2px solid #0a5;padding-bottom:3px;color:#063}
.sub{color:#666;font-size:11px;margin-bottom:14px}
table{border-collapse:collapse;width:100%;margin:6px 0}
th,td{border:1px solid #ccc;padding:5px 7px;text-align:left;vertical-align:top}
th{background:#f0f5f2;font-weight:600}
.kv{display:grid;grid-template-columns:1fr 1fr;gap:0}
.kv div{border:1px solid #e3e3e3;padding:5px 8px}.kv b{color:#555;font-weight:600;display:inline-block;min-width:140px}
.right{text-align:right}.muted{color:#888}.badge{display:inline-block;padding:1px 7px;border-radius:10px;background:#eee;font-size:10px}
.brand{color:#0a5;font-weight:700}.totrow td{font-weight:700;background:#f7f7f7}
.head{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #0a5;padding-bottom:8px;margin-bottom:12px}
@media print{body{padding:0}.noprint{display:none}}
.noprint{margin-bottom:12px}
"#;

fn doc(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title><style>{css}</style></head>
<body><div class="noprint" style="font-family:sans-serif;font-size:12px;background:#f0f5f2;padding:8px 12px;border:1px solid #cde">
This is a printable report. Use your browser's <b>Print → Save as PDF</b>, or append <code>?format=pdf</code> to the URL for a server-rendered PDF.
</div>{body}</body></html>"#,
        title = esc(title), css = REPORT_CSS, body = body)
}

/// Render as PDF (if the engine is compiled in & requested) or printable HTML.
async fn deliver(html: String, filename: &str, q: &HashMap<String, String>, landscape: bool) -> Response {
    if q.get("format").map(|s| s == "pdf").unwrap_or(false) && pdf::available() {
        let opts = PdfOptions { landscape, ..Default::default() };
        match pdf::html_to_pdf(&html, &opts).await {
            Ok(bytes) => {
                return (
                    [(header::CONTENT_TYPE, "application/pdf".to_string()),
                     (header::CONTENT_DISPOSITION, format!("inline; filename=\"{}.pdf\"", filename))],
                    bytes,
                ).into_response();
            }
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("PDF render failed: {e}")).into_response(),
        }
    }
    Html(html).into_response()
}

// ═══════════════════════════════ Reports hub ════════════════════════════════

async fn hub(
    State(state): State<Arc<AppState>>, Db(_db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.reports");
    let pdf_note = if pdf::available() { "Server-side PDF is enabled (append ?format=pdf)." } else { "Server-side PDF engine is not compiled in — use browser Print → Save as PDF." };
    let card = |title: &str, desc: &str, hint: &str| format!(
        r#"<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title text-base">{t}</h2><p class="text-sm opacity-70">{d}</p><p class="text-xs opacity-50">{h}</p></div></div>"#,
        t = esc(title), d = esc(desc), h = esc(hint));
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Reports</h1><p class="opacity-60 text-sm mb-4">{note}</p>
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
{wo}{ds}{ar}{rel}</div>"#,
        note = esc(pdf_note),
        wo = card("Work Order", "Per-order timeline, work record, checklist, materials, cost & signatures.", "Open from any work order → /sesb-eam/reports/work-order/{id}"),
        ds = card("Equipment Datasheet", "Identification, location, condition & risk for one asset.", "/sesb-eam/reports/equipment/{id}"),
        ar = card("Asset Register & Hierarchy", "Substation attributes + per-bay equipment tree.", "/sesb-eam/reports/asset-register/{substation_id}"),
        rel = card("Reliability (Region)", "YTD SAIDI/SAIFI/CAIDI, IEEE-1366.", "/sesb-eam/reports/reliability/{region_id}"));
    Html(page_shell(&sidebar, "Reports", &content)).into_response()
}

// ═══════════════════════════════ Work Order ═════════════════════════════════

async fn work_order(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT m.name, m.description, m.state, m.maintenance_type, m.priority, e.name AS equip, e.code AS equip_code, m.request_date::text AS rd, m.scheduled_date::text AS sd, m.start_date::text AS st, m.end_date::text AS et, m.actual_duration_hours::text AS dur, m.work_description, m.findings, m.actions_taken, m.recommendations, m.labor_cost::text AS labor, m.materials_cost::text AS mat, m.total_cost::text AS tot, m.signed_by_name, m.verification_rating FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id WHERE m.id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let g = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let parts = vortex_plugin_sdk::sqlx::query("SELECT name, part_number, quantity::text AS qty, unit_cost::text AS uc, cost::text AS cost FROM eam_maintenance_part_line WHERE maintenance_id=$1 ORDER BY sequence").bind(id).fetch_all(&db).await.unwrap_or_default();
    let cl = vortex_plugin_sdk::sqlx::query("SELECT name, input_type, value_pass_fail, value_yes_no, value_measurement::text AS vm, value_text, value_selection, value_rating::text AS vr, note FROM eam_checklist_line WHERE maintenance_id=$1 ORDER BY sequence").bind(id).fetch_all(&db).await.unwrap_or_default();

    let part_rows: String = parts.iter().map(|p| format!(
        "<tr><td>{n}</td><td>{pn}</td><td class=\"right\">{q}</td><td class=\"right\">{uc}</td><td class=\"right\">{c}</td></tr>",
        n = esc(&p.get::<String,_>("name")), pn = esc(&p.try_get::<Option<String>,_>("part_number").ok().flatten().unwrap_or_default()),
        q = esc(&p.try_get::<Option<String>,_>("qty").ok().flatten().unwrap_or_default()), uc = esc(&p.try_get::<Option<String>,_>("uc").ok().flatten().unwrap_or_default()), c = esc(&p.try_get::<Option<String>,_>("cost").ok().flatten().unwrap_or_default()))).collect();
    let part_tbl = if parts.is_empty() { "<p class=\"muted\">No materials recorded.</p>".to_string() } else {
        format!("<table><thead><tr><th>Part</th><th>Part No</th><th class=\"right\">Qty</th><th class=\"right\">Unit</th><th class=\"right\">Cost</th></tr></thead><tbody>{}</tbody></table>", part_rows) };

    let cl_rows: String = cl.iter().map(|l| {
        let it: String = l.get("input_type");
        let v = match it.as_str() {
            "pass_fail" => l.try_get::<Option<String>,_>("value_pass_fail").ok().flatten(),
            "yes_no" => l.try_get::<Option<String>,_>("value_yes_no").ok().flatten(),
            "measurement" => l.try_get::<Option<String>,_>("vm").ok().flatten(),
            "rating" => l.try_get::<Option<String>,_>("vr").ok().flatten(),
            "selection" => l.try_get::<Option<String>,_>("value_selection").ok().flatten(),
            _ => l.try_get::<Option<String>,_>("value_text").ok().flatten(),
        }.unwrap_or_default();
        format!("<tr><td>{n}</td><td>{v}</td><td>{note}</td></tr>", n = esc(&l.get::<String,_>("name")), v = esc(&v), note = esc(&l.try_get::<Option<String>,_>("note").ok().flatten().unwrap_or_default()))
    }).collect();
    let cl_tbl = if cl.is_empty() { "<p class=\"muted\">No checklist.</p>".to_string() } else {
        format!("<table><thead><tr><th>Item</th><th>Result</th><th>Note</th></tr></thead><tbody>{}</tbody></table>", cl_rows) };

    let body = format!(
        r#"<div class="head"><div><h1>Work Order {name}</h1><div class="sub">{equip_code} · {equip} · <span class="badge">{state}</span></div></div><div class="brand">SESB EAM</div></div>
<h2>Order</h2><div class="kv">
<div><b>Type</b>{ty}</div><div><b>Priority</b>{pri}</div>
<div><b>Requested</b>{rd}</div><div><b>Scheduled</b>{sd}</div>
<div><b>Started</b>{st}</div><div><b>Ended</b>{et}</div>
<div><b>Actual Hours</b>{dur}</div><div><b>Verification</b>{vr}</div></div>
<h2>Work Record</h2><div class="kv"><div><b>Description</b>{wd}</div><div><b>Findings</b>{fnd}</div><div><b>Actions Taken</b>{act}</div><div><b>Recommendations</b>{rec}</div></div>
<h2>Checklist Results</h2>{cl}
<h2>Materials</h2>{parts}
<h2>Cost Summary</h2><table><tbody><tr><td>Labour</td><td class="right">RM {labor}</td></tr><tr><td>Materials</td><td class="right">RM {mat}</td></tr><tr class="totrow"><td>Total</td><td class="right">RM {tot}</td></tr></tbody></table>
<h2>Signatures</h2><div class="kv"><div><b>Signed By</b>{sign}</div><div><b>Date</b>{et}</div></div>"#,
        name = esc(&g("name")), equip_code = esc(&g("equip_code")), equip = esc(&g("equip")), state = esc(&g("state")),
        ty = esc(&g("maintenance_type")), pri = esc(&g("priority")), rd = esc(&g("rd")), sd = esc(&g("sd")),
        st = esc(&g("st")), et = esc(&g("et")), dur = esc(&g("dur")), vr = esc(&g("verification_rating")),
        wd = esc(&g("work_description")), fnd = esc(&g("findings")), act = esc(&g("actions_taken")), rec = esc(&g("recommendations")),
        cl = cl_tbl, parts = part_tbl, labor = esc(&g("labor")), mat = esc(&g("mat")), tot = esc(&g("tot")), sign = esc(&g("signed_by_name")));
    deliver(doc(&format!("Work Order {}", g("name")), &body), &format!("work-order-{}", g("name").replace('/', "-")), &q, false).await
}

// ═══════════════════════════════ Equipment datasheet ════════════════════════

async fn equipment_datasheet(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT e.name, e.code, e.asset_id, e.equipment_category, e.condition_status, e.operational_status, e.risk_level, e.commissioning_date::text AS cd, e.useful_life_years, e.failure_record, s.name AS sub, mf.name AS maker FROM eam_equipment e LEFT JOIN eam_substation s ON s.id=e.substation_id LEFT JOIN eam_manufacturer mf ON mf.id=e.manufacturer_id WHERE e.id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let g = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let condition = g("condition_status"); let op = g("operational_status"); let risk = g("risk_level");
    let health = analytics::health_index(&condition, &op);
    let ul_years: Option<i32> = row.try_get("useful_life_years").ok();
    let failure_record: i32 = row.try_get("failure_record").unwrap_or(0);
    // age + useful-life pct
    let cd: Option<vortex_plugin_sdk::chrono::NaiveDate> = g("cd").parse().ok();
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    let age_years = cd.map(|d| ((today - d).num_days() as f64 / 365.25).floor() as i64).unwrap_or(0);
    let ul_pct = match ul_years { Some(y) if y > 0 => age_years as f64 / y as f64 * 100.0, _ => 0.0 };
    let rel = analytics::equip_reliability(&db, id).await;
    let plan = analytics::action_plan(&condition, &risk, ul_pct, failure_record);
    let body = format!(
        r#"<div class="head"><div><h1>{name}</h1><div class="sub">{code} · {asset_id}</div></div><div class="brand">SESB EAM</div></div>
<h2>Identification</h2><div class="kv">
<div><b>Category</b>{cat}</div><div><b>Manufacturer</b>{maker}</div>
<div><b>Substation</b>{sub}</div><div><b>Commissioned</b>{cd}</div></div>
<h2>Condition & Risk</h2><div class="kv">
<div><b>Condition</b>{cond}</div><div><b>Operational</b>{op}</div>
<div><b>Risk</b>{risk}</div><div><b>Health Index</b>{health:.0} / 100</div>
<div><b>Age</b>{age} yr</div><div><b>Useful-life Used</b>{ul:.0}%</div>
<div><b>Failures</b>{fr}</div><div><b>Action Plan</b>{plan}</div></div>
<h2>Reliability (§4.2)</h2><div class="kv">
<div><b>Failure Count</b>{fc}</div><div><b>Last Failure</b>{lf}</div>
<div><b>MTBF (days)</b>{mtbf}</div><div><b>MTTR (hours)</b>{mttr}</div></div>"#,
        name = esc(&g("name")), code = esc(&g("code")), asset_id = esc(&g("asset_id")), cat = esc(&g("equipment_category")),
        maker = esc(&g("maker")), sub = esc(&g("sub")), cd = esc(&g("cd")),
        cond = esc(&condition), op = esc(&op), risk = esc(&risk), health = health, age = age_years, ul = ul_pct, fr = failure_record, plan = esc(plan),
        fc = rel.failure_count, lf = esc(rel.last_failure.as_deref().unwrap_or("—")), mtbf = rel.mtbf_days, mttr = rel.mttr_hours);
    deliver(doc(&format!("Datasheet {}", g("name")), &body), &format!("datasheet-{}", g("code").replace('/', "-")), &q, false).await
}

// ═══════════════════════════════ Asset register ═════════════════════════════

async fn asset_register(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sub = match vortex_plugin_sdk::sqlx::query(
        "SELECT s.name, s.code, s.asset_id, s.substation_type, s.customers_served, si.name AS site, r.name AS region FROM eam_substation s LEFT JOIN eam_site si ON si.id=s.site_id LEFT JOIN eam_region r ON r.id=si.region_id WHERE s.id=$1")
        .bind(id).fetch_optional(&db).await { Ok(Some(r)) => r, _ => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let g = |k: &str| -> String { sub.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let cust: i32 = sub.try_get("customers_served").unwrap_or(0);
    let bays = vortex_plugin_sdk::sqlx::query("SELECT id, name, code FROM eam_bay WHERE substation_id=$1 ORDER BY code").bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut bay_sections = String::new();
    for b in &bays {
        let bid: Uuid = b.get("id");
        let bname: String = b.try_get::<Option<String>,_>("name").ok().flatten().unwrap_or_default();
        let bcode: String = b.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default();
        let eq = vortex_plugin_sdk::sqlx::query("SELECT code, name, equipment_category, condition_status, operational_status FROM eam_equipment WHERE bay_id=$1 ORDER BY code").bind(bid).fetch_all(&db).await.unwrap_or_default();
        let rows: String = eq.iter().map(|e| format!("<tr><td>{c}</td><td>{n}</td><td>{cat}</td><td>{cond}</td><td>{op}</td></tr>",
            c = esc(&e.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default()), n = esc(&e.get::<String,_>("name")),
            cat = esc(&e.try_get::<Option<String>,_>("equipment_category").ok().flatten().unwrap_or_default()),
            cond = esc(&e.get::<String,_>("condition_status")), op = esc(&e.get::<String,_>("operational_status")))).collect();
        let tbl = if eq.is_empty() { "<p class=\"muted\">No equipment.</p>".to_string() } else {
            format!("<table><thead><tr><th>Code</th><th>Name</th><th>Category</th><th>Condition</th><th>Status</th></tr></thead><tbody>{}</tbody></table>", rows) };
        bay_sections.push_str(&format!("<h2>Bay {code} · {name}</h2>{tbl}", code = esc(&bcode), name = esc(&bname), tbl = tbl));
    }
    if bays.is_empty() { bay_sections = "<p class=\"muted\">No bays defined.</p>".into(); }
    let body = format!(
        r#"<div class="head"><div><h1>Asset Register — {name}</h1><div class="sub">{code} · {asset_id}</div></div><div class="brand">SESB EAM</div></div>
<h2>Substation</h2><div class="kv">
<div><b>Type</b>{ty}</div><div><b>Region</b>{region}</div>
<div><b>Site</b>{site}</div><div><b>Customers Served</b>{cust}</div></div>
{bays}"#,
        name = esc(&g("name")), code = esc(&g("code")), asset_id = esc(&g("asset_id")), ty = esc(&g("substation_type")),
        region = esc(&g("region")), site = esc(&g("site")), cust = cust, bays = bay_sections);
    deliver(doc(&format!("Asset Register {}", g("name")), &body), &format!("asset-register-{}", g("code").replace('/', "-")), &q, false).await
}

// ═══════════════════════════════ Reliability ════════════════════════════════

async fn reliability_report(
    State(_s): State<Arc<AppState>>, Db(db): Db,
    Extension(_u): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let region_name: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT name FROM eam_region WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let region_name = match region_name { Some(n) => n, None => return (StatusCode::NOT_FOUND, "Region not found").into_response() };
    let now = vortex_plugin_sdk::chrono::Utc::now();
    let year = vortex_plugin_sdk::chrono::Datelike::year(&now);
    let ytd_from = format!("{year}-01-01T00:00:00Z");
    let ytd = analytics::reliability(&db, Some(id), &ytd_from, &now.to_rfc3339(), true).await;

    // monthly breakdown
    let mut monthly = String::new();
    for m in 1..=12 {
        let mstart = format!("{year}-{m:02}-01T00:00:00Z", year = year, m = m);
        let mend = if m == 12 { format!("{}-12-31T23:59:59Z", year) } else { format!("{year}-{nm:02}-01T00:00:00Z", year = year, nm = m + 1) };
        let r = analytics::reliability(&db, Some(id), &mstart, &mend, true).await;
        if r.outage_count == 0 && r.saidi == 0.0 { continue; }
        monthly.push_str(&format!(
            "<tr><td>{year}-{m:02}</td><td class=\"right\">{saidi:.2}</td><td class=\"right\">{saifi:.3}</td><td class=\"right\">{caidi:.2}</td><td class=\"right\">{n}</td></tr>",
            year = year, m = m, saidi = r.saidi, saifi = r.saifi, caidi = r.caidi, n = r.outage_count));
    }
    if monthly.is_empty() { monthly = "<tr><td colspan=\"5\" class=\"muted\">No outages this year.</td></tr>".into(); }

    let body = format!(
        r#"<div class="head"><div><h1>Reliability — {region}</h1><div class="sub">YTD {year} · IEEE-1366 · Major Event Days excluded</div></div><div class="brand">SESB EAM</div></div>
<h2>Year to Date</h2><div class="kv">
<div><b>SAIDI</b>{saidi:.2} min/customer</div><div><b>SAIFI</b>{saifi:.3} int/customer</div>
<div><b>CAIDI</b>{caidi:.2} min/int</div><div><b>Customers Served</b>{tc}</div>
<div><b>SAIDI (unplanned)</b>{saidiu:.2}</div><div><b>SAIFI (unplanned)</b>{saifiu:.3}</div></div>
<h2>Monthly</h2><table><thead><tr><th>Month</th><th class="right">SAIDI</th><th class="right">SAIFI</th><th class="right">CAIDI</th><th class="right">Outages</th></tr></thead><tbody>{monthly}</tbody></table>
<p class="sub">IEEE 1366: SAIDI = Σ(customers×minutes)/total customers; SAIFI = Σcustomers/total; CAIDI = SAIDI/SAIFI.</p>"#,
        region = esc(&region_name), year = year, saidi = ytd.saidi, saifi = ytd.saifi, caidi = ytd.caidi, tc = ytd.total_customers,
        saidiu = ytd.saidi_unplanned, saifiu = ytd.saifi_unplanned, monthly = monthly);
    deliver(doc(&format!("Reliability {}", region_name), &body), &format!("reliability-{}", region_name.replace(' ', "-")), &q, true).await
}
