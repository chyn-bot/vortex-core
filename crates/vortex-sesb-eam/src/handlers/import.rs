//! Asset Import wizard (spec §12) — bulk load from a generated CSV template.
//!
//! Contract highlights reproduced here:
//! - **Templates are generated from the column spec**, not hand-written: the
//!   header row is the field labels and enum columns advertise their allowed
//!   values, so the template can't drift from the loader.
//! - **Rows load independently**: each row runs in its own transaction, so one
//!   bad row (duplicate composed asset-ID, unknown reference, invalid enum)
//!   fails *that row* with a logged reason and leaves the rest committed.
//! - A **load report** lists every created record and every rejected row.
//! - Loaded in dependency order (Substations → Bays → Equipment) so later
//!   sheets reference what earlier ones created; the Equipment sheet takes a
//!   bay **or** a feeder route, exactly one.
//!
//! Format is CSV (one entity per file) rather than a multi-sheet workbook —
//! dependency-safe and round-trippable; a multi-sheet .xlsx export is a
//! follow-up (`calamine` is available for reading).

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::{Multipart, Path};
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::{PgPool, Postgres, Row, Transaction};
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

type Tx<'a> = Transaction<'a, Postgres>;

/// A column in an import template. `enums` advertises allowed values in the
/// template and (when set) is validated on load.
struct Col {
    label: &'static str,
    key: &'static str,
    required: bool,
    enums: Option<&'static [(&'static str, &'static str)]>,
}
const fn col(label: &'static str, key: &'static str) -> Col { Col { label, key, required: false, enums: None } }
const fn req(label: &'static str, key: &'static str) -> Col { Col { label, key, required: true, enums: None } }
const fn en(label: &'static str, key: &'static str, e: &'static [(&'static str, &'static str)]) -> Col {
    Col { label, key, required: false, enums: Some(e) }
}

const SUB_TYPES: &[(&str, &str)] = &[("pmu","PMU"),("ppu","PPU"),("ssu_33kv","SSU 33kV"),("ssu_11kv","SSU 11kV"),("pp","PP"),("pe","PE"),("ss","SS")];
const COND: &[(&str, &str)] = &[("excellent","Excellent"),("good","Good"),("fair","Fair"),("poor","Poor"),("critical","Critical")];
const OPST: &[(&str, &str)] = &[("operational","Operational"),("standby","Standby"),("out_of_service","Out of Service"),("under_repair","Under Repair"),("decommissioned","Decommissioned")];

fn spec(entity: &str) -> Option<Vec<Col>> {
    Some(match entity {
        "substation" => vec![
            req("Code", "code"), req("Name", "name"), req("Site Code", "site_code"),
            col("Location Acronym", "acronym"),
            col("Primary Voltage (kV)", "primary_voltage_kv"),
            en("Substation Type", "substation_type", SUB_TYPES),
        ],
        "bay" => vec![
            req("Code", "code"), req("Name", "name"), req("Substation Code", "substation_code"),
            req("Bay Number", "bay_number"), col("Bay Type", "bay_type"),
        ],
        "equipment" => vec![
            req("Code", "code"), req("Name", "name"),
            col("Bay Code (bay OR feeder)", "bay_code"),
            col("Feeder Code (bay OR feeder)", "feeder_code"),
            req("Asset Type Acronym", "asset_type_acronym"),
            col("Equipment Category", "equipment_category"),
            col("MNEC Sequence", "mnec_sequence"),
            col("Serial Number", "serial_number"),
            en("Condition", "condition_status", COND),
            en("Operational Status", "operational_status", OPST),
        ],
        _ => return None,
    })
}

const ENTITIES: &[(&str, &str)] = &[
    ("substation", "Substations"), ("bay", "Bays"), ("equipment", "Equipment"),
];

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/import", get(landing))
        .route("/sesb-eam/import/template/{entity}", get(template))
        .route("/sesb-eam/import/{entity}", post(upload))
}

async fn landing(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.import");
    let cards: String = ENTITIES.iter().map(|(key, label)| format!(r#"
<div class="card bg-base-100 shadow"><div class="card-body">
  <h3 class="card-title text-base">{label}</h3>
  <p class="text-sm opacity-70">Download the template, fill it in, then upload. Rows load independently — a bad row is reported and skipped, the rest commit.</p>
  <div class="flex gap-2 items-center mt-2">
    <a class="btn btn-sm" href="/sesb-eam/import/template/{key}">Download template</a>
    <form method="post" action="/sesb-eam/import/{key}" enctype="multipart/form-data" class="flex gap-2 items-center" data-no-guard>
      <input type="file" name="file" accept=".csv" class="file-input file-input-bordered file-input-sm" required>
      <button class="btn btn-sm btn-primary">Import</button>
    </form>
  </div>
</div></div>"#, label = label, key = key)).collect();
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Asset Import</h1>
<p class="opacity-70 mb-4">Bulk-load assets in dependency order: <b>Substations → Bays → Equipment</b>. Equipment attaches to a bay <i>or</i> a feeder route — exactly one.</p>
<div class="grid gap-4 lg:grid-cols-3">{cards}</div>"#, cards = cards);
    Html(page_shell(&sidebar, "Asset Import", &content)).into_response()
}

/// Generated CSV template: header row of labels + a hint row listing allowed
/// enum values for enum columns (blank otherwise).
async fn template(Path(entity): Path<String>) -> Response {
    let cols = match spec(&entity) { Some(c) => c, None => return (StatusCode::NOT_FOUND, "Unknown entity").into_response() };
    let headers: Vec<String> = cols.iter().map(|c| {
        let star = if c.required { " *" } else { "" };
        format!("{}{}", c.label, star)
    }).collect();
    let hints: Vec<String> = cols.iter().map(|c| match c.enums {
        Some(e) => format!("one of: {}", e.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(" | ")),
        None => String::new(),
    }).collect();
    let mut wtr = csv::Writer::from_writer(vec![]);
    let _ = wtr.write_record(&headers);
    let _ = wtr.write_record(&hints);
    let body = wtr.into_inner().unwrap_or_default();
    (
        [
            (vortex_plugin_sdk::axum::http::header::CONTENT_TYPE, "text/csv".to_string()),
            (vortex_plugin_sdk::axum::http::header::CONTENT_DISPOSITION,
             format!("attachment; filename=\"eam_{entity}_template.csv\"")),
        ],
        body,
    ).into_response()
}

struct LoadReport { created: Vec<String>, rejected: Vec<(usize, String)> }

async fn upload(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(entity): Path<String>, mut multipart: Multipart,
) -> Response {
    if spec(&entity).is_none() { return (StatusCode::NOT_FOUND, "Unknown entity").into_response(); }
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.import");
    let mut data: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            if let Ok(bytes) = field.bytes().await { data = Some(bytes.to_vec()); }
        }
    }
    let bytes = match data { Some(b) if !b.is_empty() => b, _ => return bad("No file uploaded") };
    let company_id = default_company(&db).await;
    let report = run_import(&db, company_id, &entity, &bytes).await;

    // Audit the batch outcome.
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_import", entity.clone())
     .with_resource_name(&format!("{entity} import"))
     .with_details(vortex_plugin_sdk::serde_json::json!({
         "created": report.created.len(), "rejected": report.rejected.len()
     }));
    let _ = state.audit.log(entry).await;

    let created_rows: String = report.created.iter().map(|c| format!("<li class=\"text-success\">✓ {}</li>", html_escape(c))).collect();
    let rejected_rows: String = report.rejected.iter().map(|(row, why)| format!("<li class=\"text-error\">✗ row {}: {}</li>", row, html_escape(why))).collect();
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Import report — {entity}</h1>
<div class="flex gap-4 my-3">
  <div class="stat bg-base-100 rounded shadow"><div class="stat-title">Created</div><div class="stat-value text-success">{nc}</div></div>
  <div class="stat bg-base-100 rounded shadow"><div class="stat-title">Rejected</div><div class="stat-value text-error">{nr}</div></div>
</div>
<div class="grid gap-4 lg:grid-cols-2">
  <div class="card bg-base-100 shadow"><div class="card-body"><h3 class="card-title text-sm">Created</h3><ul class="text-sm space-y-1">{cr}</ul></div></div>
  <div class="card bg-base-100 shadow"><div class="card-body"><h3 class="card-title text-sm">Rejected</h3><ul class="text-sm space-y-1">{rr}</ul></div></div>
</div>
<a class="btn btn-sm mt-4" href="/sesb-eam/import">Back to import</a>"#,
        entity = entity, nc = report.created.len(), nr = report.rejected.len(),
        cr = if created_rows.is_empty() { "<li class=\"opacity-50\">none</li>".into() } else { created_rows },
        rr = if rejected_rows.is_empty() { "<li class=\"opacity-50\">none</li>".into() } else { rejected_rows },
    );
    Html(page_shell(&sidebar, "Import report", &content)).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Parse the CSV and load each row in its own transaction (per-row isolation).
async fn run_import(db: &PgPool, company_id: Option<Uuid>, entity: &str, bytes: &[u8]) -> LoadReport {
    let cols = spec(entity).unwrap_or_default();
    let mut report = LoadReport { created: Vec::new(), rejected: Vec::new() };
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_reader(bytes);
    // Map each spec column key to the CSV header index by matching the label.
    let headers: Vec<String> = match rdr.headers() {
        Ok(h) => h.iter().map(|s| s.trim().trim_end_matches('*').trim().to_lowercase()).collect(),
        Err(_) => return report,
    };
    let idx: HashMap<&str, usize> = cols.iter().filter_map(|c| {
        let want = c.label.to_lowercase();
        headers.iter().position(|h| *h == want).map(|i| (c.key, i))
    }).collect();

    let mut row_no = 1usize; // header is row 1
    for rec in rdr.records() {
        row_no += 1;
        let rec = match rec { Ok(r) => r, Err(e) => { report.rejected.push((row_no, format!("unreadable: {e}"))); continue; } };
        // Skip the enum-hint row the template ships (all-empty required cells).
        let row: HashMap<String, String> = idx.iter()
            .map(|(k, i)| ((*k).to_string(), rec.get(*i).unwrap_or("").trim().to_string()))
            .collect();
        if cols.iter().all(|c| row.get(c.key).map(|v| v.is_empty()).unwrap_or(true)) { continue; }
        // Required + enum validation before touching the DB.
        if let Err(why) = validate(&cols, &row) { report.rejected.push((row_no, why)); continue; }

        let mut tx = match db.begin().await { Ok(t) => t, Err(e) => { report.rejected.push((row_no, format!("tx: {e}"))); continue; } };
        let outcome = match entity {
            "substation" => load_substation(&mut tx, company_id, &row).await,
            "bay" => load_bay(&mut tx, company_id, &row).await,
            "equipment" => load_equipment(&mut tx, company_id, &row).await,
            _ => Err("unknown entity".into()),
        };
        match outcome {
            Ok(created) => match tx.commit().await {
                Ok(_) => report.created.push(created),
                Err(e) => report.rejected.push((row_no, format!("commit: {e}"))),
            },
            Err(why) => { let _ = tx.rollback().await; report.rejected.push((row_no, why)); }
        }
    }
    report
}

fn validate(cols: &[Col], row: &HashMap<String, String>) -> Result<(), String> {
    for c in cols {
        let v = row.get(c.key).map(|s| s.as_str()).unwrap_or("");
        if c.required && v.is_empty() {
            return Err(format!("missing required '{}'", c.label));
        }
        if let (Some(allowed), false) = (c.enums, v.is_empty()) {
            if !allowed.iter().any(|(k, _)| *k == v) {
                return Err(format!("'{}'='{}' not in allowed set", c.label, v));
            }
        }
    }
    Ok(())
}

/// Which parent an equipment row hangs off (bay XOR feeder), per §12.
#[derive(Debug)]
enum ParentKind<'a> { Bay(&'a str), Feeder(&'a str) }

/// The both-or-neither rule: an equipment row must give a bay **or** a feeder,
/// exactly one, with a readable rejection otherwise.
fn choose_parent<'a>(bay: Option<&'a str>, feeder: Option<&'a str>) -> Result<ParentKind<'a>, String> {
    match (bay, feeder) {
        (Some(_), Some(_)) => Err("equipment has both a bay and a feeder — give exactly one".into()),
        (None, None) => Err("equipment has neither a bay nor a feeder — give exactly one".into()),
        (Some(b), None) => Ok(ParentKind::Bay(b)),
        (None, Some(f)) => Ok(ParentKind::Feeder(f)),
    }
}

fn g<'a>(row: &'a HashMap<String, String>, k: &str) -> &'a str { row.get(k).map(|s| s.as_str()).unwrap_or("") }
fn opt<'a>(row: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    row.get(k).map(|s| s.as_str()).filter(|s| !s.is_empty())
}

async fn load_substation(tx: &mut Tx<'_>, company_id: Option<Uuid>, row: &HashMap<String, String>) -> Result<String, String> {
    let site_code = g(row, "site_code");
    let site: Option<(Uuid, Uuid)> = vortex_plugin_sdk::sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, region_id FROM eam_site WHERE code=$1")
        .bind(site_code).fetch_optional(&mut **tx).await.map_err(|e| e.to_string())?;
    let (site_id, _region_id) = site.ok_or_else(|| format!("unknown site code '{site_code}'"))?;
    let kv: i32 = g(row, "primary_voltage_kv").parse::<f64>().ok().map(|v| v.round() as i32).unwrap_or(0);
    let acronym = opt(row, "acronym").map(|s| s.to_string()).unwrap_or_else(|| g(row, "code").to_string());
    let asset_id = if kv > 0 && !acronym.is_empty() {
        let n: i64 = vortex_plugin_sdk::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM eam_substation WHERE company_id=$1 AND acronym=$2")
            .bind(company_id).bind(&acronym).fetch_one(&mut **tx).await.map_err(|e| e.to_string())?;
        Some(super::mnec::substation_asset_id(kv, &acronym, Some((n + 1) as i32)))
    } else { None };
    let id = Uuid::now_v7();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_substation (id, name, code, asset_id, acronym, primary_voltage_kv, site_id, substation_type, state, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'operational',$9)")
        .bind(id).bind(g(row, "name")).bind(g(row, "code")).bind(asset_id.as_deref())
        .bind(opt(row, "acronym")).bind(kv as f64).bind(site_id)
        .bind(opt(row, "substation_type")).bind(company_id)
        .execute(&mut **tx).await.map_err(|e| clean_err(e))?;
    Ok(format!("Substation {} ({})", g(row, "code"), asset_id.unwrap_or_default()))
}

async fn load_bay(tx: &mut Tx<'_>, company_id: Option<Uuid>, row: &HashMap<String, String>) -> Result<String, String> {
    let sub_code = g(row, "substation_code");
    let sub: Option<(Uuid, Option<String>)> = vortex_plugin_sdk::sqlx::query_as::<_, (Uuid, Option<String>)>(
        "SELECT id, asset_id FROM eam_substation WHERE code=$1")
        .bind(sub_code).fetch_optional(&mut **tx).await.map_err(|e| e.to_string())?;
    let (substation_id, sub_asset) = sub.ok_or_else(|| format!("unknown substation code '{sub_code}'"))?;
    let bay_number = g(row, "bay_number");
    // Bay MNEC id = {substation.asset_id}-{bay_number}.
    let asset_id = sub_asset.filter(|s| !s.is_empty()).map(|s| format!("{s}-{bay_number}"));
    let id = Uuid::now_v7();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_bay (id, name, code, bay_number, asset_id, substation_id, bay_type, state, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'operational',$8)")
        .bind(id).bind(g(row, "name")).bind(g(row, "code")).bind(bay_number)
        .bind(asset_id.as_deref()).bind(substation_id).bind(opt(row, "bay_type")).bind(company_id)
        .execute(&mut **tx).await.map_err(|e| clean_err(e))?;
    Ok(format!("Bay {} ({})", g(row, "code"), asset_id.unwrap_or_default()))
}

async fn load_equipment(tx: &mut Tx<'_>, company_id: Option<Uuid>, row: &HashMap<String, String>) -> Result<String, String> {
    // Exactly one parent — the contract's both-or-neither rejection.
    let (parent_asset, bay_uuid, dline_uuid): (Option<String>, Option<Uuid>, Option<Uuid>) =
        match choose_parent(opt(row, "bay_code"), opt(row, "feeder_code"))? {
            ParentKind::Bay(bc) => {
                let r: Option<(Uuid, Option<String>)> = vortex_plugin_sdk::sqlx::query_as::<_, (Uuid, Option<String>)>(
                    "SELECT id, asset_id FROM eam_bay WHERE code=$1").bind(bc).fetch_optional(&mut **tx).await.map_err(|e| e.to_string())?;
                let (id, a) = r.ok_or_else(|| format!("unknown bay code '{bc}'"))?;
                (a, Some(id), None)
            }
            ParentKind::Feeder(fc) => {
                let r: Option<(Uuid, Option<String>)> = vortex_plugin_sdk::sqlx::query_as::<_, (Uuid, Option<String>)>(
                    "SELECT id, asset_id FROM eam_distribution_line WHERE code=$1").bind(fc).fetch_optional(&mut **tx).await.map_err(|e| e.to_string())?;
                let (id, a) = r.ok_or_else(|| format!("unknown feeder code '{fc}'"))?;
                (a, None, Some(id))
            }
        };
    // Acronym → asset_type_id.
    let acr = g(row, "asset_type_acronym");
    let at: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM eam_asset_type WHERE acronym=$1").bind(acr).fetch_optional(&mut **tx).await.map_err(|e| e.to_string())?;
    let asset_type_id = at.ok_or_else(|| format!("unknown asset-type acronym '{acr}'"))?;
    let seq = g(row, "mnec_sequence").parse::<i32>().ok();
    let parent_asset = parent_asset.filter(|s| !s.is_empty())
        .ok_or_else(|| "parent has no composed asset ID to hang the equipment off".to_string())?;
    let asset_id = super::mnec::equipment_asset_id(&parent_asset, acr, seq);
    let id = Uuid::now_v7();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_equipment (id, name, code, asset_id, asset_type_id, mnec_sequence, bay_id, distribution_line_id, equipment_category, serial_number, condition_status, operational_status, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9,'other'),$10,COALESCE($11,'good'),COALESCE($12,'operational'),$13)")
        .bind(id).bind(g(row, "name")).bind(g(row, "code")).bind(&asset_id).bind(asset_type_id).bind(seq)
        .bind(bay_uuid).bind(dline_uuid)
        .bind(opt(row, "equipment_category")).bind(opt(row, "serial_number"))
        .bind(opt(row, "condition_status")).bind(opt(row, "operational_status")).bind(company_id)
        .execute(&mut **tx).await.map_err(|e| clean_err(e))?;
    Ok(format!("Equipment {} ({})", g(row, "code"), asset_id))
}

/// Turn a DB error into a short row reason (surfacing unique-violation cleanly,
/// as §4.9 requires for the composed asset-ID conflict).
fn clean_err(e: vortex_plugin_sdk::sqlx::Error) -> String {
    if let Some(dbe) = e.as_database_error() {
        if dbe.is_unique_violation() {
            return "duplicate — composed asset ID or code already exists".to_string();
        }
        return dbe.message().to_string();
    }
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_must_be_exactly_one() {
        assert!(matches!(choose_parent(Some("B01"), None), Ok(ParentKind::Bay("B01"))));
        assert!(matches!(choose_parent(None, Some("F9")), Ok(ParentKind::Feeder("F9"))));
        // both → rejected with a readable reason
        let both = choose_parent(Some("B01"), Some("F9")).unwrap_err();
        assert!(both.contains("both"));
        // neither → rejected
        let neither = choose_parent(None, None).unwrap_err();
        assert!(neither.contains("neither"));
    }

    #[test]
    fn validate_enforces_required_and_enums() {
        let cols = spec("substation").unwrap();
        let mut row: HashMap<String, String> = HashMap::new();
        // missing required 'code'/'name'/'site_code'
        assert!(validate(&cols, &row).is_err());
        row.insert("code".into(), "SS1".into());
        row.insert("name".into(), "Test".into());
        row.insert("site_code".into(), "SITE1".into());
        assert!(validate(&cols, &row).is_ok());
        // bad enum value on substation_type
        row.insert("substation_type".into(), "not_a_type".into());
        assert!(validate(&cols, &row).is_err());
        row.insert("substation_type".into(), "pmu".into());
        assert!(validate(&cols, &row).is_ok());
    }

    #[test]
    fn every_entity_has_a_spec() {
        for (key, _) in ENTITIES {
            assert!(spec(key).is_some(), "missing spec for {key}");
        }
    }
}
