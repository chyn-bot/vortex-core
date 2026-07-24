//! REST API (§7) — JSON over HTTP, mounted under `/sesb-eam/api/v1`. Auth is
//! the platform's session cookie or bearer `api_token` (both surface as the
//! `AuthUser` extension via the host auth middleware). List envelopes follow
//! `{total,count,offset,limit,results}`.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::Json;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::{json, Value};
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

const API: &str = "/sesb-eam/api/v1";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(&format!("{API}/ping"), get(ping))
        .route(&format!("{API}/me"), get(me))
        .route(&format!("{API}/equipment"), get(list_equipment))
        .route(&format!("{API}/equipment/{{id}}"), get(get_equipment))
        .route(&format!("{API}/maintenance"), get(list_maintenance))
        .route(&format!("{API}/maintenance/{{id}}"), get(get_maintenance))
        .route(&format!("{API}/maintenance/{{id}}/action"), post(maintenance_action))
        .route(&format!("{API}/maintenance/{{id}}/checklist/line/{{line_id}}"), post(checklist_line))
        .route(&format!("{API}/defects"), get(list_defects).post(create_defect))
        .route(&format!("{API}/location"), get(list_location).post(ingest_location))
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"error": msg, "status": status.as_u16()}))).into_response()
}

fn paged(q: &HashMap<String, String>) -> (i64, i64) {
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0);
    (limit, offset)
}

async fn ping() -> Response {
    Json(json!({"ok": true, "version": "0.1.0", "module": "sesb_eam"})).into_response()
}

async fn me(
    Db(db): Db, Extension(user): Extension<AuthUser>,
) -> Response {
    let agent = vortex_plugin_sdk::sqlx::query(
        "SELECT a.id, a.name, a.employee_no, a.agent_level, a.skill_category, a.is_supervisor, \
           (SELECT COUNT(*) FROM eam_maintenance m WHERE m.assigned_to=$1 AND m.state NOT IN ('completed','verified','cancelled'))::bigint AS active_jobs, \
           EXISTS(SELECT 1 FROM eam_field_agent_leave l WHERE l.user_id=$1 AND l.state='approved' AND CURRENT_DATE BETWEEN l.date_from AND l.date_to) AS on_leave \
         FROM eam_field_agent a WHERE a.user_id=$1")
        .bind(user.id).fetch_optional(&db).await.ok().flatten();
    let profile = agent.map(|a| json!({
        "agent_id": a.get::<Uuid,_>("id"),
        "name": a.get::<String,_>("name"),
        "employee_no": a.try_get::<Option<String>,_>("employee_no").ok().flatten(),
        "level": a.try_get::<Option<String>,_>("agent_level").ok().flatten(),
        "skill": a.try_get::<Option<String>,_>("skill_category").ok().flatten(),
        "is_supervisor": a.try_get::<bool,_>("is_supervisor").unwrap_or(false),
        "active_jobs": a.try_get::<i64,_>("active_jobs").unwrap_or(0),
        "on_leave": a.try_get::<bool,_>("on_leave").unwrap_or(false),
    }));
    Json(json!({
        "id": user.id, "username": user.username,
        "full_name": user.full_name, "roles": user.roles,
        "field_agent": profile,
    })).into_response()
}

async fn list_equipment(
    Db(db): Db, Extension(user): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let (limit, offset) = paged(&q);
    let search = q.get("search").cloned().unwrap_or_default();
    let like = format!("%{}%", search);
    // Division boundary (§6.3): scope the REST list too, so a DAMS token can
    // never enumerate transmission assets by any route.
    let scope = division::division_predicate(&user, "division")
        .map(|p| format!(" AND {p}")).unwrap_or_default();
    let total: i64 = vortex_plugin_sdk::sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint FROM eam_equipment WHERE ($1='' OR name ILIKE $2 OR code ILIKE $2 OR asset_id ILIKE $2){scope}"))
        .bind(&search).bind(&like).fetch_one(&db).await.unwrap_or(0);
    let rows = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT id, code, asset_id, name, equipment_category, condition_status, operational_status, risk_level \
         FROM eam_equipment WHERE ($1='' OR name ILIKE $2 OR code ILIKE $2 OR asset_id ILIKE $2){scope} ORDER BY code LIMIT $3 OFFSET $4"))
        .bind(&search).bind(&like).bind(limit).bind(offset).fetch_all(&db).await.unwrap_or_default();
    let results: Vec<Value> = rows.iter().map(equip_json).collect();
    Json(json!({"total": total, "count": results.len(), "offset": offset, "limit": limit, "results": results})).into_response()
}

fn equip_json(r: &vortex_plugin_sdk::sqlx::postgres::PgRow) -> Value {
    let condition: String = r.get("condition_status");
    let op: String = r.get("operational_status");
    json!({
        "id": r.get::<Uuid,_>("id"),
        "code": r.try_get::<Option<String>,_>("code").ok().flatten(),
        "asset_id": r.try_get::<Option<String>,_>("asset_id").ok().flatten(),
        "name": r.get::<String,_>("name"),
        "category": r.try_get::<Option<String>,_>("equipment_category").ok().flatten(),
        "condition": condition, "operational_status": op,
        "risk": r.try_get::<Option<String>,_>("risk_level").ok().flatten(),
        "health_index": super::analytics::health_index(&condition, &op),
    })
}

async fn get_equipment(
    Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_equipment", id).await { return resp; }
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, asset_id, name, equipment_category, condition_status, operational_status, risk_level FROM eam_equipment WHERE id=$1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    match row { Some(r) => Json(equip_json(&r)).into_response(), None => err(StatusCode::NOT_FOUND, "equipment not found") }
}

async fn list_maintenance(
    Db(db): Db, Extension(user): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let (limit, offset) = paged(&q);
    let state_f = q.get("state").cloned().unwrap_or_default();
    let mine = q.get("assigned_to_me").map(|s| s == "1" || s == "true").unwrap_or(false);
    let scope = division::division_predicate(&user, "m.division")
        .map(|p| format!(" AND {p}")).unwrap_or_default();
    let sql = format!(
        "SELECT m.id, m.name, m.description, m.state, m.maintenance_type, m.priority, m.scheduled_date::text AS sd, e.name AS equip, e.code AS equip_code \
         FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id \
         WHERE ($1='' OR m.state=$1) {mine}{scope} ORDER BY m.scheduled_date NULLS LAST, m.created_at DESC LIMIT $3 OFFSET $4",
        mine = if mine { "AND m.assigned_to=$2" } else { "" });
    let q2 = vortex_plugin_sdk::sqlx::query(&sql).bind(&state_f).bind(user.id).bind(limit).bind(offset);
    let rows = q2.fetch_all(&db).await.unwrap_or_default();
    let results: Vec<Value> = rows.iter().map(|r| json!({
        "id": r.get::<Uuid,_>("id"),
        "name": r.try_get::<Option<String>,_>("name").ok().flatten(),
        "description": r.get::<String,_>("description"),
        "state": r.get::<String,_>("state"),
        "type": r.get::<String,_>("maintenance_type"),
        "priority": r.get::<String,_>("priority"),
        "scheduled_date": r.try_get::<Option<String>,_>("sd").ok().flatten(),
        "equipment": r.try_get::<Option<String>,_>("equip").ok().flatten(),
        "equipment_code": r.try_get::<Option<String>,_>("equip_code").ok().flatten(),
    })).collect();
    Json(json!({"total": results.len(), "count": results.len(), "offset": offset, "limit": limit, "results": results})).into_response()
}

async fn get_maintenance(
    Db(db): Db, Extension(user): Extension<AuthUser>, Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = division::guard_division(&db, &user, "eam_maintenance", id).await { return resp; }
    let m = vortex_plugin_sdk::sqlx::query(
        "SELECT m.id, m.name, m.description, m.state, m.maintenance_type, m.priority, m.scheduled_date::text AS sd, m.work_description, e.name AS equip FROM eam_maintenance m LEFT JOIN eam_equipment e ON e.id=m.equipment_id WHERE m.id=$1")
        .bind(id).fetch_optional(&db).await.ok().flatten();
    let m = match m { Some(r) => r, None => return err(StatusCode::NOT_FOUND, "work order not found") };
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, section, input_type, is_required, value_pass_fail, value_yes_no, value_measurement::text AS vm, value_text, value_selection, value_rating, note FROM eam_checklist_line WHERE maintenance_id=$1 ORDER BY sequence")
        .bind(id).fetch_all(&db).await.unwrap_or_default();
    let checklist: Vec<Value> = lines.iter().map(|l| json!({
        "id": l.get::<Uuid,_>("id"),
        "name": l.get::<String,_>("name"),
        "section": l.try_get::<Option<String>,_>("section").ok().flatten(),
        "input_type": l.get::<String,_>("input_type"),
        "is_required": l.try_get::<bool,_>("is_required").unwrap_or(false),
        "value_pass_fail": l.try_get::<Option<String>,_>("value_pass_fail").ok().flatten(),
        "value_yes_no": l.try_get::<Option<String>,_>("value_yes_no").ok().flatten(),
        "value_measurement": l.try_get::<Option<String>,_>("vm").ok().flatten(),
        "value_text": l.try_get::<Option<String>,_>("value_text").ok().flatten(),
        "value_selection": l.try_get::<Option<String>,_>("value_selection").ok().flatten(),
        "value_rating": l.try_get::<Option<i32>,_>("value_rating").ok().flatten(),
        "note": l.try_get::<Option<String>,_>("note").ok().flatten(),
    })).collect();
    Json(json!({
        "id": m.get::<Uuid,_>("id"),
        "name": m.try_get::<Option<String>,_>("name").ok().flatten(),
        "description": m.get::<String,_>("description"),
        "state": m.get::<String,_>("state"),
        "type": m.get::<String,_>("maintenance_type"),
        "priority": m.get::<String,_>("priority"),
        "scheduled_date": m.try_get::<Option<String>,_>("sd").ok().flatten(),
        "work_description": m.try_get::<Option<String>,_>("work_description").ok().flatten(),
        "equipment": m.try_get::<Option<String>,_>("equip").ok().flatten(),
        "checklist": checklist,
    })).into_response()
}

/// POST body: action=accept|reject|start|hold|resume|complete (+reason).
///
/// Authorization: the transition must be a legal edge in `work_order_machine()`
/// **and** permitted by Cedar for this principal (see
/// [`crate::workflow::guarded_transition`]) — this replaces the old hardcoded
/// `match` that let any authenticated token drive the state machine. The domain
/// `UPDATE` and the WORM audit entry are then committed in one tenant-pool
/// transaction, so a failed audit write rolls the state change back.
pub async fn maintenance_action(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    use crate::workflow::{guarded_transition, policy_enforced, work_order_machine, Guard};
    use vortex_plugin_sdk::policy::{PolicyPrincipal, PolicyResource};

    let action = form.get("action").cloned().unwrap_or_default();
    let cur: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM eam_maintenance WHERE id=$1").bind(id).fetch_optional(&db).await.ok().flatten();
    let cur = match cur { Some(c) => c, None => return err(StatusCode::NOT_FOUND, "work order not found") };

    // ── Authorization: legality (state machine) + Cedar policy ──────────
    let principal = PolicyPrincipal {
        user_id: user.id,
        username: user.username.clone(),
        company_id: default_company(&db).await.unwrap_or_default(),
        roles: user.roles.clone(),
    };
    let resource = PolicyResource {
        type_name: "WorkOrder".into(),
        id: id.to_string(),
        attributes: json!({ "from_state": cur, "action": action }),
    };
    let to = match guarded_transition(
        state.policy.as_ref(), work_order_machine(), &cur, &action, &principal, resource, policy_enforced(),
    ).await {
        Guard::Allow(to) => to,
        Guard::Illegal => return err(StatusCode::CONFLICT, &format!("illegal transition: cannot {action} from {cur}")),
        Guard::Denied => return err(StatusCode::FORBIDDEN, &format!("not permitted to {action} this work order")),
        Guard::Error(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("policy check failed: {e}")),
    };

    let now = vortex_plugin_sdk::chrono::Utc::now();

    // `complete` gate: all required checklist lines must carry a value.
    if action == "complete" {
        let missing: i64 = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT COUNT(*) FROM eam_checklist_line WHERE maintenance_id=$1 AND is_required AND value_pass_fail IS NULL AND value_yes_no IS NULL AND value_measurement IS NULL AND value_text IS NULL AND value_selection IS NULL AND value_rating IS NULL")
            .bind(id).fetch_one(&db).await.unwrap_or(0);
        if missing > 0 { return err(StatusCode::CONFLICT, "required checklist items incomplete"); }
    }

    // ── Domain side-effects + WORM audit, committed atomically ──────────
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("tx begin: {e}")),
    };
    let upd = match action.as_str() {
        "accept" | "start" => vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_maintenance SET state=$2, accepted_by=$3, acceptance_date=$4, start_date=COALESCE(start_date,$4) WHERE id=$1")
            .bind(id).bind(&to).bind(user.id).bind(now).execute(&mut *tx).await,
        "reject" => vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_maintenance SET state=$2, assigned_to=NULL, rejected_by=$3, rejection_date=$4, rejection_reason=$5, rejection_count=rejection_count+1 WHERE id=$1")
            .bind(id).bind(&to).bind(user.id).bind(now).bind(opt_str(&form, "reason")).execute(&mut *tx).await,
        "hold" | "resume" => vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_maintenance SET state=$2 WHERE id=$1")
            .bind(id).bind(&to).execute(&mut *tx).await,
        "complete" => vortex_plugin_sdk::sqlx::query(
            "UPDATE eam_maintenance SET state=$2, end_date=$3, actual_duration_hours = CASE WHEN start_date IS NOT NULL THEN EXTRACT(EPOCH FROM ($3 - start_date))/3600.0 END WHERE id=$1")
            .bind(id).bind(&to).bind(now).execute(&mut *tx).await,
        // Unreachable: the state machine already rejected any action not
        // handled above with `Guard::Illegal`.
        other => { let _ = tx.rollback().await; return err(StatusCode::CONFLICT, &format!("unhandled action {other}")); }
    };
    if let Err(e) = upd {
        let _ = tx.rollback().await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("update failed: {e}"));
    }

    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::WorkflowTransition, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource("eam_maintenance", id.to_string())
     .with_details(json!({"api": true, "action": action, "from": cur, "to": to}));
    if let Err(e) = state.audit.log_tx(entry, &mut tx).await {
        let _ = tx.rollback().await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("audit write failed: {e}"));
    }
    if let Err(e) = tx.commit().await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("commit failed: {e}"));
    }
    Json(json!({"ok": true, "state": to})).into_response()
}

/// POST one typed checklist-line value.
async fn checklist_line(
    Db(db): Db, Extension(_u): Extension<AuthUser>,
    Path((id, line_id)): Path<(Uuid, Uuid)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let itype: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT input_type FROM eam_checklist_line WHERE id=$1 AND maintenance_id=$2").bind(line_id).bind(id).fetch_optional(&db).await.ok().flatten();
    let itype = match itype { Some(t) => t, None => return err(StatusCode::NOT_FOUND, "checklist line not found") };
    let (col, cast) = match itype.as_str() {
        "pass_fail" => ("value_pass_fail", ""), "yes_no" => ("value_yes_no", ""),
        "measurement" => ("value_measurement", "::numeric"), "rating" => ("value_rating", "::int"),
        "selection" => ("value_selection", ""), _ => ("value_text", ""),
    };
    let sql = format!("UPDATE eam_checklist_line SET {col} = $1{cast}, note = COALESCE($2, note) WHERE id = $3", col = col, cast = cast);
    if let Err(e) = vortex_plugin_sdk::sqlx::query(&sql).bind(opt_str(&form, "value")).bind(opt_str(&form, "note")).bind(line_id).execute(&db).await {
        return err(StatusCode::BAD_REQUEST, &format!("update failed: {e}"));
    }
    Json(json!({"ok": true})).into_response()
}

async fn list_defects(
    Db(db): Db, Extension(user): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>,
) -> Response {
    let (limit, offset) = paged(&q);
    let state_f = q.get("state").cloned().unwrap_or_default();
    let scope = division::division_predicate(&user, "d.division")
        .map(|p| format!(" AND {p}")).unwrap_or_default();
    let rows = vortex_plugin_sdk::sqlx::query(&format!(
        "SELECT d.id, d.name, d.title, d.severity, d.defect_category, d.state, e.name AS equip FROM eam_defect d LEFT JOIN eam_equipment e ON e.id=d.equipment_id WHERE ($1='' OR d.state=$1){scope} ORDER BY d.created_at DESC LIMIT $2 OFFSET $3"))
        .bind(&state_f).bind(limit).bind(offset).fetch_all(&db).await.unwrap_or_default();
    let results: Vec<Value> = rows.iter().map(|r| json!({
        "id": r.get::<Uuid,_>("id"),
        "name": r.try_get::<Option<String>,_>("name").ok().flatten(),
        "title": r.get::<String,_>("title"),
        "severity": r.get::<String,_>("severity"),
        "category": r.try_get::<Option<String>,_>("defect_category").ok().flatten(),
        "state": r.get::<String,_>("state"),
        "equipment": r.try_get::<Option<String>,_>("equip").ok().flatten(),
    })).collect();
    Json(json!({"total": results.len(), "count": results.len(), "offset": offset, "limit": limit, "results": results})).into_response()
}

async fn create_defect(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(_c): Extension<DatabaseContext>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let equipment_id = match opt_uuid(&form, "equipment_id") { Some(e) => e, None => return err(StatusCode::BAD_REQUEST, "equipment_id is required") };
    let title = form.get("title").cloned().unwrap_or_default();
    if title.trim().is_empty() { return err(StatusCode::BAD_REQUEST, "title is required"); }
    let seq = vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sesb_eam.defect", "DEF").with_padding(5).yearly();
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, &seq).await.unwrap_or_default();
    let company_id = default_company(&db).await;
    let id = Uuid::now_v7();
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_defect (id, name, title, equipment_id, bay_id, substation_id, discovered_date, discovered_by, severity, defect_category, source_inspection_id, source_patrol_id, state, company_id, created_by) \
         SELECT $1,$2,$3,$4, e.bay_id, e.substation_id, NOW(), $5, $6, $7, $8, $9, 'open', $10, $5 FROM eam_equipment e WHERE e.id=$4")
        .bind(id).bind(&number).bind(&title).bind(equipment_id).bind(user.id)
        .bind(form.get("severity").map(|s| s.as_str()).unwrap_or("moderate")).bind(opt_str(&form, "category"))
        .bind(opt_uuid(&form, "source_inspection_id")).bind(opt_uuid(&form, "source_patrol_id")).bind(company_id)
        .execute(&db).await;
    if let Err(e) = res { return err(StatusCode::BAD_REQUEST, &format!("create failed: {e}")); }
    (StatusCode::CREATED, Json(json!({"ok": true, "id": id, "name": number}))).into_response()
}

/// POST a GPS fix (source=api); upserts the one current row per user.
async fn ingest_location(
    Db(db): Db, Extension(user): Extension<AuthUser>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let lat = form.get("lat").and_then(|s| s.parse::<f64>().ok());
    let lng = form.get("lng").and_then(|s| s.parse::<f64>().ok());
    if lat.is_none() || lng.is_none() { return err(StatusCode::BAD_REQUEST, "lat and lng are required"); }
    let dec = |k: &str| form.get(k).and_then(|s| s.parse::<vortex_plugin_sdk::rust_decimal::Decimal>().ok());
    let status = form.get("status").map(|s| s.as_str()).unwrap_or("available");
    let res = upsert_location(&db, user.id, lat, lng, dec("accuracy_m"), dec("speed_kmh"), dec("heading"), opt_i32(&form, "battery"), status, "api").await;
    match res { Ok(_) => Json(json!({"ok": true})).into_response(), Err(e) => err(StatusCode::BAD_REQUEST, &format!("ingest failed: {e}")) }
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_location(
    db: &PgPool, user_id: Uuid, lat: Option<f64>, lng: Option<f64>,
    accuracy: Option<vortex_plugin_sdk::rust_decimal::Decimal>, speed: Option<vortex_plugin_sdk::rust_decimal::Decimal>,
    heading: Option<vortex_plugin_sdk::rust_decimal::Decimal>, battery: Option<i32>, status: &str, source: &str,
) -> Result<(), vortex_plugin_sdk::sqlx::Error> {
    let latd = lat.and_then(|v| vortex_plugin_sdk::rust_decimal::Decimal::from_f64_retain(v));
    let lngd = lng.and_then(|v| vortex_plugin_sdk::rust_decimal::Decimal::from_f64_retain(v));
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_field_agent_location (user_id, agent_id, name, lat, lng, accuracy_m, speed_kmh, heading, battery_pct, status, source, last_seen, is_active) \
         SELECT $1, (SELECT id FROM eam_field_agent WHERE user_id=$1), (SELECT username FROM users WHERE id=$1), $2,$3,$4,$5,$6,$7,$8,$9, NOW(), TRUE \
         ON CONFLICT (user_id) DO UPDATE SET lat=$2, lng=$3, accuracy_m=$4, speed_kmh=$5, heading=$6, battery_pct=$7, status=$8, source=$9, last_seen=NOW(), is_active=TRUE")
        .bind(user_id).bind(latd).bind(lngd).bind(accuracy).bind(speed).bind(heading).bind(battery).bind(status).bind(source)
        .execute(db).await?;
    Ok(())
}

/// Active field-agent positions in the last 15 minutes.
async fn list_location(
    Db(db): Db, Extension(_u): Extension<AuthUser>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT user_id, name, lat::text AS lat, lng::text AS lng, status, source, last_seen::text AS last_seen, maintenance_id FROM eam_field_agent_location WHERE is_active AND last_seen > NOW() - INTERVAL '15 minutes' ORDER BY last_seen DESC")
        .fetch_all(&db).await.unwrap_or_default();
    let results: Vec<Value> = rows.iter().map(|r| json!({
        "user_id": r.get::<Uuid,_>("user_id"),
        "name": r.try_get::<Option<String>,_>("name").ok().flatten(),
        "lat": r.try_get::<Option<String>,_>("lat").ok().flatten(),
        "lng": r.try_get::<Option<String>,_>("lng").ok().flatten(),
        "status": r.get::<String,_>("status"),
        "source": r.get::<String,_>("source"),
        "last_seen": r.try_get::<Option<String>,_>("last_seen").ok().flatten(),
        "maintenance_id": r.try_get::<Option<Uuid>,_>("maintenance_id").ok().flatten(),
    })).collect();
    Json(json!({"count": results.len(), "results": results})).into_response()
}
