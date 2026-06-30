//! Governance actions: the asset creation/verification workflow (§5.1) shared
//! by Equipment, Substation and Bay, and cross-boundary (sempadanan)
//! reassignment (§5.5) on Maintenance and Defect.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::axum::extract::Form;
use vortex_plugin_sdk::axum::http::StatusCode;
use vortex_plugin_sdk::axum::response::Redirect;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sesb-eam/verification", get(inbox))
        .route("/sesb-eam/verification/{model}/{id}/action/{action}", post(verify_action))
        .route("/sesb-eam/reassign/{model}/{id}", get(reassign_form))
        .route("/sesb-eam/reassign/{model}/{id}", post(reassign_apply))
}

/// Allow-listed verification targets → (table, back-url-prefix, label).
fn verify_target(model: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match model {
        "equipment" => Some(("eam_equipment", "/sesb-eam/equipment", "Equipment")),
        "substation" => Some(("eam_substation", "/sesb-eam/substations", "Substation")),
        "bay" => Some(("eam_bay", "/sesb-eam/bays", "Bay")),
        _ => None,
    }
}
/// Allow-listed reassignment targets → (table, back-url-prefix, label).
fn reassign_target(model: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match model {
        "maintenance" => Some(("eam_maintenance", "/sesb-eam/maintenance", "Work Order")),
        "defect" => Some(("eam_defect", "/sesb-eam/defects", "Defect")),
        _ => None,
    }
}

const VSTATE_BADGES: &[(&str, &str, &str)] = &[("draft","Draft","badge-ghost"),("submitted","Submitted","badge-info"),("verified","Verified","badge-warning"),("approved","Approved","badge-success"),("rejected","Rejected","badge-error")];
fn vbadge(s: &str) -> String {
    VSTATE_BADGES.iter().find(|(v,_,_)| *v==s).map(|(_,l,c)| format!(r#"<span class="badge {c}">{l}</span>"#, c=c, l=l)).unwrap_or_else(|| format!(r#"<span class="badge">{}</span>"#, s))
}

// ═════════════════════════════════ Verification inbox (§5.1) ════════════════

async fn inbox(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.verification");
    let mut sections = String::new();
    for (model, table, label, name_col) in [
        ("equipment", "eam_equipment", "Equipment", "name"),
        ("substation", "eam_substation", "Substations", "name"),
        ("bay", "eam_bay", "Bays", "name"),
    ] {
        let sql = format!(
            "SELECT id, {nc} AS nm, verification_state AS vs, verification_revision AS rev FROM {t} WHERE verification_state IN ('submitted','verified') ORDER BY submitted_date NULLS LAST LIMIT 200",
            nc = name_col, t = table);
        let rows = vortex_plugin_sdk::sqlx::query(&sql).fetch_all(&db).await.unwrap_or_default();
        let body = if rows.is_empty() {
            "<tr><td colspan=\"4\" class=\"opacity-50 text-sm\">Nothing pending.</td></tr>".to_string()
        } else {
            rows.iter().map(|r| {
                let id: Uuid = r.get("id");
                let nm: Option<String> = r.try_get("nm").ok();
                let vs: String = r.get("vs");
                let rev: i32 = r.try_get("rev").unwrap_or(0);
                let acts = action_buttons(model, id, &vs);
                format!(r#"<tr><td class="font-mono text-xs">{nm}</td><td>{badge}</td><td>{rev}</td><td class="flex flex-wrap gap-1">{acts}</td></tr>"#,
                    nm = esc(nm.as_deref().unwrap_or("")), badge = vbadge(&vs), rev = rev, acts = acts)
            }).collect::<String>()
        };
        sections.push_str(&format!(
            r#"<h2 class="text-lg font-semibold mt-4 mb-2">{label}</h2>
<div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Name</th><th>State</th><th>Rev</th><th>Actions</th></tr></thead><tbody>{body}</tbody></table></div>"#,
            label = label, body = body));
    }
    let content = format!(r#"<h1 class="text-2xl font-bold mb-2">Asset Verification</h1>
<p class="opacity-60 text-sm mb-4">DAMS workflow: draft → submitted → verified → approved (§5.1). Verifiers verify/reject; managers approve.</p>{}"#, sections);
    Html(page_shell(&sidebar, "Asset Verification", &content)).into_response()
}

fn action_buttons(model: &str, id: Uuid, vs: &str) -> String {
    let btn = |a: &str, l: &str, c: &str, extra: &str| format!(
        r#"<form method="POST" action="/sesb-eam/verification/{m}/{id}/action/{a}" class="inline">{extra}<button class="btn btn-xs {c}">{l}</button></form>"#,
        m = model, id = id, a = a, c = c, l = l, extra = extra);
    let reason = r#"<input name="reason" class="input input-bordered input-xs w-28 mr-1" placeholder="reason" required/>"#;
    match vs {
        "submitted" => format!("{}{}", btn("verify", "Verify", "btn-success", ""), btn("reject", "Reject", "btn-error btn-outline", reason)),
        "verified" => format!("{}{}", btn("approve", "Approve", "btn-success", ""), btn("reject", "Reject", "btn-error btn-outline", reason)),
        _ => String::new(),
    }
}

async fn verify_action(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id, action)): Path<(String, Uuid, String)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (table, back, label) = match verify_target(&model) { Some(t) => t, None => return (StatusCode::BAD_REQUEST, "Unknown model").into_response() };
    let cur: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(&format!("SELECT verification_state FROM {t} WHERE id=$1", t = table)).bind(id).fetch_optional(&db).await.ok().flatten();
    let cur = match cur { Some(c) => c, None => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let is_mgr = user.roles.iter().any(|r| r == "EAM Manager" || r == "EAM Admin" || r == "System Administrator");

    // (sql, new_state) per allowed transition.
    let result: Result<(String, &str), &str> = match (action.as_str(), cur.as_str()) {
        ("submit", "draft") | ("submit", "rejected") => Ok((
            format!("UPDATE {t} SET verification_state='submitted', submitted_by_id=$2, submitted_date=NOW(), verification_revision = verification_revision + CASE WHEN verification_state='rejected' THEN 1 ELSE 0 END WHERE id=$1", t = table), "submitted")),
        ("verify", "submitted") => Ok((format!("UPDATE {t} SET verification_state='verified', verified_by_id=$2, verified_date=NOW() WHERE id=$1", t = table), "verified")),
        ("approve", "verified") => {
            if !is_mgr { return (StatusCode::FORBIDDEN, "Only a Manager/Admin may approve assets (§5.1)").into_response(); }
            Ok((format!("UPDATE {t} SET verification_state='approved', approved_by_id=$2, approved_date=NOW() WHERE id=$1", t = table), "approved"))
        }
        ("reject", "submitted") | ("reject", "verified") => {
            if opt_str(&form, "reason").is_none() { return bad("A rejection reason is required (§5.1)"); }
            Ok((format!("UPDATE {t} SET verification_state='rejected', rejected_by_id=$2, rejected_date=NOW(), rejection_reason=$3 WHERE id=$1", t = table), "rejected"))
        }
        ("reset", "approved") | ("reset", "rejected") => {
            if !is_mgr { return (StatusCode::FORBIDDEN, "Only a Manager/Admin may reopen for amendment (§5.1)").into_response(); }
            Ok((format!("UPDATE {t} SET verification_state='draft' WHERE id=$1", t = table), "draft"))
        }
        _ => Err("Illegal transition"),
    };
    let (sql, to) = match result { Ok(x) => x, Err(m) => return (StatusCode::CONFLICT, format!("{m}: cannot {action} from {cur}")).into_response() };
    let q = vortex_plugin_sdk::sqlx::query(&sql).bind(id).bind(user.id);
    let q = if action == "reject" { q.bind(form.get("reason").cloned().unwrap_or_default()) } else { q };
    if let Err(e) = q.execute(&db).await { return bad(&format!("Failed: {e}")); }

    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource(table, id.to_string())
     .with_details(json!({"workflow": "asset_verification", "action": action, "from": cur, "to": to}));
    let _ = state.audit.log(entry).await;
    let _ = label; let _ = back;
    Redirect::to("/sesb-eam/verification").into_response()
}

// ═════════════════════════════ Boundary reassignment (§5.5) ═════════════════

async fn reassign_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    let (table, back, label) = match reassign_target(&model) { Some(t) => t, None => return (StatusCode::BAD_REQUEST, "Unknown model").into_response() };
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, &format!("sesb_eam.{}", if model == "defect" { "defects" } else { "maintenance" }));
    let row = vortex_plugin_sdk::sqlx::query(&format!("SELECT name, kawasan_id::text AS native_kawasan, responsible_kawasan_id::text AS resp_kawasan, assigned_to::text AS assigned_to, reassignment_count::text AS rc FROM {t} WHERE id=$1", t = table)).bind(id).fetch_optional(&db).await.ok().flatten();
    let row = match row { Some(r) => r, None => return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let number: Option<String> = row.try_get("name").ok();
    let resp: Option<Uuid> = row.try_get::<Option<String>,_>("resp_kawasan").ok().flatten().and_then(|s| s.parse().ok());
    let native: Option<Uuid> = row.try_get::<Option<String>,_>("native_kawasan").ok().flatten().and_then(|s| s.parse().ok());
    let assigned: Option<Uuid> = row.try_get::<Option<String>,_>("assigned_to").ok().flatten().and_then(|s| s.parse().ok());
    let rc: String = row.try_get::<Option<String>,_>("rc").ok().flatten().unwrap_or_default();
    let kawasans = kawasan_options(&db, resp.or(native)).await;
    let users = user_options(&db, assigned).await;
    let body = format!("{}{}{}",
        grid2(&format!("{}{}",
            select_field("Responsible Kawasan *", "responsible_kawasan_id", &kawasans),
            select_field("Reassign To (optional)", "assigned_to", &users))),
        textarea_field("Reason *", "reason", ""),
        format!(r#"<p class="text-xs opacity-60">Reassigned {rc}× so far. If the assignee is a field agent, their coverage must include the target kawasan (§5.5).</p>"#, rc = rc));
    let header = format!(r#"<a href="{back}/{id}" class="btn btn-ghost btn-sm mb-3">← Back to {label}</a>
<h1 class="text-2xl font-bold mb-3">Reassign {label} <span class="font-mono text-sm opacity-50">{num}</span></h1>"#,
        back = back, id = id, label = label, num = esc(number.as_deref().unwrap_or("")));
    Html(page_shell(&sidebar, "Reassign", &form_page(&format!("/sesb-eam/reassign/{model}/{id}"), &header, &body))).into_response()
}

async fn reassign_apply(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path((model, id)): Path<(String, Uuid)>, Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (table, back, _label) = match reassign_target(&model) { Some(t) => t, None => return (StatusCode::BAD_REQUEST, "Unknown model").into_response() };
    let new_kawasan = match opt_uuid(&form, "responsible_kawasan_id") { Some(k) => k, None => return bad("Responsible kawasan is required") };
    let reason = match opt_str(&form, "reason") { Some(r) => r.clone(), None => return bad("A reason is required (§5.5)") };
    let new_assignee = opt_uuid(&form, "assigned_to");

    // Eligibility: a field-agent assignee must cover the target kawasan.
    if let Some(uid) = new_assignee {
        let is_agent: bool = vortex_plugin_sdk::sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM eam_field_agent WHERE user_id=$1)").bind(uid).fetch_one(&db).await.unwrap_or(false);
        if is_agent {
            let covers: bool = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM eam_field_agent a JOIN eam_field_agent_kawasan_rel r ON r.agent_id=a.id WHERE a.user_id=$1 AND r.kawasan_id=$2)")
                .bind(uid).bind(new_kawasan).fetch_one(&db).await.unwrap_or(false);
            if !covers {
                return (StatusCode::CONFLICT, "That field agent does not cover the target kawasan (§5.5). Choose another assignee or a planner/engineer.".to_string()).into_response();
            }
        }
    }

    // responsible_region derives from the kawasan; is_cross_boundary = responsible != native.
    let sql = format!(
        "UPDATE {t} SET responsible_kawasan_id=$2, \
            responsible_region_id=(SELECT COALESCE(k.region_id, z.region_id) FROM eam_kawasan k LEFT JOIN eam_zon z ON z.id=k.zon_id WHERE k.id=$2), \
            is_cross_boundary=(kawasan_id IS DISTINCT FROM $2), \
            reassignment_reason=$3, reassigned_by_id=$4, reassigned_date=NOW(), reassignment_count=reassignment_count+1{assign} WHERE id=$1",
        t = table, assign = if new_assignee.is_some() { ", assigned_to=$5" } else { "" });
    let q = vortex_plugin_sdk::sqlx::query(&sql).bind(id).bind(new_kawasan).bind(&reason).bind(user.id);
    let q = if let Some(a) = new_assignee { q.bind(a) } else { q };
    if let Err(e) = q.execute(&db).await { return bad(&format!("Failed: {e}")); }

    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated, vortex_plugin_sdk::security::AuditSeverity::Info,
    ).with_user(vortex_plugin_sdk::common::UserId(user.id)).with_username(&user.username)
     .with_database(&db_ctx.db_name).with_resource(table, id.to_string())
     .with_details(json!({"action": "reassign_boundary", "responsible_kawasan_id": new_kawasan, "reason": reason}));
    let _ = state.audit.log(entry).await;
    Redirect::to(&format!("{back}/{id}")).into_response()
}

/// Helper kept for the reassign chooser (delegates to the shared kawasan opts).
async fn kawasan_options(db: &PgPool, sel: Option<Uuid>) -> String {
    super::kawasan_options(db, sel).await
}
