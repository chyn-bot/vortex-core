//! Vortex Intake — governed public web-forms.
//!
//! Intake accepts data from *outside* the trust boundary: a `web_form` publishes
//! a chosen subset of a model's fields at a public URL, and a logged-out visitor
//! submits it. Every public write is treated as hostile by construction:
//!
//! 1. A **signed nonce** (HMAC over slug+timestamp) + a **honeypot** + a
//!    min-fill-time gate the POST against CSRF/replay and dumb bots — the
//!    running app has no other CSRF protection, so the public surface brings its
//!    own (see `sign_nonce`/`verify_nonce`).
//! 2. The **field allow-list** is the security seam: only the fields the form
//!    declares are writable, so a submitter can never set `record_state`, an
//!    internal price, `company_id`, or any column the form didn't publish. This
//!    closes mass-assignment.
//! 3. Tenant/owner are **stamped server-side** (`company_id` from the form,
//!    default `record_state` from `record_stages`); the client never supplies
//!    them. Anonymous rows carry `created_by = NULL`.
//! 4. Every accepted submission is **WORM-audited** (`intake_submitted`).
//!
//! The target is any `ir_model.name` — compiled or Blueprint (`x_`) — so Intake
//! reuses the same catalog-typed INSERT the authed generic form uses.

use crate::state::AppState;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;
use vortex_security::{AuditAction, AuditEntry, AuditSeverity};

/// Hidden control fields a form posts that are never record data.
pub const TS_FIELD: &str = "_ts";
pub const NONCE_FIELD: &str = "_nonce";
pub const HONEYPOT_FIELD: &str = "_hp";
const CONTROL_FIELDS: &[&str] = &[TS_FIELD, NONCE_FIELD, HONEYPOT_FIELD];

/// A nonce younger than this (seconds) is a bot submitting instantly.
pub const MIN_FILL_SECS: i64 = 2;
/// A nonce older than this (seconds) is stale/replayed — reload required.
pub const MAX_AGE_SECS: i64 = 3600;

fn dberr(e: sqlx::Error) -> String {
    format!("database error: {e}")
}

/// Constant-time compare so nonce verification doesn't leak via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// One published field in a form's allow-list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub label: String,
    #[serde(default)]
    pub help: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// A public form definition, loaded from `web_form`.
#[derive(Debug, Clone)]
pub struct WebForm {
    pub id: Uuid,
    pub slug: String,
    pub model: String,
    pub title: String,
    pub description: Option<String>,
    pub fields: Vec<FormField>,
    pub company_id: Option<Uuid>,
    pub success_msg: Option<String>,
    pub origins: Vec<String>,
}

/// Sign a form nonce: `HMAC(master_key, "<slug>|<issued_at>")`. Stateless — the
/// timestamp travels in the form and the tag proves it was issued by us.
pub fn sign_nonce(slug: &str, issued_at: i64) -> String {
    let msg = format!("{slug}|{issued_at}");
    vortex_security::crypto::hmac_sha256_hex(&vortex_security::crypto::master_key(), msg.as_bytes())
}

/// Verify a posted nonce: the tag must match and the age must be within
/// `[MIN_FILL_SECS, MAX_AGE_SECS]` (too fast ⇒ bot, too old ⇒ replay/stale).
pub fn verify_nonce(slug: &str, issued_at: i64, token: &str, now: i64) -> Result<(), String> {
    let expected = sign_nonce(slug, issued_at);
    if !ct_eq(expected.as_bytes(), token.as_bytes()) {
        return Err("This form token is invalid — please reload the page and try again.".into());
    }
    let age = now - issued_at;
    if age < MIN_FILL_SECS {
        return Err("That was too fast — please try again.".into());
    }
    if age > MAX_AGE_SECS {
        return Err("This form has expired — please reload the page and try again.".into());
    }
    Ok(())
}

/// The honeypot must be empty. A real user never sees or fills it.
pub fn honeypot_ok(submitted: &BTreeMap<String, String>) -> bool {
    submitted
        .get(HONEYPOT_FIELD)
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
}

/// Intersect the submitted values with the form's field allow-list. Control
/// fields are dropped; any *other* key that isn't published is rejected loud
/// (not silently ignored) so a mass-assignment attempt is a visible error.
pub fn select_writable(
    allow: &[FormField],
    submitted: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let allowset: HashSet<&str> = allow.iter().map(|f| f.name.as_str()).collect();
    let mut out = BTreeMap::new();
    for (k, v) in submitted {
        if CONTROL_FIELDS.contains(&k.as_str()) {
            continue;
        }
        if !allowset.contains(k.as_str()) {
            return Err(format!("Unexpected field '{k}'."));
        }
        out.insert(k.clone(), v.clone());
    }
    Ok(out)
}

/// Labels of required fields that are absent or blank in the submission.
pub fn missing_required(allow: &[FormField], writable: &BTreeMap<String, String>) -> Vec<String> {
    allow
        .iter()
        .filter(|f| {
            f.required
                && writable
                    .get(&f.name)
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
        })
        .map(|f| f.label.clone())
        .collect()
}

/// Load an active form by slug, parsing its allow-list and settings.
pub async fn fetch_form(db: &PgPool, slug: &str) -> Option<WebForm> {
    let row = sqlx::query(
        "SELECT id, slug, model, title, description, fields, settings, company_id
         FROM web_form WHERE slug = $1 AND active = true",
    )
    .bind(slug)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    let fields: Vec<FormField> =
        serde_json::from_value(row.get("fields")).unwrap_or_default();
    let settings: serde_json::Value = row.get("settings");
    let origins = settings
        .get("origins")
        .and_then(|o| o.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Some(WebForm {
        id: row.get("id"),
        slug: row.get("slug"),
        model: row.get("model"),
        title: row.get("title"),
        description: row.get("description"),
        fields,
        company_id: row.get("company_id"),
        success_msg: settings
            .get("success_msg")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        origins,
    })
}

/// The model's first status stage (lowest sequence), used to default
/// `record_state` on an intake row when the model uses the status bar.
async fn default_stage(db: &PgPool, model: &str) -> Option<String> {
    sqlx::query_scalar("SELECT code FROM record_stages WHERE model = $1 ORDER BY sequence ASC LIMIT 1")
        .bind(model)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Write an accepted submission: a catalog-typed INSERT restricted to the
/// allow-listed values, with `company_id` and default `record_state` stamped
/// server-side, then the submission ledger row and a WORM audit entry. Returns
/// the new record id. `writable` must already be allow-listed + required-checked.
pub async fn submit(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    form: &WebForm,
    writable: &BTreeMap<String, String>,
    source_ip: Option<String>,
) -> Result<Uuid, String> {
    // Resolve the target table (server-side, from the form's model — the client
    // never names it).
    let table: String = sqlx::query_scalar(
        "SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true",
    )
    .bind(&form.model)
    .fetch_optional(db)
    .await
    .map_err(dberr)?
    .ok_or("This form's target model is unavailable.")?;
    if !valid_ident(&table) {
        return Err("Invalid form target.".into());
    }

    // Real columns + their udt, for type-correct casts.
    let cols: HashMap<String, String> = sqlx::query(
        "SELECT column_name, udt_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(&table)
    .fetch_all(db)
    .await
    .map_err(dberr)?
    .iter()
    .map(|r| (r.get::<String, _>("column_name"), r.get::<String, _>("udt_name")))
    .collect();

    let mut names: Vec<String> = Vec::new();
    let mut placeholders: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let mut i = 1;
    for (k, v) in writable {
        // Only real columns (belt-and-suspenders on top of the allow-list) with
        // a validated identifier are ever interpolated into the statement.
        if let Some(udt) = cols.get(k) {
            if !valid_ident(k) {
                return Err(format!("Invalid field '{k}'."));
            }
            names.push(k.clone());
            placeholders.push(format!("${i}::{udt}"));
            values.push(v.clone());
            i += 1;
        }
    }
    if names.is_empty() {
        return Err("Nothing to submit.".into());
    }

    // Server-side stamps — never from the request body.
    if let Some(cid) = form.company_id {
        if cols.contains_key("company_id") {
            names.push("company_id".into());
            placeholders.push(format!("${i}::uuid"));
            values.push(cid.to_string());
            i += 1;
        }
    }
    if cols.contains_key("record_state") {
        if let Some(stage) = default_stage(db, &form.model).await {
            names.push("record_state".into());
            placeholders.push(format!("${i}::varchar"));
            values.push(stage);
            i += 1;
        }
    }

    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({}) RETURNING id",
        names.join(", "),
        placeholders.join(", ")
    );
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql);
    for v in &values {
        q = q.bind(v);
    }
    let record_id: Uuid = q.fetch_one(db).await.map_err(|_| {
        "One or more values are not valid for their field. Please check and try again.".to_string()
    })?;

    sqlx::query(
        "INSERT INTO web_form_submission (form_id, record_id, status, source_ip)
         VALUES ($1, $2, 'accepted', $3::inet)",
    )
    .bind(form.id)
    .bind(record_id)
    .bind(&source_ip)
    .execute(db)
    .await
    .map_err(dberr)?;

    // Anonymous WORM audit: no user_id (nullable FK), denormalized username.
    let entry = AuditEntry::new(AuditAction::Custom("intake_submitted".into()), AuditSeverity::Info)
        .with_database(db_name)
        .with_username("anonymous-intake")
        .with_resource(&form.model, &record_id.to_string())
        .with_details(serde_json::json!({ "form": form.slug, "source_ip": source_ip }));
    if let Err(e) = state.audit.log(entry).await {
        tracing::error!(form = form.slug, error = %e, "intake audit write failed");
    }

    Ok(record_id)
}

// ===========================================================================
// Admin side — create / edit / list / delete form definitions.
// ===========================================================================

/// A slug is a URL segment: `[a-z0-9](-?[a-z0-9])*`, 2–64 chars.
pub fn valid_slug(s: &str) -> bool {
    let n = s.len();
    n >= 2
        && n <= 64
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
}

/// Row for the admin list.
pub struct FormSummary {
    pub id: Uuid,
    pub slug: String,
    pub model: String,
    pub title: String,
    pub active: bool,
    pub fields: i64,
    pub submissions: i64,
}

/// The model's exposable fields (registered, non-system) — the candidate
/// allow-list an admin picks from. Returns `(name, label, field_type)`.
pub async fn exposable_fields(db: &PgPool, model: &str) -> Vec<(String, String, String)> {
    sqlx::query(
        "SELECT f.name, f.display_name, f.field_type
         FROM ir_model_field f JOIN ir_model m ON m.id = f.model_id
         WHERE m.name = $1
           AND f.name NOT IN ('id','company_id','active','created_at','updated_at','record_state','code')
         ORDER BY f.sequence, f.name",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| (r.get("name"), r.get("display_name"), r.get("field_type")))
    .collect()
}

/// Create a form. Every exposable field of the model is published by default
/// (not required); the admin refines the allow-list on the edit page.
pub async fn create_form(
    db: &PgPool,
    user_id: Uuid,
    slug: &str,
    model: &str,
    title: &str,
    description: &str,
) -> Result<Uuid, String> {
    if !valid_slug(slug) {
        return Err("Slug must be 2–64 chars, lowercase letters/digits/hyphens.".into());
    }
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1 AND is_active = true")
        .bind(model)
        .fetch_optional(db)
        .await
        .map_err(dberr)?;
    if exists.is_none() {
        return Err(format!("Model '{model}' not found."));
    }
    let dup: Option<Uuid> = sqlx::query_scalar("SELECT id FROM web_form WHERE slug = $1")
        .bind(slug)
        .fetch_optional(db)
        .await
        .map_err(dberr)?;
    if dup.is_some() {
        return Err(format!("A form with slug '{slug}' already exists."));
    }

    let fields: Vec<FormField> = exposable_fields(db, model)
        .await
        .into_iter()
        .map(|(name, label, _)| FormField { name, label, help: None, required: false })
        .collect();
    let fields_json = serde_json::to_value(&fields).unwrap_or_else(|_| serde_json::json!([]));
    // Stamp the tenant's primary company so submissions are attributable.
    let company_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM companies ORDER BY created_at LIMIT 1")
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO web_form (slug, model, title, description, fields, company_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(slug)
    .bind(model)
    .bind(title)
    .bind(if description.trim().is_empty() { None } else { Some(description) })
    .bind(&fields_json)
    .bind(company_id)
    .bind(user_id)
    .fetch_one(db)
    .await
    .map_err(dberr)?;
    Ok(id)
}

/// List all forms with field + submission counts.
pub async fn list_forms(db: &PgPool) -> Vec<FormSummary> {
    sqlx::query(
        "SELECT w.id, w.slug, w.model, w.title, w.active,
                jsonb_array_length(w.fields) AS fields,
                (SELECT COUNT(*) FROM web_form_submission s WHERE s.form_id = w.id) AS submissions
         FROM web_form w ORDER BY w.created_at DESC",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| FormSummary {
        id: r.get("id"),
        slug: r.get("slug"),
        model: r.get("model"),
        title: r.get("title"),
        active: r.get("active"),
        fields: r.get::<Option<i32>, _>("fields").unwrap_or(0) as i64,
        submissions: r.get("submissions"),
    })
    .collect()
}

/// Load a form's full definition for editing (any status, unlike `fetch_form`).
pub async fn load_form(db: &PgPool, id: Uuid) -> Option<(WebForm, bool)> {
    let row = sqlx::query(
        "SELECT id, slug, model, title, description, fields, settings, company_id, active
         FROM web_form WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    let fields: Vec<FormField> = serde_json::from_value(row.get("fields")).unwrap_or_default();
    let settings: serde_json::Value = row.get("settings");
    let origins = settings
        .get("origins")
        .and_then(|o| o.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Some((
        WebForm {
            id: row.get("id"),
            slug: row.get("slug"),
            model: row.get("model"),
            title: row.get("title"),
            description: row.get("description"),
            fields,
            company_id: row.get("company_id"),
            success_msg: settings.get("success_msg").and_then(|v| v.as_str()).map(str::to_string),
            origins,
        },
        row.get("active"),
    ))
}

/// Update a form's allow-list + settings + active flag.
pub async fn update_form(
    db: &PgPool,
    id: Uuid,
    fields: &[FormField],
    success_msg: &str,
    origins: &[String],
    active: bool,
) -> Result<(), String> {
    let fields_json = serde_json::to_value(fields).map_err(|e| format!("serialize fields: {e}"))?;
    let settings = serde_json::json!({
        "success_msg": success_msg,
        "origins": origins,
    });
    sqlx::query(
        "UPDATE web_form SET fields = $2, settings = $3, active = $4, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&fields_json)
    .bind(&settings)
    .bind(active)
    .execute(db)
    .await
    .map_err(dberr)?;
    Ok(())
}

/// Delete a form (and its submission ledger via ON DELETE CASCADE).
pub async fn delete_form(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM web_form WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(dberr)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rules() {
        for ok in ["contact", "job-app", "rma-2026", "ab"] {
            assert!(valid_slug(ok), "{ok} should be valid");
        }
        for bad in ["a", "-x", "x-", "x--y", "Contact", "a_b", "with space", ""] {
            assert!(!valid_slug(bad), "{bad} should be invalid");
        }
    }

    fn f(name: &str, required: bool) -> FormField {
        FormField { name: name.into(), label: name.into(), help: None, required }
    }
    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn nonce_round_trips_and_rejects_tamper_and_age() {
        let tok = sign_nonce("contact", 1000);
        assert!(verify_nonce("contact", 1000, &tok, 1010).is_ok()); // 10s old — fine
        assert!(verify_nonce("contact", 1000, "deadbeef", 1010).is_err()); // bad tag
        assert!(verify_nonce("other", 1000, &tok, 1010).is_err()); // slug mismatch
        assert!(verify_nonce("contact", 1000, &tok, 1000).is_err()); // too fast (<2s)
        assert!(verify_nonce("contact", 1000, &tok, 1000 + MAX_AGE_SECS + 1).is_err()); // stale
    }

    #[test]
    fn honeypot_must_be_empty() {
        assert!(honeypot_ok(&map(&[])));
        assert!(honeypot_ok(&map(&[(HONEYPOT_FIELD, "  ")])));
        assert!(!honeypot_ok(&map(&[(HONEYPOT_FIELD, "http://spam")])));
    }

    #[test]
    fn allow_list_drops_control_and_rejects_extras() {
        let allow = vec![f("name", true), f("email", false)];
        let ok = select_writable(
            &allow,
            &map(&[("name", "A"), ("email", "a@b.c"), (TS_FIELD, "1"), (NONCE_FIELD, "x")]),
        )
        .unwrap();
        assert_eq!(ok.len(), 2); // control fields dropped
        // A field not on the allow-list (e.g. an injected internal column) is rejected loud.
        assert!(select_writable(&allow, &map(&[("name", "A"), ("record_state", "done")])).is_err());
    }

    #[test]
    fn missing_required_reports_blank_and_absent() {
        let allow = vec![f("name", true), f("email", true), f("note", false)];
        let miss = missing_required(&allow, &map(&[("name", "A"), ("email", "  ")]));
        assert_eq!(miss, vec!["email".to_string()]); // blank required; note not required
    }
}
