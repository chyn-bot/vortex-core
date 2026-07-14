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
use vortex_security::{AuditAction, AuditEntry, AuditLog, AuditSeverity};

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
    /// Hold submissions for admin review instead of writing the record now.
    pub quarantine: bool,
    /// Email to notify on each new submission (best-effort, via the job queue).
    pub notify_to: Option<String>,
    /// Max accepted+quarantined submissions per calendar day (0/None = no cap).
    pub daily_cap: Option<i64>,
    /// Also offered to signed-in customer-portal users (Phase 3).
    pub portal: bool,
    /// Target column that receives the portal submitter's partner id (owner
    /// stamping). Validated identifier; only stamped for portal submissions.
    pub partner_field: Option<String>,
    /// File-upload fields (Phase 4). Distinct from `fields` — a file is stored
    /// via the FileStore and linked as an `ir_attachment` on the record, never
    /// written as a column, so these never touch the column allow-list.
    pub attach_fields: Vec<FormField>,
    /// Max size per uploaded file, in MB (defaults to `DEFAULT_MAX_UPLOAD_MB`).
    pub attach_max_mb: i64,
    /// Accepted upload types: lowercase extensions (".pdf") and/or MIME globs
    /// ("image/*", "application/pdf"). Empty = a safe built-in default set.
    pub attach_accept: Vec<String>,
    /// Require a solved CAPTCHA challenge on the public path. Only enforced when
    /// a provider is configured globally (`[captcha]`); otherwise inert.
    pub captcha: bool,
}

/// Default per-file upload ceiling when a form doesn't set one.
pub const DEFAULT_MAX_UPLOAD_MB: i64 = 10;

/// The governance knobs parsed out of a form's `settings` JSONB.
struct ParsedSettings {
    success_msg: Option<String>,
    origins: Vec<String>,
    quarantine: bool,
    notify_to: Option<String>,
    daily_cap: Option<i64>,
    portal: bool,
    partner_field: Option<String>,
    attach_fields: Vec<FormField>,
    attach_max_mb: i64,
    attach_accept: Vec<String>,
    captcha: bool,
}

fn parse_settings(settings: &serde_json::Value) -> ParsedSettings {
    let str_opt = |k: &str| {
        settings.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
    };
    let attach = settings.get("attachments");
    let attach_fields: Vec<FormField> = attach
        .and_then(|a| a.get("fields"))
        .and_then(|f| serde_json::from_value(f.clone()).ok())
        .unwrap_or_default();
    let attach_max_mb = attach
        .and_then(|a| a.get("max_mb"))
        .and_then(|v| v.as_i64())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_UPLOAD_MB);
    let attach_accept: Vec<String> = attach
        .and_then(|a| a.get("accept"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_lowercase())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    ParsedSettings {
        success_msg: settings.get("success_msg").and_then(|v| v.as_str()).map(str::to_string),
        origins: settings
            .get("origins")
            .and_then(|o| o.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        quarantine: settings.get("quarantine").and_then(|v| v.as_bool()).unwrap_or(false),
        notify_to: str_opt("notify_to"),
        daily_cap: settings.get("daily_cap").and_then(|v| v.as_i64()).filter(|n| *n > 0),
        attach_fields,
        attach_max_mb,
        attach_accept,
        portal: settings.get("portal").and_then(|v| v.as_bool()).unwrap_or(false),
        partner_field: str_opt("partner_field").filter(|s| valid_ident(s)),
        captcha: settings.get("captcha").and_then(|v| v.as_bool()).unwrap_or(false),
    }
}

/// The outcome of a public submission.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// Record written immediately; carries the new record id.
    Accepted(Uuid),
    /// Held for review; carries the submission id.
    Quarantined(Uuid),
    /// The form's daily cap was reached — nothing was written.
    Capped,
}

/// Who is submitting — decides owner stamping, ledger attribution, and audit
/// identity. Public (`/i/{slug}`) is anonymous; the customer portal (Phase 3)
/// submits as the signed-in partner.
pub enum Submitter {
    /// Logged-out public visitor: no owner, `created_by` NULL, anon audit.
    Anonymous,
    /// Signed-in portal user: owner = their partner, real attribution.
    Portal { user_id: Uuid, partner_id: Uuid, username: String },
}

impl Submitter {
    fn partner_id(&self) -> Option<Uuid> {
        match self {
            Submitter::Portal { partner_id, .. } => Some(*partner_id),
            Submitter::Anonymous => None,
        }
    }
    fn user_id(&self) -> Option<Uuid> {
        match self {
            Submitter::Portal { user_id, .. } => Some(*user_id),
            Submitter::Anonymous => None,
        }
    }
}

/// Server-side owner stamps applied to the target record — never client-supplied.
/// `created_by`/`partner_field` are only set for an attributable (portal)
/// submission or its later approval.
#[derive(Default)]
struct OwnerStamp {
    created_by: Option<Uuid>,
    /// `(column, value)` — the form's `partner_field` set to the partner id.
    partner: Option<(String, Uuid)>,
}

impl OwnerStamp {
    /// Derive the stamps for a submitter against a form's `partner_field`.
    fn for_submitter(sub: &Submitter, form: &WebForm) -> Self {
        match sub {
            Submitter::Anonymous => OwnerStamp::default(),
            Submitter::Portal { user_id, partner_id, .. } => OwnerStamp {
                created_by: Some(*user_id),
                partner: form.partner_field.clone().map(|f| (f, *partner_id)),
            },
        }
    }
}

// ===========================================================================
// Attachments (Phase 4) — policy-bounded file uploads, FileStore-backed.
// ===========================================================================

/// A raw uploaded file parsed from a multipart submission (pre-validation).
pub struct RawUpload {
    pub field: String,
    pub filename: String,
    pub mime: String,
    pub data: Vec<u8>,
}

/// A stored upload, recorded on the submission and linked as an `ir_attachment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUpload {
    pub key: String,
    pub name: String,
    pub size: i64,
    pub mime: String,
    pub checksum: String,
}

/// Strip any path components and keep a filesystem-safe basename.
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches(['.', '_']).to_string();
    if trimmed.is_empty() { "upload".to_string() } else { trimmed.chars().take(120).collect() }
}

/// Does `mime`/`filename` satisfy the form's accept list? An empty list means a
/// safe built-in default (common documents + images); otherwise a rule matches
/// if it equals the mime, is a `type/*` glob prefix, or a matching `.ext`.
pub fn upload_accepted(form: &WebForm, mime: &str, filename: &str) -> bool {
    const DEFAULT_ACCEPT: &[&str] = &[
        "application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp",
        "text/plain", "text/csv",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ];
    let mime = mime.to_lowercase();
    let fname = filename.to_lowercase();
    let rule_matches = |rule: &str| -> bool {
        if let Some(prefix) = rule.strip_suffix("/*") {
            mime.starts_with(&format!("{prefix}/"))
        } else if let Some(ext) = rule.strip_prefix('.') {
            fname.ends_with(&format!(".{ext}"))
        } else {
            mime == rule
        }
    };
    if form.attach_accept.is_empty() {
        DEFAULT_ACCEPT.iter().any(|r| mime == *r)
    } else {
        form.attach_accept.iter().any(|r| rule_matches(r))
    }
}

/// Validate one upload against the form's size + type policy. `Ok(())` to store.
pub fn validate_upload(form: &WebForm, up: &RawUpload) -> Result<(), String> {
    if up.data.is_empty() {
        return Err(format!("'{}' is empty.", up.filename));
    }
    let max_bytes = form.attach_max_mb.max(1) * 1024 * 1024;
    if up.data.len() as i64 > max_bytes {
        return Err(format!("'{}' exceeds the {} MB limit.", up.filename, form.attach_max_mb));
    }
    if !upload_accepted(form, &up.mime, &up.filename) {
        return Err(format!("'{}' is not an accepted file type.", up.filename));
    }
    Ok(())
}

/// Required file fields with no uploaded file (by field name).
pub fn missing_required_files(form: &WebForm, present: &HashSet<String>) -> Vec<String> {
    form.attach_fields
        .iter()
        .filter(|f| f.required && !present.contains(&f.name))
        .map(|f| f.label.clone())
        .collect()
}

/// Screen every upload with the configured scanner *before* anything is stored.
/// An infected file (or, when the scanner fails closed, an unscannable one) is
/// rejected with a user-facing message; the offending file/signature is logged.
pub async fn screen_uploads(
    scanner: &dyn crate::antivirus::AvScanner,
    raws: &[RawUpload],
) -> Result<(), String> {
    use crate::antivirus::AvVerdict;
    if !scanner.is_active() {
        return Ok(());
    }
    for r in raws {
        match scanner.scan(&r.data).await {
            Ok(AvVerdict::Clean) => {}
            Ok(AvVerdict::Infected(sig)) => {
                tracing::warn!(file = %r.filename, signature = %sig, "intake upload blocked by AV");
                return Err(format!("'{}' failed a security scan and was rejected.", r.filename));
            }
            Err(e) => {
                tracing::warn!(file = %r.filename, error = %e, "intake upload could not be scanned");
                return Err(format!(
                    "'{}' could not be security-scanned right now. Please try again later.",
                    r.filename
                ));
            }
        }
    }
    Ok(())
}

/// Insert `ir_attachment` rows linking already-stored blobs to a record.
async fn link_attachments(
    db: &PgPool,
    model: &str,
    record_id: Uuid,
    uploads: &[StoredUpload],
    created_by: Option<Uuid>,
) -> Result<(), String> {
    for u in uploads {
        sqlx::query(
            "INSERT INTO ir_attachment
                 (name, res_model, res_id, store_fname, file_size, mimetype, checksum, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&u.name)
        .bind(model)
        .bind(record_id)
        .bind(&u.key)
        .bind(u.size)
        .bind(&u.mime)
        .bind(&u.checksum)
        .bind(created_by)
        .execute(db)
        .await
        .map_err(dberr)?;
    }
    Ok(())
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
    Some(web_form_from_row(&row, fields, parse_settings(&settings)))
}

/// Build a `WebForm` from a `web_form` row + its parsed settings. The row must
/// carry `id, slug, model, title, description, company_id`.
fn web_form_from_row(row: &sqlx::postgres::PgRow, fields: Vec<FormField>, s: ParsedSettings) -> WebForm {
    WebForm {
        id: row.get("id"),
        slug: row.get("slug"),
        model: row.get("model"),
        title: row.get("title"),
        description: row.get("description"),
        fields,
        company_id: row.get("company_id"),
        success_msg: s.success_msg,
        origins: s.origins,
        quarantine: s.quarantine,
        notify_to: s.notify_to,
        daily_cap: s.daily_cap,
        portal: s.portal,
        partner_field: s.partner_field,
        attach_fields: s.attach_fields,
        attach_max_mb: s.attach_max_mb,
        attach_accept: s.attach_accept,
        captcha: s.captcha,
    }
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

/// Catalog-typed INSERT into the form's target model, restricted to the
/// allow-listed values, with `company_id` and default `record_state` stamped
/// server-side. Returns the new record id. `writable` must already be
/// allow-listed + required-checked. This is the single write path shared by an
/// immediate submission and a later quarantine approval.
async fn insert_target_record(
    db: &PgPool,
    form: &WebForm,
    writable: &BTreeMap<String, String>,
    stamp: &OwnerStamp,
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
    // Owner stamps (portal submissions / their approvals). `created_by` and the
    // configured partner column are set from the trusted actor, never the body.
    if let Some(uid) = stamp.created_by {
        if cols.contains_key("created_by") && !names.iter().any(|n| n == "created_by") {
            names.push("created_by".into());
            placeholders.push(format!("${i}::uuid"));
            values.push(uid.to_string());
            i += 1;
        }
    }
    if let Some((col, pid)) = &stamp.partner {
        // `partner_field` was validated as an identifier at parse time; only
        // stamp it if it is a real column not already written by the allow-list.
        if let Some(udt) = cols.get(col) {
            if valid_ident(col) && !names.iter().any(|n| n == col) {
                names.push(col.clone());
                placeholders.push(format!("${i}::{udt}"));
                values.push(pid.to_string());
                i += 1;
            }
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
    q.fetch_one(db).await.map_err(|_| {
        "One or more values are not valid for their field. Please check and try again.".to_string()
    })
}

/// Count today's non-rejected submissions for a form (for the daily cap).
async fn daily_count(db: &PgPool, form_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM web_form_submission
         WHERE form_id = $1 AND status <> 'rejected' AND created_at >= date_trunc('day', now())",
    )
    .bind(form_id)
    .fetch_one(db)
    .await
    .unwrap_or(0)
}

/// Enqueue a best-effort new-submission notification email (rides the durable
/// job queue; SMTP outages never block the submitter).
async fn notify_submission(state: &AppState, db_name: &str, form: &WebForm, held: bool) {
    let Some(to) = form.notify_to.as_deref() else { return };
    let subject = if held {
        format!("New Intake submission awaiting review: {}", form.title)
    } else {
        format!("New Intake submission: {}", form.title)
    };
    let review = if held {
        "\n\nIt is held for review — approve or reject it under Settings ▸ Intake Forms."
    } else {
        ""
    };
    let body = format!(
        "A new submission was received on the form \"{}\" (/i/{}).{}",
        form.title, form.slug, review
    );
    let job = crate::jobs::NewJob::new(
        "mail.send",
        serde_json::json!({ "to": to, "subject": subject, "text": body, "context": "intake" }),
    )
    .for_db(db_name)
    .trace("web_form", form.id.to_string());
    if let Err(e) = crate::jobs::enqueue(&state.db, job).await {
        tracing::warn!(form = form.slug, error = %e, "could not enqueue intake notification");
    }
}

/// Handle a validated submission from `submitter`. Enforces the daily cap, then
/// either writes the record immediately (`Accepted`) or holds it for review
/// (`Quarantined`) per the form's setting. Records the ledger row (with actor
/// attribution), a WORM audit entry, and a best-effort notification. `writable`
/// must already be allow-listed + required-checked.
pub async fn submit(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    form: &WebForm,
    writable: &BTreeMap<String, String>,
    source_ip: Option<String>,
    submitter: &Submitter,
    attachments: &[StoredUpload],
) -> Result<SubmitOutcome, String> {
    // Daily cap — counts today's accepted + quarantined submissions.
    if let Some(cap) = form.daily_cap {
        if daily_count(db, form.id).await >= cap {
            return Ok(SubmitOutcome::Capped);
        }
    }

    let payload = serde_json::to_value(writable).unwrap_or_else(|_| serde_json::json!({}));
    let attach_json = serde_json::to_value(attachments).unwrap_or_else(|_| serde_json::json!([]));
    let partner_id = submitter.partner_id();
    let submitted_by = submitter.user_id();

    if form.quarantine {
        // Hold for review: capture the payload + actor + stored blobs (linked to
        // the record only on approval), write NO record yet.
        let sub_id: Uuid = sqlx::query_scalar(
            "INSERT INTO web_form_submission
                 (form_id, record_id, status, source_ip, payload, partner_id, submitted_by, attachments)
             VALUES ($1, NULL, 'quarantined', $2::inet, $3, $4, $5, $6) RETURNING id",
        )
        .bind(form.id)
        .bind(&source_ip)
        .bind(&payload)
        .bind(partner_id)
        .bind(submitted_by)
        .bind(&attach_json)
        .fetch_one(db)
        .await
        .map_err(dberr)?;

        audit_submit(
            state, db_name, submitter, "intake_quarantined", AuditSeverity::Info,
            "web_form_submission", &sub_id.to_string(),
            serde_json::json!({ "form": form.slug, "model": form.model, "source_ip": source_ip,
                                "attachments": attachments.len() }),
        ).await;
        notify_submission(state, db_name, form, true).await;
        return Ok(SubmitOutcome::Quarantined(sub_id));
    }

    // Immediate write, with owner stamping for portal submissions.
    let stamp = OwnerStamp::for_submitter(submitter, form);
    let record_id = insert_target_record(db, form, writable, &stamp).await?;
    link_attachments(db, &form.model, record_id, attachments, submitted_by).await?;
    sqlx::query(
        "INSERT INTO web_form_submission
             (form_id, record_id, status, source_ip, payload, partner_id, submitted_by, attachments)
         VALUES ($1, $2, 'accepted', $3::inet, $4, $5, $6, $7)",
    )
    .bind(form.id)
    .bind(record_id)
    .bind(&source_ip)
    .bind(&payload)
    .bind(partner_id)
    .bind(submitted_by)
    .bind(&attach_json)
    .execute(db)
    .await
    .map_err(dberr)?;

    audit_submit(
        state, db_name, submitter, "intake_submitted", AuditSeverity::Info,
        &form.model, &record_id.to_string(),
        serde_json::json!({ "form": form.slug, "source_ip": source_ip }),
    ).await;
    notify_submission(state, db_name, form, false).await;
    Ok(SubmitOutcome::Accepted(record_id))
}

/// WORM audit for a submission, attributed to the actor: anonymous for public
/// (no user, denormalized username), the real portal user otherwise.
async fn audit_submit(
    state: &AppState,
    db_name: &str,
    submitter: &Submitter,
    code: &str,
    severity: AuditSeverity,
    resource_type: &str,
    resource_id: &str,
    details: serde_json::Value,
) {
    let mut entry = AuditEntry::new(AuditAction::Custom(code.into()), severity)
        .with_database(db_name)
        .with_resource(resource_type, resource_id)
        .with_details(details);
    entry = match submitter {
        Submitter::Anonymous => entry.with_username("anonymous-intake"),
        Submitter::Portal { user_id, username, .. } => {
            entry.with_user(vortex_common::UserId(*user_id)).with_username(username)
        }
    };
    if let Err(e) = state.audit.log(entry).await {
        tracing::error!(code, error = %e, "intake audit write failed");
    }
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
    let active: bool = row.get("active");
    Some((web_form_from_row(&row, fields, parse_settings(&settings)), active))
}

/// Settings an admin edits on the form page (the governance knobs).
pub struct FormSettings<'a> {
    pub success_msg: &'a str,
    pub origins: &'a [String],
    pub quarantine: bool,
    pub notify_to: &'a str,
    pub daily_cap: i64,
    pub active: bool,
    /// Offer this form to signed-in customer-portal users (Phase 3).
    pub portal: bool,
    /// Target column stamped with the portal submitter's partner id ("" = none).
    pub partner_field: &'a str,
    /// File-upload fields (Phase 4).
    pub attach_fields: &'a [FormField],
    pub attach_max_mb: i64,
    pub attach_accept: &'a [String],
    /// Require a solved CAPTCHA on the public path (only enforced when a
    /// provider is configured globally).
    pub captcha: bool,
}

/// Update a form's allow-list + settings + active flag.
pub async fn update_form(
    db: &PgPool,
    id: Uuid,
    fields: &[FormField],
    s: &FormSettings<'_>,
) -> Result<(), String> {
    let fields_json = serde_json::to_value(fields).map_err(|e| format!("serialize fields: {e}"))?;
    let partner_field = s.partner_field.trim();
    if !partner_field.is_empty() && !valid_ident(partner_field) {
        return Err("Partner field must be a valid column identifier.".into());
    }
    let settings = serde_json::json!({
        "success_msg": s.success_msg,
        "origins": s.origins,
        "quarantine": s.quarantine,
        "notify_to": s.notify_to.trim(),
        "daily_cap": s.daily_cap.max(0),
        "portal": s.portal,
        "partner_field": partner_field,
        "captcha": s.captcha,
        "attachments": {
            "fields": s.attach_fields,
            "max_mb": s.attach_max_mb.max(0),
            "accept": s.attach_accept,
        },
    });
    sqlx::query(
        "UPDATE web_form SET fields = $2, settings = $3, active = $4, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&fields_json)
    .bind(&settings)
    .bind(s.active)
    .execute(db)
    .await
    .map_err(dberr)?;
    Ok(())
}

/// Delete a form (and its submission ledger via ON DELETE CASCADE).
///
/// Before the cascade drops the submission rows — which is the only place a
/// held-but-unlinked blob key survives — this proactively deletes the blobs of
/// every **non-`accepted`** submission. An `accepted` submission's blobs are
/// linked to a live governed record via `ir_attachment` (the record outlives
/// the form), so they must not be swept; the defensive reference check inside
/// [`purge_unlinked_blobs`] is a second guard. Without this, deleting a form
/// would strand every quarantined/rejected blob with no DB row left to find it.
pub async fn delete_form(
    files: &dyn crate::files::FileStore,
    db: &PgPool,
    db_name: &str,
    id: Uuid,
) -> Result<(), String> {
    // Gather blobs from non-accepted submissions before the cascade removes them.
    let held: Vec<Option<serde_json::Value>> = sqlx::query_scalar(
        "SELECT attachments FROM web_form_submission \
         WHERE form_id = $1 AND status <> 'accepted' \
           AND attachments IS NOT NULL AND jsonb_array_length(attachments) > 0",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(dberr)?;
    for attach in held {
        let uploads: Vec<StoredUpload> =
            attach.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        purge_unlinked_blobs(files, db, db_name, &uploads).await;
    }

    sqlx::query("DELETE FROM web_form WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(dberr)?;
    Ok(())
}

// ===========================================================================
// Orphaned-blob sweep — reclaim FileStore blobs no live record references.
// ===========================================================================

/// Grace period (days) a rejected submission's blobs are retained before the
/// sweep reclaims them — a window in which an operator can still inspect what a
/// rejected submission tried to attach. Override with
/// `VORTEX_INTAKE_BLOB_GRACE_DAYS` (0 = sweep as soon as the next run fires).
pub fn blob_grace_days() -> i64 {
    std::env::var("VORTEX_INTAKE_BLOB_GRACE_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|d| *d >= 0)
        .unwrap_or(7)
}

/// Delete the FileStore blobs behind `uploads`, skipping any key still
/// referenced by an `ir_attachment` row — a linked blob belongs to a live
/// record and must never be reclaimed. Returns how many blobs were deleted.
/// Best-effort: a failed blob delete is logged and the key is left in place
/// (it will be retried on the next run) rather than aborting the batch.
async fn purge_unlinked_blobs(
    files: &dyn crate::files::FileStore,
    db: &PgPool,
    db_name: &str,
    uploads: &[StoredUpload],
) -> u64 {
    let mut deleted = 0u64;
    for u in uploads {
        // Never reclaim a blob a live record still points at.
        let referenced = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM ir_attachment WHERE store_fname = $1 LIMIT 1",
        )
        .bind(&u.key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .is_some();
        if referenced {
            continue;
        }
        match files.delete(db_name, &u.key).await {
            Ok(()) => deleted += 1,
            Err(e) => tracing::warn!(error = %e, key = %u.key, "intake sweep: blob delete failed"),
        }
    }
    deleted
}

/// Sweep orphaned attachment blobs left behind by rejected quarantine
/// submissions.
///
/// When a quarantined submission is **rejected**, no record is ever created, so
/// the blobs stored at submit time are never linked to an `ir_attachment` and
/// would otherwise sit in the FileStore forever. This finds rejected
/// submissions older than `grace_days` that still carry attachment metadata,
/// deletes each stored blob (skipping any still referenced by a live record —
/// defensive), then clears the metadata so the row isn't reconsidered next run.
/// The submission row itself — and its WORM-audited rejection — is preserved;
/// only the now-dangling blob pointers are dropped. Returns the number of blobs
/// deleted.
///
/// This is DB-driven: it reclaims blobs whose keys are still recorded on a
/// submission row. Blobs stranded by a store-then-DB-failure (a key that was
/// never persisted anywhere) are outside its reach and would need a FileStore
/// enumeration to find — an accepted limitation, since the FileStore contract
/// has no `list`.
pub async fn sweep_orphaned_attachments(
    files: &dyn crate::files::FileStore,
    db: &PgPool,
    db_name: &str,
    grace_days: i64,
) -> u64 {
    let rows: Vec<(Uuid, Option<serde_json::Value>)> = match sqlx::query_as(
        "SELECT id, attachments FROM web_form_submission \
         WHERE status = 'rejected' \
           AND attachments IS NOT NULL \
           AND jsonb_array_length(attachments) > 0 \
           AND reviewed_at < NOW() - make_interval(days => $1)",
    )
    .bind(grace_days.max(0) as i32)
    .fetch_all(db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, %db_name, "intake sweep: query failed");
            return 0;
        }
    };

    let mut deleted = 0u64;
    for (sub_id, attach) in rows {
        let uploads: Vec<StoredUpload> =
            attach.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        if uploads.is_empty() {
            continue;
        }
        deleted += purge_unlinked_blobs(files, db, db_name, &uploads).await;
        // Clear the pointers so this row isn't swept again. Best-effort: if the
        // update fails, the reference check keeps the next run from double-deleting.
        if let Err(e) =
            sqlx::query("UPDATE web_form_submission SET attachments = '[]'::jsonb WHERE id = $1")
                .bind(sub_id)
                .execute(db)
                .await
        {
            tracing::warn!(error = %e, %sub_id, "intake sweep: clearing attachments failed");
        }
    }
    if deleted > 0 {
        tracing::info!(deleted, %db_name, "intake sweep removed orphaned attachment blobs");
    }
    deleted
}

// ===========================================================================
// Customer portal (Phase 3) — signed-in partners submit + track requests.
// ===========================================================================

/// A portal-available form, for the "Submit a request" list.
pub struct PortalForm {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
}

/// Active forms flagged `portal` in settings.
pub async fn list_portal_forms(db: &PgPool) -> Vec<PortalForm> {
    sqlx::query(
        "SELECT slug, title, description FROM web_form
         WHERE active = true AND (settings->>'portal')::boolean = true
         ORDER BY title",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| PortalForm {
        slug: r.get("slug"),
        title: r.get("title"),
        description: r.try_get("description").ok().flatten(),
    })
    .collect()
}

/// Load an active portal-enabled form by slug (else `None` — a form not flagged
/// `portal` is not reachable from the portal even if it's public).
pub async fn fetch_portal_form(db: &PgPool, slug: &str) -> Option<WebForm> {
    let form = fetch_form(db, slug).await?;
    form.portal.then_some(form)
}

/// A created record's current workflow stage, resolved for portal display so a
/// partner sees where their request actually is (e.g. "In progress · step 2 of
/// 4"), not just that it was accepted.
#[derive(Debug, Clone)]
pub struct StageInfo {
    pub code: String,
    pub label: String,
    /// daisyUI colour name from `record_stages.color` (whitelisted at render).
    pub color: String,
    /// 1-based position among the model's active stages.
    pub index: i32,
    /// Number of active stages for the model (for "step {index} of {total}").
    pub total: i32,
}

/// One of a partner's tracked submissions.
pub struct PartnerSubmission {
    pub form_title: String,
    /// Submission-level status: `accepted` / `quarantined` / `rejected`.
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The created record (present once accepted), used to resolve `stage`.
    pub record_id: Option<Uuid>,
    /// The target `ir_model.name`.
    pub model: String,
    /// The record's current workflow stage, when the model uses a status bar
    /// and the stage is resolvable. `None` ⇒ show the submission status instead.
    pub stage: Option<StageInfo>,
}

/// Resolve the current stage of each accepted record for one model, in a single
/// pass: load the model's ordered active-stage catalogue (for label/colour +
/// step position), then batch-read `record_state` for `ids` from the model's
/// table. A model with no status bar (no stages, or no `record_state` column)
/// yields an empty map, so those submissions fall back to the plain status.
async fn resolve_stages_for_model(
    db: &PgPool,
    model: &str,
    ids: &[Uuid],
) -> HashMap<Uuid, StageInfo> {
    let mut out = HashMap::new();
    if ids.is_empty() {
        return out;
    }
    // Ordered active-stage catalogue → gives step index/total + label/colour.
    let catalog: Vec<(String, String, String)> = sqlx::query(
        "SELECT code, label, color FROM record_stages
         WHERE model = $1 AND active = true ORDER BY sequence ASC, code ASC",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| (r.get("code"), r.get("label"), r.get("color")))
    .collect();
    if catalog.is_empty() {
        return out;
    }
    let total = catalog.len() as i32;
    let by_code: HashMap<&str, (i32, &str, &str)> = catalog
        .iter()
        .enumerate()
        .map(|(i, (c, l, col))| (c.as_str(), (i as i32 + 1, l.as_str(), col.as_str())))
        .collect();

    // Target table (server-side + validated), then confirm it has record_state.
    let table: Option<String> =
        sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
            .bind(model)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let Some(table) = table.filter(|t| valid_ident(t)) else {
        return out;
    };
    let has_state: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'record_state')",
    )
    .bind(&table)
    .fetch_one(db)
    .await
    .unwrap_or(false);
    if !has_state {
        return out;
    }

    // Batch-read the current stage code for every accepted record of this model.
    let sql = format!("SELECT id, record_state FROM {table} WHERE id = ANY($1::uuid[])");
    let rows = sqlx::query(&sql).bind(ids).fetch_all(db).await.unwrap_or_default();
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: Option<String> = r.try_get("record_state").ok().flatten();
        if let Some(code) = code {
            if let Some((idx, label, color)) = by_code.get(code.as_str()) {
                out.insert(
                    id,
                    StageInfo {
                        code: code.clone(),
                        label: label.to_string(),
                        color: color.to_string(),
                        index: *idx,
                        total,
                    },
                );
            }
        }
    }
    out
}

/// A portal partner's own submissions across all forms, newest first. For each
/// accepted submission whose target model uses a status bar, the created
/// record's current stage is resolved (batched per model) so the portal can show
/// live progress rather than a static "Received".
pub async fn list_partner_submissions(db: &PgPool, partner_id: Uuid, limit: i64) -> Vec<PartnerSubmission> {
    let mut subs: Vec<PartnerSubmission> = sqlx::query(
        "SELECT w.title AS form_title, s.status, s.created_at, s.record_id, w.model
         FROM web_form_submission s JOIN web_form w ON w.id = s.form_id
         WHERE s.partner_id = $1 ORDER BY s.created_at DESC LIMIT $2",
    )
    .bind(partner_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| PartnerSubmission {
        form_title: r.get("form_title"),
        status: r.get("status"),
        created_at: r.get("created_at"),
        record_id: r.try_get("record_id").ok().flatten(),
        model: r.get("model"),
        stage: None,
    })
    .collect();

    // Group accepted records by model and resolve stages one model at a time.
    let mut by_model: HashMap<String, Vec<Uuid>> = HashMap::new();
    for s in &subs {
        if s.status == "accepted" {
            if let Some(rid) = s.record_id {
                by_model.entry(s.model.clone()).or_default().push(rid);
            }
        }
    }
    let mut resolved: HashMap<Uuid, StageInfo> = HashMap::new();
    for (model, ids) in &by_model {
        resolved.extend(resolve_stages_for_model(db, model, ids).await);
    }
    for s in &mut subs {
        if let Some(rid) = s.record_id {
            s.stage = resolved.get(&rid).cloned();
        }
    }
    subs
}

// ===========================================================================
// Triage — the submission inbox + quarantine approve/reject.
// ===========================================================================

/// A row in a form's submission inbox.
pub struct SubmissionRow {
    pub id: Uuid,
    pub status: String,
    pub record_id: Option<Uuid>,
    pub source_ip: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reviewed_by: Option<String>,
    /// Allow-listed values captured at submit (for quarantine preview).
    pub payload: BTreeMap<String, String>,
    /// Number of files attached to this submission.
    pub attachments: i64,
}

/// List a form's submissions, newest first (capped).
pub async fn list_submissions(db: &PgPool, form_id: Uuid, limit: i64) -> Vec<SubmissionRow> {
    sqlx::query(
        "SELECT s.id, s.status, s.record_id, host(s.source_ip) AS source_ip, s.created_at,
                s.payload, COALESCE(jsonb_array_length(s.attachments), 0) AS n_attach,
                u.username AS reviewed_by
         FROM web_form_submission s
         LEFT JOIN users u ON u.id = s.reviewed_by
         WHERE s.form_id = $1 ORDER BY s.created_at DESC LIMIT $2",
    )
    .bind(form_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| {
        let payload: BTreeMap<String, String> = r
            .try_get::<Option<serde_json::Value>, _>("payload")
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        SubmissionRow {
            id: r.get("id"),
            status: r.get("status"),
            record_id: r.try_get("record_id").ok().flatten(),
            source_ip: r.try_get("source_ip").ok().flatten(),
            created_at: r.get("created_at"),
            reviewed_by: r.try_get("reviewed_by").ok().flatten(),
            payload,
            attachments: r.try_get::<Option<i32>, _>("n_attach").ok().flatten().unwrap_or(0) as i64,
        }
    })
    .collect()
}

/// Approve a quarantined submission: re-validate the captured payload against
/// the *current* allow-list, write the governed record, and settle the ledger
/// row. Idempotent-guarded — only a `quarantined` row is actionable.
pub async fn approve_submission(
    audit: &AuditLog,
    db: &PgPool,
    db_name: &str,
    submission_id: Uuid,
    reviewer: Uuid,
    reviewer_name: &str,
) -> Result<Uuid, String> {
    let row = sqlx::query(
        "SELECT form_id, status, payload, partner_id, submitted_by, attachments
         FROM web_form_submission WHERE id = $1",
    )
    .bind(submission_id)
    .fetch_optional(db)
    .await
    .map_err(dberr)?
    .ok_or("Submission not found.")?;
    let status: String = row.get("status");
    if status != "quarantined" {
        return Err(format!("This submission is already {status}."));
    }
    let form_id: Uuid = row.get("form_id");
    let payload: BTreeMap<String, String> = row
        .try_get::<Option<serde_json::Value>, _>("payload")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    // The original submitter, captured at hold time — so the approved record
    // carries the same owner it would have had on an immediate write.
    let partner_id: Option<Uuid> = row.try_get("partner_id").ok().flatten();
    let submitted_by: Option<Uuid> = row.try_get("submitted_by").ok().flatten();
    // Blobs stored at submit time — linked to the record now that it exists.
    let held_uploads: Vec<StoredUpload> = row
        .try_get::<Option<serde_json::Value>, _>("attachments")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    let (form, _active) = load_form(db, form_id).await.ok_or("Form no longer exists.")?;
    // Re-validate against the current allow-list (the form may have changed
    // since capture) — never trust the stored payload blindly.
    let writable = select_writable(&form.fields, &payload)?;
    let missing = missing_required(&form.fields, &writable);
    if !missing.is_empty() {
        return Err(format!("Cannot approve — required now-missing: {}.", missing.join(", ")));
    }
    let stamp = OwnerStamp {
        created_by: submitted_by,
        partner: form.partner_field.clone().zip(partner_id),
    };
    let record_id = insert_target_record(db, &form, &writable, &stamp).await?;
    link_attachments(db, &form.model, record_id, &held_uploads, submitted_by).await?;

    sqlx::query(
        "UPDATE web_form_submission
         SET status = 'accepted', record_id = $2, reviewed_by = $3, reviewed_at = now()
         WHERE id = $1",
    )
    .bind(submission_id)
    .bind(record_id)
    .bind(reviewer)
    .execute(db)
    .await
    .map_err(dberr)?;

    let entry = AuditEntry::new(AuditAction::Custom("intake_approved".into()), AuditSeverity::Info)
        .with_database(db_name)
        .with_user(vortex_common::UserId(reviewer))
        .with_username(reviewer_name)
        .with_resource(&form.model, &record_id.to_string())
        .with_details(serde_json::json!({ "form": form.slug, "submission": submission_id }));
    if let Err(e) = audit.log(entry).await {
        tracing::error!(error = %e, "intake approve audit write failed");
    }
    Ok(record_id)
}

/// Reject a quarantined submission — no record is ever written.
pub async fn reject_submission(
    audit: &AuditLog,
    db: &PgPool,
    db_name: &str,
    submission_id: Uuid,
    reviewer: Uuid,
    reviewer_name: &str,
) -> Result<(), String> {
    let n = sqlx::query(
        "UPDATE web_form_submission
         SET status = 'rejected', reviewed_by = $2, reviewed_at = now()
         WHERE id = $1 AND status = 'quarantined'",
    )
    .bind(submission_id)
    .bind(reviewer)
    .execute(db)
    .await
    .map_err(dberr)?
    .rows_affected();
    if n == 0 {
        return Err("This submission is not awaiting review.".into());
    }
    let entry = AuditEntry::new(AuditAction::Custom("intake_rejected".into()), AuditSeverity::Warning)
        .with_database(db_name)
        .with_user(vortex_common::UserId(reviewer))
        .with_username(reviewer_name)
        .with_resource("web_form_submission", &submission_id.to_string())
        .with_details(serde_json::json!({}));
    if let Err(e) = audit.log(entry).await {
        tracing::error!(error = %e, "intake reject audit write failed");
    }
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

    fn form_with_partner(partner_field: Option<&str>) -> WebForm {
        WebForm {
            id: Uuid::nil(), slug: "s".into(), model: "x_m".into(), title: "T".into(),
            description: None, fields: vec![], company_id: None, success_msg: None,
            origins: vec![], quarantine: false, notify_to: None, daily_cap: None,
            portal: true, partner_field: partner_field.map(str::to_string),
            attach_fields: vec![], attach_max_mb: DEFAULT_MAX_UPLOAD_MB, attach_accept: vec![],
            captcha: false,
        }
    }

    fn upload(name: &str, mime: &str, size: usize) -> RawUpload {
        RawUpload { field: "file".into(), filename: name.into(), mime: mime.into(), data: vec![0u8; size] }
    }

    #[test]
    fn sanitize_filename_strips_paths_and_unsafe_chars() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("my file (1).PDF"), "my_file__1_.PDF");
        assert_eq!(sanitize_filename("C:\\Users\\a\\x.png"), "x.png");
        assert_eq!(sanitize_filename("..."), "upload");
    }

    #[test]
    fn upload_policy_enforces_type_and_size() {
        let mut form = form_with_partner(None);
        // Default accept-set: pdf ok, exe rejected.
        assert!(upload_accepted(&form, "application/pdf", "a.pdf"));
        assert!(!upload_accepted(&form, "application/x-msdownload", "a.exe"));
        // Custom accept: image/* glob + .csv extension.
        form.attach_accept = vec!["image/*".into(), ".csv".into()];
        assert!(upload_accepted(&form, "image/png", "a.png"));
        assert!(upload_accepted(&form, "text/plain", "data.csv")); // by extension
        assert!(!upload_accepted(&form, "application/pdf", "a.pdf")); // not in custom set

        form.attach_accept = vec![];
        form.attach_max_mb = 1;
        assert!(validate_upload(&form, &upload("a.pdf", "application/pdf", 500)).is_ok());
        assert!(validate_upload(&form, &upload("a.pdf", "application/pdf", 2 * 1024 * 1024)).is_err()); // too big
        assert!(validate_upload(&form, &upload("a.pdf", "application/pdf", 0)).is_err()); // empty
        assert!(validate_upload(&form, &upload("a.exe", "application/x-msdownload", 100)).is_err()); // bad type
    }

    #[test]
    fn missing_required_files_reports_absent() {
        let mut form = form_with_partner(None);
        form.attach_fields = vec![f("id_doc", true), f("extra", false)];
        let present: HashSet<String> = ["extra".to_string()].into_iter().collect();
        assert_eq!(missing_required_files(&form, &present), vec!["id_doc".to_string()]);
        let both: HashSet<String> = ["id_doc".to_string(), "extra".to_string()].into_iter().collect();
        assert!(missing_required_files(&form, &both).is_empty());
    }

    struct FakeScanner(crate::antivirus::AvVerdict, bool /* err */);
    #[async_trait::async_trait]
    impl crate::antivirus::AvScanner for FakeScanner {
        async fn scan(&self, _d: &[u8]) -> Result<crate::antivirus::AvVerdict, crate::antivirus::AvError> {
            if self.1 { Err(crate::antivirus::AvError::Unreachable("down".into())) } else { Ok(self.0.clone()) }
        }
        fn backend_name(&self) -> &'static str { "fake" }
    }

    #[tokio::test]
    async fn screen_uploads_blocks_infected_and_unscannable() {
        use crate::antivirus::AvVerdict;
        let files = vec![upload("a.pdf", "application/pdf", 10)];
        // Clean → passes.
        let clean = FakeScanner(AvVerdict::Clean, false);
        assert!(screen_uploads(&clean, &files).await.is_ok());
        // Infected → rejected.
        let bad = FakeScanner(AvVerdict::Infected("EICAR".into()), false);
        assert!(screen_uploads(&bad, &files).await.is_err());
        // Scanner error (fail-closed backend surfaced Err) → rejected.
        let err = FakeScanner(AvVerdict::Clean, true);
        assert!(screen_uploads(&err, &files).await.is_err());
    }

    #[test]
    fn owner_stamp_maps_actor_to_stamps() {
        // Anonymous: no owner stamps at all.
        let anon = OwnerStamp::for_submitter(&Submitter::Anonymous, &form_with_partner(Some("partner_id")));
        assert!(anon.created_by.is_none() && anon.partner.is_none());

        let user = Uuid::from_u128(7);
        let partner = Uuid::from_u128(9);
        let portal = Submitter::Portal { user_id: user, partner_id: partner, username: "p".into() };

        // Portal + partner_field configured: created_by + partner column stamped.
        let s = OwnerStamp::for_submitter(&portal, &form_with_partner(Some("partner_id")));
        assert_eq!(s.created_by, Some(user));
        assert_eq!(s.partner, Some(("partner_id".to_string(), partner)));

        // Portal but no partner_field: still attributes created_by, no partner column.
        let s2 = OwnerStamp::for_submitter(&portal, &form_with_partner(None));
        assert_eq!(s2.created_by, Some(user));
        assert!(s2.partner.is_none());
    }
}
