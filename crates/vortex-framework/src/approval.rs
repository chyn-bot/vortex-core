//! Generic multi-step approval workflow.
//!
//! Sits on top of the stage-button system ([`crate::status`]). A button that
//! has one or more [`approval_rules`] requires approval: rather than
//! transitioning immediately, the module creates an [`ApprovalRequest`] and
//! the record stays put. Eligible approvers act per ordered step (inbox or
//! on-record); once the final step's quota is met the *stored* transition is
//! applied — and because the request carries the status table/column, that
//! apply step is fully generic, so any module gets approvals for free.
//!
//! Integration from a module's transition handler:
//! ```ignore
//! if approval::requires_approval(&db, action_id).await {
//!     approval::create_request(&db, &audit, &db_name, approval::NewRequest {
//!         model: "contacts", record_id: id, action_id,
//!         status_table: "contacts", status_column: "record_state",
//!         from_stage: &current, target_stage: &new_state,
//!         resource_name: &name, requested_by: user.id, requested_by_name: &user.username,
//!     }).await.ok();
//!     return /* "submitted for approval" */;
//! }
//! // else: apply the transition directly
//! ```

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_common::UserId;
use vortex_security::{AuditAction, AuditEntry, AuditLog, AuditSeverity};

use crate::ui::{format_time_ago, html_escape};

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One ordered approval step for a button.
pub struct ApprovalStep {
    pub step: i32,
    pub label: Option<String>,
    pub approver_role: String,
    pub min_approvals: i32,
}

/// An in-progress approval request for one record transition.
pub struct ApprovalRequest {
    pub id: Uuid,
    pub model: String,
    pub record_id: Uuid,
    pub action_id: Option<Uuid>,
    pub status_table: String,
    pub status_column: String,
    pub from_stage: Option<String>,
    pub target_stage: String,
    pub resource_name: Option<String>,
    pub requested_by: Option<Uuid>,
    pub requested_by_name: Option<String>,
    pub current_step: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Parameters for [`create_request`].
pub struct NewRequest<'a> {
    pub model: &'a str,
    pub record_id: Uuid,
    pub action_id: Uuid,
    pub status_table: &'a str,
    pub status_column: &'a str,
    pub from_stage: &'a str,
    pub target_stage: &'a str,
    pub resource_name: &'a str,
    pub requested_by: Uuid,
    pub requested_by_name: &'a str,
}

/// Outcome of [`decide`].
#[derive(Debug, PartialEq)]
pub enum DecisionOutcome {
    /// Approval recorded; this step still needs more approvals.
    Recorded,
    /// Step quota met; advanced to the next step (carries its number).
    Advanced(i32),
    /// Final step met; the transition was applied.
    Approved,
    /// Request rejected; no transition.
    Rejected,
    /// User may not act on this request right now.
    NotEligible,
    /// Request was already resolved / not pending.
    AlreadyResolved,
}

/// Ordered steps declared for a button (empty => no approval needed).
pub async fn rules_for_action(db: &PgPool, action_id: Uuid) -> Vec<ApprovalStep> {
    let rows = sqlx::query(
        "SELECT step, label, approver_role, min_approvals FROM approval_rules \
         WHERE action_id = $1 ORDER BY step",
    )
    .bind(action_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| ApprovalStep {
            step: r.get("step"),
            label: r.try_get("label").ok(),
            approver_role: r.get("approver_role"),
            min_approvals: r.get("min_approvals"),
        })
        .collect()
}

/// Does this button require approval?
pub async fn requires_approval(db: &PgPool, action_id: Uuid) -> bool {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM approval_rules WHERE action_id = $1")
        .bind(action_id)
        .fetch_one(db)
        .await
        .unwrap_or(0);
    n > 0
}

fn map_request(r: &sqlx::postgres::PgRow) -> ApprovalRequest {
    ApprovalRequest {
        id: r.get("id"),
        model: r.get("model"),
        record_id: r.get("record_id"),
        action_id: r.try_get("action_id").ok(),
        status_table: r.get("status_table"),
        status_column: r.get("status_column"),
        from_stage: r.try_get("from_stage").ok(),
        target_stage: r.get("target_stage"),
        resource_name: r.try_get("resource_name").ok(),
        requested_by: r.try_get("requested_by").ok(),
        requested_by_name: r.try_get("requested_by_name").ok(),
        current_step: r.get("current_step"),
        status: r.get("status"),
        created_at: r.get("created_at"),
    }
}

const REQ_COLS: &str = "id, model, record_id, action_id, status_table, status_column, \
    from_stage, target_stage, resource_name, requested_by, requested_by_name, \
    current_step, status, created_at";

/// The open (pending) request for a record, if any.
pub async fn pending_for_record(db: &PgPool, model: &str, record_id: Uuid) -> Option<ApprovalRequest> {
    let sql = format!(
        "SELECT {REQ_COLS} FROM approval_requests \
         WHERE model = $1 AND record_id = $2 AND status = 'pending' \
         ORDER BY created_at DESC LIMIT 1"
    );
    sqlx::query(&sql)
        .bind(model)
        .bind(record_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|r| map_request(&r))
}

/// Create a pending request starting at the first declared step. Returns the
/// request id, or `Err` if the button has no rules / a request already exists.
pub async fn create_request(
    db: &PgPool,
    jobs_pool: &PgPool,
    audit: &AuditLog,
    db_name: &str,
    req: NewRequest<'_>,
) -> Result<Uuid, String> {
    let steps = rules_for_action(db, req.action_id).await;
    let Some(first) = steps.first() else {
        return Err("This action does not require approval".into());
    };
    if pending_for_record(db, req.model, req.record_id).await.is_some() {
        return Err("An approval is already pending for this record".into());
    }

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO approval_requests \
         (id, model, record_id, action_id, status_table, status_column, from_stage, \
          target_stage, resource_name, requested_by, requested_by_name, current_step, status) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending')",
    )
    .bind(id)
    .bind(req.model)
    .bind(req.record_id)
    .bind(req.action_id)
    .bind(req.status_table)
    .bind(req.status_column)
    .bind(req.from_stage)
    .bind(req.target_stage)
    .bind(req.resource_name)
    .bind(req.requested_by)
    .bind(req.requested_by_name)
    .bind(first.step)
    .execute(db)
    .await
    .map_err(|e| format!("Could not create approval request: {e}"))?;

    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(req.requested_by))
        .with_username(req.requested_by_name)
        .with_database(db_name)
        .with_resource(req.model, req.record_id.to_string())
        .with_resource_name(req.resource_name)
        .with_details(serde_json::json!({
            "changes": [{ "field": "Approval", "from": "—", "to": format!("Requested → {}", req.target_stage) }]
        }));
    let _ = audit.log(entry).await;

    // Notify the first step's approvers via the durable job queue — each email
    // becomes a retryable `mail.send` job, so SMTP latency/outages never block
    // the request and a transient failure is retried, not lost.
    notify_step_approvers(
        db,
        jobs_pool,
        db_name,
        &first.approver_role,
        req.requested_by,
        req.resource_name,
        req.target_stage,
    )
    .await;

    Ok(id)
}

/// Enqueue a `mail.send` job for everyone holding `role` (except the requester)
/// who has an email. Recipients are resolved now (cheap query on the tenant
/// `db`); delivery is deferred to the worker against `jobs_pool`.
#[allow(clippy::too_many_arguments)]
async fn notify_step_approvers(
    db: &PgPool,
    jobs_pool: &PgPool,
    db_name: &str,
    role: &str,
    requester: Uuid,
    resource_name: &str,
    target: &str,
) {
    let emails: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT u.email FROM users u \
         JOIN user_roles ur ON ur.user_id = u.id \
         JOIN roles r ON r.id = ur.role_id \
         WHERE r.name = $1 AND u.active = true AND u.email IS NOT NULL AND u.id <> $2",
    )
    .bind(role)
    .bind(requester)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    if emails.is_empty() {
        return;
    }
    let subject = format!("Approval needed: {resource_name}");
    let body = format!(
        "{resource_name} has been submitted for approval and is awaiting your sign-off \
         (transition to '{target}').\n\nReview it in Vortex under Approvals.",
    );
    for to in emails {
        let job = crate::jobs::NewJob::new(
            "mail.send",
            serde_json::json!({ "to": to, "subject": subject, "text": body, "context": "approval" }),
        )
        .for_db(db_name)
        .trace("approval_notify", &to);
        if let Err(e) = crate::jobs::enqueue(jobs_pool, job).await {
            tracing::warn!(error = %e, to = %to, "could not enqueue approval notification");
        }
    }
}

/// Has this user already decided at the request's current step?
async fn already_decided(db: &PgPool, request_id: Uuid, step: i32, user_id: Uuid) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_decisions WHERE request_id = $1 AND step = $2 AND decided_by = $3",
    )
    .bind(request_id)
    .bind(step)
    .bind(user_id)
    .fetch_one(db)
    .await
    .unwrap_or(0);
    n > 0
}

/// May this user approve/reject the request's current step right now?
/// (right role, not the requester, hasn't already decided this step)
pub async fn eligible_to_decide(
    db: &PgPool,
    req: &ApprovalRequest,
    user_id: Uuid,
    user_roles: &[String],
) -> bool {
    if req.status != "pending" {
        return false;
    }
    if req.requested_by == Some(user_id) {
        return false; // no self-approval
    }
    let steps = rules_for_action(db, req.action_id.unwrap_or_default()).await;
    let Some(step) = steps.iter().find(|s| s.step == req.current_step) else {
        return false;
    };
    if !user_roles.iter().any(|r| r == &step.approver_role) {
        return false;
    }
    !already_decided(db, req.id, req.current_step, user_id).await
}

/// Record a decision and advance / approve / reject. On final approval the
/// stored transition is applied to `status_table.status_column` and audited.
pub async fn decide(
    db: &PgPool,
    audit: &AuditLog,
    db_name: &str,
    request_id: Uuid,
    user_id: Uuid,
    user_name: &str,
    user_roles: &[String],
    approve: bool,
    comment: &str,
) -> DecisionOutcome {
    let sql = format!("SELECT {REQ_COLS} FROM approval_requests WHERE id = $1");
    let Some(req) = sqlx::query(&sql)
        .bind(request_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|r| map_request(&r))
    else {
        return DecisionOutcome::AlreadyResolved;
    };
    if req.status != "pending" {
        return DecisionOutcome::AlreadyResolved;
    }
    if !eligible_to_decide(db, &req, user_id, user_roles).await {
        return DecisionOutcome::NotEligible;
    }

    let steps = rules_for_action(db, req.action_id.unwrap_or_default()).await;
    let Some(cur) = steps.iter().find(|s| s.step == req.current_step) else {
        return DecisionOutcome::AlreadyResolved;
    };

    // Record the decision (unique constraint guards a double-vote race).
    if sqlx::query(
        "INSERT INTO approval_decisions (request_id, step, decided_by, decided_by_name, decision, comment) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(request_id)
    .bind(req.current_step)
    .bind(user_id)
    .bind(user_name)
    .bind(if approve { "approve" } else { "reject" })
    .bind(comment)
    .execute(db)
    .await
    .is_err()
    {
        return DecisionOutcome::NotEligible;
    }

    if !approve {
        let _ = sqlx::query("UPDATE approval_requests SET status = 'rejected', resolved_at = NOW() WHERE id = $1")
            .bind(request_id)
            .execute(db)
            .await;
        audit_record(db, audit, db_name, &req, user_id, user_name, "Rejected").await;
        return DecisionOutcome::Rejected;
    }

    // Approvals so far at this step.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_decisions WHERE request_id = $1 AND step = $2 AND decision = 'approve'",
    )
    .bind(request_id)
    .bind(req.current_step)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if (count as i32) < cur.min_approvals {
        return DecisionOutcome::Recorded;
    }

    // Step quota met — advance or finalize.
    if let Some(next) = steps.iter().find(|s| s.step > req.current_step) {
        let _ = sqlx::query("UPDATE approval_requests SET current_step = $1 WHERE id = $2")
            .bind(next.step)
            .bind(request_id)
            .execute(db)
            .await;
        return DecisionOutcome::Advanced(next.step);
    }

    // Final approval — apply the stored transition generically.
    apply_transition(db, audit, db_name, &req, user_id, user_name).await;
    let _ = sqlx::query("UPDATE approval_requests SET status = 'approved', resolved_at = NOW() WHERE id = $1")
        .bind(request_id)
        .execute(db)
        .await;
    DecisionOutcome::Approved
}

/// Apply the request's transition to its status column and audit it.
async fn apply_transition(
    db: &PgPool,
    audit: &AuditLog,
    db_name: &str,
    req: &ApprovalRequest,
    user_id: Uuid,
    user_name: &str,
) {
    if !is_ident(&req.status_table) || !is_ident(&req.status_column) {
        return;
    }
    let upd = format!("UPDATE {} SET {} = $1 WHERE id = $2", req.status_table, req.status_column);
    if sqlx::query(&upd)
        .bind(&req.target_stage)
        .bind(req.record_id)
        .execute(db)
        .await
        .is_err()
    {
        return;
    }
    let from_label = req.from_stage.clone().unwrap_or_default();
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user_id))
        .with_username(user_name)
        .with_database(db_name)
        .with_resource(&req.model, req.record_id.to_string())
        .with_resource_name(req.resource_name.as_deref().unwrap_or(""))
        .with_details(serde_json::json!({
            "changes": [{ "field": "Status", "from": from_label, "to": req.target_stage }],
            "via": "approval"
        }));
    let _ = audit.log(entry).await;
}

async fn audit_record(
    db: &PgPool,
    audit: &AuditLog,
    db_name: &str,
    req: &ApprovalRequest,
    user_id: Uuid,
    user_name: &str,
    what: &str,
) {
    let _ = db;
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user_id))
        .with_username(user_name)
        .with_database(db_name)
        .with_resource(&req.model, req.record_id.to_string())
        .with_resource_name(req.resource_name.as_deref().unwrap_or(""))
        .with_details(serde_json::json!({
            "changes": [{ "field": "Approval", "from": "Pending", "to": what }]
        }));
    let _ = audit.log(entry).await;
}

/// Pending requests this user can act on right now (their inbox).
pub async fn inbox(db: &PgPool, user_id: Uuid, user_roles: &[String]) -> Vec<ApprovalRequest> {
    let sql = format!(
        "SELECT {REQ_COLS} FROM approval_requests r \
         WHERE r.status = 'pending' \
           AND EXISTS (SELECT 1 FROM approval_rules ru WHERE ru.action_id = r.action_id \
                       AND ru.step = r.current_step AND ru.approver_role = ANY($1)) \
           AND (r.requested_by IS NULL OR r.requested_by <> $2) \
           AND NOT EXISTS (SELECT 1 FROM approval_decisions d WHERE d.request_id = r.id \
                           AND d.step = r.current_step AND d.decided_by = $2) \
         ORDER BY r.created_at"
    );
    let rows = sqlx::query(&sql)
        .bind(user_roles)
        .bind(user_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();
    rows.iter().map(map_request).collect()
}

/// Render the on-record approval panel: pending state, step progress,
/// decisions so far, and an approve/reject form when the user is eligible.
/// Empty string when there's no open request.
pub async fn render_for_record(
    db: &PgPool,
    model: &str,
    record_id: Uuid,
    user_id: Uuid,
    user_roles: &[String],
) -> String {
    let Some(req) = pending_for_record(db, model, record_id).await else {
        return String::new();
    };
    let steps = rules_for_action(db, req.action_id.unwrap_or_default()).await;

    // Step progress list.
    let mut steps_html = String::new();
    for s in &steps {
        let state = if s.step < req.current_step {
            r#"<span class="badge badge-success badge-sm">done</span>"#
        } else if s.step == req.current_step {
            r#"<span class="badge badge-warning badge-sm">awaiting</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">pending</span>"#
        };
        let lbl = s.label.clone().unwrap_or_else(|| format!("Step {}", s.step));
        steps_html.push_str(&format!(
            r#"<li class="flex items-center gap-2 text-sm"><span class="font-medium">{}</span><span class="text-base-content/50">· {} (×{})</span> {}</li>"#,
            html_escape(&lbl),
            html_escape(&s.approver_role),
            s.min_approvals,
            state,
        ));
    }

    // Decisions so far.
    let decisions = sqlx::query(
        "SELECT step, decided_by_name, decision, comment, created_at FROM approval_decisions \
         WHERE request_id = $1 ORDER BY created_at",
    )
    .bind(req.id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut dec_html = String::new();
    for d in &decisions {
        let who: Option<String> = d.try_get("decided_by_name").ok();
        let decision: String = d.get("decision");
        let comment: Option<String> = d.try_get("comment").ok();
        let ts: DateTime<Utc> = d.get("created_at");
        let badge = if decision == "approve" { "badge-success" } else { "badge-error" };
        dec_html.push_str(&format!(
            r#"<li class="text-sm"><span class="badge {badge} badge-sm">{decision}</span> {who} <span class="text-base-content/40">· {ago}</span>{comment}</li>"#,
            badge = badge,
            decision = html_escape(&decision),
            who = html_escape(who.as_deref().unwrap_or("")),
            ago = html_escape(&format_time_ago(ts)),
            comment = comment.filter(|c| !c.is_empty()).map(|c| format!(r#" — <span class="italic">{}</span>"#, html_escape(&c))).unwrap_or_default(),
        ));
    }

    let eligible = eligible_to_decide(db, &req, user_id, user_roles).await;
    let action_form = if eligible {
        format!(
            r#"<div class="mt-3">
<textarea name="comment" form="approve-form" class="textarea textarea-bordered textarea-sm w-full" placeholder="Comment (optional)"></textarea>
<div class="flex gap-2 mt-2">
<form id="approve-form" method="POST" action="/approvals/{id}/approve"><button class="btn btn-success btn-sm">Approve</button></form>
<form method="POST" action="/approvals/{id}/reject"><button class="btn btn-error btn-outline btn-sm">Reject</button></form>
</div></div>"#,
            id = req.id,
        )
    } else {
        r#"<p class="text-sm text-base-content/50 mt-2">Awaiting approval from the assigned approver.</p>"#.to_string()
    };

    format!(
        r#"<div class="card bg-base-100 shadow border border-warning/40 mb-4"><div class="card-body">
<h2 class="card-title text-lg">⏳ Pending Approval</h2>
<p class="text-sm text-base-content/60">Requested by {req_by} to move to <code>{target}</code>.</p>
<ul class="mt-2 space-y-1">{steps}</ul>
{decisions}
{form}
</div></div>"#,
        req_by = html_escape(req.requested_by_name.as_deref().unwrap_or("")),
        target = html_escape(&req.target_stage),
        steps = steps_html,
        decisions = if dec_html.is_empty() { String::new() } else { format!(r#"<div class="divider my-1"></div><ul class="space-y-1">{dec_html}</ul>"#) },
        form = action_form,
    )
}
