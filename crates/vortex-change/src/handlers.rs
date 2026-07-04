//! HTTP handlers for the Change Request plugin.
//!
//! These are intentionally the smallest handlers that exercise every
//! core primitive in one request lifecycle:
//!
//! - **RBAC + session**: `Extension<AuthUser>` is injected by the
//!   host's auth middleware.
//! - **Per-tenant DB**: [`vortex_framework::Db`] extractor pulls the
//!   request-scoped pool out of the `DatabaseContext`.
//! - **Workflow engine**: `state.workflow.create_instance(...)` and
//!   `state.workflow.transition(...)` drive the CR state machine.
//! - **WORM audit**: every transition the engine performs writes a
//!   chained audit entry automatically — handlers don't touch
//!   `state.audit` directly except for the CR-created event.
//! - **Cedar policy**: the engine wraps every transition in a
//!   `state.policy.check(...)` call, so the segregation-of-duties
//!   policies in the plugin migration are enforced without any
//!   code here.
//!
//! The HTML is built with `format!` strings — the standard plugin
//! convention. The CR plugin is small on purpose; a future
//! phase can extract shared chrome (header/footer) into
//! `vortex-framework::ui` when a second plugin needs it.

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use tracing::{error, warn};
use uuid::Uuid;
use vortex_common::UserId;
use vortex_framework::{
    build_sidebar, error_response, forbidden_page, get_initials, html_escape, AppState, AuthUser,
    DatabaseContext, Db,
};
use vortex_policy::PolicyPrincipal;
use vortex_workflow::{InstanceId, TransitionContext, WorkflowType};

use crate::model::{CrCategory, CrCriticality, CrState};

/// Fallback company used when the user row has no tenant scope.
/// Matches the seed value from `001_initial_schema` and the same
/// constant in `vortex-security/src/audit/pg.rs`. Pulled out as a
/// `const` so the two copies stay textually identical.
const FALLBACK_COMPANY_ID: Uuid = Uuid::from_bytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// Build the CR router. Registered by
/// [`crate::plugin::ChangeRequestPlugin::routes`] and merged into
/// the host router at startup.
pub fn cr_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/change-requests", get(cr_list))
        .route("/change-requests/new", get(cr_new_form))
        .route("/change-requests/new", post(cr_create))
        .route("/change-requests/{id}", get(cr_detail))
        .route("/change-requests/{id}/transition", post(cr_transition))
}

// ─── Shared helpers ───────────────────────────────────────────────

/// Resolve the user's company id. Falls back to
/// [`FALLBACK_COMPANY_ID`] if the `users` row lacks `company_id` —
/// which only happens for the seed admin in local dev.
async fn resolve_company_id(db: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    sqlx::query_scalar::<_, Uuid>("SELECT company_id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .unwrap_or(FALLBACK_COMPANY_ID)
}

/// Build the `PolicyPrincipal` for a request. This is what the
/// workflow engine passes to Cedar.
fn principal_for(user: &AuthUser, company_id: Uuid) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id: user.id,
        username: user.username.clone(),
        company_id,
        roles: user.roles.clone(),
    }
}

/// Generate the next `CR/YYYY/NNNNN` number for a tenant. Uses a
/// `SELECT MAX + 1` read followed by an INSERT; real production
/// numbering should move to the core `vortex_orm::sequence` service
/// (atomic no-gap upsert), but this is Phase 0.5 and the CR plugin is a
/// demonstrator. Collisions are handled by the unique constraint on
/// `(company_id, number)` — callers retry.
async fn generate_cr_number(db: &sqlx::PgPool, company_id: Uuid) -> Result<String, sqlx::Error> {
    let year = Utc::now().format("%Y").to_string();
    let prefix = format!("CR/{}/", year);

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM change_requests
         WHERE company_id = $1 AND number LIKE $2",
    )
    .bind(company_id)
    .bind(format!("{}%", prefix))
    .fetch_one(db)
    .await?;

    Ok(format!("{}{:05}", prefix, count + 1))
}

/// Render a colored badge for a CR state.
fn state_badge(state: &str) -> String {
    let (cls, label) = match CrState::parse(state) {
        Some(CrState::Draft) => ("badge-ghost", "Draft"),
        Some(CrState::Submitted) => ("badge-info", "Submitted"),
        Some(CrState::UnderReview) => ("badge-warning", "Under Review"),
        Some(CrState::Approved) => ("badge-success", "Approved"),
        Some(CrState::Rejected) => ("badge-error", "Rejected"),
        Some(CrState::Withdrawn) => ("badge-neutral", "Withdrawn"),
        Some(CrState::Closed) => ("badge-neutral", "Closed"),
        None => ("badge-ghost", "Unknown"),
    };
    format!(r#"<span class="badge {}">{}</span>"#, cls, html_escape(label))
}

/// Render a colored badge for CR criticality.
fn criticality_badge(c: &str) -> String {
    let (cls, label) = match CrCriticality::parse(c) {
        Some(CrCriticality::Low) => ("badge-success", "Low"),
        Some(CrCriticality::Medium) => ("badge-warning", "Medium"),
        Some(CrCriticality::High) => ("badge-error", "High"),
        None => ("badge-ghost", "?"),
    };
    format!(r#"<span class="badge {}">{}</span>"#, cls, html_escape(label))
}

/// Shared HTML page shell — head + mobile topbar + theme toggle.
/// Returns `(prefix, suffix)` to wrap a handler's main content.
fn page_shell(title: &str, sidebar: &str) -> (String, &'static str) {
    let prefix = format!(
        r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><title>{}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css" rel="stylesheet"/>
<script src="/static/vendor/tailwind.js"></script></head>
<body class="min-h-screen bg-base-200">
<div class="flex">{}<main class="flex-1 p-4 lg:p-6 min-w-0">"#,
        html_escape(title),
        sidebar
    );
    (prefix, r#"</main></div></body></html>"#)
}

// ─── List ─────────────────────────────────────────────────────────

async fn cr_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id = resolve_company_id(&db, user.id).await;

    // Join workflow_instances so we can show current_state without
    // a second round-trip. `updated_at` on the instance reflects the
    // most-recent transition, which is what operators want to sort
    // by — not the CR row's own `updated_at` which only tracks
    // edits to the CR's fields.
    let rows = match sqlx::query(
        r#"
        SELECT c.id, c.number, c.title, c.category, c.criticality,
               c.created_at, wi.current_state, wi.updated_at AS wf_updated
          FROM change_requests c
          JOIN workflow_instances wi ON wi.id = c.workflow_instance_id
         WHERE c.company_id = $1
      ORDER BY wi.updated_at DESC
         LIMIT 200
        "#,
    )
    .bind(company_id)
    .fetch_all(&db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "cr_list query failed");
            return error_response("database error");
        }
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar(
        "change_request.list",
        display_name,
        &initials,
        &installed,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
    );

    let mut body = String::new();
    body.push_str(r#"<div class="flex items-center justify-between mb-6"><div><h1 class="text-2xl font-bold">Change Requests</h1><p class="text-base-content/60">NERC CIP-010 change management</p></div><a href="/change-requests/new" class="btn btn-primary">New Change Request</a></div>"#);

    if rows.is_empty() {
        body.push_str(r#"<div class="card bg-base-100 shadow"><div class="card-body text-center py-12"><p class="text-base-content/60">No change requests yet.</p><a href="/change-requests/new" class="btn btn-primary mt-4">Create the first one</a></div></div>"#);
    } else {
        body.push_str(r#"<div class="card bg-base-100 shadow overflow-hidden"><table class="table table-zebra"><thead><tr><th>Number</th><th>Title</th><th>Category</th><th>Criticality</th><th>State</th><th>Last Update</th></tr></thead><tbody>"#);
        for row in &rows {
            let id: Uuid = row.get("id");
            let number: String = row.get("number");
            let title: String = row.get("title");
            let category: String = row.get("category");
            let criticality: String = row.get("criticality");
            let current_state: String = row.get("current_state");
            let wf_updated: DateTime<Utc> = row.get("wf_updated");
            body.push_str(&format!(
                r#"<tr><td><a href="/change-requests/{}" class="link link-primary font-mono">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="text-sm">{}</td></tr>"#,
                id,
                html_escape(&number),
                html_escape(&title),
                html_escape(&category),
                criticality_badge(&criticality),
                state_badge(&current_state),
                wf_updated.format("%Y-%m-%d %H:%M"),
            ));
        }
        body.push_str("</tbody></table></div>");
    }

    let (prefix, suffix) = page_shell("Change Requests - Vortex", &sidebar);
    Html(format!("{}{}{}", prefix, body, suffix)).into_response()
}

// ─── New form ─────────────────────────────────────────────────────

async fn cr_new_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let _ = resolve_company_id(&db, user.id).await;

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar(
        "change_request.list",
        display_name,
        &initials,
        &installed,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
    );

    let mut cat_opts = String::new();
    for c in CrCategory::all() {
        cat_opts.push_str(&format!(
            r#"<option value="{}">{}</option>"#,
            c.as_str(),
            c.as_str()
        ));
    }
    let mut crit_opts = String::new();
    for c in CrCriticality::all() {
        crit_opts.push_str(&format!(
            r#"<option value="{}">{}</option>"#,
            c.as_str(),
            c.as_str()
        ));
    }

    let body = format!(
        r#"
<div class="max-w-3xl mx-auto">
<div class="mb-6"><h1 class="text-2xl font-bold">New Change Request</h1><p class="text-base-content/60">Draft a new change. You'll be able to submit it for review after saving.</p></div>
<form method="POST" action="/change-requests/new" class="card bg-base-100 shadow">
<div class="card-body space-y-4">
<div><label class="label"><span class="label-text">Title <span class="text-error">*</span></span></label>
<input name="title" required maxlength="255" class="input input-bordered w-full"></div>
<div><label class="label"><span class="label-text">Description <span class="text-error">*</span></span></label>
<textarea name="description" required rows="5" class="textarea textarea-bordered w-full"></textarea></div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div><label class="label"><span class="label-text">Category</span></label>
<select name="category" class="select select-bordered w-full">{cat_opts}</select></div>
<div><label class="label"><span class="label-text">Criticality</span></label>
<select name="criticality" class="select select-bordered w-full">{crit_opts}</select></div>
</div>
<div><label class="label"><span class="label-text">Rollback plan <span class="text-base-content/60">(required for High criticality)</span></span></label>
<textarea name="rollback_plan" rows="3" class="textarea textarea-bordered w-full"></textarea></div>
<div class="flex gap-2 justify-end pt-4">
<a href="/change-requests" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary">Save as draft</button>
</div></div></form></div>
"#
    );

    let (prefix, suffix) = page_shell("New Change Request - Vortex", &sidebar);
    Html(format!("{}{}{}", prefix, body, suffix)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CreateCrForm {
    pub title: String,
    pub description: String,
    pub category: String,
    pub criticality: String,
    #[serde(default)]
    pub rollback_plan: String,
}

async fn cr_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<CreateCrForm>,
) -> Response {
    // Validate enum values against the model so malformed input is
    // rejected before it reaches the DB. Cedar will still re-check
    // at transition time, but catching this here gives a better
    // error page.
    let category = match CrCategory::parse(&form.category) {
        Some(c) => c,
        None => return error_response("invalid category"),
    };
    let criticality = match CrCriticality::parse(&form.criticality) {
        Some(c) => c,
        None => return error_response("invalid criticality"),
    };
    if form.title.trim().is_empty() || form.description.trim().is_empty() {
        return error_response("title and description are required");
    }

    // Enforce the CIP-010 rule that high-criticality changes must
    // ship with a rollback plan. Not a Cedar policy — it's a domain
    // invariant that doesn't depend on request context.
    let rollback_plan = if form.rollback_plan.trim().is_empty() {
        if matches!(criticality, CrCriticality::High) {
            return error_response("rollback plan is required for high-criticality changes");
        }
        None
    } else {
        Some(form.rollback_plan.trim().to_string())
    };

    let company_id = resolve_company_id(&db, user.id).await;

    // Step 1: create the workflow instance via the engine. The
    // engine picks the initial state from the state machine, so we
    // don't hard-code "draft" here. This is intentional — if the
    // state machine ever changes its entry point the handler stays
    // correct.
    let instance = match state
        .workflow
        .create_instance(
            &WorkflowType::new("change_request"),
            company_id,
            user.id,
            json!({}),
        )
        .await
    {
        Ok(i) => i,
        Err(e) => {
            error!(error = %e, "workflow instance creation failed");
            return error_response("failed to start workflow");
        }
    };

    // Step 2: generate number and insert the CR row. Retry on
    // unique-constraint collision — another concurrent create may
    // have grabbed our number between SELECT and INSERT.
    let cr_id = Uuid::now_v7();
    let now = Utc::now();
    let mut attempts = 0u8;
    let created_number: String;
    loop {
        attempts += 1;
        if attempts > 5 {
            error!("cr_create: too many unique-number retries");
            return error_response("failed to allocate CR number");
        }
        let number = match generate_cr_number(&db, company_id).await {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "generate_cr_number failed");
                return error_response("failed to allocate CR number");
            }
        };
        let res = sqlx::query(
            r#"
            INSERT INTO change_requests (
                id, number, title, description, category, criticality,
                rollback_plan, requested_by, workflow_instance_id,
                company_id, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
            "#,
        )
        .bind(cr_id)
        .bind(&number)
        .bind(form.title.trim())
        .bind(form.description.trim())
        .bind(category.as_str())
        .bind(criticality.as_str())
        .bind(rollback_plan.as_deref())
        .bind(user.id)
        .bind(instance.id.0)
        .bind(company_id)
        .bind(now)
        .execute(&db)
        .await;
        match res {
            Ok(_) => {
                created_number = number;
                break;
            }
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                warn!("cr_create: number collision on attempt {}, retrying", attempts);
                continue;
            }
            Err(e) => {
                error!(error = %e, "cr insert failed");
                return error_response("failed to create change request");
            }
        }
    }

    // Step 3: write a 'created' audit event. This is *not* a
    // workflow transition (there's no `create` edge in the state
    // machine — instances are born in `draft`), so we emit it
    // directly to the WORM ledger so the CR's first event has
    // a chain entry.
    use vortex_common::CompanyId;
    use vortex_security::{AuditAction, AuditEntry, AuditSeverity};
    let entry = AuditEntry::new(
        AuditAction::Custom("change_request_created".into()),
        AuditSeverity::Info,
    )
    .with_user(UserId(user.id))
    .with_username(user.username.clone())
    .with_company(CompanyId(company_id))
    .with_resource("change_request", cr_id.to_string())
    .with_resource_name(created_number.clone())
    .with_details(json!({
        "number": created_number,
        "category": category.as_str(),
        "criticality": criticality.as_str(),
        "workflow_instance_id": instance.id.0,
    }));
    if let Err(e) = state.audit.log(entry).await {
        // Audit failure on a creation is serious but not fatal —
        // the CR row already exists. Log and continue so the user
        // gets a response; operators can replay via the workflow
        // history + DB state.
        error!(error = %e, "audit log failed for cr_create");
    }

    Redirect::to(&format!("/change-requests/{}", cr_id)).into_response()
}

// ─── Detail ───────────────────────────────────────────────────────

async fn cr_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id = resolve_company_id(&db, user.id).await;

    let row = match sqlx::query(
        r#"
        SELECT c.id, c.number, c.title, c.description, c.category, c.criticality,
               c.rollback_plan, c.requested_by, c.workflow_instance_id,
               c.created_at, c.updated_at,
               wi.current_state,
               u.username AS requester_username, u.full_name AS requester_name
          FROM change_requests c
          JOIN workflow_instances wi ON wi.id = c.workflow_instance_id
          JOIN users u ON u.id = c.requested_by
         WHERE c.id = $1 AND c.company_id = $2
        "#,
    )
    .bind(id)
    .bind(company_id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return error_response("change request not found"),
        Err(e) => {
            error!(error = %e, "cr_detail query failed");
            return error_response("database error");
        }
    };

    let number: String = row.get("number");
    let title: String = row.get("title");
    let description: String = row.get("description");
    let category: String = row.get("category");
    let criticality: String = row.get("criticality");
    let rollback_plan: Option<String> = row.get("rollback_plan");
    let workflow_instance_id: Uuid = row.get("workflow_instance_id");
    let current_state: String = row.get("current_state");
    let requester_username: String = row.get("requester_username");
    let requester_name: Option<String> = row.get("requester_name");
    let created_at: DateTime<Utc> = row.get("created_at");

    // Load transition history so auditors have a visible trail on
    // the detail page. Ordered ascending so the oldest event is at
    // the top.
    let history = sqlx::query(
        r#"
        SELECT wt.transition_name, wt.from_state, wt.to_state,
               wt.occurred_at, wt.audit_entry_id, wt.context,
               u.username AS actor_username
          FROM workflow_transitions wt
          LEFT JOIN users u ON u.id = wt.actor_user_id
         WHERE wt.instance_id = $1
      ORDER BY wt.occurred_at ASC
        "#,
    )
    .bind(workflow_instance_id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Figure out which transitions are legal from the current state
    // so we can render the right set of action buttons. The state
    // machine is the source of truth — do not hard-code here.
    let wf_type = WorkflowType::new("change_request");
    let legal_transitions: Vec<String> = state
        .workflow
        .machine(&wf_type)
        .map(|m| {
            m.all_transitions()
                .iter()
                .filter(|t| t.from_state == current_state)
                .map(|t| t.name.clone())
                .collect()
        })
        .unwrap_or_default();

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar(
        "change_request.list",
        display_name,
        &initials,
        &installed,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
    );

    let requester_display = requester_name.as_deref().unwrap_or(&requester_username);

    let mut action_buttons = String::new();
    if !legal_transitions.is_empty() {
        action_buttons.push_str(r#"<div class="flex flex-wrap gap-2">"#);
        for t in &legal_transitions {
            let label = match t.as_str() {
                "submit" => "Submit for Review",
                "review" => "Start Review",
                "approve" => "Approve",
                "reject" => "Reject",
                "close" => "Close",
                "send_back" => "Send Back",
                "withdraw" => "Withdraw",
                other => other,
            };
            let btn_cls = match t.as_str() {
                "approve" | "close" => "btn-success",
                "reject" => "btn-error",
                "withdraw" | "send_back" => "btn-warning",
                _ => "btn-primary",
            };
            action_buttons.push_str(&format!(
                r#"<form method="POST" action="/change-requests/{}/transition" class="inline"><input type="hidden" name="transition" value="{}"><button type="submit" class="btn btn-sm {}">{}</button></form>"#,
                id,
                html_escape(t),
                btn_cls,
                html_escape(label),
            ));
        }
        action_buttons.push_str("</div>");
    } else {
        action_buttons.push_str(
            r#"<p class="text-base-content/60 text-sm">No transitions available from this state.</p>"#,
        );
    }

    let mut history_html = String::new();
    if history.is_empty() {
        history_html
            .push_str(r#"<p class="text-base-content/60 text-sm">No transitions yet.</p>"#);
    } else {
        history_html.push_str(
            r#"<table class="table table-sm"><thead><tr><th>When</th><th>Who</th><th>Transition</th><th>From → To</th><th>Audit</th></tr></thead><tbody>"#,
        );
        for h in &history {
            let name: String = h.get("transition_name");
            let from: String = h.get("from_state");
            let to: String = h.get("to_state");
            let occurred_at: DateTime<Utc> = h.get("occurred_at");
            let actor: Option<String> = h.get("actor_username");
            let audit_entry_id: Option<Uuid> = h.get("audit_entry_id");
            history_html.push_str(&format!(
                r#"<tr><td class="text-sm">{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code> → <code>{}</code></td><td class="font-mono text-xs">{}</td></tr>"#,
                occurred_at.format("%Y-%m-%d %H:%M"),
                html_escape(actor.as_deref().unwrap_or("system")),
                html_escape(&name),
                html_escape(&from),
                html_escape(&to),
                audit_entry_id
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ));
        }
        history_html.push_str("</tbody></table>");
    }

    let rollback_html = match rollback_plan.as_deref() {
        Some(p) if !p.trim().is_empty() => format!(
            r#"<div><h3 class="font-semibold mt-4">Rollback plan</h3><pre class="bg-base-200 p-3 rounded whitespace-pre-wrap">{}</pre></div>"#,
            html_escape(p)
        ),
        _ => String::new(),
    };

    let body = format!(
        r#"
<div class="mb-4"><a href="/change-requests" class="link link-hover text-sm">&larr; Back to list</a></div>
<div class="flex items-start justify-between mb-6">
  <div><h1 class="text-2xl font-bold font-mono">{number}</h1><p class="text-base-content/60">{title}</p></div>
  <div class="text-right space-y-1">{state_badge}<br>{crit_badge}</div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
<div class="card bg-base-100 shadow lg:col-span-2"><div class="card-body">
<h2 class="card-title">Details</h2>
<p class="whitespace-pre-wrap">{description}</p>
<dl class="mt-4 grid grid-cols-2 gap-y-2 text-sm">
<dt class="text-base-content/60">Category</dt><dd><code>{category}</code></dd>
<dt class="text-base-content/60">Requested by</dt><dd>{requester}</dd>
<dt class="text-base-content/60">Created</dt><dd>{created_at}</dd>
<dt class="text-base-content/60">Workflow instance</dt><dd class="font-mono text-xs">{workflow_instance_id}</dd>
</dl>
{rollback_html}
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Actions</h2>
{action_buttons}
</div></div>
</div>
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Transition history</h2>
{history_html}
<p class="text-xs text-base-content/60 mt-3">Each transition is hash-chained in the WORM audit ledger. Use <code>vortex audit verify</code> to verify integrity.</p>
</div></div>
"#,
        number = html_escape(&number),
        title = html_escape(&title),
        state_badge = state_badge(&current_state),
        crit_badge = criticality_badge(&criticality),
        description = html_escape(&description),
        category = html_escape(&category),
        requester = html_escape(requester_display),
        created_at = created_at.format("%Y-%m-%d %H:%M UTC"),
        workflow_instance_id = workflow_instance_id,
        rollback_html = rollback_html,
        action_buttons = action_buttons,
        history_html = history_html,
    );

    let (prefix, suffix) = page_shell(&format!("{} - Change Request", number), &sidebar);
    Html(format!("{}{}{}", prefix, body, suffix)).into_response()
}

// ─── Transition ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TransitionForm {
    pub transition: String,
    #[serde(default)]
    pub comment: String,
}

async fn cr_transition(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Form(form): Form<TransitionForm>,
) -> Response {
    let company_id = resolve_company_id(&db, user.id).await;

    // Resolve the CR → workflow_instance_id, scoped to tenant so a
    // cross-tenant id guess is a 404, not a stack trace.
    let instance_id: Uuid = match sqlx::query_scalar(
        "SELECT workflow_instance_id FROM change_requests WHERE id = $1 AND company_id = $2",
    )
    .bind(id)
    .bind(company_id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Html(forbidden_page("this change request")))
                .into_response();
        }
        Err(e) => {
            error!(error = %e, "cr_transition lookup failed");
            return error_response("database error");
        }
    };

    // Segregation of duties at the Rust level, as a belt-and-braces
    // second layer on top of the Cedar policies seeded by the
    // plugin's own migration.
    // The Cedar rule *should* already cover this, but a domain
    // invariant like "approver ≠ requester" is cheap to enforce
    // twice and the CI tests rely on both layers.
    if form.transition == "approve" {
        let requester: Uuid = sqlx::query_scalar(
            "SELECT requested_by FROM change_requests WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap_or_default();
        if requester == user.id {
            return (
                StatusCode::FORBIDDEN,
                Html(forbidden_page(
                    "approve your own change request (segregation of duties)",
                )),
            )
                .into_response();
        }
    }

    let principal = principal_for(&user, company_id);
    let ctx = TransitionContext {
        actor: principal,
        context: json!({
            "comment": form.comment,
            "cr_id": id,
        }),
    };

    match state
        .workflow
        .transition(InstanceId(instance_id), &form.transition, ctx)
        .await
    {
        Ok(outcome) => {
            // Touch the CR row's updated_at so list sort stays
            // consistent with the workflow instance. The workflow
            // engine doesn't know about the CR table.
            let _ = sqlx::query("UPDATE change_requests SET updated_at = NOW() WHERE id = $1")
                .bind(id)
                .execute(&db)
                .await;
            warn!(
                cr_id = %id,
                transition = %form.transition,
                from = %outcome.from_state,
                to = %outcome.to_state,
                "cr transition succeeded"
            );
            Redirect::to(&format!("/change-requests/{}", id)).into_response()
        }
        Err(e) => {
            warn!(cr_id = %id, transition = %form.transition, error = %e, "cr transition refused");
            (
                StatusCode::FORBIDDEN,
                Html(forbidden_page(&format!(
                    "transition '{}': {}",
                    form.transition, e
                ))),
            )
                .into_response()
        }
    }
}
